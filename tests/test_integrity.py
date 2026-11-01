"""Ambiguous outcomes, replay, tampering, ledger integrity, concurrency."""

import json
import threading

from writ.canon import hash_obj
from writ.signing import Signer, signed_envelope

from .conftest import INTERNAL_TOKEN


def test_ambiguous_outcome_keeps_budget_until_reconciled(h):
    task, tok = h.create_scenario_task()
    h.chaos(fail_after_commit=1)
    r = h.agent(tok).invoke(
        "billing.refund", {"charge_id": "ch_1002", "amount_cents": 14900, "reason": "dup"}
    )
    assert r["status"] == "unknown", r
    assert r["budgets"]["money_cents"] == {"reserved": 14900, "committed": 0}
    # The upstream did apply it; nobody can spend the reserved amount again meanwhile.
    assert h.saas_state()["charges"]["ch_1002"]["refunded_cents"] == 14900
    r2 = h.agent(tok).invoke(
        "billing.refund", {"charge_id": "ch_1001", "amount_cents": 6000, "reason": "dup"}
    )
    assert r2["denial"]["reason"] == "BUDGET_EXCEEDED"

    rec = h.admin.reconcile(r["authorization_id"])
    assert rec["reconciled"] and rec["status"] == "committed"
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"] == {"reserved": 0, "committed": 14900}
    assert len(h.saas_state()["refunds"]) == 1  # no duplicate refund was ever issued


def test_reconcile_not_executed_releases_budget(h):
    """Executor never saw the authorization (e.g. gate->executor transport failed)."""
    task, tok = h.create_scenario_task()
    r = h.agent(tok).invoke("billing.refund", {"charge_id": "ch_1002", "amount_cents": 1000, "reason": "dup"})
    auth = h.admin.get_authorization(r["authorization_id"])
    # Forge an 'unknown' state as the gate would after a transport failure, for an auth the executor never saw.
    fresh = h.service.invoke  # noqa: F841
    envelope = signed_envelope(h.gate_signer, {**auth["envelope"]["payload"], "id": "auth_never_sent"})
    h.store.insert_authorization(
        {
            "id": "auth_never_sent",
            "task_id": task["id"],
            "command": "billing.refund",
            "args_json": json.dumps(auth["args"]),
            "args_hash": auth["args"] and hash_obj(auth["args"]),
            "charges_json": json.dumps({"money_cents": 1000, "refunds": 1}),
            "integration": "demo_billing",
            "config_version": "static-1",
            "effects_json": "[]",
            "envelope_json": json.dumps(envelope),
            "status": "unknown",
            "issued_at": auth["issued_at"],
            "expires_at": auth["expires_at"],
        }
    )
    h.store.reserve_budgets(h.store.task_chain(task["id"]), {"money_cents": 1000, "refunds": 1})
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"]["reserved"] == 1000
    rec = h.admin.reconcile("auth_never_sent")
    assert rec["reconciled"] and rec["status"] == "released"
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"] == {"reserved": 0, "committed": 1000}


def test_replay_and_tamper_against_executor(h):
    _, tok = h.create_scenario_task()
    r = h.agent(tok).invoke("billing.refund", {"charge_id": "ch_1002", "amount_cents": 100, "reason": "dup"})
    auth = h.admin.get_authorization(r["authorization_id"])
    hdr = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}
    # Replay of a consumed authorization: executor's nonce store rejects it before even calling the gate.
    rr = h.executor.post(
        "/v1/execute", json={"authorization": auth["envelope"], "args": auth["args"]}, headers=hdr
    ).json()
    assert rr["status"] == "rejected" and "already presented" in rr["error"]
    # Tampered arguments under a valid signature.
    args2 = {**auth["args"], "amount_cents": 14900}
    rr = h.executor.post(
        "/v1/execute", json={"authorization": auth["envelope"], "args": args2}, headers=hdr
    ).json()
    assert rr["status"] == "rejected" and "do not match" in rr["error"]
    # Forged authorization signed by someone else.
    forged = signed_envelope(
        Signer.generate(), {**auth["envelope"]["payload"], "id": "auth_forged", "args_hash": hash_obj(args2)}
    )
    rr = h.executor.post("/v1/execute", json={"authorization": forged, "args": args2}, headers=hdr).json()
    assert rr["status"] == "rejected" and "signature" in rr["error"]
    # Without the internal token nothing is reachable.
    assert (
        h.executor.post(
            "/v1/execute", json={"authorization": auth["envelope"], "args": auth["args"]}
        ).status_code
        == 401
    )
    assert h.saas_state()["charges"]["ch_1002"]["refunded_cents"] == 100


def test_gate_rejects_bad_receipts(h, monkeypatch):
    """A compromised executor cannot report success with an unverifiable receipt."""
    _, tok = h.create_scenario_task()
    real = h.service.executor.execute

    def lying_execute(envelope, args, timeout):
        resp = real(envelope, args, timeout)
        resp["receipt"]["signature"] = resp["receipt"]["signature"][:-4] + "AAAA"
        return resp

    monkeypatch.setattr(h.service.executor, "execute", lying_execute)
    r = h.agent(tok).invoke("billing.refund", {"charge_id": "ch_1002", "amount_cents": 100, "reason": "dup"})
    assert r["status"] == "unknown" and "receipt" in r["error"]


def test_ledger_chain_verifies_and_detects_tampering(h):
    _, tok = h.create_scenario_task()
    h.agent(tok).invoke("crm.get_customer", {"customer_id": "cus_123"})
    h.agent(tok).invoke("email.send", {"to": "nobody@evil.example", "subject": "s", "body": "b"})
    v = h.admin.ledger_verify()
    assert v["ok"] and v["entries"] >= 4
    types = [e["type"] for e in h.admin.ledger()]
    assert "TASK_CREATED" in types and "INVOKE_DENIED" in types and "AUTHORIZATION_SETTLED" in types
    # Tamper with history directly in the database.
    with h.store.tx() as c:
        c.execute(
            "UPDATE ledger SET payload_json = replace(payload_json, 'INVOKE', 'XX') WHERE type='INVOKE_DENIED'"
        )
        c.execute(
            "UPDATE ledger SET payload_json = json_set(payload_json, '$.reason', 'nothing happened') WHERE type='INVOKE_DENIED'"
        )
    v = h.admin.ledger_verify()
    assert not v["ok"] and "hash mismatch" in v["error"]


def test_concurrent_subagents_cannot_overspend(h):
    """20 parallel refunds of 1000 against a 5000 budget: exactly five commit."""
    grant = h.template_grant(max_refund_cents=5000)
    grant["budgets"]["refunds"] = 100
    task = h.admin.create_task("concurrency", grant)
    tok = task["token"]
    results: list[dict] = []
    lock = threading.Lock()

    def worker():
        r = h.agent(tok).invoke(
            "billing.refund", {"charge_id": "ch_1001", "amount_cents": 1000, "reason": "race"}
        )
        with lock:
            results.append(r)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    committed = [r for r in results if r.get("status") == "committed"]
    denied = [r for r in results if r.get("decision") == "denied"]
    assert len(committed) == 5, [r.get("status") or r["denial"]["reason"] for r in results]
    assert len(denied) == 15 and all(r["denial"]["reason"] == "BUDGET_EXCEEDED" for r in denied)
    assert h.saas_state()["charges"]["ch_1001"]["refunded_cents"] == 5000
    assert h.admin.get_task(task["task"]["id"])["budgets"]["money_cents"] == {
        "reserved": 0,
        "committed": 5000,
    }
    assert h.admin.ledger_verify()["ok"]
