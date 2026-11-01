"""Production hardening: settlement idempotency, orphan sweeps, receipt binding, key rotation,
per-tree serialization, information exposure, request limits, grant hygiene, operator identity."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from writ.canon import hash_obj
from writ.client import GateAPIError, GateClient
from writ.executor.nonces import NonceStore
from writ.gate.app import create_app as create_gate
from writ.gate.store import SCHEMA_VERSION, SchemaTooNew, Store, iso
from writ.grant import Constraint, ConstraintViolation, check_constraint
from writ.signing import KeyRing, Signer, signed_envelope, verify_envelope

from .conftest import ADMIN_TOKEN, INTERNAL_TOKEN, Harness

REFUND = {"charge_id": "ch_1002", "amount_cents": 100, "reason": "dup"}


def _orphan_authorization(h: Harness, task: dict, status: str, **overrides) -> str:
    """Insert an authorization as a crashed gate would have left it, with its budget reserved."""
    auth_id = f"auth_{status}_orphan"
    now = h.clock()
    row = {
        "id": auth_id,
        "task_id": task["id"],
        "command": "billing.refund",
        "args_json": json.dumps(REFUND, sort_keys=True),
        "args_hash": hash_obj(REFUND),
        "charges_json": json.dumps({"money_cents": 100, "refunds": 1}),
        "integration": "demo_billing",
        "config_version": "static-1",
        "effects_json": "[]",
        "envelope_json": "{}",
        "status": status,
        "issued_at": iso(now),
        "expires_at": iso(now.replace(microsecond=0)) if status != "issued" else overrides.pop("expires_at"),
    }
    row.update(overrides)
    h.store.insert_authorization(row)
    if status == "consumed":
        with h.store.tx() as c:
            c.execute("UPDATE authorizations SET consumed_at=? WHERE id=?", (iso(now), auth_id))
    h.store.reserve_budgets(h.store.task_chain(task["id"]), {"money_cents": 100, "refunds": 1})
    return auth_id


# ----------------------------------------------------------------------------- settlement


def test_settlement_happens_at_most_once(h):
    task, tok = h.create_scenario_task()
    r = h.agent(tok).invoke("billing.refund", REFUND)
    assert r["status"] == "committed"
    row = h.store.get_authorization(r["authorization_id"])
    # Any later settlement attempt, from any path, is a no-op: the row is already final.
    assert not h.service._settle(
        row,
        commit=False,
        final_status="released",
        outcome={"error": "late revoke"},
        receipt=None,
        expected=("issued", "held", "consumed"),
    )
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"] == {"reserved": 0, "committed": 100}
    assert h.store.get_authorization(r["authorization_id"])["status"] == "committed"


def test_sweep_releases_expired_issued_authorizations(h):
    """A gate that minted an authorization and died before dispatch must not pin the budget forever."""
    task, _ = h.create_scenario_task()
    from datetime import timedelta

    _orphan_authorization(h, task, "issued", expires_at=iso(h.clock() + timedelta(seconds=60)))
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"]["reserved"] == 100
    assert h.service.authorization_sweep()["released_expired"] == 0  # not expired yet
    h.clock.advance(61)
    assert h.service.authorization_sweep()["released_expired"] == 1
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"] == {"reserved": 0, "committed": 0}
    assert h.store.get_authorization("auth_issued_orphan")["status"] == "released"


def test_sweep_marks_stale_consumed_as_unknown_and_keeps_reservation(h):
    task, _ = h.create_scenario_task()
    _orphan_authorization(h, task, "consumed")
    h.clock.advance(h.service.stale_consumed_seconds + 1)
    assert h.service.authorization_sweep()["marked_unknown"] == 1
    assert h.store.get_authorization("auth_consumed_orphan")["status"] == "unknown"
    # The upstream may have acted: nobody may spend this reservation until reconciled.
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"]["reserved"] == 100


def test_sweep_auto_reconciles_unknown_outcomes(h):
    task, tok = h.create_scenario_task()
    h.chaos(fail_after_commit=1)
    r = h.agent(tok).invoke("billing.refund", {**REFUND, "amount_cents": 14900})
    assert r["status"] == "unknown"
    assert h.service.authorization_sweep()["reconciled"] == 0  # too fresh
    h.clock.advance(h.service.reconcile_after_seconds + 1)
    assert h.service.authorization_sweep()["reconciled"] == 1
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"] == {"reserved": 0, "committed": 14900}
    types = [e["type"] for e in h.admin.ledger(root_id=task["id"])]
    assert "AUTHORIZATION_RECONCILED" in types


def test_admin_sweep_endpoint(h):
    task, tok = h.create_scenario_task(ttl=100)
    h.clock.advance(101)
    out = h.admin.sweep()
    assert out["expired_tasks"] == 1
    assert h.admin.get_task(task["id"])["status"] == "expired"


def test_expired_task_sweep_voids_held_authorizations(h):
    task, tok = h.create_scenario_task(intent=True, ttl=300)
    agent = h.agent(tok)
    agent.invoke("crm.get_customer", {"customer_id": "cus_123"})
    r = agent.invoke(
        "email.send", {"to": "ap@acme.example", "subject": "s", "body": "Owner: cfo@acme.example"}
    )
    assert r["status"] == "held"
    assert h.admin.get_task(task["id"])["budgets"]["sends"]["reserved"] == 1
    h.clock.advance(301)
    assert h.service.expire_sweep() == 1
    assert h.store.get_authorization(r["authorization_id"])["status"] == "released"
    assert h.admin.get_task(task["id"])["budgets"]["sends"] == {"reserved": 0, "committed": 0}


# ----------------------------------------------------------------------------- receipts


def test_response_without_receipt_is_unknown_until_reconciled(h, monkeypatch):
    """Something on the control network strips the receipt: the gate does not believe the status."""
    task, tok = h.create_scenario_task()
    real = h.service.executor.execute

    def strip(envelope, args, timeout):
        resp = real(envelope, args, timeout)
        resp.pop("receipt", None)
        return resp

    monkeypatch.setattr(h.service.executor, "execute", strip)
    r = h.agent(tok).invoke("billing.refund", REFUND)
    assert r["status"] == "unknown" and "no receipt" in r["error"]
    assert r["result"] is None
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"] == {"reserved": 100, "committed": 0}
    rec = h.admin.reconcile(r["authorization_id"])
    assert rec["reconciled"] and rec["status"] == "committed"
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"] == {"reserved": 0, "committed": 100}


@pytest.mark.parametrize("tamper", ["status", "result"])
def test_receipt_must_agree_with_response(h, monkeypatch, tamper):
    _, tok = h.create_scenario_task()
    real = h.service.executor.execute

    def lie(envelope, args, timeout):
        resp = real(envelope, args, timeout)
        if tamper == "status":
            resp["status"] = "failed"  # receipt still says ok
        else:
            resp["result"] = {"refund": {"id": "re_forged", "amount_cents": 1}}
        return resp

    monkeypatch.setattr(h.service.executor, "execute", lie)
    r = h.agent(tok).invoke("billing.refund", REFUND)
    assert r["status"] == "unknown", r
    assert "receipt" in r["error"] and r["receipt"] is None


def test_early_rejections_carry_verifiable_receipts(h):
    """Even a rejection before any work is signed, so a forged 'rejected' cannot free a budget."""
    _, tok = h.create_scenario_task()
    r = h.agent(tok).invoke("billing.refund", REFUND)
    auth = h.admin.get_authorization(r["authorization_id"])
    forged = signed_envelope(Signer.generate(), {**auth["envelope"]["payload"], "id": "auth_forged"})
    rr = h.executor.post(
        "/v1/execute",
        json={"authorization": forged, "args": auth["args"]},
        headers={"Authorization": f"Bearer {INTERNAL_TOKEN}"},
    ).json()
    assert rr["status"] == "rejected"
    assert verify_envelope(h.exec_signer.verifier, rr["receipt"])
    assert rr["receipt"]["payload"]["status"] == "rejected"
    assert rr["receipt"]["payload"]["authorization_id"] == "auth_forged"


def test_executor_adapter_bug_after_consume_is_unknown(h, monkeypatch):
    task, tok = h.create_scenario_task()
    adapter = h.registry.get("billing")

    def boom(*a, **k):
        raise RuntimeError("adapter bug")

    monkeypatch.setattr(adapter, "execute", boom)
    r = h.agent(tok).invoke("billing.refund", REFUND)
    assert r["status"] == "unknown" and "adapter failure" in r["error"]
    # Reconcile: the nonce was claimed but the upstream never saw the key.
    rec = h.admin.reconcile(r["authorization_id"])
    assert rec["reconciled"] and rec["status"] == "released"
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"] == {"reserved": 0, "committed": 0}


# ----------------------------------------------------------------------------- key rotation


def test_key_ring_accepts_any_trusted_key_and_nothing_else():
    a, b, c = Signer.generate(), Signer.generate(), Signer.generate()
    ring = KeyRing.from_encoded(f"{a.verifier.encoded_public()},{b.verifier.encoded_public()}")
    assert ring.key_ids == sorted([a.verifier.key_id, b.verifier.key_id])
    env = signed_envelope(b, {"x": 1})
    assert verify_envelope(ring, env)
    assert not verify_envelope(ring, signed_envelope(c, {"x": 1}))
    # Key id spoofing: a signature by c presented under b's key id does not verify.
    assert not verify_envelope(ring, {**signed_envelope(c, {"x": 1}), "key_id": b.verifier.key_id})
    with pytest.raises(ValueError):
        KeyRing.from_encoded("")


def test_gate_accepts_receipts_from_a_rotated_executor_key(h, monkeypatch):
    new_signer = Signer.generate()
    real = h.service.executor.execute

    def resign(envelope, args, timeout):
        resp = real(envelope, args, timeout)
        resp["receipt"] = signed_envelope(new_signer, resp["receipt"]["payload"])
        return resp

    monkeypatch.setattr(h.service.executor, "execute", resign)
    _, tok = h.create_scenario_task()
    # Not yet trusted: unknown.
    assert h.agent(tok).invoke("billing.refund", REFUND)["status"] == "unknown"
    # Operator adds the new key alongside the old one: committed.
    h.service.executor_keys = KeyRing([h.exec_signer.verifier, new_signer.verifier])
    r = h.agent(tok).invoke("billing.refund", {**REFUND, "charge_id": "ch_1001"})
    assert r["status"] == "committed", r
    assert len(h.admin.keys()["executor_keys"]) == 2


# ----------------------------------------------------------------------------- concurrency


def test_concurrent_denials_are_all_counted_as_evidence(h):
    """Parallel probes must not race each other out of the intent state (lost updates)."""
    task, tok = h.create_scenario_task(intent=True)
    n = 16
    results: list[dict] = []
    lock = threading.Lock()

    def worker():
        r = h.agent(tok).invoke("crm.get_customer", {"customer_id": "cus_999"})
        with lock:
            results.append(r)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r["denial"]["reason"] == "CONSTRAINT_VIOLATION" for r in results)
    assert h.admin.get_task(task["id"])["intent"]["steps"] == n


# ----------------------------------------------------------------------------- exposure


def test_agent_sees_decisions_not_detector_statistics(h):
    task, tok = h.create_scenario_task(intent=True)
    agent = h.agent(tok)
    me = agent.me()
    assert me["intent"] == {"mode": "normal"}
    assert "intent_spec" not in me and "principal" not in me
    r = agent.invoke(
        "crm.update_customer", {"customer_id": "cus_123", "fields": {"billing_contact": "x@evil.example"}}
    )
    assert r["decision"] == "denied"
    assert set(r["intent"]) <= {"claims", "provenance", "mode"}
    view = h.admin.get_task(task["id"])
    assert {"e_value", "forecast", "non_goal_mass", "steps"} <= set(view["intent"])
    child = agent.delegate(
        "c", {"commands": [{"command": "crm.get_customer", "args": {"customer_id": {"eq": "cus_123"}}}]}
    )
    assert "intent_spec" not in child["task"]


def test_unknown_commands_do_not_create_metric_series(h):
    _, tok = h.create_scenario_task()
    h.agent(tok).invoke("totally.made_up_" + "x" * 50, {})
    text = h.gate.get("/metrics").text
    assert 'command="<unknown>"' in text
    assert "made_up" not in text


def test_docs_are_off_by_default(h):
    assert h.gate.get("/docs").status_code == 404
    assert h.gate.get("/openapi.json").status_code == 404


# ----------------------------------------------------------------------------- idempotency


def test_idempotency_key_replays_the_original_result(h):
    task, tok = h.create_scenario_task()
    agent = h.agent(tok)
    r1 = agent.invoke("billing.refund", REFUND, idempotency_key="retry-1")
    r2 = agent.invoke("billing.refund", REFUND, idempotency_key="retry-1")
    assert r1["status"] == "committed" and not r1["replayed"]
    assert r2["replayed"] and r2["authorization_id"] == r1["authorization_id"]
    assert len(h.saas_state()["refunds"]) == 1
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"]["committed"] == 100
    with pytest.raises(GateAPIError) as ei:
        agent.invoke("billing.refund", {**REFUND, "amount_cents": 200}, idempotency_key="retry-1")
    assert ei.value.code == "IDEMPOTENCY_MISMATCH"
    # Keys are per task: another task may reuse the same key.
    _, tok2 = h.create_scenario_task()
    assert h.agent(tok2).invoke("billing.refund", REFUND, idempotency_key="retry-1")["status"] == "committed"


def test_idempotency_key_bounds(h):
    _, tok = h.create_scenario_task()
    r = h.gate.post(
        "/v1/invoke",
        json={"command": "crm.get_customer", "args": {"customer_id": "cus_123"}},
        headers={"Authorization": f"Bearer {tok}", "Idempotency-Key": "k" * 129},
    )
    assert r.status_code == 422 and r.json()["code"] == "INVALID_REQUEST"


# ----------------------------------------------------------------------------- request limits


def test_body_size_and_rate_limits(tmp_path: Path):
    h = Harness(tmp_path)
    gate = TestClient(
        create_gate(
            h.service,
            ADMIN_TOKEN,
            INTERNAL_TOKEN,
            sweep_interval=0,
            max_body_bytes=2048,
            agent_rate_per_second=1,
            agent_burst=3,
        )
    )
    admin = GateClient(http=gate, token=ADMIN_TOKEN)
    tok = admin.create_task("t", h.template_grant())["token"]
    hdr = {"Authorization": f"Bearer {tok}"}
    big = gate.post("/v1/invoke", json={"command": "x", "args": {"pad": "a" * 5000}}, headers=hdr)
    assert big.status_code == 413 and big.json()["code"] == "PAYLOAD_TOO_LARGE"
    codes = [gate.get("/v1/me", headers=hdr).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and 429 in codes[3:]
    # Operators are not rate limited by the agent limiter.
    assert all(
        gate.get("/v1/admin/status", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}).status_code == 200
        for _ in range(5)
    )


def test_oversized_names_and_metadata_are_rejected(h):
    with pytest.raises(GateAPIError) as ei:
        h.admin.create_task("n" * 201, h.template_grant())
    assert ei.value.status_code == 422
    with pytest.raises(GateAPIError) as ei:
        h.admin.create_task("ok", h.template_grant(), metadata={"blob": "x" * 20000})
    assert ei.value.status_code == 422


# ----------------------------------------------------------------------------- grant hygiene


def test_booleans_never_satisfy_numeric_or_enum_constraints():
    with pytest.raises(ConstraintViolation):
        check_constraint("n", True, Constraint.model_validate({"eq": 1}))
    with pytest.raises(ConstraintViolation):
        check_constraint("n", True, Constraint.model_validate({"in": [1, 2]}))
    check_constraint("n", 1, Constraint.model_validate({"eq": 1}))
    with pytest.raises(ValueError):
        Constraint.model_validate({"min": 5, "max": 1})


def test_negative_budget_is_rejected_at_creation(h):
    grant = h.template_grant()
    grant["budgets"]["sends"] = -1
    with pytest.raises(GateAPIError) as ei:
        h.admin.create_task("x", grant)
    assert ei.value.status_code == 422


def test_agents_cannot_introduce_regex_constraints(h):
    _, tok = h.create_scenario_task()
    with pytest.raises(GateAPIError) as ei:
        h.agent(tok).delegate(
            "c",
            {
                "commands": [
                    {
                        "command": "email.send",
                        "args": {"to": {"eq": "ap@acme.example"}, "subject": {"matches": "(a+)+$"}},
                    }
                ],
                "budgets": {"sends": 1},
            },
        )
    assert ei.value.code == "ATTENUATION_VIOLATION" and "matches" in ei.value.detail
    # Enumerations on new paths are fine.
    h.agent(tok).delegate(
        "c",
        {
            "commands": [
                {
                    "command": "email.send",
                    "args": {"to": {"eq": "ap@acme.example"}, "subject": {"in": ["Refund"]}},
                }
            ],
            "budgets": {"sends": 1},
        },
    )


def test_tree_size_is_capped(h):
    h.service.max_tasks_per_tree = 3
    _, tok = h.create_scenario_task()
    g = {"commands": [{"command": "crm.get_customer", "args": {"customer_id": {"eq": "cus_123"}}}]}
    h.agent(tok).delegate("a", g)
    h.agent(tok).delegate("b", g)
    with pytest.raises(GateAPIError) as ei:
        h.agent(tok).delegate("c", g)
    assert ei.value.code == "TREE_LIMIT" and ei.value.status_code == 429


def test_approve_rechecks_consequences(h, monkeypatch):
    """A hold is approved later; if the action would now cause a forbidden effect, it is refused and released."""
    task, tok = h.create_scenario_task(intent=True)
    agent = h.agent(tok)
    agent.invoke("crm.get_customer", {"customer_id": "cus_123"})
    r = agent.invoke(
        "email.send", {"to": "ap@acme.example", "subject": "s", "body": "Owner: cfo@acme.example"}
    )
    assert r["status"] == "held"
    real = h.service.executor.predict

    def predict_export(*a, **k):
        out = real(*a, **k)
        out["effects"] = out["effects"] + [{"type": "external_export", "detail": {"destination": "x"}}]
        return out

    monkeypatch.setattr(h.service.executor, "predict", predict_export)
    with pytest.raises(GateAPIError) as ei:
        h.admin.approve(r["authorization_id"])
    assert ei.value.code == "FORBIDDEN_EFFECT"
    assert h.admin.get_authorization(r["authorization_id"])["status"] == "released"
    assert h.admin.get_task(task["id"])["budgets"]["sends"] == {"reserved": 0, "committed": 0}
    assert h.saas_state()["emails"] == []


# ----------------------------------------------------------------------------- operators


def test_named_operators_are_recorded_in_the_ledger(tmp_path: Path):
    h = Harness(tmp_path)
    alice, bob = "alice-token-0123456789abcdef", "bob-token-0123456789abcdefgh"
    gate = TestClient(create_gate(h.service, {"alice": alice, "bob": bob}, INTERNAL_TOKEN, sweep_interval=0))
    a, b = GateClient(http=gate, token=alice), GateClient(http=gate, token=bob)
    assert a.status()["operator"] == "alice"
    task = a.create_task("t", h.template_grant())["task"]
    assert task["principal"] == "alice"
    b.revoke(task["id"], "cleanup")
    entries = {e["type"]: e["payload"] for e in b.ledger(root_id=task["id"])}
    assert entries["TASK_CREATED"]["actor"] == "alice"
    assert entries["TASK_REVOKED"]["actor"] == "bob"
    with pytest.raises(GateAPIError):
        GateClient(http=gate, token="not-a-token-0123456789abcdef").status()


# ----------------------------------------------------------------------------- stores


def test_nonce_store_purges_old_records():
    n = NonceStore(":memory:")
    assert n.claim("a", "2026-01-01T00:00:00Z") and n.claim("b", "2026-06-01T00:00:00Z")
    assert not n.claim("a", "2026-07-01T00:00:00Z")
    assert n.purge_before("2026-03-01T00:00:00Z") == 1
    assert n.status("a") is None and n.status("b") == "claimed" and n.count() == 1


def test_schema_version_is_recorded_and_newer_databases_are_refused(tmp_path: Path):
    path = str(tmp_path / "g.db")
    s = Store(path)
    assert s.get_setting("schema_version") == str(SCHEMA_VERSION)
    s.set_setting("schema_version", str(SCHEMA_VERSION + 1))
    s.close()
    with pytest.raises(SchemaTooNew):
        Store(path)


def test_ledger_verify_streams_over_pages(h):
    _, tok = h.create_scenario_task()
    for _ in range(3):
        h.agent(tok).invoke("crm.get_customer", {"customer_id": "cus_123"})
    v = h.admin.ledger_verify()
    assert v["ok"] and v["entries"] == len(list(h.admin.iter_ledger(page=2))) and v["head"]


def test_transient_denials_are_not_pinned_to_an_idempotency_key(h):
    _, tok = h.create_scenario_task()
    agent = h.agent(tok)
    h.admin.halt("incident")
    r = agent.invoke("billing.refund", REFUND, idempotency_key="k-halt")
    assert r["denial"]["reason"] == "HALTED"
    h.admin.unhalt("over")
    r = agent.invoke("billing.refund", REFUND, idempotency_key="k-halt")
    assert r["status"] == "committed" and not r["replayed"]
    # A substantive denial is replayed as recorded.
    bad = {**REFUND, "amount_cents": 20001}
    r1 = agent.invoke("billing.refund", bad, idempotency_key="k-deny")
    r2 = agent.invoke("billing.refund", bad, idempotency_key="k-deny")
    assert r1["denial"]["reason"] == "CONSTRAINT_VIOLATION" and r2["replayed"]


# ----------------------------------------------------------------------------- review follow-ups


def test_replayed_rejection_cannot_release_an_executed_action(h, monkeypatch):
    """Transport attacker: forward the real request (it executes), then hand the gate the executor's
    signed 'replay' rejection. The gate must not take that as proof of inaction."""
    task, tok = h.create_scenario_task()
    real = h.service.executor.execute

    def forward_then_replay(envelope, args, timeout):
        real(envelope, args, timeout)  # executes upstream
        return real(envelope, args, timeout)  # second presentation: signed 'rejected' (replay)

    monkeypatch.setattr(h.service.executor, "execute", forward_then_replay)
    r = h.agent(tok).invoke("billing.refund", REFUND)
    assert r["status"] == "unknown", r
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"] == {"reserved": 100, "committed": 0}
    assert h.saas_state()["charges"]["ch_1002"]["refunded_cents"] == 100
    rec = h.admin.reconcile(r["authorization_id"])
    assert rec["status"] == "committed"
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"] == {"reserved": 0, "committed": 100}


def test_reservation_never_exists_without_an_authorization_row(h, monkeypatch):
    task, tok = h.create_scenario_task()

    def boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(h.store, "insert_authorization", boom)
    # The in-process test client re-raises server exceptions; over HTTP this is a 500 INTERNAL.
    with pytest.raises((GateAPIError, RuntimeError)):
        h.agent(tok).invoke("billing.refund", REFUND)
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"] == {"reserved": 0, "committed": 0}
    assert h.admin.authorizations(root_id=task["id"]) == []


def test_non_finite_numbers_are_not_numbers():
    with pytest.raises(ValueError):
        Constraint.model_validate({"max": float("nan")})
    with pytest.raises(ValueError):
        Constraint.model_validate({"in": [1, float("inf")]})
    with pytest.raises(ConstraintViolation):
        check_constraint("n", float("nan"), Constraint.model_validate({"max": 10}))


def test_constraint_values_are_bounded():
    with pytest.raises(ValueError):
        Constraint.model_validate({"eq": "a" * 1025})
    with pytest.raises(ValueError):
        Constraint.model_validate({"in": [{"nested": 1}]})


def test_unicode_digit_paths_do_not_crash(h):
    _, tok = h.create_scenario_task()
    child = h.agent(tok).delegate(
        "c",
        {
            "commands": [
                {"command": "email.send", "args": {"to": {"eq": "ap@acme.example"}, "to.²": {"eq": "x"}}}
            ],
            "budgets": {"sends": 1},
        },
    )
    r = h.agent(child["token"]).invoke("email.send", {"to": "ap@acme.example", "subject": "s", "body": "b"})
    assert r["decision"] == "denied" and r["denial"]["reason"] == "CONSTRAINT_VIOLATION"


def test_chunked_body_over_limit_never_reaches_the_handler(tmp_path: Path):
    h = Harness(tmp_path)
    gate = TestClient(
        create_gate(h.service, ADMIN_TOKEN, INTERNAL_TOKEN, sweep_interval=0, max_body_bytes=2048)
    )
    tok = GateClient(http=gate, token=ADMIN_TOKEN).create_task("t", h.template_grant())["token"]
    first = json.dumps({"command": "billing.refund", "args": REFUND}).encode()
    chunks = iter([first, b" " * 4096])  # valid JSON first, then padding past the limit
    r = gate.post(
        "/v1/invoke",
        content=chunks,
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
    )
    assert r.status_code == 413
    assert h.saas_state()["refunds"] == []


def test_idempotency_claims_are_owned_by_their_attempt(h):
    task, _ = h.create_scenario_task()
    s = h.store
    assert s.idempotency_begin(
        task["id"], "k", "h1", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "A"
    ) == ("new", None)
    # A is stale; B takes the claim over. A's late finish is ignored; B's is recorded.
    assert s.idempotency_begin(
        task["id"], "k", "h1", "2026-01-02T00:00:00Z", "2026-01-01T12:00:00Z", "B"
    ) == ("new", None)
    assert not s.idempotency_finish(task["id"], "k", {"from": "A"}, "A")
    assert s.idempotency_finish(task["id"], "k", {"from": "B"}, "B")
    assert s.idempotency_begin(
        task["id"], "k", "h1", "2026-01-03T00:00:00Z", "2026-01-01T00:00:00Z", "C"
    ) == (
        "done",
        {"from": "B"},
    )


def test_gate_requires_executor_keys(h):
    from writ.gate.service import GateService

    with pytest.raises(ValueError):
        GateService(h.store, h.table, h.gate_signer, h.service.executor, None)
