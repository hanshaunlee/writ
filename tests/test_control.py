"""Revocation, halt, leases, configuration drift."""

import pytest

from writ.client import GateAPIError
from writ.gate.executor_client import ExecutorClient
from writ.gate.service import GateError

from .conftest import Harness


def test_revoke_cascades_to_descendants(h):
    task, tok = h.create_scenario_task()
    child = h.agent(tok).delegate(
        "c", {"commands": [{"command": "crm.get_customer", "args": {"customer_id": {"eq": "cus_123"}}}]}
    )
    grandchild = h.agent(child["token"]).delegate(
        "gc", {"commands": [{"command": "crm.get_customer", "args": {"customer_id": {"eq": "cus_123"}}}]}
    )
    assert (
        h.agent(grandchild["token"]).invoke("crm.get_customer", {"customer_id": "cus_123"})["status"]
        == "committed"
    )

    res = h.admin.revoke(task["id"], "operator kill switch")
    assert set(res["revoked"]) == {task["id"], child["task"]["id"], grandchild["task"]["id"]}
    for t in (tok, child["token"], grandchild["token"]):
        r = h.agent(t).invoke("crm.get_customer", {"customer_id": "cus_123"})
        assert r["denial"]["reason"] == "TASK_INACTIVE"
        with pytest.raises(GateAPIError) as ei:
            h.agent(t).delegate("x", {"commands": []})
        assert ei.value.code == "TASK_INACTIVE"
    assert h.admin.get_task(grandchild["task"]["id"])["status"] == "revoked"


def test_revoking_a_child_leaves_parent_intact(h):
    task, tok = h.create_scenario_task()
    child = h.agent(tok).delegate(
        "c", {"commands": [{"command": "crm.get_customer", "args": {"customer_id": {"eq": "cus_123"}}}]}
    )
    h.admin.revoke(child["task"]["id"], "scope down")
    assert (
        h.agent(child["token"]).invoke("crm.get_customer", {"customer_id": "cus_123"})["denial"]["reason"]
        == "TASK_INACTIVE"
    )
    assert h.agent(tok).invoke("crm.get_customer", {"customer_id": "cus_123"})["status"] == "committed"


def test_revocation_mid_flight_blocks_execution(tmp_path):
    """Authorization issued, then the task is revoked before the executor consumes it."""
    state = {}

    def wrapper(harness: Harness, inner: ExecutorClient):
        class Interposer(ExecutorClient):
            def __init__(self):
                self._inner = inner

            def config_versions(self, i):
                return inner.config_versions(i)

            def predict(self, *a, **k):
                return inner.predict(*a, **k)

            def execute(self, envelope, args, timeout):
                harness.admin.revoke(state["task_id"], "revoked while executor was about to act")
                return inner.execute(envelope, args, timeout)

            def reconcile(self, *a, **k):
                return inner.reconcile(*a, **k)

            def health(self):
                return inner.health()

        return Interposer()

    h = Harness(tmp_path, executor_client_wrapper=wrapper)
    task, tok = h.create_scenario_task()
    state["task_id"] = task["id"]
    r = h.agent(tok).invoke(
        "billing.refund", {"charge_id": "ch_1002", "amount_cents": 14900, "reason": "dup"}
    )
    assert r["decision"] == "allowed" and r["status"] in ("rejected", "released"), r
    assert h.saas_state()["refunds"] == []
    auth = h.admin.get_authorization(r["authorization_id"])
    assert auth["status"] == "released"
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"] == {"reserved": 0, "committed": 0}


def test_halt_stops_everything_including_consume(h):
    _, tok = h.create_scenario_task()
    h.admin.halt("incident")
    r = h.agent(tok).invoke("crm.get_customer", {"customer_id": "cus_123"})
    assert r["denial"]["reason"] == "HALTED"
    with pytest.raises(GateError):
        h.service.consume("auth_anything")
    h.admin.unhalt("resolved")
    assert h.agent(tok).invoke("crm.get_customer", {"customer_id": "cus_123"})["status"] == "committed"


def test_lease_expiry_and_operator_renewal(h):
    task, tok = h.create_scenario_task(ttl=100)
    agent = h.agent(tok)
    assert agent.invoke("crm.get_customer", {"customer_id": "cus_123"})["status"] == "committed"
    h.clock.advance(101)
    assert agent.invoke("crm.get_customer", {"customer_id": "cus_123"})["denial"]["reason"] == "TASK_EXPIRED"
    assert h.service.expire_sweep() == 1
    # Sweep marks it expired; renewal of an inactive task is refused (operator creates a new one).
    with pytest.raises(GateAPIError) as ei:
        h.admin.renew(task["id"], 100)
    assert ei.value.code == "TASK_INACTIVE"


def test_renewal_is_capped(h):
    task, tok = h.create_scenario_task(ttl=100)
    renewed = h.admin.renew(task["id"], 10**9)
    assert renewed["expires_at"] == task["max_expires_at"]
    h.clock.advance(50)
    assert h.agent(tok).invoke("crm.get_customer", {"customer_id": "cus_123"})["status"] == "committed"


def test_config_change_invalidates_until_repin(h):
    task, tok = h.create_scenario_task()
    agent = h.agent(tok)
    assert (
        agent.invoke("crm.update_customer", {"customer_id": "cus_123", "fields": {"note": "v1"}})["status"]
        == "committed"
    )
    # An administrator changes automations: now a note change also exports.
    h.set_rules(
        [{"id": "r2", "when": {"field": "tags", "contains": "enterprise"}, "then": {"export_to": "x"}}]
    )
    r = agent.invoke("crm.update_customer", {"customer_id": "cus_123", "fields": {"note": "v2"}})
    assert r["denial"]["reason"] == "CONFIG_CHANGED"
    assert h.saas_state()["customers"]["cus_123"]["note"] == "v1"
    # Reads are not pinned to integration configuration.
    assert agent.invoke("crm.get_customer", {"customer_id": "cus_123"})["status"] == "committed"
    h.admin.repin(task["id"])
    assert (
        agent.invoke("crm.update_customer", {"customer_id": "cus_123", "fields": {"note": "v2"}})["status"]
        == "committed"
    )


def test_config_change_between_check_and_act_is_refused(tmp_path):
    def wrapper(harness: Harness, inner: ExecutorClient):
        class Interposer(ExecutorClient):
            def __init__(self):
                pass

            def config_versions(self, i):
                return inner.config_versions(i)

            def predict(self, *a, **k):
                return inner.predict(*a, **k)

            def execute(self, envelope, args, timeout):
                harness.set_rules([])  # config moves after the gate evaluated it
                return inner.execute(envelope, args, timeout)

            def reconcile(self, *a, **k):
                return inner.reconcile(*a, **k)

            def health(self):
                return inner.health()

        return Interposer()

    h = Harness(tmp_path, executor_client_wrapper=wrapper)
    task, tok = h.create_scenario_task()
    r = h.agent(tok).invoke("crm.update_customer", {"customer_id": "cus_123", "fields": {"note": "x"}})
    assert r["status"] == "rejected" and "configuration changed" in r["error"]
    assert h.saas_state()["customers"]["cus_123"]["note"] == ""
    assert h.admin.get_task(task["id"])["budgets"]["writes"] == {"reserved": 0, "committed": 0}
