"""Sub-agents can only hold less authority than their parent, and share its budgets."""

import pytest

from writ.client import GateAPIError


def refund_only(max_cents: int, charge_ids: list[str], budget: int | None = None) -> dict:
    g = {
        "commands": [
            {
                "command": "billing.refund",
                "args": {"charge_id": {"in": charge_ids}, "amount_cents": {"max": max_cents}},
            }
        ],
        "budgets": {"refunds": 1},
    }
    if budget is not None:
        g["budgets"]["money_cents"] = budget
    return g


def test_two_subagents_cannot_exceed_shared_budget(h):
    task, tok = h.create_scenario_task()  # money_cents budget 20000
    planner = h.agent(tok)
    a = planner.delegate("refunder-a", refund_only(15000, ["ch_1001"], budget=15000))
    b = planner.delegate("refunder-b", refund_only(15000, ["ch_1002"], budget=15000))
    assert a["task"]["grant"]["budgets"]["money_cents"] == 15000
    assert a["task"]["grant"]["budgets"]["sends"] == 1  # inherited, cannot be dropped
    assert a["task"]["parent_id"] == task["id"] and a["task"]["root_id"] == task["id"]

    r = h.agent(a["token"]).invoke(
        "billing.refund", {"charge_id": "ch_1001", "amount_cents": 14900, "reason": "dup"}
    )
    assert r["status"] == "committed"
    r = h.agent(b["token"]).invoke(
        "billing.refund", {"charge_id": "ch_1002", "amount_cents": 14900, "reason": "dup"}
    )
    assert r["denial"]["reason"] == "BUDGET_EXCEEDED"
    assert r["denial"]["extra"]["task"] == task["id"]  # the *parent's* budget stopped it
    r = h.agent(b["token"]).invoke(
        "billing.refund", {"charge_id": "ch_1002", "amount_cents": 5100, "reason": "dup"}
    )
    assert r["status"] == "committed"
    root = h.admin.get_task(task["id"])
    assert root["budgets"]["money_cents"]["committed"] == 20000
    assert len(h.saas_state()["refunds"]) == 2


@pytest.mark.parametrize(
    "grant",
    [
        {
            "commands": [{"command": "email.send", "args": {"to": {"eq": "attacker@evil.example"}}}],
            "budgets": {"sends": 1},
        },
        {"commands": [{"command": "email.send", "args": {}}], "budgets": {"sends": 1}},
        {
            "commands": [
                {
                    "command": "billing.refund",
                    "args": {"charge_id": {"eq": "ch_1001"}, "amount_cents": {"max": 20001}},
                }
            ],
            "budgets": {"money_cents": 1, "refunds": 1},
        },
        {
            "commands": [
                {
                    "command": "billing.refund",
                    "args": {"charge_id": {"eq": "ch_2001"}, "amount_cents": {"max": 1}},
                }
            ],
            "budgets": {"money_cents": 1, "refunds": 1},
        },
        {"commands": [], "budgets": {"money_cents": 20001}},
        {
            "commands": [
                {
                    "command": "crm.update_customer",
                    "args": {
                        "customer_id": {"eq": "cus_123"},
                        "fields": {"keys_subset": ["billing_contact"]},
                    },
                }
            ],
            "budgets": {"writes": 1},
        },
    ],
)
def test_delegation_cannot_widen(h, grant):
    _, tok = h.create_scenario_task()
    with pytest.raises(GateAPIError) as ei:
        h.agent(tok).delegate("evil", grant)
    assert ei.value.code == "ATTENUATION_VIOLATION"
    # The attempt is in the ledger.
    assert any(e["type"] == "DELEGATION_DENIED" for e in h.admin.ledger())


def test_delegation_chain_depth_and_expiry_clamp(h):
    task, tok = h.create_scenario_task(ttl=600)
    cur = tok
    for i in range(3):
        child = h.agent(cur).delegate(f"level-{i}", refund_only(100, ["ch_1001"]), ttl_seconds=10**6)
        assert child["task"]["expires_at"] <= task["expires_at"]
        cur = child["token"]
    # Grandchild can still act within the root's bounds.
    r = h.agent(cur).invoke("billing.refund", {"charge_id": "ch_1001", "amount_cents": 100, "reason": "x"})
    assert r["status"] == "committed"
    assert h.admin.get_task(task["id"])["budgets"]["money_cents"]["committed"] == 100


def test_delegation_depth_limit(h):
    h.service.max_depth = 2
    _, tok = h.create_scenario_task()
    c1 = h.agent(tok).delegate("c1", refund_only(100, ["ch_1001"]))
    c2 = h.agent(c1["token"]).delegate("c2", refund_only(100, ["ch_1001"]))
    with pytest.raises(GateAPIError) as ei:
        h.agent(c2["token"]).delegate("c3", refund_only(100, ["ch_1001"]))
    assert ei.value.code == "DEPTH_EXCEEDED"


def test_child_cannot_renew_or_repin(h):
    _, tok = h.create_scenario_task()
    child = h.agent(tok).delegate("c", refund_only(100, ["ch_1001"]))
    # Agent-side API has no renew; admin API rejects task tokens.
    with pytest.raises(GateAPIError) as ei:
        h.agent(child["token"]).renew(child["task"]["id"], 100)
    assert ei.value.status_code == 401
