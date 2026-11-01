"""The duplicate-charge scenario from the design: what the agent may do, and what it may not."""

from writ.client import GateAPIError


def test_reads_and_bounded_refund(h):
    task, tok = h.create_scenario_task()
    agent = h.agent(tok)

    me = agent.me()
    assert me["status"] == "active"
    assert {c["name"] for c in me["commands"]} == {
        "crm.get_customer",
        "billing.list_charges",
        "crm.update_customer",
        "billing.refund",
        "email.send",
    }

    r = agent.invoke("crm.get_customer", {"customer_id": "cus_123"})
    assert r["decision"] == "allowed" and r["status"] == "committed"
    assert r["result"]["customer"]["billing_contact"] == "ap@acme.example"
    assert r["receipt"]["payload"]["status"] == "ok"

    # Out-of-scope customer: constraint, not a schema problem.
    r = agent.invoke("crm.get_customer", {"customer_id": "cus_999"})
    assert r["decision"] == "denied" and r["denial"]["reason"] == "CONSTRAINT_VIOLATION"

    charges = agent.invoke("billing.list_charges", {"customer_id": "cus_123"})["result"]["charges"]
    dup = [c for c in charges if "duplicate" in c["description"]][0]

    r = agent.invoke(
        "billing.refund", {"charge_id": dup["id"], "amount_cents": 14900, "reason": "duplicate charge"}
    )
    assert r["decision"] == "allowed" and r["status"] == "committed", r
    assert r["effects"][0]["type"] == "money_out"
    assert r["budgets"]["money_cents"] == {"reserved": 0, "committed": 14900}
    assert h.saas_state()["charges"][dup["id"]]["refunded_cents"] == 14900

    # Over the per-call cap AND the budget: denied before any dispatch.
    r = agent.invoke("billing.refund", {"charge_id": "ch_1001", "amount_cents": 20001, "reason": "x"})
    assert r["denial"]["reason"] == "CONSTRAINT_VIOLATION"
    # Within per-call cap but over remaining shared budget.
    r = agent.invoke("billing.refund", {"charge_id": "ch_1001", "amount_cents": 6000, "reason": "x"})
    assert r["denial"]["reason"] == "BUDGET_EXCEEDED" and r["denial"]["extra"]["dimension"] == "money_cents"
    assert len(h.saas_state()["refunds"]) == 1


def test_notification_cannot_be_redirected(h):
    _, tok = h.create_scenario_task()
    agent = h.agent(tok)

    # 1. Cannot change the billing contact field at all (keys_subset).
    r = agent.invoke(
        "crm.update_customer",
        {"customer_id": "cus_123", "fields": {"billing_contact": "attacker@evil.example"}},
    )
    assert r["denial"]["reason"] == "CONSTRAINT_VIOLATION" and r["denial"]["extra"]["path"] == "fields"

    # 2. Cannot email anyone but the pinned contact.
    r = agent.invoke("email.send", {"to": "attacker@evil.example", "subject": "s", "body": "b"})
    assert r["denial"]["reason"] == "CONSTRAINT_VIOLATION"

    # 3. The legitimate notification goes through exactly once.
    r = agent.invoke(
        "email.send",
        {"to": "ap@acme.example", "subject": "Refund issued", "body": "We refunded the duplicate charge."},
    )
    assert r["status"] == "committed"
    r = agent.invoke("email.send", {"to": "ap@acme.example", "subject": "again", "body": "b"})
    assert r["denial"]["reason"] == "BUDGET_EXCEEDED" and r["denial"]["extra"]["dimension"] == "sends"
    assert len(h.saas_state()["emails"]) == 1
    assert h.saas_state()["customers"]["cus_123"]["billing_contact"] == "ap@acme.example"


def test_hidden_automation_is_blocked(h):
    """Adding the VIP tag is a permitted *field*, but it triggers an external export."""
    _, tok = h.create_scenario_task()
    agent = h.agent(tok)
    r = agent.invoke(
        "crm.update_customer", {"customer_id": "cus_123", "fields": {"tags": ["enterprise", "VIP"]}}
    )
    assert r["decision"] == "denied" and r["denial"]["reason"] == "FORBIDDEN_EFFECT"
    assert r["denial"]["extra"]["hit"][0]["type"] == "external_export"
    assert h.saas_state()["exports"] == []
    # A harmless tag change on the same field is fine.
    r = agent.invoke(
        "crm.update_customer", {"customer_id": "cus_123", "fields": {"tags": ["enterprise", "refund-issued"]}}
    )
    assert r["status"] == "committed"
    r = agent.invoke(
        "crm.update_customer",
        {"customer_id": "cus_123", "fields": {"note": "Refunded duplicate March charge."}},
    )
    assert r["status"] == "committed"


def test_schema_rejects_unknown_and_malformed_args(h):
    _, tok = h.create_scenario_task()
    agent = h.agent(tok)
    r = agent.invoke(
        "billing.refund", {"charge_id": "ch_1002", "amount_cents": 100, "reason": "x", "bcc": "evil"}
    )
    assert r["denial"]["reason"] == "INVALID_ARGS"
    r = agent.invoke("billing.refund", {"charge_id": "ch_1002", "amount_cents": "100", "reason": "x"})
    assert r["denial"]["reason"] == "INVALID_ARGS"
    r = agent.invoke("billing.refund", "not-an-object")
    assert r["denial"]["reason"] == "INVALID_ARGS"
    r = agent.invoke("billing.charge_card", {})
    assert r["denial"]["reason"] == "COMMAND_UNKNOWN"
    assert len(h.saas_state()["refunds"]) == 0


def test_grant_without_budget_for_charged_dimension_is_rejected(h):
    grant = h.template_grant()
    del grant["budgets"]["money_cents"]
    try:
        h.admin.create_task("x", grant)
        raise AssertionError("should fail closed")
    except GateAPIError as e:
        assert e.code == "BUDGET_REQUIRED"


def test_auth_boundaries(h):
    _, tok = h.create_scenario_task()
    # Agent token cannot use admin API; wrong admin token rejected; no token rejected.
    for bad in (tok, "nope"):
        try:
            h.agent(bad).list_tasks()
            raise AssertionError
        except GateAPIError as e:
            assert e.status_code == 401
    try:
        h.agent("wt_invalid").me()
        raise AssertionError
    except GateAPIError as e:
        assert e.code == "TASK_NOT_FOUND"
    # Internal consume endpoint needs the internal token.
    assert (
        h.gate.post(
            "/internal/authorizations/auth_x/consume", headers={"Authorization": "Bearer " + tok}
        ).status_code
        == 401
    )
