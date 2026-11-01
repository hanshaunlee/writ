import pytest

from writ.grant import (
    AttenuationError,
    CommandGrant,
    Constraint,
    ConstraintViolation,
    Grant,
    attenuate,
    check_args,
)


def cg(command: str, **args) -> CommandGrant:
    return CommandGrant(command=command, args={k: Constraint.model_validate(v) for k, v in args.items()})


def test_constraints_enforced():
    g = cg("email.send", to={"eq": "a@x.com"})
    check_args({"to": "a@x.com", "subject": "s"}, g)
    with pytest.raises(ConstraintViolation):
        check_args({"to": "b@x.com"}, g)
    with pytest.raises(ConstraintViolation):  # constrained arg missing
        check_args({"subject": "s"}, g)


def test_nested_paths_and_ops():
    g = cg(
        "crm.update_customer", **{"fields": {"keys_subset": ["note"]}, "customer_id": {"matches": "cus_1.*"}}
    )
    check_args({"customer_id": "cus_1", "fields": {"note": "x"}}, g)
    with pytest.raises(ConstraintViolation):
        check_args({"customer_id": "cus_1", "fields": {"note": "x", "billing_contact": "evil@x"}}, g)
    with pytest.raises(ConstraintViolation):
        check_args({"customer_id": "cus_2", "fields": {"note": "x"}}, g)
    g2 = cg("billing.refund", amount_cents={"max": 100, "min": 1})
    check_args({"amount_cents": 100}, g2)
    with pytest.raises(ConstraintViolation):
        check_args({"amount_cents": 101}, g2)
    with pytest.raises(ConstraintViolation):
        check_args({"amount_cents": "100"}, g2)  # type confusion is a violation
    with pytest.raises(ConstraintViolation):
        check_args({"amount_cents": True}, g2)


def test_constraint_requires_operator():
    with pytest.raises(ValueError):
        Constraint.model_validate({})
    with pytest.raises(ValueError):
        Constraint.model_validate({"bogus": 1})


def parent() -> Grant:
    return Grant(
        commands=[
            cg("billing.refund", amount_cents={"max": 20000}, charge_id={"in": ["ch_1", "ch_2"]}),
            cg("email.send", to={"eq": "a@x.com"}),
            cg("crm.update_customer", fields={"keys_subset": ["note", "tags"]}),
        ],
        budgets={"money_cents": 20000, "sends": 1},
        forbidden_effects=["external_export"],
    )


def test_attenuate_narrowing_allowed():
    child = Grant(
        commands=[cg("billing.refund", amount_cents={"max": 5000}, charge_id={"eq": "ch_1"})],
        budgets={"money_cents": 5000},
        forbidden_effects=["notification_redirect"],
    )
    eff = attenuate(parent(), child)
    assert [c.command for c in eff.commands] == ["billing.refund"]
    assert eff.budgets == {"money_cents": 5000, "sends": 1}  # inherits sends
    assert eff.forbidden_effects == ["external_export", "notification_redirect"]


@pytest.mark.parametrize(
    "child",
    [
        Grant(commands=[cg("crm.get_customer")]),  # not held by parent
        Grant(
            commands=[cg("billing.refund", amount_cents={"max": 20001}, charge_id={"in": ["ch_1"]})]
        ),  # wider max
        Grant(
            commands=[cg("billing.refund", amount_cents={"max": 100}, charge_id={"in": ["ch_1", "ch_3"]})]
        ),  # new value
        Grant(commands=[cg("billing.refund", amount_cents={"max": 100})]),  # drops a constraint
        Grant(commands=[cg("email.send", to={"eq": "b@x.com"})]),  # different fixed value
        Grant(commands=[cg("email.send", to={"matches": ".*"})]),  # pattern cannot imply eq
        Grant(
            commands=[cg("crm.update_customer", fields={"keys_subset": ["note", "billing_contact"]})]
        ),  # new key
        Grant(commands=[], budgets={"money_cents": 20001}),  # bigger budget
        Grant(
            commands=[cg("email.send", to={"eq": "a@x.com"}), cg("email.send", to={"eq": "a@x.com"})]
        ),  # duplicate
    ],
)
def test_attenuate_widening_rejected(child):
    with pytest.raises(AttenuationError):
        attenuate(parent(), child)


def test_attenuate_enumeration_satisfies_bounds():
    child = Grant(
        commands=[cg("billing.refund", amount_cents={"in": [100, 20000]}, charge_id={"eq": "ch_2"})]
    )
    attenuate(parent(), child)
    bad = Grant(commands=[cg("billing.refund", amount_cents={"in": [100, 20001]}, charge_id={"eq": "ch_2"})])
    with pytest.raises(AttenuationError):
        attenuate(parent(), bad)
