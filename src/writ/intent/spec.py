"""Intent specification attached to a task contract.

A grant says which *operations* a task may perform. An IntentSpec says which *outcomes* the
task exists to achieve, which outcomes it must not advance by any means, and how to
recognise those outcomes in effects and in content.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator


class OutcomeRule(BaseModel):
    """How an outcome is realised directly by an effect produced by an adapter."""

    model_config = ConfigDict(extra="forbid")

    effect: str | None = (
        None  # effect type reported by the executor, e.g. external_export, field_change, money_out
    )
    field: str | None = None  # for field_change effects: which field
    command: str | None = None  # the command that realises it (required for enumeration)

    @model_validator(mode="after")
    def _some(self) -> OutcomeRule:
        if self.effect is None and self.command is None:
            raise ValueError("outcome rule needs an effect or a command")
        return self


class NonGoal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    realized_by: list[OutcomeRule] = Field(default_factory=list)
    # Content-level recognition (rule extractor). Keywords are matched case-insensitively as
    # whole phrases; request verbs turn a mention into a request-of-recipient claim.
    keywords: list[str] = Field(default_factory=list)
    protected_fields: list[str] = Field(default_factory=list)
    # Can a human recipient realise this outcome if asked? With what probability?
    human_realizable: bool = True
    compliance: float = Field(default=0.3, ge=0.0, le=1.0)


class AuthorizedOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    realized_by: list[OutcomeRule] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)


class IntentSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcomes: list[AuthorizedOutcome] = Field(default_factory=list)
    non_goals: list[NonGoal] = Field(default_factory=list)
    # Which argument/result fields are free text (untrusted as a source of identifiers).
    free_text_fields: list[str] = Field(
        default_factory=lambda: ["note", "description", "body", "subject", "reason", "name"]
    )
    # Commands whose payload leaves the system (sinks): content and provenance are checked here.
    sink_commands: list[str] = Field(default_factory=list)
    # Model parameters
    prior_compromise: float = Field(default=0.02, gt=0.0, lt=1.0)  # rho
    rationality: list[float] = Field(default_factory=lambda: [2.0, 4.0, 8.0])  # beta mixture
    hidden_goal_weight: float = Field(default=1.0, gt=0.0)  # w_f
    action_cost: float = Field(default=0.1, ge=0.0)
    extractor_recall: float = Field(default=0.8, gt=0.0, le=1.0)  # r
    risk_budget: float = Field(default=0.03, gt=0.0, le=1.0)  # epsilon
    false_hold_alpha: float = Field(default=0.01, gt=0.0, lt=1.0)  # alpha for the e-process
    lookahead: int = Field(default=3, ge=0, le=8)  # k
    untrusted_atoms_policy: str = Field(default="hold")  # deny | hold | observe

    @model_validator(mode="after")
    def _check(self) -> IntentSpec:
        names = [o.name for o in self.outcomes] + [n.name for n in self.non_goals]
        if len(set(names)) != len(names):
            raise ValueError("outcome and non_goal names must be unique")
        if self.untrusted_atoms_policy not in ("deny", "hold", "observe"):
            raise ValueError("untrusted_atoms_policy must be deny|hold|observe")
        return self

    def non_goal(self, name: str) -> NonGoal | None:
        return next((n for n in self.non_goals if n.name == name), None)

    def merge_child(self, child: IntentSpec | None) -> IntentSpec:
        """Children inherit the parent's spec; they may only add non-goals or tighten budgets."""
        if child is None:
            return self
        extra = [n for n in child.non_goals if self.non_goal(n.name) is None]
        return self.model_copy(
            update={
                "non_goals": self.non_goals + extra,
                "risk_budget": min(self.risk_budget, child.risk_budget),
                "false_hold_alpha": min(self.false_hold_alpha, child.false_hold_alpha),
            }
        )

    def to_dict(self) -> dict:
        return self.model_dump()
