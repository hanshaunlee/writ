"""Wires the abstract model, claims and provenance into the gate's invoke pipeline."""

from __future__ import annotations

import json
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from ..canon import hash_obj
from ..commands import CommandDef, CommandTable
from ..grant import Grant
from .abstract import AbstractAction, Assessment, IntentModel, IntentState, Observation
from .claims import ClaimExtractor, ClaimSet, RuleClaimExtractor, free_texts
from .provenance import ProvenanceReport, atoms_in, classify, contract_atoms
from .spec import IntentSpec


@dataclass
class IntentDecision:
    decision: str  # allow | hold | deny
    reason: str | None
    detail: str | None
    abstract: AbstractAction
    claims: ClaimSet
    provenance: ProvenanceReport | None
    assessment: Assessment | None
    new_state: IntentState
    extra: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict:
        d: dict[str, Any] = {"abstract_action": self.abstract.to_dict(), "claims": self.claims.to_dict()}
        if self.provenance:
            d["provenance"] = self.provenance.to_dict()
        if self.assessment:
            a = self.assessment
            d["e_value"] = round(a.e_value, 4)
            d["forecast"] = round(a.forecast, 4)
            d["residual_risk"] = round(a.residual_risk, 5)
            d["non_goal_mass"] = {k: round(v, 4) for k, v in self.extra.get("non_goal_mass", {}).items()}
        d["mode"] = self.new_state.mode
        return d


def statically_blocked(spec: IntentSpec, grant: Grant) -> list[str]:
    """Non-goals whose direct routes the grant already closes (visible to the agent in tool descriptions)."""
    blocked: list[str] = []
    for ng in spec.non_goals:
        routes = [r for r in ng.realized_by if r.command]
        if not routes:
            continue
        open_route = False
        for r in routes:
            cg = grant.command_grant(r.command)
            if cg is None:
                continue  # command not granted: route does not exist
            if r.field:
                ks = cg.args.get("fields")
                if ks is not None and ks.keys_subset is not None and r.field not in ks.keys_subset:
                    continue  # field excluded by the grant
            open_route = True
        if not open_route:
            blocked.append(ng.name)
    return blocked


class IntentEngine:
    """Builds and caches intent models. A model is a pure function of (spec, grant) and holds
    memoised policy and lookahead tables, so reusing it across requests for the same task tree
    removes most of the per-request cost."""

    MODEL_CACHE_SIZE = 256

    def __init__(self, table: CommandTable, extractor: ClaimExtractor | None = None):
        self.table = table
        self.extractor: ClaimExtractor = extractor or RuleClaimExtractor()
        self._models: OrderedDict[str, IntentModel] = OrderedDict()
        self._models_lock = threading.Lock()

    def model_for(self, spec: IntentSpec, grant: Grant) -> IntentModel:
        key = hash_obj({"spec": spec.to_dict(), "grant": grant.to_dict()})
        with self._models_lock:
            model = self._models.get(key)
            if model is not None:
                self._models.move_to_end(key)
                return model
        granted = [cg.command for cg in grant.commands]
        reads = [c for c in granted if (cd := self.table.get(c)) and not cd.is_mutating()]
        model = IntentModel(
            spec, granted, read_commands=reads, initially_blocked=statically_blocked(spec, grant)
        )
        with self._models_lock:
            self._models[key] = model
            while len(self._models) > self.MODEL_CACHE_SIZE:
                self._models.popitem(last=False)
        return model

    # ------------------------------------------------------------------ mapping
    def abstract_action(
        self,
        spec: IntentSpec,
        cd: CommandDef | None,
        command: str,
        args: Any,
        effects: list[dict],
        claims: ClaimSet,
        *,
        denied_out_of_scope: bool,
    ) -> AbstractAction:
        direct: set[str] = set()
        fields = args.get("fields", {}) if isinstance(args, dict) else {}
        changed_fields = set(fields.keys()) if isinstance(fields, dict) else set()
        effect_types = {e.get("type") for e in effects}
        effect_fields = {e.get("detail", {}).get("field") for e in effects if e.get("type") == "field_change"}
        for o in list(spec.outcomes) + list(spec.non_goals):
            for r in o.realized_by:
                if r.command and r.command != command:
                    continue
                if r.effect is None and r.field is None:
                    direct.add(o.name)  # command alone realises it
                    continue
                if r.effect == "field_change" and r.field:
                    # Use predicted effects when available, else the requested fields (for denied attempts).
                    if (effect_fields and r.field in effect_fields) or (
                        not effects and r.field in changed_fields
                    ):
                        direct.add(o.name)
                elif r.effect and r.effect in effect_types:
                    direct.add(o.name)
        sink = command in spec.sink_commands
        return AbstractAction(
            command,
            direct=frozenset(direct),
            requests=frozenset(claims.requests()),
            sink=sink,
            probe=denied_out_of_scope and not direct,
        )

    # ------------------------------------------------------------------ main entry points
    def observe_denial(
        self,
        spec: IntentSpec,
        grant: Grant,
        state: IntentState,
        command: str,
        args: Any,
        effects: list[dict],
        *,
        out_of_scope: bool,
    ) -> tuple[IntentState, AbstractAction]:
        """Record a denied attempt (constraint/schema violation or forbidden effect) as an observation."""
        model = self.model_for(spec, grant)
        texts = free_texts(args, spec) if isinstance(args, dict) else []
        claims = self.extractor.extract(texts, spec, {"denied_values": []}) if texts else ClaimSet()
        a = self.abstract_action(
            spec, self.table.get(command), command, args, effects, claims, denied_out_of_scope=out_of_scope
        )
        new = model.observe(state, Observation(a, executed=False))
        new.history[-1]["denied_values"] = _denied_values(args)
        return new, a

    def evaluate(
        self,
        spec: IntentSpec,
        grant: Grant,
        state: IntentState,
        command: str,
        args: Any,
        effects: list[dict],
        trusted_atoms: set[str],
    ) -> IntentDecision:
        """Evaluate a request that passed the deterministic grant checks."""
        model = self.model_for(spec, grant)
        cd = self.table.get(command)
        is_sink = command in spec.sink_commands
        texts = free_texts(args, spec) if isinstance(args, dict) else []
        denied_values = [v for h in state.history for v in h.get("denied_values", [])]
        claims = (
            self.extractor.extract(texts, spec, {"denied_values": denied_values})
            if (texts and is_sink)
            else ClaimSet()
        )
        a = self.abstract_action(spec, cd, command, args, effects, claims, denied_out_of_scope=False)
        prov = classify(args, trusted_atoms, spec.free_text_fields) if is_sink else None

        # Deterministic content layer: explicit requests/commitments toward a non-goal are denied.
        strong = [
            c
            for c in claims.claims
            if c.type in ("request_of_recipient", "commitment") and c.confidence >= 0.75
        ]
        if strong:
            new = model.observe(state, Observation(a, executed=False))
            names = sorted({c.non_goal for c in strong})
            return IntentDecision(
                "deny",
                "NON_GOAL_ADVANCED",
                f"content asks or claims to realise non-goal(s) {names}: {strong[0].evidence[:120]!r}",
                a,
                claims,
                prov,
                model.assess(new, a),
                new,
                {"non_goal_mass": model.non_goal_mass(new.log_weights)},
            )

        new = model.observe(state, Observation(a, executed=True))
        asm = model.assess(new, a)
        extra = {"non_goal_mass": model.non_goal_mass(new.log_weights)}
        # Supervision is a property of the evidence, not of which branch decides this action.
        if asm.supervise and new.mode != "supervised":
            new.mode, new.mode_reason = "supervised", asm.supervise_reason

        if prov is not None and prov.untrusted and spec.untrusted_atoms_policy != "observe":
            new2 = state.model_copy(
                deep=True
            )  # not executed yet; keep the observation but mark the action pending
            new2 = (
                model.observe(new2, Observation(a, executed=False))
                if spec.untrusted_atoms_policy == "deny"
                else new
            )
            kind = "deny" if spec.untrusted_atoms_policy == "deny" else "hold"
            return IntentDecision(
                kind,
                "UNTRUSTED_PROVENANCE",
                f"payload carries identifiers of unknown provenance {sorted(prov.untrusted)}; they appear in no authorized read result or in the contract",
                a,
                claims,
                prov,
                asm,
                new2,
                extra,
            )

        if state.mode == "supervised" and (is_sink or (cd is not None and cd.effect_class == "money")):
            return IntentDecision(
                "hold",
                "INTENT_SUPERVISED",
                f"task is under supervision ({state.mode_reason}); consequential actions require operator approval",
                a,
                claims,
                prov,
                asm,
                new,
                extra,
            )

        if asm.supervise and (is_sink or (cd is not None and cd.effect_class == "money")):
            return IntentDecision(
                "hold",
                "INTENT_HOLD",
                asm.supervise_reason or "intent threshold crossed",
                a,
                claims,
                prov,
                asm,
                new,
                extra,
            )

        if a.sink:
            new.residual_risk_spent += asm.residual_risk
        new.last_forecast = asm.forecast
        return IntentDecision("allow", None, None, a, claims, prov, asm, new, extra)

    # ------------------------------------------------------------------ provenance bookkeeping
    def trusted_atoms_from_grant(self, grant: Grant) -> set[str]:
        return contract_atoms(grant.to_dict())

    def atoms_from_read_result(self, spec: IntentSpec, result: Any) -> set[str]:
        return atoms_in(result, spec.free_text_fields, structured_only=True)


def _denied_values(args: Any) -> list[str]:
    out: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str) and ("@" in v or "_" in v) and len(v) < 120:
            out.append(v)

    walk(args)
    return out[:20]


def intent_spec_from_json(s: str | None) -> IntentSpec | None:
    if not s:
        return None
    d = json.loads(s)
    return IntentSpec.model_validate(d) if d else None
