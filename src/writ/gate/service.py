"""The authority: task contracts, delegation, the invoke pipeline, revocation and leases.

Design rules enforced here (see docs/architecture.md):
  * Authority is created only by an operator; agents can only attenuate it.
  * Every consequential action gets a single-use, short-lived, signed authorization bound to
    the task, the exact arguments, and the integration configuration it was evaluated against.
  * Budgets are reserved atomically across the whole delegation tree before dispatch.
  * Revocation cascades to all descendants and voids every outstanding authorization.
  * Leases are extended only by operators, never by the task holding them.
  * Anything the gate cannot evaluate is denied (fail closed). An executor answer without a
    valid receipt is not an answer: the outcome is `unknown` until reconciled.
  * Budgets move at most once per authorization: every terminal transition is conditional on
    the current status, so concurrent settlement paths (revoke, sweep, outcome) cannot double
    release or double commit.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import threading
import time
import zlib
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field

from ..canon import hash_obj
from ..commands import CommandTable
from ..grant import AttenuationError, ConstraintViolation, Grant, attenuate, check_args
from ..intent.abstract import IntentState
from ..intent.engine import IntentEngine
from ..intent.spec import IntentSpec
from ..signing import KeyRing, Signer, Verifier, signed_envelope, verify_envelope
from .executor_client import ExecutorClient, ExecutorError
from .store import FINAL_AUTH_STATUSES, BudgetExceeded, Store, iso, parse_iso, utcnow

log = logging.getLogger("writ.gate")

HALT_KEY = "halt"
TOKEN_PREFIX = "wt_"
SYSTEM_ACTOR = "system:gate"

# Denial reasons that the intent layer treats as evidence about the agent.
OBSERVABLE_DENIALS = (
    "CONSTRAINT_VIOLATION",
    "INVALID_ARGS",
    "COMMAND_NOT_GRANTED",
    "FORBIDDEN_EFFECT",
    "BUDGET_EXCEEDED",
)
OUT_OF_SCOPE_DENIALS = ("CONSTRAINT_VIOLATION", "INVALID_ARGS", "COMMAND_NOT_GRANTED")
# Denials caused by the gate's or executor's state rather than by the request: an idempotent
# retry after these must be re-evaluated, not replayed.
TRANSIENT_DENIALS = ("HALTED", "PREDICTION_UNAVAILABLE")
# Executor rejection reasons that are only ever produced *after* a successful consume and before
# any upstream call. A signed receipt with one of these on a consumed row proves nothing happened.
POST_CONSUME_REJECTIONS = ("config_changed", "config_unverifiable")

# Parts of the intent summary an agent may see. Detector statistics (e-value, forecast,
# posterior mass) are operator-only: an untrusted agent must not be able to watch the test.
AGENT_VISIBLE_INTENT_KEYS = ("claims", "provenance", "mode")


class GateError(Exception):
    status_code = 400
    code = "GATE_ERROR"

    def __init__(self, detail: str, code: str | None = None, status_code: int | None = None):
        super().__init__(detail)
        self.detail = detail
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code


class NotFound(GateError):
    status_code = 404
    code = "NOT_FOUND"


class Unauthorized(GateError):
    status_code = 401
    code = "UNAUTHORIZED"


class Denial(BaseModel):
    reason: str
    detail: str
    extra: dict[str, Any] = Field(default_factory=dict)


class InvokeResult(BaseModel):
    decision: str  # allowed | denied
    command: str
    denial: Denial | None = None
    authorization_id: str | None = None
    status: str | None = None  # committed | failed | rejected | unknown | held
    result: Any = None
    error: str | None = None
    effects: list[dict] = Field(default_factory=list)
    receipt: dict | None = None
    budgets: dict[str, dict[str, int]] | None = None
    intent: dict | None = None
    hold: dict | None = None
    replayed: bool = False  # served from the idempotency record

    def agent_view(self) -> dict:
        """What the acting agent is told. Everything else stays in the ledger and admin views."""
        d = self.model_dump()
        if d.get("intent"):
            d["intent"] = {k: v for k, v in d["intent"].items() if k in AGENT_VISIBLE_INTENT_KEYS}
        if d.get("hold") and isinstance(d["hold"], dict):
            d["hold"] = {k: v for k, v in d["hold"].items() if k in ("reason", "detail")}
        return d


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


def task_view(t: dict, usage: dict | None = None) -> dict:
    return {
        "id": t["id"],
        "parent_id": t["parent_id"],
        "root_id": t["root_id"],
        "depth": t["depth"],
        "name": t["name"],
        "principal": t["principal"],
        "status": t["status"],
        "status_reason": t["status_reason"],
        "grant": json.loads(t["grant_json"]),
        "config_versions": json.loads(t["config_versions_json"]),
        "metadata": json.loads(t["metadata_json"]),
        "created_at": t["created_at"],
        "expires_at": t["expires_at"],
        "max_expires_at": t["max_expires_at"],
        "budgets": usage,
        "intent_spec": json.loads(t["intent_json"]) if t.get("intent_json") else None,
    }


def agent_task_view(view: dict) -> dict:
    """The task as the agent holding its token may see it."""
    out = dict(view)
    out.pop("intent_spec", None)
    out.pop("principal", None)
    if isinstance(out.get("intent"), dict):
        out["intent"] = {"mode": out["intent"].get("mode")}
    return out


class GateService:
    def __init__(
        self,
        store: Store,
        table: CommandTable,
        signer: Signer,
        executor: ExecutorClient,
        executor_verifier: Verifier | KeyRing,
        *,
        authorization_ttl_seconds: int = 60,
        max_task_ttl_seconds: int = 7 * 24 * 3600,
        max_delegation_depth: int = 8,
        max_tasks_per_tree: int = 256,
        stale_consumed_seconds: int = 300,
        reconcile_after_seconds: int = 30,
        clock: Callable[[], datetime] = utcnow,
        intent_engine: IntentEngine | None = None,
    ):
        self.store = store
        self.table = table
        self.intent = intent_engine or IntentEngine(table)
        self.signer = signer
        self.executor = executor
        if executor_verifier is None:
            raise ValueError("executor_verifier is required: the gate must be able to verify receipts")
        self.executor_keys: KeyRing = KeyRing.coerce(executor_verifier)
        self.auth_ttl = authorization_ttl_seconds
        self.max_task_ttl = max_task_ttl_seconds
        self.max_depth = max_delegation_depth
        self.max_tasks_per_tree = max_tasks_per_tree
        self.stale_consumed_seconds = stale_consumed_seconds
        self.reconcile_after_seconds = reconcile_after_seconds
        self.clock = clock
        # Decisions for one task tree are serialized (intent state is a read-modify-write per
        # root); different trees proceed in parallel. Striped so the table never grows.
        self._tree_locks = [threading.RLock() for _ in range(64)]
        self._reconcile_backoff: dict[str, tuple[float, int]] = {}

    # Backwards-compatible name used by older callers and tests.
    @property
    def executor_verifier(self) -> KeyRing:
        return self.executor_keys

    # ------------------------------------------------------------------ helpers
    def now(self) -> datetime:
        return self.clock()

    def _tree_lock(self, root_id: str) -> threading.RLock:
        return self._tree_locks[zlib.crc32(root_id.encode()) % len(self._tree_locks)]

    def _log(self, event: str, payload: dict, task_id: str | None = None) -> None:
        self.store.append_ledger(event, payload, task_id=task_id, ts=iso(self.now()))

    def _validate_grant_against_table(self, grant: Grant) -> None:
        for dim, lim in grant.budgets.items():
            if not isinstance(lim, int) or isinstance(lim, bool) or lim < 0:
                raise GateError(f"budget '{dim}' must be a non-negative integer", code="INVALID_GRANT")
        seen: set[str] = set()
        for cg in grant.commands:
            if cg.command in seen:
                raise GateError(f"duplicate command grant: {cg.command}", code="INVALID_GRANT")
            seen.add(cg.command)
            cd = self.table.get(cg.command)
            if cd is None:
                raise GateError(f"unknown command in grant: {cg.command}", code="COMMAND_UNKNOWN")
            for dim in cd.budgets:
                if dim not in grant.budgets:
                    raise GateError(
                        f"grant for '{cg.command}' must declare a budget for dimension '{dim}' (fail-closed)",
                        code="BUDGET_REQUIRED",
                    )
            for path in cg.args:
                if not path or any(p == "" for p in path.split(".")):
                    raise GateError(f"invalid constraint path '{path}'", code="INVALID_GRANT")

    def _validate_intent_against_table(self, intent: IntentSpec) -> None:
        for c in intent.sink_commands:
            if self.table.get(c) is None:
                raise GateError(
                    f"intent sink command '{c}' is not in the command table", code="INVALID_INTENT"
                )
        for o in list(intent.outcomes) + list(intent.non_goals):
            for r in o.realized_by:
                if r.command and self.table.get(r.command) is None:
                    raise GateError(
                        f"intent rule for '{o.name}' names unknown command '{r.command}'",
                        code="INVALID_INTENT",
                    )

    def _integrations_for(self, grant: Grant) -> list[str]:
        out: set[str] = set()
        for cg in grant.commands:
            cd = self.table.get(cg.command)
            if cd and cd.is_mutating():
                out.add(cd.integration)
        return sorted(out)

    def _pin_config_versions(self, grant: Grant) -> dict[str, str]:
        integrations = self._integrations_for(grant)
        if not integrations:
            return {}
        try:
            versions = self.executor.config_versions(integrations)
        except ExecutorError as e:
            raise GateError(
                f"cannot pin integration configuration: {e}", code="EXECUTOR_UNAVAILABLE", status_code=503
            ) from e
        missing = [i for i in integrations if i not in versions]
        if missing:
            raise GateError(
                f"executor reports no configuration for integrations {missing}", code="INTEGRATION_UNKNOWN"
            )
        return {i: versions[i] for i in integrations}

    # ------------------------------------------------------------------ halt
    def halted(self) -> bool:
        return self.store.get_setting(HALT_KEY, "0") == "1"

    def set_halt(self, on: bool, actor: str, reason: str = "") -> None:
        with self.store.tx():
            self.store.set_setting(HALT_KEY, "1" if on else "0")
            self._log("HALT_SET" if on else "HALT_CLEARED", {"actor": actor, "reason": reason})

    # ------------------------------------------------------------------ tasks
    def create_task(
        self,
        principal: str,
        name: str,
        grant: Grant,
        ttl_seconds: int,
        max_ttl_seconds: int | None = None,
        metadata: dict | None = None,
        intent: IntentSpec | None = None,
        *,
        actor: str | None = None,
    ) -> tuple[dict, str]:
        if ttl_seconds <= 0:
            raise GateError("ttl_seconds must be positive", code="INVALID_TTL")
        max_ttl = max_ttl_seconds or max(ttl_seconds, min(self.max_task_ttl, ttl_seconds * 4))
        if ttl_seconds > max_ttl or max_ttl > self.max_task_ttl:
            raise GateError(f"ttl exceeds limits (max {self.max_task_ttl}s)", code="INVALID_TTL")
        self._validate_grant_against_table(grant)
        if intent is not None:
            self._validate_intent_against_table(intent)
        versions = self._pin_config_versions(grant)
        now = self.now()
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        tid = _new_id("task")
        row = {
            "id": tid,
            "parent_id": None,
            "root_id": tid,
            "depth": 0,
            "name": name,
            "principal": principal,
            "status": "active",
            "status_reason": None,
            "token_hash": _hash_token(token),
            "grant_json": json.dumps(grant.to_dict(), sort_keys=True),
            "config_versions_json": json.dumps(versions, sort_keys=True),
            "metadata_json": json.dumps(metadata or {}, sort_keys=True),
            "created_at": iso(now),
            "expires_at": iso(now + timedelta(seconds=ttl_seconds)),
            "max_expires_at": iso(now + timedelta(seconds=max_ttl)),
            "updated_at": iso(now),
            "intent_json": json.dumps(intent.to_dict(), sort_keys=True) if intent else None,
        }
        with self.store.tx():
            self.store.insert_task(row)
            if intent:
                model = self.intent.model_for(intent, grant)
                self.store.set_intent_state(tid, model.initial_state().model_dump(), iso(now))
                self.store.add_trusted_atoms(tid, self.intent.trusted_atoms_from_grant(grant), "contract")
            self._log(
                "TASK_CREATED",
                {
                    "name": name,
                    "principal": principal,
                    "actor": actor or principal,
                    "grant": grant.to_dict(),
                    "intent": intent.to_dict() if intent else None,
                    "config_versions": versions,
                    "expires_at": row["expires_at"],
                    "max_expires_at": row["max_expires_at"],
                },
                task_id=tid,
            )
        return self._with_intent(task_view(row, self.store.budget_usage(tid)), tid), token

    # ------------------------------------------------------------------ intent helpers
    def _root_intent(self, t: dict) -> tuple[IntentSpec | None, dict | None, IntentState | None]:
        root = t if t["parent_id"] is None else self.store.get_task(t["root_id"])
        if root is None or not root.get("intent_json"):
            return None, root, None
        spec = IntentSpec.model_validate(json.loads(root["intent_json"]))
        st = self.store.get_intent_state(root["id"])
        return spec, root, IntentState.model_validate(st) if st else None

    def _with_intent(self, view: dict, task_id: str) -> dict:
        t = self.store.get_task(task_id)
        if t is None:
            return view
        spec, root, state = self._root_intent(t)
        if spec and root and state:
            model = self.intent.model_for(spec, Grant.model_validate(json.loads(root["grant_json"])))
            view["intent"] = {
                "mode": state.mode,
                "mode_reason": state.mode_reason,
                "e_value": round(state.last_e_value, 4),
                "forecast": round(model.forecast(state), 4),
                "non_goal_mass": {k: round(v, 4) for k, v in model.non_goal_mass(state.log_weights).items()},
                "residual_risk_spent": round(state.residual_risk_spent, 5),
                "steps": state.steps,
                "achieved": state.achieved,
                "blocked": state.blocked,
            }
        return view

    def explain_intent(self, task_id: str) -> dict:
        """Operator view of a task tree's intent state: every attempt, what it meant, the evidence after it."""
        t = self.store.get_task(task_id)
        if t is None:
            raise NotFound(f"task {task_id} not found")
        spec, root, state = self._root_intent(t)
        if not (spec and root and state):
            raise GateError("task has no intent state", code="NO_INTENT", status_code=409)
        model = self.intent.model_for(spec, Grant.model_validate(json.loads(root["grant_json"])))
        return {
            "task_id": task_id,
            "root_id": root["id"],
            "mode": state.mode,
            "mode_reason": state.mode_reason,
            "e_value": state.last_e_value,
            "threshold": 1.0 / spec.false_hold_alpha,
            "forecast": model.forecast(state),
            "risk_budget": spec.risk_budget,
            "residual_risk_spent": state.residual_risk_spent,
            "non_goal_mass": model.non_goal_mass(state.log_weights),
            "posterior": model.posterior(state),
            "steps": state.steps,
            "achieved": state.achieved,
            "blocked": state.blocked,
            "history": state.history,
        }

    def unsupervise(self, task_id: str, actor: str) -> dict:
        t = self.store.get_task(task_id)
        if t is None:
            raise NotFound(f"task {task_id} not found")
        with self._tree_lock(t["root_id"]):
            spec, root, state = self._root_intent(t)
            if not (spec and root and state):
                raise GateError("task has no intent state", code="NO_INTENT", status_code=409)
            state.mode, state.mode_reason = "normal", None
            with self.store.tx():
                self.store.set_intent_state(root["id"], state.model_dump(), iso(self.now()))
                self._log("INTENT_UNSUPERVISED", {"actor": actor}, task_id=root["id"])
        return self.get_task(task_id)

    def delegate(
        self, parent_token: str, name: str, requested: Grant, ttl_seconds: int | None = None
    ) -> tuple[dict, str]:
        parent = self._active_task_by_token(parent_token)
        if parent["depth"] + 1 > self.max_depth:
            raise GateError("maximum delegation depth reached", code="DEPTH_EXCEEDED")
        try:
            child_grant = attenuate(Grant.model_validate(json.loads(parent["grant_json"])), requested)
        except AttenuationError as e:
            self._log(
                "DELEGATION_DENIED",
                {"parent": parent["id"], "name": name, "reason": str(e)},
                task_id=parent["id"],
            )
            raise GateError(str(e), code="ATTENUATION_VIOLATION", status_code=403) from e
        self._validate_grant_against_table(child_grant)
        now = self.now()
        parent_exp = parse_iso(parent["expires_at"])
        exp = (
            parent_exp
            if ttl_seconds is None
            else min(parent_exp, now + timedelta(seconds=max(1, ttl_seconds)))
        )
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        tid = _new_id("task")
        row = {
            "id": tid,
            "parent_id": parent["id"],
            "root_id": parent["root_id"],
            "depth": parent["depth"] + 1,
            "name": name,
            "principal": f"delegated:{parent['id']}",
            "status": "active",
            "status_reason": None,
            "token_hash": _hash_token(token),
            "grant_json": json.dumps(child_grant.to_dict(), sort_keys=True),
            # Children inherit the parent's pinned configuration; they cannot re-pin.
            "config_versions_json": parent["config_versions_json"],
            "metadata_json": json.dumps({}, sort_keys=True),
            "intent_json": None,  # intent lives on the root; the whole tree shares one state
            "created_at": iso(now),
            "expires_at": iso(exp),
            "max_expires_at": parent["max_expires_at"],
            "updated_at": iso(now),
        }
        with self.store.tx():
            if self.store.count_tree(parent["root_id"]) >= self.max_tasks_per_tree:
                self._log(
                    "DELEGATION_DENIED",
                    {"parent": parent["id"], "name": name, "reason": "tree size limit"},
                    task_id=parent["id"],
                )
                raise GateError(
                    f"task tree already holds {self.max_tasks_per_tree} tasks",
                    code="TREE_LIMIT",
                    status_code=429,
                )
            self.store.insert_task(row)
            self._log(
                "TASK_DELEGATED",
                {
                    "parent": parent["id"],
                    "name": name,
                    "grant": child_grant.to_dict(),
                    "expires_at": row["expires_at"],
                },
                task_id=tid,
            )
        return task_view(row, self.store.budget_usage(tid)), token

    def _task_live(self, t: dict, now: datetime) -> tuple[bool, str, str]:
        if t["status"] != "active":
            return (
                False,
                "TASK_INACTIVE",
                f"task {t['id']} is {t['status']}"
                + (f": {t['status_reason']}" if t["status_reason"] else ""),
            )
        if parse_iso(t["expires_at"]) <= now:
            return False, "TASK_EXPIRED", f"task {t['id']} lease expired at {t['expires_at']}"
        return True, "", ""

    def _check_chain_live(self, chain: list[dict]) -> tuple[bool, str, str]:
        now = self.now()
        if not chain:
            return False, "TASK_NOT_FOUND", "task not found"
        for t in chain:
            ok, code, detail = self._task_live(t, now)
            if not ok:
                return False, code, detail
        return True, "", ""

    def _active_task_by_token(self, token: str) -> dict:
        t = self.store.get_task_by_token_hash(_hash_token(token))
        if t is None:
            raise Unauthorized("invalid task token", code="TASK_NOT_FOUND")
        ok, code, detail = self._check_chain_live(self.store.task_chain(t["id"]))
        if not ok:
            raise GateError(detail, code=code, status_code=403)
        return t

    def task_by_token(self, token: str) -> dict:
        t = self.store.get_task_by_token_hash(_hash_token(token))
        if t is None:
            raise Unauthorized("invalid task token", code="TASK_NOT_FOUND")
        return t

    def get_task(self, task_id: str) -> dict:
        t = self.store.get_task(task_id)
        if t is None:
            raise NotFound(f"task {task_id} not found")
        return self._with_intent(task_view(t, self.store.budget_usage(task_id)), task_id)

    def list_tasks(
        self, root_id: str | None = None, status: str | None = None, limit: int = 200, offset: int = 0
    ) -> list[dict]:
        return [
            task_view(t, self.store.budget_usage(t["id"]))
            for t in self.store.list_tasks(root_id=root_id, status=status, limit=limit, offset=offset)
        ]

    def available_commands(self, task: dict) -> list[dict]:
        grant = Grant.model_validate(json.loads(task["grant_json"]))
        out = []
        for cg in grant.commands:
            cd = self.table.get(cg.command)
            if cd is None:
                continue
            out.append(
                {
                    "name": cd.name,
                    "description": cd.description,
                    "effect_class": cd.effect_class,
                    "args_schema": cd.args_schema,
                    "constraints": {p: c.to_dict() for p, c in cg.args.items()},
                    "budgets": cd.budgets,
                }
            )
        return out

    # ------------------------------------------------------------------ revoke / renew / repin
    def revoke(self, task_id: str, actor: str, reason: str) -> dict:
        root = self.store.get_task(task_id)
        if root is None:
            raise NotFound(f"task {task_id} not found")
        now = iso(self.now())
        ids = self.store.task_subtree_ids(task_id)
        voided: list[str] = []
        with self.store.tx():
            for tid in ids:
                t = self.store.get_task(tid)
                if t and t["status"] == "active":
                    self.store.update_task_status(tid, "revoked", reason, now)
            # Void every outstanding authorization in the subtree and release its reservations.
            for st in ("issued", "held"):
                for a in self.store.list_authorizations(task_ids=ids, status=st, limit=100000):
                    if self._settle(
                        a,
                        commit=False,
                        final_status="released",
                        outcome={"error": "revoked before execution"},
                        receipt=None,
                        expected=("issued", "held"),
                    ):
                        voided.append(a["id"])
            self._log(
                "TASK_REVOKED",
                {"actor": actor, "reason": reason, "subtree": ids, "voided_authorizations": voided},
                task_id=task_id,
            )
        return {"revoked": ids, "voided_authorizations": voided}

    def renew(self, task_id: str, actor: str, extend_seconds: int) -> dict:
        t = self.store.get_task(task_id)
        if t is None:
            raise NotFound(f"task {task_id} not found")
        if t["status"] != "active":
            raise GateError(f"task is {t['status']}", code="TASK_INACTIVE", status_code=409)
        if extend_seconds <= 0:
            raise GateError("extend_seconds must be positive", code="INVALID_TTL")
        now = self.now()
        base = max(now, parse_iso(t["expires_at"]))
        new_exp = base + timedelta(seconds=extend_seconds)
        cap = parse_iso(t["max_expires_at"])
        if t["parent_id"]:
            parent = self.store.get_task(t["parent_id"])
            if parent:
                cap = min(cap, parse_iso(parent["expires_at"]))
        if new_exp > cap:
            new_exp = cap
        if new_exp <= now:
            raise GateError("lease cannot be extended beyond its cap", code="LEASE_CAPPED", status_code=409)
        with self.store.tx():
            self.store.update_task_fields(task_id, iso(now), expires_at=iso(new_exp))
            self._log("TASK_RENEWED", {"actor": actor, "expires_at": iso(new_exp)}, task_id=task_id)
        return self.get_task(task_id)

    def repin(self, task_id: str, actor: str) -> dict:
        """Operator re-approves a task against the *current* integration configuration."""
        t = self.store.get_task(task_id)
        if t is None:
            raise NotFound(f"task {task_id} not found")
        if t["parent_id"] is not None:
            raise GateError("re-pin the root task; children inherit", code="NOT_ROOT", status_code=409)
        grant = Grant.model_validate(json.loads(t["grant_json"]))
        versions = self._pin_config_versions(grant)
        now = iso(self.now())
        vj = json.dumps(versions, sort_keys=True)
        with self.store.tx():
            for tid in self.store.task_subtree_ids(task_id):
                self.store.update_task_fields(tid, now, config_versions_json=vj)
            self._log("TASK_REPINNED", {"actor": actor, "config_versions": versions}, task_id=task_id)
        return self.get_task(task_id)

    # ------------------------------------------------------------------ background maintenance
    def expire_sweep(self) -> int:
        """Mark lapsed leases as expired and void their outstanding authorizations.

        Enforcement is already lazy (every request checks the lease); this keeps the ledger
        and budget reservations honest for tasks nobody touches again."""
        now = self.now()
        n = 0
        for t in self.store.list_tasks(status="active", limit=10000):
            if parse_iso(t["expires_at"]) <= now:
                with self.store.tx():
                    self.store.update_task_status(t["id"], "expired", "lease lapsed", iso(now))
                    for st in ("issued", "held"):
                        for a in self.store.list_authorizations(task_ids=[t["id"]], status=st):
                            self._settle(
                                a,
                                commit=False,
                                final_status="released",
                                outcome={"error": "task expired"},
                                receipt=None,
                                expected=("issued", "held"),
                            )
                    self._log("TASK_EXPIRED", {"expires_at": t["expires_at"]}, task_id=t["id"])
                n += 1
        return n

    def authorization_sweep(self) -> dict[str, int]:
        """Settle authorizations the normal path lost track of.

        * `issued` past its expiry: nobody can consume it any more (both the gate and the
          executor check expiry), so its reservation is released.
        * `consumed` for longer than any execution can take: the gate died or lost the response
          mid-flight. The outcome is `unknown` (reservation kept) until reconciled.
        * `unknown` older than `reconcile_after_seconds`: ask the executor, with backoff.
        """
        now = self.now()
        counts = {"released_expired": 0, "marked_unknown": 0, "reconciled": 0}
        for a in self.store.list_authorizations(status="issued", expires_before=iso(now), limit=1000):
            if self._settle(
                a,
                commit=False,
                final_status="released",
                outcome={"error": "authorization expired before it was consumed"},
                receipt=None,
                expected=("issued",),
            ):
                counts["released_expired"] += 1
        stale = iso(now - timedelta(seconds=self.stale_consumed_seconds))
        for a in self.store.list_authorizations(status="consumed", consumed_before=stale, limit=1000):
            if self.store.finalize_authorization(
                a["id"],
                "unknown",
                iso(now),
                {"status": "unknown", "error": "consumed but no outcome was recorded"},
                None,
                expected=("consumed",),
            ):
                self._log(
                    "OUTCOME_UNKNOWN",
                    {"authorization_id": a["id"], "error": "consumed but no outcome was recorded"},
                    task_id=a["task_id"],
                )
                counts["marked_unknown"] += 1
        due = iso(now - timedelta(seconds=self.reconcile_after_seconds))
        wall = time.monotonic()
        for a in self.store.list_authorizations(status="unknown", finalized_before=due, limit=200):
            next_at, attempts = self._reconcile_backoff.get(a["id"], (0.0, 0))
            if wall < next_at:
                continue
            try:
                res = self.reconcile(a["id"], SYSTEM_ACTOR)
            except GateError as e:
                log.warning("auto-reconcile %s failed: %s", a["id"], e.detail)
                res = {"reconciled": False}
            if res.get("reconciled"):
                self._reconcile_backoff.pop(a["id"], None)
                counts["reconciled"] += 1
            else:
                delay = min(600.0, 15.0 * (2**attempts))
                self._reconcile_backoff[a["id"]] = (wall + delay, attempts + 1)
        if len(self._reconcile_backoff) > 10000:
            self._reconcile_backoff.clear()
        return counts

    # ------------------------------------------------------------------ invoke pipeline
    def invoke(
        self, token: str, command: str, args: Any, *, idempotency_key: str | None = None
    ) -> InvokeResult:
        t = self.store.get_task_by_token_hash(_hash_token(token))
        if t is None:
            raise Unauthorized("invalid task token", code="TASK_NOT_FOUND")
        task_id = t["id"]

        if idempotency_key is None:
            return self._invoke(t, command, args)

        req_hash = hash_obj({"command": command, "args": args})
        now = self.now()
        attempt = secrets.token_hex(8)
        stale_before = iso(now - timedelta(seconds=self._idempotency_stale_seconds()))
        state, stored = self.store.idempotency_begin(
            task_id, idempotency_key, req_hash, iso(now), stale_before, attempt
        )
        if state == "done" and stored is not None:
            res = InvokeResult.model_validate(stored)
            res.replayed = True
            return res
        if state == "mismatch":
            raise GateError(
                "Idempotency-Key was already used with different arguments",
                code="IDEMPOTENCY_MISMATCH",
                status_code=422,
            )
        if state == "in_progress":
            raise GateError(
                "a request with this Idempotency-Key is still in progress",
                code="IDEMPOTENCY_IN_PROGRESS",
                status_code=409,
            )
        try:
            res = self._invoke(t, command, args)
        except BaseException:
            self.store.idempotency_abandon(task_id, idempotency_key, attempt)
            raise
        if res.denial is not None and res.denial.reason in TRANSIENT_DENIALS:
            # Nothing was decided about the request itself; let a retry with the same key re-evaluate.
            self.store.idempotency_abandon(task_id, idempotency_key, attempt)
        else:
            self.store.idempotency_finish(task_id, idempotency_key, res.model_dump(), attempt)
        return res

    def _idempotency_stale_seconds(self) -> int:
        """An in-progress idempotency claim older than this is assumed dead (its process crashed before
        recording a result). It must exceed any legitimate end-to-end invoke: prediction, queueing
        behind the tree lock, dispatch with the longest command timeout, and the authorization TTL."""
        longest = max((c.timeout_seconds for c in self.table.commands.values()), default=15.0)
        return int(self.auth_ttl + longest + 300)

    def _invoke(self, t: dict, command: str, args: Any) -> InvokeResult:
        # Everything up to and including dispatch preparation runs under the tree lock so the
        # intent state and budget reservation are updated consistently per tree. The executor
        # round-trip runs outside it.
        with self._tree_lock(t["root_id"]):
            prepared = self._prepare(t, command, args)
        if isinstance(prepared, InvokeResult):
            return prepared
        arow, envelope, cd, chain, effects, intent_summary = prepared
        try:
            resp = self.executor.execute(
                envelope, json.loads(arow["args_json"]), timeout=cd.timeout_seconds + 5
            )
        except ExecutorError as e:
            # We do not know whether the executor acted. Keep budgets reserved and require reconciliation.
            res = self._record_outcome(arow, chain, {"status": "unknown", "error": str(e)}, effects)
        except Exception as e:  # noqa: BLE001 - never leave a reservation dangling on a bug
            log.exception("dispatch failed for authorization %s", arow["id"])
            res = self._record_outcome(
                arow,
                chain,
                {"status": "unknown", "error": f"dispatch failure: {e.__class__.__name__}"},
                effects,
            )
        else:
            res = self._record_outcome(arow, chain, resp, effects)
        res.intent = intent_summary
        return res

    def _prepare(self, t: dict, command: str, args: Any) -> InvokeResult | tuple:
        """Run every check and, if the action is admitted, reserve budgets and mint the authorization.

        Returns an InvokeResult for denials and holds, or the tuple needed to dispatch."""
        task_id = t["id"]
        spec, root, istate = self._root_intent(t)
        root_grant = Grant.model_validate(json.loads(root["grant_json"])) if root else None

        def deny(
            reason: str,
            detail: str,
            *,
            effects: list[dict] | None = None,
            observe: bool = True,
            intent: dict | None = None,
            **extra: Any,
        ) -> InvokeResult:
            intent_summary = intent
            if observe and spec and root_grant and istate is not None and reason in OBSERVABLE_DENIALS:
                out_of_scope = reason in OUT_OF_SCOPE_DENIALS
                new_state, abstract = self.intent.observe_denial(
                    spec,
                    root_grant,
                    istate,
                    command,
                    args if isinstance(args, dict) else {},
                    effects or [],
                    out_of_scope=out_of_scope,
                )
                model = self.intent.model_for(spec, root_grant)
                asm = model.assess(new_state, abstract)
                if asm.supervise and new_state.mode != "supervised":
                    new_state.mode, new_state.mode_reason = "supervised", asm.supervise_reason
                    self._log(
                        "INTENT_SUPERVISED",
                        {"reason": asm.supervise_reason, "trigger": "denied attempt", "command": command},
                        task_id=root["id"],
                    )
                self.store.set_intent_state(root["id"], new_state.model_dump(), iso(self.now()))
                intent_summary = {
                    "abstract_action": abstract.to_dict(),
                    "e_value": round(asm.e_value, 4),
                    "forecast": round(asm.forecast, 4),
                    "non_goal_mass": {
                        k: round(v, 4) for k, v in model.non_goal_mass(new_state.log_weights).items()
                    },
                    "mode": new_state.mode,
                }
            self._log(
                "INVOKE_DENIED",
                {
                    "command": command,
                    "args": args,
                    "reason": reason,
                    "detail": detail,
                    "intent": intent_summary,
                    **extra,
                },
                task_id=task_id,
            )
            log.info("denied task=%s command=%s reason=%s", task_id, command, reason)
            return InvokeResult(
                decision="denied",
                command=command,
                denial=Denial(reason=reason, detail=detail, extra=extra),
                intent=intent_summary,
            )

        if self.halted():
            return deny("HALTED", "gate is halted by operator; no protected actions are permitted")

        chain = self.store.task_chain(task_id)
        ok, code, detail = self._check_chain_live(chain)
        if not ok:
            return deny(code, detail)

        cd = self.table.get(command)
        if cd is None:
            return deny("COMMAND_UNKNOWN", f"no such command '{command}' in the command table")
        grant = Grant.model_validate(json.loads(t["grant_json"]))
        cg = grant.command_grant(command)
        if cg is None:
            return deny("COMMAND_NOT_GRANTED", f"task {task_id} does not hold '{command}'")

        if not isinstance(args, dict):
            return deny("INVALID_ARGS", "arguments must be an object", observe=False)
        errors = cd.validate_args(args)
        if errors:
            return deny("INVALID_ARGS", "; ".join(errors[:5]))
        try:
            check_args(args, cg)
        except ConstraintViolation as e:
            return deny("CONSTRAINT_VIOLATION", str(e), path=e.path, op=e.op)

        try:
            charges = cd.budget_charges(args)
        except ValueError as e:
            return deny("INVALID_ARGS", str(e))

        # Consequence check: ask the executor what this operation will cause under the current
        # configuration. Mutating commands that cannot be predicted are denied.
        effects: list[dict] = []
        config_version: str | None = None
        if cd.is_mutating():
            try:
                pred = self.executor.predict(cd.adapter, cd.operation, cd.integration, args)
            except ExecutorError as e:
                return deny("PREDICTION_UNAVAILABLE", f"cannot evaluate consequences: {e}")
            raw_effects = pred.get("effects", [])
            if not isinstance(raw_effects, list) or not all(isinstance(e, dict) for e in raw_effects):
                return deny("PREDICTION_UNAVAILABLE", "executor returned a malformed prediction")
            effects = list(raw_effects)
            config_version = pred.get("config_version")
            pinned = json.loads(t["config_versions_json"]).get(cd.integration)
            if pinned is None or not isinstance(config_version, str):
                return deny("CONFIG_UNPINNED", f"no pinned configuration for integration '{cd.integration}'")
            if pinned != config_version:
                return deny(
                    "CONFIG_CHANGED",
                    f"integration '{cd.integration}' configuration changed since this task was approved; operator must re-pin",
                    pinned=pinned,
                    current=config_version,
                )
            hit = self._forbidden_hits(grant, effects)
            if hit:
                return deny(
                    "FORBIDDEN_EFFECT",
                    self._forbidden_detail(effects, hit),
                    effects=effects,
                    hit=hit,
                )

        # Intent layer: content claims, provenance, and the probabilistic assessment.
        intent_summary: dict | None = None
        hold_info: dict | None = None
        if spec and root_grant and istate is not None:
            dec = self.intent.evaluate(
                spec, root_grant, istate, command, args, effects, self.store.trusted_atoms(root["id"])
            )
            intent_summary = dec.summary()
            if dec.new_state.mode == "supervised" and istate.mode != "supervised":
                self._log(
                    "INTENT_SUPERVISED",
                    {"reason": dec.new_state.mode_reason, "command": command},
                    task_id=root["id"],
                )
            self.store.set_intent_state(root["id"], dec.new_state.model_dump(), iso(self.now()))
            if dec.decision == "deny":
                return deny(
                    dec.reason or "INTENT_DENIED", dec.detail or "", observe=False, intent=intent_summary
                )
            if dec.decision == "hold":
                hold_info = {"reason": dec.reason, "detail": dec.detail}

        # Reserve budgets and mint the authorization in ONE transaction: a reservation must never
        # exist without the authorization row that the sweeper and the settlement paths key on.
        try:
            with self.store.tx():
                self.store.reserve_budgets(chain, charges)
                return self._mint(
                    t, cd, command, args, charges, effects, config_version, intent_summary, hold_info, chain
                )
        except BudgetExceeded as e:
            return deny(
                "BUDGET_EXCEEDED",
                str(e),
                dimension=e.dimension,
                limit=e.limit,
                used=e.used,
                requested=e.requested,
                task=e.task_id,
            )

    def _mint(
        self,
        t: dict,
        cd: Any,
        command: str,
        args: dict,
        charges: dict,
        effects: list[dict],
        config_version: str | None,
        intent_summary: dict | None,
        hold_info: dict | None,
        chain: list[dict],
    ) -> InvokeResult | tuple:
        """Insert the authorization row (held or issued). Runs inside the reservation transaction."""
        task_id = t["id"]
        now = self.now()
        auth_id = _new_id("auth")
        args_json = json.dumps(args, sort_keys=True)
        intent_json = json.dumps(intent_summary, sort_keys=True) if intent_summary is not None else None
        if hold_info is not None:
            arow = {
                "id": auth_id,
                "task_id": task_id,
                "command": command,
                "args_json": args_json,
                "args_hash": hash_obj(args),
                "charges_json": json.dumps(charges, sort_keys=True),
                "integration": cd.integration,
                "config_version": config_version,
                "effects_json": json.dumps(effects, sort_keys=True),
                "envelope_json": "{}",
                "status": "held",
                "issued_at": iso(now),
                "expires_at": iso(parse_iso(t["expires_at"])),
                "hold_json": json.dumps({**hold_info, "intent": intent_summary}, sort_keys=True),
                "intent_json": intent_json,
            }
            with self.store.tx():
                self.store.insert_authorization(arow)
                self._log(
                    "AUTHORIZATION_HELD",
                    {
                        "authorization_id": auth_id,
                        "command": command,
                        "args": args,
                        "charges": charges,
                        "effects": effects,
                        **hold_info,
                        "intent": intent_summary,
                    },
                    task_id=task_id,
                )
            return InvokeResult(
                decision="allowed",
                command=command,
                authorization_id=auth_id,
                status="held",
                effects=effects,
                budgets=self.store.budget_usage(task_id),
                intent=intent_summary,
                hold=hold_info,
            )
        payload = {
            "id": auth_id,
            "task_id": task_id,
            "root_id": t["root_id"],
            "command": command,
            "adapter": cd.adapter,
            "operation": cd.operation,
            "integration": cd.integration,
            "args_hash": hash_obj(args),
            "config_version": config_version,
            "effects": effects,
            "issued_at": iso(now),
            "expires_at": iso(now + timedelta(seconds=self.auth_ttl)),
        }
        envelope = signed_envelope(self.signer, payload)
        arow = {
            "id": auth_id,
            "task_id": task_id,
            "command": command,
            "args_json": args_json,
            "args_hash": payload["args_hash"],
            "charges_json": json.dumps(charges, sort_keys=True),
            "integration": cd.integration,
            "config_version": config_version,
            "effects_json": json.dumps(effects, sort_keys=True),
            "envelope_json": json.dumps(envelope, sort_keys=True),
            "status": "issued",
            "issued_at": payload["issued_at"],
            "expires_at": payload["expires_at"],
            "intent_json": intent_json,
        }
        with self.store.tx():
            self.store.insert_authorization(arow)
            self._log(
                "AUTHORIZATION_ISSUED",
                {
                    "authorization_id": auth_id,
                    "command": command,
                    "args": args,
                    "charges": charges,
                    "effects": effects,
                    "config_version": config_version,
                    "intent": intent_summary,
                },
                task_id=task_id,
            )
        return arow, envelope, cd, chain, effects, intent_summary

    @staticmethod
    def _forbidden_hits(grant: Grant, effects: list[dict]) -> list[dict]:
        forbidden = set(grant.forbidden_effects)
        return [e for e in effects if e.get("type") in forbidden]

    @staticmethod
    def _forbidden_detail(effects: list[dict], hit: list[dict]) -> str:
        def field_of(e: dict) -> str | None:
            d = e.get("detail")
            return d.get("field") if isinstance(d, dict) and isinstance(d.get("field"), str) else None

        hit_fields = {field_of(e) for e in hit if field_of(e)}
        all_fields = {field_of(e) for e in effects if e.get("type") == "field_change" and field_of(e)}
        allowed_fields = sorted(all_fields - hit_fields)
        hint = (
            f" Permitted path: a separate update touching only {allowed_fields} would be allowed."
            if allowed_fields
            else ""
        )
        return (
            f"operation would cause forbidden effect(s): {sorted({str(e.get('type')) for e in hit})}.{hint}"
        )

    # ------------------------------------------------------------------ outcomes
    def _check_receipt(self, auth_id: str, resp: dict) -> tuple[Any, dict | None, str | None]:
        """Validate the executor's receipt against the response.

        Returns (status, receipt, error). Without a verifiable receipt that names this
        authorization and agrees with the reported status, the outcome is `unknown`."""
        status = resp.get("status")
        receipt = resp.get("receipt")
        if receipt is None:
            return "unknown", None, "executor response carried no receipt; treating outcome as unknown"
        if not verify_envelope(self.executor_keys, receipt):
            return "unknown", None, "executor receipt signature invalid; treating outcome as unknown"
        rp = receipt.get("payload", {})
        if rp.get("authorization_id") != auth_id:
            return (
                "unknown",
                None,
                "executor receipt bound to a different authorization; treating outcome as unknown",
            )
        if rp.get("status") != status:
            return (
                "unknown",
                None,
                f"executor receipt status {rp.get('status')!r} disagrees with response {status!r}; treating outcome as unknown",
            )
        result = resp.get("result")
        if status == "ok" and rp.get("result_hash") != (hash_obj(result) if result is not None else None):
            return (
                "unknown",
                None,
                "executor receipt does not cover the returned result; treating outcome as unknown",
            )
        return status, receipt, None

    def _record_outcome(self, arow: dict, chain: list[dict], resp: dict, effects: list[dict]) -> InvokeResult:
        auth_id = arow["id"]
        status, receipt, err = self._check_receipt(auth_id, resp)
        if err:
            resp = {**resp, "error": err}
            log.warning("authorization %s: %s", auth_id, err)
        current = self.store.get_authorization(auth_id)
        if current and current["status"] in FINAL_AUTH_STATUSES:
            # Already settled (e.g. revoked mid-flight). Report what the ledger says.
            outcome = json.loads(current["outcome_json"]) if current["outcome_json"] else {}
            return InvokeResult(
                decision="allowed",
                command=arow["command"],
                authorization_id=auth_id,
                status=current["status"],
                error=(outcome or {}).get("error"),
                effects=effects,
                budgets=self.store.budget_usage(arow["task_id"]),
            )
        live = ("issued", "consumed")
        if status == "ok":
            if self._settle(
                arow, commit=True, final_status="committed", outcome=resp, receipt=receipt, expected=live
            ):
                self._record_read_atoms(arow, resp.get("result"))
            final = "committed"
        elif status == "failed":
            self._settle(
                arow, commit=False, final_status="failed", outcome=resp, receipt=receipt, expected=live
            )
            final = "failed"
        elif status == "rejected":
            # Executor refused. If the row was never consumed nothing can have happened. If it *was*
            # consumed, only a rejection the executor issues after consuming (configuration drift)
            # proves inaction; any other rejection (replay, verification) on a consumed row may be a
            # replayed answer for an action that executed, so the outcome is unknown.
            reason = (receipt or {}).get("payload", {}).get("reason") if receipt else None
            if self._settle(
                arow,
                commit=False,
                final_status="released",
                outcome=resp,
                receipt=receipt,
                expected=("issued",),
            ):
                final = "rejected"
            elif reason in POST_CONSUME_REJECTIONS and self._settle(
                arow,
                commit=False,
                final_status="released",
                outcome=resp,
                receipt=receipt,
                expected=("consumed",),
            ):
                final = "rejected"
            else:
                resp = {
                    **resp,
                    "error": f"executor rejection ({reason or 'unspecified'}) after consumption cannot prove inaction; treating outcome as unknown",
                }
                if self.store.finalize_authorization(
                    auth_id, "unknown", iso(self.now()), resp, receipt, expected=("consumed",)
                ):
                    log.warning("authorization %s: %s", auth_id, resp["error"])
                    self._log(
                        "OUTCOME_UNKNOWN",
                        {"authorization_id": auth_id, "error": resp["error"]},
                        task_id=arow["task_id"],
                    )
                final = "unknown"
        else:
            if self.store.finalize_authorization(
                auth_id, "unknown", iso(self.now()), resp, receipt, expected=live
            ):
                self._log(
                    "OUTCOME_UNKNOWN",
                    {"authorization_id": auth_id, "error": resp.get("error")},
                    task_id=arow["task_id"],
                )
            final = "unknown"
        current = self.store.get_authorization(auth_id)
        stored = current["status"] if current else None
        expected_stored = "released" if final == "rejected" else final
        if stored is not None and stored != expected_stored:
            # A concurrent path (revoke, sweep) won the race. Report the stored truth.
            final = stored
        usage = self.store.budget_usage(arow["task_id"])
        return InvokeResult(
            decision="allowed",
            command=arow["command"],
            authorization_id=auth_id,
            status=final,
            result=resp.get("result") if final == "committed" else None,
            error=resp.get("error"),
            effects=effects,
            receipt=receipt,
            budgets=usage,
        )

    def _record_read_atoms(self, arow: dict, result: Any) -> None:
        """Identifiers in the structured fields of any committed result are legitimate observations
        of this task (a refund id the agent just created, a charge id it listed) and become trusted
        provenance for its payloads. Free-text fields never do."""
        cd = self.table.get(arow["command"])
        if cd is None or result is None:
            return
        t = self.store.get_task(arow["task_id"])
        if t is None:
            return
        spec, root, _ = self._root_intent(t)
        if spec and root:
            self.store.add_trusted_atoms(
                root["id"], self.intent.atoms_from_read_result(spec, result), f"read:{arow['command']}"
            )

    def approve(self, auth_id: str, actor: str) -> InvokeResult:
        """Operator approves a held authorization: re-check consequences, sign, dispatch, execute now."""
        a = self.store.get_authorization(auth_id)
        if a is None:
            raise NotFound("authorization not found")
        if a["status"] != "held":
            raise GateError(f"authorization is {a['status']}, not held", code="NOT_HELD", status_code=409)
        t = self.store.get_task(a["task_id"])
        if t is None:
            raise NotFound("task not found")
        chain = self.store.task_chain(t["id"])
        ok, code, detail = self._check_chain_live(chain)
        if not ok:
            raise GateError(detail, code=code, status_code=409)
        if self.halted():
            raise GateError("gate halted", code="HALTED", status_code=409)
        cd = self.table.get(a["command"])
        if cd is None:
            raise GateError("command no longer in table", code="COMMAND_UNKNOWN", status_code=409)
        args = json.loads(a["args_json"])
        effects = json.loads(a["effects_json"])
        config_version = a["config_version"]
        grant = Grant.model_validate(json.loads(t["grant_json"]))
        if cd.is_mutating():
            try:
                pred = self.executor.predict(cd.adapter, cd.operation, cd.integration, args)
            except ExecutorError as e:
                raise GateError(
                    f"cannot re-evaluate consequences: {e}", code="PREDICTION_UNAVAILABLE", status_code=503
                ) from e
            config_version = pred.get("config_version")
            effects = list(pred.get("effects", []))
            pinned = json.loads(t["config_versions_json"]).get(cd.integration)
            if pinned != config_version:
                raise GateError(
                    "integration configuration changed since the hold; re-pin first",
                    code="CONFIG_CHANGED",
                    status_code=409,
                )
            hit = self._forbidden_hits(grant, effects)
            if hit:
                # The world moved under the hold: what was admissible now causes a forbidden effect.
                detail = self._forbidden_detail(effects, hit)
                self._settle(
                    a,
                    commit=False,
                    final_status="released",
                    outcome={"error": "forbidden effect at approval time: " + detail},
                    receipt=None,
                    expected=("held",),
                )
                raise GateError(detail, code="FORBIDDEN_EFFECT", status_code=409)
        now = self.now()
        payload = {
            "id": auth_id,
            "task_id": t["id"],
            "root_id": t["root_id"],
            "command": a["command"],
            "adapter": cd.adapter,
            "operation": cd.operation,
            "integration": cd.integration,
            "args_hash": a["args_hash"],
            "config_version": config_version,
            "effects": effects,
            "issued_at": iso(now),
            "expires_at": iso(now + timedelta(seconds=self.auth_ttl)),
            "approved_by": actor,
        }
        envelope = signed_envelope(self.signer, payload)
        with self.store.tx():
            if not self.store.release_hold(
                auth_id,
                json.dumps(envelope, sort_keys=True),
                payload["issued_at"],
                payload["expires_at"],
                config_version,
            ):
                raise GateError("authorization is no longer held", code="NOT_HELD", status_code=409)
            self._log(
                "AUTHORIZATION_APPROVED",
                {"authorization_id": auth_id, "actor": actor, "command": a["command"], "effects": effects},
                task_id=t["id"],
            )
        arow = {**a, "envelope_json": json.dumps(envelope, sort_keys=True), "status": "issued"}
        try:
            resp = self.executor.execute(envelope, args, timeout=cd.timeout_seconds + 5)
        except ExecutorError as e:
            return self._record_outcome(arow, chain, {"status": "unknown", "error": str(e)}, effects)
        except Exception as e:  # noqa: BLE001
            log.exception("dispatch failed for approved authorization %s", auth_id)
            return self._record_outcome(
                arow,
                chain,
                {"status": "unknown", "error": f"dispatch failure: {e.__class__.__name__}"},
                effects,
            )
        return self._record_outcome(arow, chain, resp, effects)

    def reject(self, auth_id: str, actor: str, reason: str) -> dict:
        a = self.store.get_authorization(auth_id)
        if a is None:
            raise NotFound("authorization not found")
        if a["status"] != "held":
            raise GateError(f"authorization is {a['status']}, not held", code="NOT_HELD", status_code=409)
        if not self._settle(
            a,
            commit=False,
            final_status="released",
            outcome={"error": f"rejected by {actor}: {reason}"},
            receipt=None,
            expected=("held",),
        ):
            raise GateError("authorization is no longer held", code="NOT_HELD", status_code=409)
        return {"authorization_id": auth_id, "status": "released", "reason": reason}

    def _settle(
        self,
        arow: dict,
        *,
        commit: bool,
        final_status: str,
        outcome: dict | None,
        receipt: dict | None,
        expected: tuple[str, ...],
    ) -> bool:
        """Move an authorization to a terminal status and settle its budgets exactly once.

        The status transition is conditional on `expected`; if another path already settled
        the row, nothing moves and False is returned."""
        chain = self.store.task_chain(arow["task_id"])
        charges = json.loads(arow["charges_json"])
        now = iso(self.now())
        with self.store.tx():
            if not self.store.finalize_authorization(
                arow["id"], final_status, now, outcome, receipt, expected=expected
            ):
                return False
            self.store.settle_budgets(chain, charges, commit=commit)
            self._log(
                "AUTHORIZATION_SETTLED",
                {
                    "authorization_id": arow["id"],
                    "command": arow["command"],
                    "status": final_status,
                    "charges": charges,
                    "result": (outcome or {}).get("result"),
                    "error": (outcome or {}).get("error"),
                    "receipt": receipt,
                },
                task_id=arow["task_id"],
            )
            return True

    # ------------------------------------------------------------------ consume (executor callback)
    def consume(self, auth_id: str) -> dict:
        """Single-use consumption. Re-checks halt, task liveness and revocation at the moment of action,
        in the same transaction that flips the status."""
        now = self.now()
        with self.store.tx():
            a = self.store.get_authorization(auth_id)
            if a is None:
                raise NotFound("authorization not found", code="AUTH_NOT_FOUND")
            if self.halted():
                raise GateError("gate halted", code="HALTED", status_code=409)
            chain = self.store.task_chain(a["task_id"])
            ok, code, detail = self._check_chain_live(chain)
            if not ok:
                raise GateError(detail, code=code, status_code=409)
            row = self.store.consume_authorization(auth_id, iso(now))
            if row is None:
                raise GateError(
                    "authorization is not consumable (already used, expired, or voided)",
                    code="AUTH_NOT_CONSUMABLE",
                    status_code=409,
                )
            self._log("AUTHORIZATION_CONSUMED", {"authorization_id": auth_id}, task_id=a["task_id"])
        return {
            "consumed": True,
            "authorization_id": auth_id,
            "args_hash": a["args_hash"],
            "config_version": a["config_version"],
        }

    # ------------------------------------------------------------------ reconcile
    def reconcile(self, auth_id: str, actor: str) -> dict:
        a = self.store.get_authorization(auth_id)
        if a is None:
            raise NotFound("authorization not found")
        if a["status"] != "unknown":
            return {"authorization_id": auth_id, "status": a["status"], "reconciled": False}
        envelope = json.loads(a["envelope_json"])
        args = json.loads(a["args_json"])
        try:
            resp = self.executor.reconcile(envelope, args)
        except ExecutorError as e:
            raise GateError(f"reconcile failed: {e}", code="EXECUTOR_UNAVAILABLE", status_code=503) from e
        status, receipt, err = self._check_receipt(auth_id, resp)
        if err and resp.get("status") != "unknown":
            raise GateError(err, code="BAD_RECEIPT", status_code=502)
        settled = False
        if status == "ok":
            settled = self._settle(
                a, commit=True, final_status="committed", outcome=resp, receipt=receipt, expected=("unknown",)
            )
            if settled:
                self._record_read_atoms(a, resp.get("result"))
        elif status in ("failed", "not_executed"):
            settled = self._settle(
                a,
                commit=False,
                final_status="failed" if status == "failed" else "released",
                outcome=resp,
                receipt=receipt,
                expected=("unknown",),
            )
        else:
            return {
                "authorization_id": auth_id,
                "status": "unknown",
                "reconciled": False,
                "error": resp.get("error"),
            }
        if settled:
            self._log(
                "AUTHORIZATION_RECONCILED",
                {"authorization_id": auth_id, "actor": actor, "status": status},
                task_id=a["task_id"],
            )
        current = self.store.get_authorization(auth_id)
        return {
            "authorization_id": auth_id,
            "status": current["status"] if current else status,
            "reconciled": True,
            "result": resp.get("result"),
        }

    def get_authorization(self, auth_id: str) -> dict:
        a = self.store.get_authorization(auth_id)
        if a is None:
            raise NotFound("authorization not found")
        return {
            **{
                k: a[k]
                for k in (
                    "id",
                    "task_id",
                    "command",
                    "integration",
                    "config_version",
                    "status",
                    "issued_at",
                    "expires_at",
                    "consumed_at",
                    "finalized_at",
                )
            },
            "args": json.loads(a["args_json"]),
            "charges": json.loads(a["charges_json"]),
            "effects": json.loads(a["effects_json"]),
            "envelope": json.loads(a["envelope_json"]),
            "outcome": json.loads(a["outcome_json"]) if a["outcome_json"] else None,
            "receipt": json.loads(a["receipt_json"]) if a["receipt_json"] else None,
            "hold": json.loads(a["hold_json"]) if a.get("hold_json") else None,
            "intent": json.loads(a["intent_json"]) if a.get("intent_json") else None,
        }

    def list_authorizations(
        self, root_id: str | None = None, status: str | None = None, limit: int = 500
    ) -> list[dict]:
        ids = self.store.task_subtree_ids(root_id) if root_id else None
        return [
            self.get_authorization(a["id"])
            for a in self.store.list_authorizations(task_ids=ids, status=status, limit=limit)
        ]

    def count_held(self) -> int:
        return len(self.store.list_authorizations(status="held", limit=100000))
