"""Gate HTTP API.

Three audiences, three credentials:
  * agents       -> task token        (/v1/me, /v1/invoke, /v1/delegate)
  * operators    -> admin token(s)    (/v1/admin/...)
  * executor     -> internal token    (/internal/...)

Agents see decisions, denial reasons, claims and provenance. They do not see the intent
detector's statistics, other tasks, or operator identities.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from collections.abc import Mapping
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, Field, field_validator

from .. import __version__
from ..canon import canonical_json
from ..grant import Grant
from ..intent.spec import IntentSpec
from .service import GateError, GateService, agent_task_view

log = logging.getLogger("writ.gate.api")

INVOKES = Counter("writ_gate_invocations_total", "Invocation requests", ["command", "decision", "reason"])
LATENCY = Histogram(
    "writ_gate_invoke_seconds",
    "End-to-end invoke latency including executor",
    ["command"],
    buckets=(0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
DENIALS = Counter("writ_gate_denials_total", "Denied invocations", ["reason"])
HOLDS = Counter("writ_gate_holds_total", "Authorizations held for operator review", ["reason"])
SUPERVISION = Counter("writ_gate_supervision_total", "Task trees entering supervised mode", ["trigger"])
HELD_GAUGE = Gauge("writ_gate_held_authorizations", "Authorizations currently held")
RATE_LIMITED = Counter("writ_gate_rate_limited_total", "Agent requests rejected by the rate limiter")
SWEEPS = Counter("writ_gate_sweep_actions_total", "Background maintenance actions", ["action"])

MAX_NAME = 200
MAX_METADATA_BYTES = 16 * 1024
MAX_IDEMPOTENCY_KEY = 128
UNKNOWN_COMMAND_LABEL = "<unknown>"


class InvokeBody(BaseModel):
    command: str = Field(max_length=200)
    args: Any = Field(default_factory=dict)


class DelegateBody(BaseModel):
    name: str = Field(default="sub-agent", max_length=MAX_NAME)
    grant: Grant
    ttl_seconds: int | None = Field(default=None, ge=1)


class CreateTaskBody(BaseModel):
    name: str = Field(min_length=1, max_length=MAX_NAME)
    grant: Grant
    ttl_seconds: int = Field(default=3600, ge=1)
    max_ttl_seconds: int | None = Field(default=None, ge=1)
    metadata: dict = Field(default_factory=dict)
    principal: str | None = Field(default=None, max_length=MAX_NAME)
    intent: IntentSpec | None = None

    @field_validator("metadata")
    @classmethod
    def _metadata_size(cls, v: dict) -> dict:
        if len(canonical_json(v).encode()) > MAX_METADATA_BYTES:
            raise ValueError(f"metadata exceeds {MAX_METADATA_BYTES} bytes")
        return v


class ReasonBody(BaseModel):
    reason: str = Field(default="", max_length=2000)


class RenewBody(BaseModel):
    extend_seconds: int = Field(ge=1)


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401, detail={"code": "UNAUTHORIZED", "detail": "missing bearer token"}
        )
    return authorization[len("Bearer ") :].strip()


_TOO_LARGE = b'{"code":"PAYLOAD_TOO_LARGE","detail":"request body exceeds limit"}'


class BodySizeLimit:
    """Pure ASGI middleware: reject request bodies above `max_bytes` with 413.

    A declared Content-Length above the limit is refused before the app runs. For chunked
    bodies the byte count is enforced while streaming: past the limit the app sees a client
    disconnect (so no handler ever runs on a truncated body) and the response is replaced by 413.
    """

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = None
        for k, v in scope.get("headers", []):
            if k == b"content-length":
                try:
                    declared = int(v)
                except ValueError:
                    declared = None
                break
        if declared is not None and declared > self.max_bytes:
            await self._reject(send)
            return
        seen = 0
        tripped = False
        body_sent = False

        async def limited_receive():
            nonlocal seen, tripped
            if tripped:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    tripped = True
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message):
            nonlocal body_sent
            if not tripped:
                await send(message)
                return
            if message["type"] == "http.response.start":
                await send(
                    {
                        "type": "http.response.start",
                        "status": 413,
                        "headers": [(b"content-type", b"application/json")],
                    }
                )
            elif message["type"] == "http.response.body" and not body_sent:
                body_sent = True
                await send({"type": "http.response.body", "body": _TOO_LARGE, "more_body": False})

        await self.app(scope, limited_receive, guarded_send)

    @staticmethod
    async def _reject(send):
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": _TOO_LARGE})


class TokenBucketLimiter:
    """Per-key token bucket. Keys are hashes of task tokens, so the table never holds secrets."""

    def __init__(self, rate_per_second: float, burst: int, max_keys: int = 50000):
        self.rate = rate_per_second
        self.burst = burst
        self.max_keys = max_keys
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_ts)

    def allow(self, key: str) -> bool:
        if self.rate <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(self.burst), now))
            tokens = min(float(self.burst), tokens + (now - last) * self.rate)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1.0, now)
            if len(self._buckets) > self.max_keys:
                # Drop the stalest half; a dropped key simply starts with a full bucket again.
                for k, _ in sorted(self._buckets.items(), key=lambda kv: kv[1][1])[: self.max_keys // 2]:
                    self._buckets.pop(k, None)
            return True


def create_app(
    service: GateService,
    admin_token: str | Mapping[str, str],
    internal_token: str,
    *,
    sweep_interval: float = 30.0,
    max_body_bytes: int = 1024 * 1024,
    agent_rate_per_second: float = 50.0,
    agent_burst: int = 100,
    enable_docs: bool = False,
) -> FastAPI:
    """Build the gate application.

    `admin_token` is either one token (actor recorded as "operator") or a mapping of operator
    name to token, in which case every ledger entry names the operator who acted.
    """
    app = FastAPI(
        title="Writ Gate",
        version=__version__,
        docs_url="/docs" if enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if enable_docs else None,
    )
    app.state.service = service
    admin_tokens: dict[str, str] = (
        {"operator": admin_token} if isinstance(admin_token, str) else dict(admin_token)
    )
    if not admin_tokens:
        raise ValueError("at least one admin token is required")
    limiter = TokenBucketLimiter(agent_rate_per_second, agent_burst)

    def require_admin(authorization: str | None = Header(default=None)) -> str:
        tok = _bearer(authorization)
        actor = None
        # Compare against every token so timing does not reveal which operator names exist.
        for name, expected in admin_tokens.items():
            if secrets.compare_digest(tok, expected):
                actor = name
        if actor is None:
            raise HTTPException(
                status_code=401, detail={"code": "UNAUTHORIZED", "detail": "invalid admin token"}
            )
        return actor

    def require_internal(authorization: str | None = Header(default=None)) -> str:
        tok = _bearer(authorization)
        if not secrets.compare_digest(tok, internal_token):
            raise HTTPException(
                status_code=401, detail={"code": "UNAUTHORIZED", "detail": "invalid internal token"}
            )
        return "executor"

    def task_token(authorization: str | None = Header(default=None)) -> str:
        tok = _bearer(authorization)
        key = hashlib.sha256(tok.encode()).hexdigest()[:32]
        if not limiter.allow(key):
            RATE_LIMITED.inc()
            raise HTTPException(
                status_code=429,
                detail={"code": "RATE_LIMITED", "detail": "too many requests for this task token"},
                headers={"Retry-After": "1"},
            )
        return tok

    @app.exception_handler(GateError)
    async def _gate_error(_: Request, exc: GateError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"code": exc.code, "detail": exc.detail})

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        errs = exc.errors()
        first = errs[0] if errs else {}
        loc = ".".join(str(p) for p in first.get("loc", ()) if p != "body")
        msg = first.get("msg", "invalid request")
        detail = f"{loc}: {msg}" if loc else msg
        return JSONResponse(status_code=422, content={"code": "INVALID_REQUEST", "detail": detail})

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error: %s", exc.__class__.__name__)
        return JSONResponse(status_code=500, content={"code": "INTERNAL", "detail": "internal error"})

    def _command_label(command: str) -> str:
        return command if command in service.table.commands else UNKNOWN_COMMAND_LABEL

    # ---------------------------------------------------------------- public
    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "version": __version__}

    @app.get("/readyz")
    def readyz() -> JSONResponse:
        try:
            service.executor.health()
            return JSONResponse({"ok": True, "halted": service.halted()})
        except Exception as e:  # noqa: BLE001
            return JSONResponse(
                status_code=503, content={"ok": False, "error": f"executor: {e.__class__.__name__}"}
            )

    @app.get("/metrics")
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/v1/keys")
    def keys() -> dict:
        v = service.signer.verifier
        out: dict[str, Any] = {
            "gate": {"key_id": v.key_id, "public_key": v.encoded_public(), "algorithm": "Ed25519"}
        }
        if service.executor_keys:
            trusted = service.executor_keys.describe()
            out["executor"] = trusted[0]
            out["executor_keys"] = trusted
        return out

    # ---------------------------------------------------------------- agent
    @app.get("/v1/me")
    def me(token: str = Depends(task_token)) -> dict:
        t = service.task_by_token(token)
        view = agent_task_view(service.get_task(t["id"]))
        view["commands"] = service.available_commands(t)
        view["halted"] = service.halted()
        return view

    @app.post("/v1/invoke")
    def invoke(
        body: InvokeBody,
        token: str = Depends(task_token),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict:
        if idempotency_key is not None:
            idempotency_key = idempotency_key.strip()
            if not idempotency_key or len(idempotency_key) > MAX_IDEMPOTENCY_KEY:
                raise GateError(
                    "Idempotency-Key must be 1-128 characters", code="INVALID_REQUEST", status_code=422
                )
        label = _command_label(body.command)
        start = time.perf_counter()
        res = service.invoke(token, body.command, body.args, idempotency_key=idempotency_key)
        LATENCY.labels(label).observe(time.perf_counter() - start)
        reason = res.denial.reason if res.denial else (res.status or "")
        INVOKES.labels(label, res.decision, reason).inc()
        if res.replayed:
            return res.agent_view()
        if res.denial:
            DENIALS.labels(res.denial.reason).inc()
        if res.status == "held" and res.hold:
            HOLDS.labels(res.hold.get("reason", "")).inc()
            HELD_GAUGE.set(service.count_held())
        if res.intent and res.intent.get("mode") == "supervised":
            SUPERVISION.labels("invoke").inc()
        return res.agent_view()

    @app.post("/v1/delegate", status_code=201)
    def delegate(body: DelegateBody, token: str = Depends(task_token)) -> dict:
        task, child_token = service.delegate(token, body.name, body.grant, body.ttl_seconds)
        return {"task": agent_task_view(task), "token": child_token}

    # ---------------------------------------------------------------- admin
    @app.get("/v1/admin/status")
    def status(actor: str = Depends(require_admin)) -> dict:
        return {
            "halted": service.halted(),
            "version": __version__,
            "commands": sorted(service.table.commands),
            "held_authorizations": service.count_held(),
            "operator": actor,
        }

    @app.get("/v1/admin/commands")
    def commands(actor: str = Depends(require_admin)) -> dict:
        return {"commands": [c.model_dump() for c in service.table.commands.values()]}

    @app.post("/v1/admin/tasks", status_code=201)
    def create_task(body: CreateTaskBody, actor: str = Depends(require_admin)) -> dict:
        task, tok = service.create_task(
            body.principal or actor,
            body.name,
            body.grant,
            body.ttl_seconds,
            body.max_ttl_seconds,
            body.metadata,
            intent=body.intent,
            actor=actor,
        )
        return {"task": task, "token": tok}

    @app.get("/v1/admin/tasks")
    def list_tasks(
        root_id: str | None = None,
        status: str | None = None,
        limit: int = 200,
        offset: int = 0,
        actor: str = Depends(require_admin),
    ) -> dict:
        return {
            "tasks": service.list_tasks(
                root_id=root_id, status=status, limit=max(1, min(limit, 1000)), offset=max(0, offset)
            )
        }

    @app.get("/v1/admin/tasks/{task_id}")
    def get_task(task_id: str, actor: str = Depends(require_admin)) -> dict:
        return service.get_task(task_id)

    @app.post("/v1/admin/tasks/{task_id}/revoke")
    def revoke(task_id: str, body: ReasonBody, actor: str = Depends(require_admin)) -> dict:
        return service.revoke(task_id, actor, body.reason)

    @app.post("/v1/admin/tasks/{task_id}/renew")
    def renew(task_id: str, body: RenewBody, actor: str = Depends(require_admin)) -> dict:
        return service.renew(task_id, actor, body.extend_seconds)

    @app.get("/v1/admin/tasks/{task_id}/intent")
    def explain_intent(task_id: str, actor: str = Depends(require_admin)) -> dict:
        return service.explain_intent(task_id)

    @app.post("/v1/admin/tasks/{task_id}/unsupervise")
    def unsupervise(task_id: str, actor: str = Depends(require_admin)) -> dict:
        return service.unsupervise(task_id, actor)

    @app.post("/v1/admin/tasks/{task_id}/repin")
    def repin(task_id: str, actor: str = Depends(require_admin)) -> dict:
        return service.repin(task_id, actor)

    @app.post("/v1/admin/halt")
    def halt(body: ReasonBody, actor: str = Depends(require_admin)) -> dict:
        service.set_halt(True, actor, body.reason)
        return {"halted": True}

    @app.post("/v1/admin/unhalt")
    def unhalt(body: ReasonBody, actor: str = Depends(require_admin)) -> dict:
        service.set_halt(False, actor, body.reason)
        return {"halted": False}

    @app.get("/v1/admin/authorizations")
    def list_auths(
        root_id: str | None = None,
        status: str | None = None,
        limit: int = 500,
        actor: str = Depends(require_admin),
    ) -> dict:
        return {
            "authorizations": service.list_authorizations(
                root_id=root_id, status=status, limit=max(1, min(limit, 5000))
            )
        }

    @app.get("/v1/admin/authorizations/{auth_id}")
    def get_auth(auth_id: str, actor: str = Depends(require_admin)) -> dict:
        return service.get_authorization(auth_id)

    @app.post("/v1/admin/authorizations/{auth_id}/approve")
    def approve(auth_id: str, actor: str = Depends(require_admin)) -> dict:
        try:
            out = service.approve(auth_id, actor).model_dump()
        finally:
            HELD_GAUGE.set(service.count_held())
        return out

    @app.post("/v1/admin/authorizations/{auth_id}/reject")
    def reject(auth_id: str, body: ReasonBody, actor: str = Depends(require_admin)) -> dict:
        out = service.reject(auth_id, actor, body.reason)
        HELD_GAUGE.set(service.count_held())
        return out

    @app.post("/v1/admin/authorizations/{auth_id}/reconcile")
    def reconcile(auth_id: str, actor: str = Depends(require_admin)) -> dict:
        return service.reconcile(auth_id, actor)

    @app.get("/v1/admin/ledger")
    def ledger(
        after: int = 0,
        limit: int = 500,
        task_id: str | None = None,
        root_id: str | None = None,
        actor: str = Depends(require_admin),
    ) -> dict:
        return {
            "entries": service.store.ledger_entries(
                after=max(0, after), limit=max(1, min(limit, 5000)), task_id=task_id, root_id=root_id
            )
        }

    @app.get("/v1/admin/ledger/verify")
    def ledger_verify(actor: str = Depends(require_admin)) -> dict:
        from ..ledger import ChainVerifier

        verifier = ChainVerifier()
        after = 0
        while True:
            page = service.store.ledger_entries(after=after, limit=5000)
            if not page:
                break
            if not verifier.feed(page):
                break
            after = page[-1]["seq"]
        return {
            "ok": verifier.ok,
            "entries": verifier.count,
            "error": verifier.error,
            "head": verifier.head,
        }

    @app.post("/v1/admin/sweep")
    def sweep(actor: str = Depends(require_admin)) -> dict:
        """Run the maintenance pass now (lease expiry, orphaned authorizations, auto-reconcile)."""
        expired = service.expire_sweep()
        counts = service.authorization_sweep()
        return {"expired_tasks": expired, **counts}

    # ---------------------------------------------------------------- internal (executor)
    @app.post("/internal/authorizations/{auth_id}/consume")
    def consume(auth_id: str, actor: str = Depends(require_internal)) -> dict:
        return service.consume(auth_id)

    # ---------------------------------------------------------------- background maintenance
    stop = threading.Event()

    def _sweeper() -> None:
        while not stop.wait(sweep_interval):
            try:
                n = service.expire_sweep()
                if n:
                    SWEEPS.labels("expired_tasks").inc(n)
                    log.info("expired %d task leases", n)
                counts = service.authorization_sweep()
                for k, v in counts.items():
                    if v:
                        SWEEPS.labels(k).inc(v)
                        log.info("authorization sweep: %s=%d", k, v)
                HELD_GAUGE.set(service.count_held())
            except Exception:  # noqa: BLE001
                log.exception("maintenance sweep failed")

    @asynccontextmanager
    async def _lifespan(_: FastAPI):
        if sweep_interval > 0:
            threading.Thread(target=_sweeper, name="writ-sweeper", daemon=True).start()
        try:
            yield
        finally:
            stop.set()

    app.router.lifespan_context = _lifespan
    app.add_middleware(BodySizeLimit, max_bytes=max_body_bytes)
    return app
