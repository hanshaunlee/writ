"""Executor HTTP API. Runs on the control network; holds the upstream credentials.

For each execute request it:
  1. verifies the gate's Ed25519 signature on the authorization and its expiry;
  2. checks the argument hash binds the supplied arguments to the authorization;
  3. claims the authorization id locally (single use), then consumes it at the gate, which
     re-checks revocation and halt at the moment of action;
  4. re-reads the integration's configuration version and refuses if it moved;
  5. performs the operation with the authorization id as the idempotency key;
  6. returns a signed receipt.

Every response carries a signed receipt, including early rejections, so the gate can tell a
genuine executor answer from anything injected on the control network.
"""

from __future__ import annotations

import logging
import secrets
import time
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from pydantic import BaseModel, Field

from .. import __version__
from ..canon import hash_obj
from ..signing import KeyRing, Signer, Verifier, signed_envelope, verify_envelope
from .adapters import AdapterRegistry, UpstreamAmbiguous, UpstreamRejected
from .nonces import NonceStore

log = logging.getLogger("writ.executor")

EXECUTIONS = Counter(
    "writ_executor_executions_total", "Executions by outcome", ["adapter", "operation", "status"]
)
REJECTIONS = Counter("writ_executor_rejections_total", "Authorizations rejected before acting", ["reason"])

# Nonce records are purged after this many seconds. Reconciliation of an `unknown` outcome
# needs the record, so keep it far longer than any plausible reconciliation window.
DEFAULT_NONCE_RETENTION_SECONDS = 30 * 24 * 3600


class PredictBody(BaseModel):
    adapter: str
    operation: str
    integration: str
    args: dict = Field(default_factory=dict)


class ExecuteBody(BaseModel):
    authorization: dict
    args: dict = Field(default_factory=dict)


class ConfigVersionsBody(BaseModel):
    integrations: list[str] = Field(max_length=100)


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


class GateCallback:
    def __init__(self, http: httpx.Client, internal_token: str):
        self.http = http
        self.headers = {"Authorization": f"Bearer {internal_token}"}

    def consume(self, auth_id: str) -> tuple[bool, str]:
        try:
            r = self.http.post(
                f"/internal/authorizations/{auth_id}/consume", headers=self.headers, timeout=10
            )
        except httpx.HTTPError as e:
            return False, f"gate unreachable for consume: {e.__class__.__name__}"
        if r.status_code == 200:
            return True, ""
        try:
            d = r.json()
            return False, f"{d.get('code', r.status_code)}: {d.get('detail', '')}"
        except ValueError:
            return False, f"consume failed: {r.status_code}"


def create_app(
    registry: AdapterRegistry,
    gate_verifier: Verifier | KeyRing,
    signer: Signer,
    gate: GateCallback,
    nonces: NonceStore,
    internal_token: str,
    *,
    nonce_retention_seconds: int = DEFAULT_NONCE_RETENTION_SECONDS,
) -> FastAPI:
    app = FastAPI(title="Writ Executor", version=__version__, docs_url=None, redoc_url=None)
    gate_keys = KeyRing.coerce(gate_verifier)
    claims_since_purge = 0

    def require_internal(authorization: str | None = Header(default=None)) -> None:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, {"code": "UNAUTHORIZED", "detail": "missing bearer token"})
        if not secrets.compare_digest(authorization[7:].strip(), internal_token):
            raise HTTPException(401, {"code": "UNAUTHORIZED", "detail": "invalid internal token"})

    def receipt(
        payload: dict | None,
        status: str,
        result: Any,
        upstream_ref: str | None = None,
        error: str | None = None,
        reason: str | None = None,
    ) -> dict:
        p = payload or {}
        return signed_envelope(
            signer,
            {
                "authorization_id": p.get("id") if isinstance(p.get("id"), str) else None,
                "task_id": p.get("task_id"),
                "command": p.get("command"),
                "args_hash": p.get("args_hash"),
                "status": status,
                # For rejections: why. Lets the gate tell a post-consume refusal (nothing happened)
                # from a pre-consume one that may have been replayed for an action that did happen.
                "reason": reason,
                "result_hash": hash_obj(result) if result is not None else None,
                "upstream_ref": upstream_ref,
                "error": error,
                "executed_at": _iso(_now()),
            },
        )

    def rejected(payload: dict | None, reason: str, error: str) -> dict:
        REJECTIONS.labels(reason).inc()
        return {
            "status": "rejected",
            "error": error,
            "receipt": receipt(payload, "rejected", None, error=error, reason=reason),
        }

    def _verify_authorization(envelope: Any, args: dict) -> tuple[dict | None, str]:
        if not verify_envelope(gate_keys, envelope):
            return None, "authorization signature invalid"
        p = envelope["payload"]
        if not isinstance(p.get("id"), str) or not isinstance(p.get("operation"), str):
            return None, "authorization payload malformed"
        try:
            exp = datetime.fromisoformat(p["expires_at"].replace("Z", "+00:00"))
        except (KeyError, ValueError, AttributeError, TypeError):
            return None, "authorization missing expiry"
        if exp <= _now():
            return None, "authorization expired"
        if p.get("args_hash") != hash_obj(args):
            return None, "arguments do not match authorization"
        return p, ""

    def _maybe_purge() -> None:
        nonlocal claims_since_purge
        claims_since_purge += 1
        if claims_since_purge >= 1000:
            claims_since_purge = 0
            cutoff = _iso(datetime.fromtimestamp(_now().timestamp() - nonce_retention_seconds, UTC))
            try:
                n = nonces.purge_before(cutoff)
                if n:
                    log.info("purged %d nonce records older than %s", n, cutoff)
            except Exception:  # noqa: BLE001
                log.exception("nonce purge failed")

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "version": __version__, "adapters": sorted(registry.by_name)}

    @app.get("/metrics")
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/v1/keys")
    def keys() -> dict:
        return {
            "executor": {
                "key_id": signer.verifier.key_id,
                "public_key": signer.verifier.encoded_public(),
                "algorithm": "Ed25519",
            },
            "trusted_gate_keys": gate_keys.describe(),
        }

    @app.post("/v1/config-versions", dependencies=[Depends(require_internal)])
    def config_versions(body: ConfigVersionsBody) -> dict:
        out: dict[str, str] = {}
        for integ in body.integrations:
            a = registry.for_integration(integ)
            if a is None:
                continue
            try:
                out[integ] = a.config_version()
            except (UpstreamAmbiguous, UpstreamRejected) as e:
                raise HTTPException(503, f"cannot read configuration for {integ}: {e}") from e
        return {"versions": out}

    @app.post("/v1/predict", dependencies=[Depends(require_internal)])
    def predict(body: PredictBody) -> dict:
        a = registry.get(body.adapter)
        if a is None or a.integration != body.integration:
            raise HTTPException(404, f"no adapter '{body.adapter}' for integration '{body.integration}'")
        try:
            effects = a.predict(body.operation, body.args)
            version = a.config_version()
        except UpstreamRejected as e:
            raise HTTPException(400, f"prediction rejected: {e}") from e
        except UpstreamAmbiguous as e:
            raise HTTPException(503, f"prediction unavailable: {e}") from e
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            raise HTTPException(400, f"prediction failed on arguments: {e!r}") from e
        return {"effects": [e.to_dict() for e in effects], "config_version": version}

    @app.post("/v1/execute", dependencies=[Depends(require_internal)])
    def execute(body: ExecuteBody) -> dict:
        p, err = _verify_authorization(body.authorization, body.args)
        if p is None:
            log.warning("rejected authorization: %s", err)
            payload = body.authorization.get("payload") if isinstance(body.authorization, dict) else None
            return rejected(payload if isinstance(payload, dict) else None, "verification", err)
        auth_id = p["id"]
        a = registry.get(p.get("adapter", ""))
        if a is None:
            return rejected(p, "no_adapter", f"no adapter {p.get('adapter')}")
        if a.integration != p.get("integration"):
            return rejected(p, "integration_mismatch", "authorization names a different integration")
        if not nonces.claim(auth_id, _iso(_now())):
            return rejected(p, "replay", "authorization already presented to this executor")
        _maybe_purge()
        ok, why = gate.consume(auth_id)
        if not ok:
            nonces.set_status(auth_id, "consume_failed")
            return rejected(p, "consume_refused", f"gate refused consumption: {why}")
        # TOCTOU guard: the configuration the gate evaluated against must still be current.
        if p.get("config_version") is not None:
            try:
                current = a.config_version()
            except (UpstreamAmbiguous, UpstreamRejected) as e:
                nonces.set_status(auth_id, "aborted")
                return rejected(p, "config_unverifiable", f"cannot verify configuration: {e}")
            if current != p["config_version"]:
                nonces.set_status(auth_id, "aborted")
                return rejected(
                    p,
                    "config_changed",
                    "integration configuration changed between authorization and execution",
                )
        started = time.perf_counter()
        try:
            result = a.execute(p["operation"], body.args, idempotency_key=auth_id)
        except UpstreamRejected as e:
            nonces.set_status(auth_id, "failed")
            EXECUTIONS.labels(a.name, p["operation"], "failed").inc()
            return {"status": "failed", "error": str(e), "receipt": receipt(p, "failed", None, error=str(e))}
        except UpstreamAmbiguous as e:
            nonces.set_status(auth_id, "unknown")
            EXECUTIONS.labels(a.name, p["operation"], "unknown").inc()
            return {
                "status": "unknown",
                "error": str(e),
                "receipt": receipt(p, "unknown", None, error=str(e)),
            }
        except Exception as e:  # noqa: BLE001 - an adapter bug after consume: we cannot know what happened
            log.exception("adapter %s.%s raised after consume (auth=%s)", a.name, p["operation"], auth_id)
            nonces.set_status(auth_id, "unknown")
            EXECUTIONS.labels(a.name, p["operation"], "unknown").inc()
            msg = f"adapter failure: {e.__class__.__name__}"
            return {"status": "unknown", "error": msg, "receipt": receipt(p, "unknown", None, error=msg)}
        nonces.set_status(auth_id, "ok")
        EXECUTIONS.labels(a.name, p["operation"], "ok").inc()
        log.info(
            "executed %s.%s auth=%s in %.1fms",
            a.name,
            p["operation"],
            auth_id,
            (time.perf_counter() - started) * 1000,
        )
        return {
            "status": "ok",
            "result": result,
            "receipt": receipt(p, "ok", result, upstream_ref=_upstream_ref(result)),
        }

    @app.post("/v1/reconcile", dependencies=[Depends(require_internal)])
    def reconcile(body: ExecuteBody) -> dict:
        # Reconciliation is allowed on expired authorizations; we only need to know what happened.
        if not verify_envelope(gate_keys, body.authorization):
            return {"status": "unknown", "error": "authorization signature invalid"}
        p = body.authorization["payload"]
        if not isinstance(p.get("id"), str):
            return {"status": "unknown", "error": "authorization payload malformed"}
        if p.get("args_hash") != hash_obj(body.args):
            return {"status": "unknown", "error": "arguments do not match authorization"}
        a = registry.get(p.get("adapter", ""))
        if a is None:
            return {"status": "unknown", "error": "no adapter"}
        if nonces.status(p["id"]) is None:
            # Never presented here: it cannot have executed through this executor.
            return {"status": "not_executed", "receipt": receipt(p, "not_executed", None)}
        try:
            status, result = a.reconcile(p["operation"], body.args, idempotency_key=p["id"])
        except (UpstreamAmbiguous, UpstreamRejected) as e:
            return {"status": "unknown", "error": str(e)}
        except Exception as e:  # noqa: BLE001
            log.exception("adapter %s reconcile raised (auth=%s)", a.name, p["id"])
            return {"status": "unknown", "error": f"adapter failure: {e.__class__.__name__}"}
        if status not in ("ok", "failed", "not_executed", "unknown"):
            return {"status": "unknown", "error": f"adapter returned invalid reconcile status {status!r}"}
        nonces.set_status(p["id"], status)
        return {
            "status": status,
            "result": result,
            "receipt": receipt(p, status, result, upstream_ref=_upstream_ref(result)),
        }

    return app


def _upstream_ref(result: Any) -> str | None:
    if isinstance(result, dict):
        for k in ("refund", "email", "customer"):
            v = result.get(k)
            if isinstance(v, dict) and "id" in v:
                return f"{k}:{v['id']}"
    return None
