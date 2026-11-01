"""Executor entrypoint. Configuration is by environment variables (see docs/deploy.md)."""

from __future__ import annotations

import logging
import os
import sys

import httpx
import uvicorn

from ..logging_setup import setup_logging
from ..signing import KeyRing, Signer
from .adapters import AdapterRegistry, BillingAdapter, CrmAdapter, DemoSaasClient, EmailAdapter
from .app import DEFAULT_NONCE_RETENTION_SECONDS, GateCallback, create_app
from .nonces import NonceStore

log = logging.getLogger("writ.executor")

MIN_TOKEN_LENGTH = 24


def _fail(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def _require(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        _fail(f"{name} is required")
    return v  # type: ignore[return-value]


def build_app():
    setup_logging()
    internal_token = _require("WRIT_INTERNAL_TOKEN")
    if len(internal_token) < MIN_TOKEN_LENGTH:
        _fail(f"WRIT_INTERNAL_TOKEN must be at least {MIN_TOKEN_LENGTH} characters")
    gate_url = _require("WRIT_GATE_URL")
    gate_pub = os.environ.get("WRIT_GATE_PUBLIC_KEY") or os.environ.get("WRIT_GATE_PUBLIC_KEYS")
    if not gate_pub:
        _fail("WRIT_GATE_PUBLIC_KEY is required")
    try:
        gate_keys = KeyRing.from_encoded(gate_pub)
        signer = Signer.from_encoded(_require("WRIT_EXECUTOR_PRIVATE_KEY"))
    except ValueError as e:
        _fail(f"key configuration: {e}")
    saas_url = _require("WRIT_DEMO_SAAS_URL")
    saas_key = _require("WRIT_DEMO_SAAS_API_KEY")
    db_path = os.environ.get("WRIT_EXECUTOR_DB_PATH", "/var/lib/writ/executor.db")
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    retention_days = os.environ.get("WRIT_NONCE_RETENTION_DAYS")
    retention = int(retention_days) * 86400 if retention_days else DEFAULT_NONCE_RETENTION_SECONDS

    client = DemoSaasClient(httpx.Client(base_url=saas_url, timeout=15), saas_key)
    registry = AdapterRegistry([CrmAdapter(client), BillingAdapter(client), EmailAdapter(client)])
    gate = GateCallback(httpx.Client(base_url=gate_url, timeout=15), internal_token)
    log.info(
        "executor ready: adapters=%s key=%s trusted gate keys=%s",
        sorted(registry.by_name),
        signer.verifier.key_id,
        gate_keys.key_ids,
    )
    return create_app(
        registry,
        gate_keys,
        signer,
        gate,
        NonceStore(db_path),
        internal_token,
        nonce_retention_seconds=retention,
    )


def main() -> None:
    uvicorn.run(
        build_app(),
        host=os.environ.get("WRIT_HOST", "0.0.0.0"),
        port=int(os.environ.get("WRIT_PORT", "8081")),
        log_config=None,
        access_log=False,
        server_header=False,
        date_header=False,
    )


if __name__ == "__main__":
    main()
