"""Gate entrypoint. Configuration is by environment variables (see docs/deploy.md)."""

from __future__ import annotations

import logging
import os
import sys

import httpx
import uvicorn

from ..commands import CommandTable
from ..intent.engine import IntentEngine
from ..logging_setup import setup_logging
from ..signing import KeyRing, Signer
from .app import create_app
from .executor_client import ExecutorClient
from .service import GateService
from .store import Store

log = logging.getLogger("writ.gate")

MIN_TOKEN_LENGTH = 24


def _fail(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def _require(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        _fail(f"{name} is required")
    return v  # type: ignore[return-value]


def _int_env(name: str, default: int, *, minimum: int = 0) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        v = int(raw)
    except ValueError:
        _fail(f"{name} must be an integer")
    if v < minimum:
        _fail(f"{name} must be >= {minimum}")
    return v


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def parse_admin_tokens(single: str | None, named: str | None) -> dict[str, str]:
    """WRIT_ADMIN_TOKEN gives one token for the actor "operator"; WRIT_ADMIN_TOKENS gives
    `name:token` pairs separated by commas so ledger entries name who acted. Both may be set."""
    out: dict[str, str] = {}
    if single:
        out["operator"] = single
    for pair in (named or "").replace("\n", ",").split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" not in pair:
            _fail("WRIT_ADMIN_TOKENS entries must be name:token")
        name, tok = pair.split(":", 1)
        name, tok = name.strip(), tok.strip()
        if not name or not tok:
            _fail("WRIT_ADMIN_TOKENS entries must be name:token")
        if name in out:
            _fail(f"duplicate operator name {name!r} in WRIT_ADMIN_TOKENS")
        out[name] = tok
    if not out:
        _fail("WRIT_ADMIN_TOKEN or WRIT_ADMIN_TOKENS is required")
    for name, tok in out.items():
        if len(tok) < MIN_TOKEN_LENGTH:
            _fail(f"admin token for {name!r} must be at least {MIN_TOKEN_LENGTH} characters")
    if len(set(out.values())) != len(out):
        _fail("admin tokens must be distinct")
    return out


def build_app():
    setup_logging()
    db_path = os.environ.get("WRIT_DB_PATH", "/var/lib/writ/gate.db")
    commands_path = os.environ.get("WRIT_COMMANDS_PATH", "config/commands.yaml")
    executor_url = _require("WRIT_EXECUTOR_URL")
    internal_token = _require("WRIT_INTERNAL_TOKEN")
    if len(internal_token) < MIN_TOKEN_LENGTH:
        _fail(f"WRIT_INTERNAL_TOKEN must be at least {MIN_TOKEN_LENGTH} characters")
    admin_tokens = parse_admin_tokens(os.environ.get("WRIT_ADMIN_TOKEN"), os.environ.get("WRIT_ADMIN_TOKENS"))
    if internal_token in admin_tokens.values():
        _fail("WRIT_INTERNAL_TOKEN must differ from every admin token")
    try:
        signer = Signer.from_encoded(_require("WRIT_GATE_PRIVATE_KEY"))
    except ValueError as e:
        _fail(f"WRIT_GATE_PRIVATE_KEY: {e}")
    exec_pub = os.environ.get("WRIT_EXECUTOR_PUBLIC_KEY") or os.environ.get("WRIT_EXECUTOR_PUBLIC_KEYS")
    if not exec_pub:
        _fail("WRIT_EXECUTOR_PUBLIC_KEY is required (receipts must be verifiable)")
    try:
        executor_keys = KeyRing.from_encoded(exec_pub)
    except ValueError as e:
        _fail(f"WRIT_EXECUTOR_PUBLIC_KEY: {e}")

    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    store = Store(db_path)
    try:
        table = CommandTable.from_yaml(commands_path)
    except Exception as e:  # noqa: BLE001 - a bad command table must stop the gate
        _fail(f"cannot load command table {commands_path}: {e}")
    http = httpx.Client(base_url=executor_url, timeout=20)
    extractor = None
    if os.environ.get("WRIT_CLAIM_EXTRACTOR", "rules") == "openai":
        from ..intent.claims_llm import OpenAIClaimExtractor

        extractor = OpenAIClaimExtractor()
        log.info("claim extractor: openai (%s)", extractor.model)
    service = GateService(
        store,
        table,
        signer,
        ExecutorClient(http, internal_token),
        executor_keys,
        intent_engine=IntentEngine(table, extractor),
        authorization_ttl_seconds=_int_env("WRIT_AUTHORIZATION_TTL_SECONDS", 60, minimum=1),
        max_task_ttl_seconds=_int_env("WRIT_MAX_TASK_TTL_SECONDS", 7 * 24 * 3600, minimum=1),
        max_delegation_depth=_int_env("WRIT_MAX_DELEGATION_DEPTH", 8, minimum=0),
        max_tasks_per_tree=_int_env("WRIT_MAX_TASKS_PER_TREE", 256, minimum=1),
        stale_consumed_seconds=_int_env("WRIT_STALE_CONSUMED_SECONDS", 300, minimum=30),
        reconcile_after_seconds=_int_env("WRIT_RECONCILE_AFTER_SECONDS", 30, minimum=1),
    )
    log.info(
        "gate ready: %d commands, key %s, executor keys %s, operators %s, db %s",
        len(table.commands),
        signer.verifier.key_id,
        executor_keys.key_ids,
        sorted(admin_tokens),
        db_path,
    )
    return create_app(
        service,
        admin_tokens,
        internal_token,
        sweep_interval=float(_int_env("WRIT_SWEEP_INTERVAL_SECONDS", 30, minimum=0)),
        max_body_bytes=_int_env("WRIT_MAX_BODY_BYTES", 1024 * 1024, minimum=1024),
        agent_rate_per_second=float(_int_env("WRIT_AGENT_RATE_LIMIT", 50, minimum=0)),
        agent_burst=_int_env("WRIT_AGENT_RATE_BURST", 100, minimum=1),
        enable_docs=_bool_env("WRIT_ENABLE_DOCS", False),
    )


def main() -> None:
    app = build_app()
    uvicorn.run(
        app,
        host=os.environ.get("WRIT_HOST", "0.0.0.0"),
        port=int(os.environ.get("WRIT_PORT", "8080")),
        log_config=None,
        access_log=False,
        proxy_headers=True,
        server_header=False,
        date_header=False,
    )


if __name__ == "__main__":
    main()
