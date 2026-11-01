"""Demo upstream SaaS: a CRM + billing + email provider with automations.

This stands in for the real systems an executor would integrate with.  It has the
properties that make agent actions dangerous in practice:
  * Updating a customer's tags can trigger an automation that exports the account externally.
  * Changing the billing contact redirects where notifications go.
  * Mutations are idempotent by key and can be configured to commit and then fail the
    response, so that executors must reconcile ambiguous outcomes.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
from datetime import UTC, datetime
from typing import Any

from fastapi import Body, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


DEFAULT_RULES = [
    {
        "id": "rule_vip_export",
        "when": {"field": "tags", "contains": "VIP"},
        "then": {"export_to": "partner-datawarehouse"},
    },
]


class State:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.reset()

    def reset(self) -> None:
        self.customers: dict[str, dict] = {
            "cus_123": {
                "id": "cus_123",
                "name": "Acme Robotics",
                "billing_contact": "ap@acme.example",
                "tags": ["enterprise"],
                "note": "",
            },
            "cus_999": {
                "id": "cus_999",
                "name": "Globex",
                "billing_contact": "billing@globex.example",
                "tags": [],
                "note": "",
            },
        }
        self.charges: dict[str, dict] = {
            "ch_1001": {
                "id": "ch_1001",
                "customer_id": "cus_123",
                "amount_cents": 14900,
                "refunded_cents": 0,
                "description": "Pro plan - March",
            },
            "ch_1002": {
                "id": "ch_1002",
                "customer_id": "cus_123",
                "amount_cents": 14900,
                "refunded_cents": 0,
                "description": "Pro plan - March (duplicate)",
            },
            "ch_2001": {
                "id": "ch_2001",
                "customer_id": "cus_999",
                "amount_cents": 50000,
                "refunded_cents": 0,
                "description": "Annual",
            },
        }
        self.refunds: list[dict] = []
        self.emails: list[dict] = []
        self.exports: list[dict] = []
        self.rules: list[dict] = json.loads(json.dumps(DEFAULT_RULES))
        self.idempotency: dict[str, dict] = {}
        self.chaos_fail_after_commit = 0

    def automations_version(self) -> str:
        return hashlib.sha256(json.dumps(self.rules, sort_keys=True).encode()).hexdigest()[:16]


class ChaosBody(BaseModel):
    fail_after_commit: int = 0


class RulesBody(BaseModel):
    rules: list[dict] = Field(default_factory=list)


def create_app(api_key: str) -> FastAPI:
    app = FastAPI(title="Demo SaaS (CRM + Billing + Email)")
    st = State()
    app.state.state = st

    def auth(request: Request) -> None:
        if request.url.path.startswith("/_") or request.url.path == "/healthz":
            return
        if request.headers.get("x-api-key") != api_key:
            raise HTTPException(401, "invalid api key")

    @app.middleware("http")
    async def _auth_mw(request: Request, call_next):
        try:
            auth(request)
        except HTTPException as e:
            return JSONResponse(status_code=e.status_code, content={"error": e.detail})
        return await call_next(request)

    def idempotent(key: str | None, fn):
        """Run fn once per idempotency key. Supports chaos: commit, then fail the response."""
        with st.lock:
            if key and key in st.idempotency:
                stored = st.idempotency[key]
                return JSONResponse(
                    status_code=stored["status_code"],
                    content=stored["body"],
                    headers={"Idempotent-Replayed": "true"},
                )
            try:
                body = fn()
                status_code = 200
            except HTTPException as e:
                body = {"error": e.detail}
                status_code = e.status_code
            if key:
                st.idempotency[key] = {"status_code": status_code, "body": body, "at": _now()}
            if st.chaos_fail_after_commit > 0 and status_code == 200:
                st.chaos_fail_after_commit -= 1
                return JSONResponse(status_code=503, content={"error": "chaos: committed but response lost"})
            return JSONResponse(status_code=status_code, content=body)

    # ------------------------------------------------------------ CRM
    @app.get("/customers/{cid}")
    def get_customer(cid: str) -> dict:
        with st.lock:
            c = st.customers.get(cid)
            if not c:
                raise HTTPException(404, "customer not found")
            return {"customer": c}

    @app.patch("/customers/{cid}")
    def update_customer(
        cid: str, fields: dict = Body(...), idempotency_key: str | None = Header(default=None)
    ):
        def do() -> dict:
            c = st.customers.get(cid)
            if not c:
                raise HTTPException(404, "customer not found")
            allowed = {"name", "billing_contact", "tags", "note"}
            bad = set(fields) - allowed
            if bad:
                raise HTTPException(400, f"unknown fields {sorted(bad)}")
            before = dict(c)
            c.update(fields)
            triggered = []
            for rule in st.rules:
                w, t = rule["when"], rule["then"]
                val = c.get(w["field"])
                if (
                    "contains" in w
                    and isinstance(val, list)
                    and w["contains"] in val
                    and w["contains"] not in (before.get(w["field"]) or [])
                ):
                    exp = {
                        "id": f"exp_{secrets.token_hex(4)}",
                        "rule": rule["id"],
                        "customer_id": cid,
                        "destination": t["export_to"],
                        "at": _now(),
                    }
                    st.exports.append(exp)
                    triggered.append(exp)
            return {"customer": c, "triggered_automations": triggered}

        return idempotent(idempotency_key, do)

    @app.get("/automations")
    def automations() -> dict:
        with st.lock:
            return {"rules": st.rules, "version": st.automations_version()}

    @app.put("/automations")
    def set_automations(body: RulesBody) -> dict:
        with st.lock:
            st.rules = body.rules
            return {"rules": st.rules, "version": st.automations_version()}

    # ------------------------------------------------------------ Billing
    @app.get("/customers/{cid}/charges")
    def list_charges(cid: str) -> dict:
        with st.lock:
            if cid not in st.customers:
                raise HTTPException(404, "customer not found")
            return {"charges": [c for c in st.charges.values() if c["customer_id"] == cid]}

    @app.get("/charges/{chid}")
    def get_charge(chid: str) -> dict:
        with st.lock:
            c = st.charges.get(chid)
            if not c:
                raise HTTPException(404, "charge not found")
            return {"charge": c}

    @app.post("/charges/{chid}/refunds")
    def refund(chid: str, body: dict = Body(...), idempotency_key: str | None = Header(default=None)):
        def do() -> dict:
            c = st.charges.get(chid)
            if not c:
                raise HTTPException(404, "charge not found")
            amt = body.get("amount_cents")
            if not isinstance(amt, int) or amt <= 0:
                raise HTTPException(400, "amount_cents must be a positive integer")
            if c["refunded_cents"] + amt > c["amount_cents"]:
                raise HTTPException(400, "refund exceeds remaining charge amount")
            c["refunded_cents"] += amt
            r = {
                "id": f"re_{secrets.token_hex(6)}",
                "charge_id": chid,
                "customer_id": c["customer_id"],
                "amount_cents": amt,
                "reason": body.get("reason", ""),
                "status": "succeeded",
                "at": _now(),
            }
            st.refunds.append(r)
            return {"refund": r}

        return idempotent(idempotency_key, do)

    # ------------------------------------------------------------ Email
    @app.post("/emails")
    def send_email(body: dict = Body(...), idempotency_key: str | None = Header(default=None)):
        def do() -> dict:
            for f in ("to", "subject", "body"):
                if not isinstance(body.get(f), str):
                    raise HTTPException(400, f"{f} required")
            e = {
                "id": f"em_{secrets.token_hex(6)}",
                "to": body["to"],
                "subject": body["subject"],
                "body": body["body"],
                "at": _now(),
            }
            st.emails.append(e)
            return {"email": e}

        return idempotent(idempotency_key, do)

    # ------------------------------------------------------------ Idempotency / reconciliation
    @app.get("/idempotency/{key}")
    def idempotency(key: str) -> dict:
        with st.lock:
            rec = st.idempotency.get(key)
            if not rec:
                raise HTTPException(404, "no record for key")
            return rec

    # ------------------------------------------------------------ Test / demo controls (no auth)
    @app.post("/_chaos")
    def chaos(body: ChaosBody) -> dict:
        with st.lock:
            st.chaos_fail_after_commit = body.fail_after_commit
            return {"fail_after_commit": st.chaos_fail_after_commit}

    @app.post("/_reset")
    def reset() -> dict:
        with st.lock:
            st.reset()
            return {"ok": True}

    @app.get("/_state")
    def state() -> dict[str, Any]:
        with st.lock:
            return {
                "customers": st.customers,
                "charges": st.charges,
                "refunds": st.refunds,
                "emails": st.emails,
                "exports": st.exports,
                "rules": st.rules,
                "automations_version": st.automations_version(),
            }

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    return app
