"""Adapters for the demo SaaS: CRM, billing, email.

The prediction logic here is the seed of the 'effect model' described in the architecture:
it reads the *current* configuration (automation rules, current record state) and reports
what an operation will cause beyond its literal API call.
"""

from __future__ import annotations

from typing import Any

import httpx

from .base import Adapter, Effect, UpstreamAmbiguous, UpstreamRejected

STATIC_VERSION = "static-1"


class DemoSaasClient:
    def __init__(self, http: httpx.Client, api_key: str):
        self.http = http
        self.headers = {"X-API-Key": api_key}

    def _call(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        idempotency_key: str | None = None,
        timeout: float = 10,
    ) -> Any:
        headers = dict(self.headers)
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        try:
            r = self.http.request(method, path, json=json, headers=headers, timeout=timeout)
        except httpx.HTTPError as e:
            raise UpstreamAmbiguous(f"upstream transport failure: {e.__class__.__name__}") from e
        if r.status_code >= 500:
            raise UpstreamAmbiguous(f"upstream {r.status_code}: {r.text[:200]}")
        if r.status_code >= 400:
            raise UpstreamRejected(f"upstream {r.status_code}: {r.text[:200]}")
        return r.json()

    def get(self, path: str) -> Any:
        return self._call("GET", path)

    def idempotency_record(self, key: str) -> dict | None:
        try:
            return self._call("GET", f"/idempotency/{key}")
        except UpstreamRejected as e:
            if "404" in str(e):
                return None
            raise


def _reconcile_via_idempotency(client: DemoSaasClient, key: str) -> tuple[str, Any]:
    rec = client.idempotency_record(key)
    if rec is None:
        return "not_executed", None
    if rec["status_code"] == 200:
        return "ok", rec["body"]
    return "failed", rec["body"]


class CrmAdapter(Adapter):
    name = "crm"
    integration = "demo_crm"

    def __init__(self, client: DemoSaasClient):
        self.client = client

    def config_version(self) -> str:
        return self.client.get("/automations")["version"]

    def predict(self, operation: str, args: dict) -> list[Effect]:
        if operation == "get_customer":
            return [Effect("data_read", {"resource": f"customer:{args['customer_id']}"})]
        if operation != "update_customer":
            raise UpstreamRejected(f"unknown operation {operation}")
        cid = args["customer_id"]
        fields: dict = args["fields"]
        current = self.client.get(f"/customers/{cid}")["customer"]
        rules = self.client.get("/automations")["rules"]
        effects: list[Effect] = []
        for f, v in fields.items():
            if current.get(f) != v:
                effects.append(Effect("field_change", {"resource": f"customer:{cid}", "field": f}))
        if "billing_contact" in fields and fields["billing_contact"] != current.get("billing_contact"):
            effects.append(
                Effect(
                    "notification_redirect",
                    {
                        "resource": f"customer:{cid}",
                        "from": current.get("billing_contact"),
                        "to": fields["billing_contact"],
                        "field": "billing_contact",
                    },
                )
            )
        for rule in rules:
            w, t = rule.get("when", {}), rule.get("then", {})
            fld = w.get("field")
            if fld in fields and "contains" in w:
                new_val = fields[fld] if isinstance(fields[fld], list) else []
                old_val = current.get(fld) if isinstance(current.get(fld), list) else []
                if w["contains"] in new_val and w["contains"] not in old_val:
                    effects.append(
                        Effect(
                            "external_export",
                            {
                                "resource": f"customer:{cid}",
                                "rule": rule.get("id"),
                                "destination": t.get("export_to"),
                                "field": fld,
                            },
                        )
                    )
        return effects

    def execute(self, operation: str, args: dict, idempotency_key: str) -> dict:
        if operation == "get_customer":
            return self.client.get(f"/customers/{args['customer_id']}")
        if operation == "update_customer":
            return self.client._call(
                "PATCH",
                f"/customers/{args['customer_id']}",
                json=args["fields"],
                idempotency_key=idempotency_key,
            )
        raise UpstreamRejected(f"unknown operation {operation}")

    def reconcile(self, operation: str, args: dict, idempotency_key: str) -> tuple[str, Any]:
        if operation == "get_customer":
            return "not_executed", None
        return _reconcile_via_idempotency(self.client, idempotency_key)


class BillingAdapter(Adapter):
    name = "billing"
    integration = "demo_billing"

    def __init__(self, client: DemoSaasClient):
        self.client = client

    def config_version(self) -> str:
        return STATIC_VERSION

    def predict(self, operation: str, args: dict) -> list[Effect]:
        if operation == "list_charges":
            return [Effect("data_read", {"resource": f"customer:{args['customer_id']}:charges"})]
        if operation == "refund":
            charge = self.client.get(f"/charges/{args['charge_id']}")["charge"]
            effects = [
                Effect(
                    "money_out",
                    {
                        "charge_id": args["charge_id"],
                        "customer_id": charge["customer_id"],
                        "amount_cents": args["amount_cents"],
                        "destination": "original_payment_method",
                    },
                )
            ]
            if charge["refunded_cents"] + args["amount_cents"] > charge["amount_cents"]:
                effects.append(
                    Effect(
                        "upstream_rejection_expected", {"reason": "refund exceeds remaining charge amount"}
                    )
                )
            return effects
        raise UpstreamRejected(f"unknown operation {operation}")

    def execute(self, operation: str, args: dict, idempotency_key: str) -> dict:
        if operation == "list_charges":
            return self.client.get(f"/customers/{args['customer_id']}/charges")
        if operation == "refund":
            return self.client._call(
                "POST",
                f"/charges/{args['charge_id']}/refunds",
                json={"amount_cents": args["amount_cents"], "reason": args.get("reason", "")},
                idempotency_key=idempotency_key,
            )
        raise UpstreamRejected(f"unknown operation {operation}")

    def reconcile(self, operation: str, args: dict, idempotency_key: str) -> tuple[str, Any]:
        if operation == "list_charges":
            return "not_executed", None
        return _reconcile_via_idempotency(self.client, idempotency_key)


class EmailAdapter(Adapter):
    name = "email"
    integration = "demo_email"

    def __init__(self, client: DemoSaasClient):
        self.client = client

    def config_version(self) -> str:
        return STATIC_VERSION

    def predict(self, operation: str, args: dict) -> list[Effect]:
        if operation != "send":
            raise UpstreamRejected(f"unknown operation {operation}")
        return [Effect("external_message", {"channel": "email", "to": args["to"]})]

    def execute(self, operation: str, args: dict, idempotency_key: str) -> dict:
        if operation != "send":
            raise UpstreamRejected(f"unknown operation {operation}")
        return self.client._call(
            "POST",
            "/emails",
            json={"to": args["to"], "subject": args["subject"], "body": args["body"]},
            idempotency_key=idempotency_key,
        )

    def reconcile(self, operation: str, args: dict, idempotency_key: str) -> tuple[str, Any]:
        return _reconcile_via_idempotency(self.client, idempotency_key)
