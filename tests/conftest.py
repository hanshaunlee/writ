"""In-process harness: gate, executor and demo SaaS wired through ASGI test clients.

No network, no Docker. The topology matches production: the gate talks only to the executor,
the executor talks to the gate (consume) and the upstream SaaS, and the agent talks only to
the gate.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from writ.client import GateClient
from writ.commands import CommandTable
from writ.demosaas.app import create_app as create_saas
from writ.executor.adapters import AdapterRegistry, BillingAdapter, CrmAdapter, DemoSaasClient, EmailAdapter
from writ.executor.app import GateCallback
from writ.executor.app import create_app as create_executor
from writ.executor.nonces import NonceStore
from writ.gate.app import create_app as create_gate
from writ.gate.executor_client import ExecutorClient
from writ.gate.service import GateService
from writ.gate.store import Store
from writ.signing import Signer
from writ.templates import load_template, render

ROOT = Path(__file__).resolve().parents[1]
ADMIN_TOKEN = "admin-token-for-tests-0123456789"
INTERNAL_TOKEN = "internal-token-for-tests-0123456789"
SAAS_KEY = "demo-api-key"


class _Lazy:
    """Defers to a client assigned after construction (breaks the gate<->executor cycle)."""

    target = None

    def __getattr__(self, name):
        if self.target is None:
            raise RuntimeError("lazy client not bound")
        return getattr(self.target, name)


class Clock:
    def __init__(self) -> None:
        self.offset = timedelta(0)

    def __call__(self) -> datetime:
        return datetime.now(UTC) + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += timedelta(seconds=seconds)


class Harness:
    def __init__(self, tmp_path: Path, *, executor_client_wrapper=None):
        self.clock = Clock()
        self.gate_signer = Signer.generate()
        self.exec_signer = Signer.generate()

        self.saas_app = create_saas(SAAS_KEY)
        self.saas = TestClient(self.saas_app)
        saas_client = DemoSaasClient(self.saas, SAAS_KEY)
        self.registry = AdapterRegistry(
            [CrmAdapter(saas_client), BillingAdapter(saas_client), EmailAdapter(saas_client)]
        )

        gate_lazy = _Lazy()
        self.nonces = NonceStore(":memory:")
        self.executor_app = create_executor(
            self.registry,
            self.gate_signer.verifier,
            self.exec_signer,
            GateCallback(gate_lazy, INTERNAL_TOKEN),
            self.nonces,
            INTERNAL_TOKEN,
        )
        self.executor = TestClient(self.executor_app)

        self.store = Store(str(tmp_path / "gate.db"))
        self.table = CommandTable.from_yaml(ROOT / "config" / "commands.yaml")
        exec_client = ExecutorClient(self.executor, INTERNAL_TOKEN)
        if executor_client_wrapper:
            exec_client = executor_client_wrapper(self, exec_client)
        self.service = GateService(
            self.store,
            self.table,
            self.gate_signer,
            exec_client,
            self.exec_signer.verifier,
            authorization_ttl_seconds=60,
            clock=self.clock,
        )
        self.gate_app = create_gate(self.service, ADMIN_TOKEN, INTERNAL_TOKEN, sweep_interval=0)
        self.gate = TestClient(self.gate_app)
        gate_lazy.target = self.gate

        self.admin = GateClient(http=self.gate, token=ADMIN_TOKEN)

    # ---- helpers
    def agent(self, token: str) -> GateClient:
        return GateClient(http=self.gate, token=token)

    def saas_state(self) -> dict:
        return self.saas.get("/_state").json()

    def set_rules(self, rules: list[dict]) -> str:
        r = self.saas.put("/automations", json={"rules": rules}, headers={"X-API-Key": SAAS_KEY})
        assert r.status_code == 200, r.text
        return r.json()["version"]

    def chaos(self, fail_after_commit: int) -> None:
        assert self.saas.post("/_chaos", json={"fail_after_commit": fail_after_commit}).status_code == 200

    def _render(self, **overrides):
        params = {
            "customer_id": "cus_123",
            "billing_contact": "ap@acme.example",
            "max_refund_cents": "20000",
            "charge_ids": json.dumps(["ch_1001", "ch_1002"]),
        }
        params.update({k: (v if isinstance(v, str) else json.dumps(v)) for k, v in overrides.items()})
        return render(load_template(ROOT / "templates" / "resolve_duplicate_charge.yaml"), params)

    def template_grant(self, **overrides) -> dict:
        return self._render(**overrides)[1].to_dict()

    def template_intent(self, **overrides) -> dict:
        return self._render(**overrides)[4].to_dict()

    def create_scenario_task(self, ttl: int = 3600, intent: bool = False, **overrides) -> tuple[dict, str]:
        res = self.admin.create_task(
            "resolve_duplicate_charge",
            self.template_grant(**overrides),
            ttl_seconds=ttl,
            intent=self.template_intent(**overrides) if intent else None,
        )
        return res["task"], res["token"]


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    return Harness(tmp_path)
