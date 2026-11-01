"""Adapter contract.

An adapter knows one integration: how to *predict* the consequences of an operation under
the integration's current configuration, how to *execute* it idempotently, how to
*reconcile* an ambiguous outcome, and how to report the configuration version its
predictions depend on.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Effect:
    type: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class UpstreamRejected(Exception):
    """The upstream definitively refused the operation; nothing happened."""


class UpstreamAmbiguous(Exception):
    """We cannot tell whether the upstream applied the operation."""


class Adapter:
    name: str = ""
    integration: str = ""

    def config_version(self) -> str:
        raise NotImplementedError

    def predict(self, operation: str, args: dict) -> list[Effect]:
        raise NotImplementedError

    def execute(self, operation: str, args: dict, idempotency_key: str) -> dict:
        raise NotImplementedError

    def reconcile(self, operation: str, args: dict, idempotency_key: str) -> tuple[str, Any]:
        """Return (status, result) where status in {ok, failed, not_executed, unknown}."""
        raise NotImplementedError


class AdapterRegistry:
    def __init__(self, adapters: list[Adapter]):
        self.by_name = {a.name: a for a in adapters}
        self.by_integration = {a.integration: a for a in adapters}

    def get(self, name: str) -> Adapter | None:
        return self.by_name.get(name)

    def for_integration(self, integration: str) -> Adapter | None:
        return self.by_integration.get(integration)
