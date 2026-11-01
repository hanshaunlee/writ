"""HTTP client the gate uses to talk to the executor (control network only).

Every failure mode (transport, non-2xx, malformed body) surfaces as ExecutorError so the
pipeline has exactly one branch for "the executor did not give us a usable answer".
"""

from __future__ import annotations

from typing import Any

import httpx


class ExecutorError(Exception):
    pass


class ExecutorClient:
    def __init__(self, http: httpx.Client, internal_token: str):
        self._http = http
        self._headers = {"Authorization": f"Bearer {internal_token}"}

    @staticmethod
    def _json(r: httpx.Response) -> dict:
        try:
            body = r.json()
        except ValueError as e:
            raise ExecutorError(f"executor returned a malformed body ({r.status_code})") from e
        if not isinstance(body, dict):
            raise ExecutorError("executor returned a non-object body")
        return body

    def _post(self, path: str, body: dict, timeout: float) -> dict:
        try:
            r = self._http.post(path, json=body, headers=self._headers, timeout=timeout)
        except httpx.HTTPError as e:
            raise ExecutorError(f"executor unreachable: {e.__class__.__name__}") from e
        except Exception as e:  # noqa: BLE001 - any client failure is "no usable answer"
            raise ExecutorError(f"executor call failed: {e.__class__.__name__}") from e
        if r.status_code >= 500:
            raise ExecutorError(f"executor error {r.status_code}: {r.text[:300]}")
        if r.status_code >= 400:
            raise ExecutorError(f"executor rejected request {r.status_code}: {r.text[:300]}")
        return self._json(r)

    def config_versions(self, integrations: list[str]) -> dict[str, str]:
        body = self._post("/v1/config-versions", {"integrations": integrations}, 10)
        versions = body.get("versions")
        if not isinstance(versions, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in versions.items()
        ):
            raise ExecutorError("config-versions returned an invalid body")
        return versions

    def predict(
        self, adapter: str, operation: str, integration: str, args: dict, timeout: float = 10
    ) -> dict:
        return self._post(
            "/v1/predict",
            {"adapter": adapter, "operation": operation, "integration": integration, "args": args},
            timeout,
        )

    def execute(self, envelope: dict, args: dict, timeout: float) -> dict:
        return self._post("/v1/execute", {"authorization": envelope, "args": args}, timeout)

    def reconcile(self, envelope: dict, args: dict, timeout: float = 15) -> dict:
        return self._post("/v1/reconcile", {"authorization": envelope, "args": args}, timeout)

    def health(self) -> dict[str, Any]:
        r = self._http.get("/healthz", timeout=5)
        r.raise_for_status()
        return r.json()
