"""Python client for the gate. Used by the CLI, the MCP server, the example agent and tests."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx


class GateAPIError(Exception):
    def __init__(self, status_code: int, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.status_code = status_code
        self.code = code
        self.detail = detail


class GateClient:
    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        *,
        http: httpx.Client | None = None,
        timeout: float = 60,
    ):
        self.http = http or httpx.Client(base_url=base_url or "", timeout=timeout)
        self.token = token

    def with_token(self, token: str) -> GateClient:
        return GateClient(http=self.http, token=token)

    def _req(self, method: str, path: str, **kw: Any) -> Any:
        headers = kw.pop("headers", None) or {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        r = self.http.request(method, path, headers=headers, **kw)
        if r.status_code >= 400:
            try:
                d = r.json()
            except ValueError:
                raise GateAPIError(r.status_code, "ERROR", r.text[:500]) from None
            if isinstance(d, dict):
                det = d.get("detail", d)
                if isinstance(det, dict):
                    raise GateAPIError(r.status_code, det.get("code", "ERROR"), det.get("detail", str(det)))
                raise GateAPIError(r.status_code, d.get("code", "ERROR"), str(det))
            raise GateAPIError(r.status_code, "ERROR", str(d)[:500])
        return r.json() if r.content else None

    # agent
    def me(self) -> dict:
        return self._req("GET", "/v1/me")

    def invoke(self, command: str, args: dict, *, idempotency_key: str | None = None) -> dict:
        """Invoke a command. Pass `idempotency_key` to make a retried request return the original
        result instead of acting twice."""
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        return self._req("POST", "/v1/invoke", json={"command": command, "args": args}, headers=headers)

    def delegate(self, name: str, grant: dict, ttl_seconds: int | None = None) -> dict:
        return self._req(
            "POST", "/v1/delegate", json={"name": name, "grant": grant, "ttl_seconds": ttl_seconds}
        )

    def keys(self) -> dict:
        return self._req("GET", "/v1/keys")

    # admin
    def create_task(
        self,
        name: str,
        grant: dict,
        ttl_seconds: int = 3600,
        max_ttl_seconds: int | None = None,
        metadata: dict | None = None,
        intent: dict | None = None,
        principal: str | None = None,
    ) -> dict:
        return self._req(
            "POST",
            "/v1/admin/tasks",
            json={
                "name": name,
                "grant": grant,
                "ttl_seconds": ttl_seconds,
                "max_ttl_seconds": max_ttl_seconds,
                "metadata": metadata or {},
                "intent": intent,
                "principal": principal,
            },
        )

    def get_task(self, task_id: str) -> dict:
        return self._req("GET", f"/v1/admin/tasks/{task_id}")

    def list_tasks(
        self, root_id: str | None = None, status: str | None = None, limit: int = 200, offset: int = 0
    ) -> list[dict]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if root_id:
            params["root_id"] = root_id
        if status:
            params["status"] = status
        return self._req("GET", "/v1/admin/tasks", params=params)["tasks"]

    def revoke(self, task_id: str, reason: str = "") -> dict:
        return self._req("POST", f"/v1/admin/tasks/{task_id}/revoke", json={"reason": reason})

    def renew(self, task_id: str, extend_seconds: int) -> dict:
        return self._req("POST", f"/v1/admin/tasks/{task_id}/renew", json={"extend_seconds": extend_seconds})

    def repin(self, task_id: str) -> dict:
        return self._req("POST", f"/v1/admin/tasks/{task_id}/repin")

    def halt(self, reason: str = "") -> dict:
        return self._req("POST", "/v1/admin/halt", json={"reason": reason})

    def unhalt(self, reason: str = "") -> dict:
        return self._req("POST", "/v1/admin/unhalt", json={"reason": reason})

    def status(self) -> dict:
        return self._req("GET", "/v1/admin/status")

    def commands(self) -> list[dict]:
        return self._req("GET", "/v1/admin/commands")["commands"]

    def sweep(self) -> dict:
        return self._req("POST", "/v1/admin/sweep")

    def ledger(
        self, after: int = 0, limit: int = 500, task_id: str | None = None, root_id: str | None = None
    ) -> list[dict]:
        params: dict[str, Any] = {"after": after, "limit": limit}
        if task_id:
            params["task_id"] = task_id
        if root_id:
            params["root_id"] = root_id
        return self._req("GET", "/v1/admin/ledger", params=params)["entries"]

    def iter_ledger(
        self, after: int = 0, task_id: str | None = None, root_id: str | None = None, page: int = 5000
    ) -> Iterator[dict]:
        """Every ledger entry after `after`, in order, across pages."""
        while True:
            entries = self.ledger(after=after, limit=page, task_id=task_id, root_id=root_id)
            if not entries:
                return
            yield from entries
            after = entries[-1]["seq"]

    def ledger_verify(self) -> dict:
        return self._req("GET", "/v1/admin/ledger/verify")

    def authorizations(
        self, root_id: str | None = None, status: str | None = None, limit: int = 500
    ) -> list[dict]:
        params: dict[str, Any] = {"limit": limit}
        if root_id:
            params["root_id"] = root_id
        if status:
            params["status"] = status
        return self._req("GET", "/v1/admin/authorizations", params=params)["authorizations"]

    def get_authorization(self, auth_id: str) -> dict:
        return self._req("GET", f"/v1/admin/authorizations/{auth_id}")

    def approve(self, auth_id: str) -> dict:
        return self._req("POST", f"/v1/admin/authorizations/{auth_id}/approve")

    def reject(self, auth_id: str, reason: str = "") -> dict:
        return self._req("POST", f"/v1/admin/authorizations/{auth_id}/reject", json={"reason": reason})

    def explain_intent(self, task_id: str) -> dict:
        return self._req("GET", f"/v1/admin/tasks/{task_id}/intent")

    def unsupervise(self, task_id: str) -> dict:
        return self._req("POST", f"/v1/admin/tasks/{task_id}/unsupervise")

    def reconcile(self, auth_id: str) -> dict:
        return self._req("POST", f"/v1/admin/authorizations/{auth_id}/reconcile")
