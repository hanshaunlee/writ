# Gate HTTP API

All bodies are JSON. Errors are `{"code": "...", "detail": "..."}` with a 4xx/5xx status.
Interactive docs are served at `/docs` only when `WRIT_ENABLE_DOCS=1`.

Limits that apply to every request: bodies above `WRIT_MAX_BODY_BYTES` (default 1 MiB) are
refused with `413 PAYLOAD_TOO_LARGE`; agent endpoints are rate limited per task token
(`429 RATE_LIMITED`, `Retry-After: 1`); malformed bodies are `422 INVALID_REQUEST`.
Unexpected failures are `500 INTERNAL` with no detail.

## Public

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness |
| GET | `/readyz` | Readiness (executor reachable); includes `halted` |
| GET | `/metrics` | Prometheus |
| GET | `/v1/keys` | Gate public key, and every executor key the gate currently trusts (`executor_keys[]`) |

## Agent (`Authorization: Bearer <task token>`)

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/v1/me` | | Task view: grant, budgets, lease, pinned config, `intent.mode`, `commands[]` with schemas and constraints |
| POST | `/v1/invoke` | `{command, args}`; optional `Idempotency-Key` header | `InvokeResult` (below) |
| POST | `/v1/delegate` | `{name, grant, ttl_seconds?}` | `{task, token}` (403 `ATTENUATION_VIOLATION` if wider, 429 `TREE_LIMIT` if the tree is full) |

`InvokeResult` as the agent sees it:

```json
{
  "decision": "allowed" | "denied",
  "command": "billing.refund",
  "denial": {"reason": "BUDGET_EXCEEDED", "detail": "...", "extra": {...}},
  "authorization_id": "auth_...",
  "status": "committed" | "failed" | "rejected" | "unknown" | "held",
  "result": {...}, "error": null,
  "effects": [{"type": "money_out", "detail": {...}}],
  "receipt": {"payload": {...}, "key_id": "...", "signature": "..."},
  "budgets": {"money_cents": {"reserved": 0, "committed": 14900}},
  "intent": {"claims": {...}, "provenance": {"trusted": [...], "untrusted": [...]}, "mode": "normal"},
  "hold": {"reason": "UNTRUSTED_PROVENANCE", "detail": "..."},
  "replayed": false
}
```

The agent is told what was decided and why (claims it made, identifiers of unknown
provenance, whether the tree is supervised). It is not told the detector's statistics;
those are on the operator endpoints and in the ledger.

Statuses: `committed` (executed, receipt verified), `failed` (upstream refused, nothing
happened), `rejected` (executor refused before acting), `unknown` (no trustworthy answer;
budget stays reserved until reconciled, which the gate also attempts automatically),
`held` (waiting for an operator; budget reserved; do not retry).

Denial reasons: `HALTED`, `TASK_INACTIVE`, `TASK_EXPIRED`, `COMMAND_UNKNOWN`,
`COMMAND_NOT_GRANTED`, `INVALID_ARGS`, `CONSTRAINT_VIOLATION`, `PREDICTION_UNAVAILABLE`,
`CONFIG_UNPINNED`, `CONFIG_CHANGED`, `FORBIDDEN_EFFECT`, `BUDGET_EXCEEDED`,
`NON_GOAL_ADVANCED`, `UNTRUSTED_PROVENANCE` (when the policy is `deny`).

### Idempotent invoke

Send `Idempotency-Key: <1-128 chars>` with `POST /v1/invoke`. The key is scoped to the task.
A retry with the same key and the same `{command, args}` returns the original result with
`replayed: true` and performs nothing. The same key with different arguments is
`422 IDEMPOTENCY_MISMATCH`; a duplicate that arrives while the first is still running is
`409 IDEMPOTENCY_IN_PROGRESS`. Use it for every money or send command issued over a network
that can time out.

## Operator (`Authorization: Bearer <admin token>`)

With `WRIT_ADMIN_TOKENS=name:token,...` the operator's name is recorded as `actor` on every
ledger entry it causes; with a single `WRIT_ADMIN_TOKEN` the actor is `operator`.

| Method | Path | Body / query |
|---|---|---|
| GET | `/v1/admin/status` | → `{halted, version, commands[], held_authorizations, operator}` |
| GET | `/v1/admin/commands` | |
| POST | `/v1/admin/tasks` | `{name, grant, ttl_seconds, max_ttl_seconds?, metadata?, principal?, intent?}` → `{task, token}` |
| GET | `/v1/admin/tasks?root_id&status&limit&offset` | |
| GET | `/v1/admin/tasks/{id}` | full view including `intent` statistics |
| GET | `/v1/admin/tasks/{id}/intent` | every attempt in the tree with its abstract meaning and the evidence after it |
| POST | `/v1/admin/tasks/{id}/revoke` | `{reason}` → `{revoked[], voided_authorizations[]}` |
| POST | `/v1/admin/tasks/{id}/renew` | `{extend_seconds}` |
| POST | `/v1/admin/tasks/{id}/repin` | |
| POST | `/v1/admin/tasks/{id}/unsupervise` | |
| POST | `/v1/admin/halt` / `/unhalt` | `{reason}` |
| GET | `/v1/admin/authorizations?root_id&status&limit` | |
| GET | `/v1/admin/authorizations/{id}` | includes `intent`, `hold`, `receipt`, `outcome` |
| POST | `/v1/admin/authorizations/{id}/approve` | executes a held authorization now; `409 FORBIDDEN_EFFECT` / `CONFIG_CHANGED` if the world moved |
| POST | `/v1/admin/authorizations/{id}/reject` | `{reason}` |
| POST | `/v1/admin/authorizations/{id}/reconcile` | |
| POST | `/v1/admin/sweep` | run maintenance now → `{expired_tasks, released_expired, marked_unknown, reconciled}` |
| GET | `/v1/admin/ledger?after&limit&task_id&root_id` | pages of at most 5000 |
| GET | `/v1/admin/ledger/verify` | streams the whole chain → `{ok, entries, error, head}` |

`GET /v1/admin/tasks/{id}/intent` returns `{task_id, root_id, mode, mode_reason, e_value,
threshold, forecast, risk_budget, residual_risk_spent, non_goal_mass, posterior, steps,
achieved, blocked, history[]}` where each history entry is
`{action: {command, direct[], requests[], sink, probe}, executed, e_value, denied_values?}`.

## Internal (`Authorization: Bearer <internal token>`, executor only)

| Method | Path | Purpose |
|---|---|---|
| POST | `/internal/authorizations/{id}/consume` | Atomically mark issued → consumed; 409 if halted, task inactive, expired, or already used. The checks and the transition happen in one transaction. |

## Grant JSON

```json
{
  "commands": [
    {"command": "billing.refund",
     "args": {"charge_id": {"in": ["ch_1001", "ch_1002"]}, "amount_cents": {"max": 20000}}},
    {"command": "crm.update_customer",
     "args": {"customer_id": {"eq": "cus_123"}, "fields": {"keys_subset": ["note", "tags"]}}}
  ],
  "budgets": {"money_cents": 20000, "refunds": 2, "writes": 3},
  "forbidden_effects": ["external_export", "notification_redirect"]
}
```

Constraint operators: `eq`, `in` (≤ 1000 scalar values, strings ≤ 1024 chars), `max`, `min`
(finite numbers), `matches` (anchored regex, ≤ 512 chars, applied to strings ≤ 20000 chars),
`keys_subset`. Non-finite numbers (`NaN`, `Infinity`) are rejected in grants and never satisfy
a numeric constraint. Paths are dotted
(`fields.note`). Booleans never satisfy numeric or enumerated constraints. Budgets are
non-negative integers, and every budget dimension charged by a granted command must have a
limit in `budgets` (fail closed).

Delegated grants may narrow with `eq`/`in`/`max`/`min`/`keys_subset` on any path, but may
not introduce a `matches` pattern the parent did not carry.

## Executor API (control network)

`GET /v1/keys` (executor key and trusted gate keys), `POST /v1/config-versions
{integrations[]}`, `POST /v1/predict {adapter, operation, integration, args}`,
`POST /v1/execute {authorization, args}`, `POST /v1/reconcile {authorization, args}`; the
POST endpoints require the internal token. Execute returns
`{status: ok|failed|unknown|rejected, result?, error?, receipt}`. **Every** response carries
a receipt signed by the executor whose payload names the authorization, the status, the
rejection `reason` (`verification`, `no_adapter`, `integration_mismatch`, `replay`,
`consume_refused`, `config_unverifiable`, `config_changed`) and, for `ok`, the hash of `result`; the gate treats a response whose receipt is missing, unverifiable,
or inconsistent with the response as `unknown`.
