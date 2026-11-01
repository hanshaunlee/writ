# Changelog

All notable changes to Writ are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). Until 1.0, minor versions may change
the HTTP API; such changes are called out under **Changed**.

## [0.2.0] - 2026-10-10

Production-hardening release. The control-plane semantics are unchanged; this release
closes the gaps between "works in the demo" and "safe to run unattended".

### Added
- **Fail-closed receipts.** Every executor response, including early rejections, carries a
  signed receipt. The gate treats a response without a verifiable receipt that names the
  same authorization, agrees with the reported status and covers the returned result as
  `unknown`, keeping the budget reserved until reconciled.
- **Maintenance sweeps.** The gate releases `issued` authorizations that expired unconsumed,
  marks `consumed` authorizations with no recorded outcome as `unknown`, and auto-reconciles
  `unknown` outcomes with exponential backoff. `POST /v1/admin/sweep` and `writ sweep` run
  the pass on demand. Expiring tasks now also void `held` authorizations.
- **Idempotent invoke.** `Idempotency-Key` header on `POST /v1/invoke`: a retried request
  returns the original result (`replayed: true`) instead of acting twice; reuse with
  different arguments is `422 IDEMPOTENCY_MISMATCH`; a concurrent duplicate is
  `409 IDEMPOTENCY_IN_PROGRESS`.
- **Key rotation.** `WRIT_EXECUTOR_PUBLIC_KEY` and `WRIT_GATE_PUBLIC_KEY` accept a comma
  separated list; signatures are matched by key id. `/v1/keys` lists every trusted key.
- **Named operators.** `WRIT_ADMIN_TOKENS=name:token,...` records which operator created,
  revoked, approved or rejected; `/v1/admin/status` returns the caller's name.
- **Intent explanation.** `GET /v1/admin/tasks/{id}/intent` and `writ task explain` show
  every attempt in a task tree, its abstract meaning and the evidence after it.
- **Request limits.** Body size limit (`WRIT_MAX_BODY_BYTES`, default 1 MiB) and a per-task
  token bucket (`WRIT_AGENT_RATE_LIMIT`, `WRIT_AGENT_RATE_BURST`) answering `429`.
- **Tree size cap** (`WRIT_MAX_TASKS_PER_TREE`, default 256) alongside the depth cap.
- Authorization records carry the intent summary (`intent` field) for audit.
- Schema versioning in the gate database; a newer database refuses to open under an older gate.
- Executor nonce retention (`WRIT_NONCE_RETENTION_DAYS`, default 30) with periodic purge.
- Metrics: `writ_executor_rejections_total{reason}`, `writ_gate_rate_limited_total`,
  `writ_gate_sweep_actions_total{action}`.
- `LICENSE`, `CHANGELOG.md`, `CONTRIBUTING.md`, `uv.lock`, `py.typed`.

### Changed
- **Agent-facing responses no longer expose detector statistics.** `/v1/invoke`, `/v1/me`
  and `/v1/delegate` return `intent` with only `claims`, `provenance` and `mode`. The
  e-value, forecast, posterior mass and abstract action are available to operators on the
  task view, the authorization record, the intent explanation and the ledger.
- `/v1/me` no longer returns `intent_spec` or `principal`.
- Interactive API docs are off by default (`WRIT_ENABLE_DOCS=1` to enable).
- Budgets move at most once per authorization: every terminal transition is conditional on
  the current status, so revoke, sweep and outcome paths cannot double-release.
- `approve` re-runs the forbidden-effect check against fresh predictions and releases the
  hold with `409 FORBIDDEN_EFFECT` if the world moved under it.
- Consume re-checks halt and liveness inside the same transaction that flips the status.
- Delegated grants may not introduce `matches` patterns on new paths (agents cannot hand the
  gate a regular expression); `eq` and `in` remain available for narrowing.
- Boolean values never satisfy numeric or enumerated constraints (`True != 1`).
- Grant budgets are validated as non-negative integers at creation; names, metadata,
  enumerations and patterns have size bounds; `min > max` constraints are rejected.
- Metric labels for unknown commands collapse to `<unknown>` (no cardinality amplification).
- Executor refuses authorizations whose adapter does not serve the named integration, and
  turns adapter exceptions after consume into `unknown` with a receipt instead of a 500.
- The executor client treats malformed bodies as `ExecutorError`; the dispatch path never
  leaves a reservation dangling on an unexpected exception.
- `writ ledger export` pages through the whole ledger (previously capped at 5000 entries)
  and accepts `--after` for incremental export; `writ ledger verify` streams.
- `writ agent invoke` exits 0 for `held` and accepts `--idempotency-key`.
- MCP: a `held` result is reported as pending rather than as an error.
- Uvicorn no longer sends `Server`/`Date` headers; proxy headers are honoured.

### Fixed
- A replayed executor rejection (signed, same authorization id) for an action that had in fact
  executed could release its budget. Rejections now carry the executor's reason; on a consumed
  authorization only a post-consume refusal (`config_changed`, `config_unverifiable`) releases,
  anything else is `unknown` and reconciled.
- A crash between reserving budgets and inserting the authorization row could leak a
  reservation for the task's lifetime; both now happen in one transaction.
- `NaN`/`inf` in constraints or arguments could bypass numeric bounds and attenuation checks;
  non-finite numbers are rejected everywhere, and constraint values are bounded (1024 chars,
  scalars only).
- A chunked request body could exceed the size limit and still be processed; the handler now
  sees a client disconnect and the response is 413.
- Constraint paths with non-ASCII digits (`to.²`) crashed argument evaluation.
- Idempotency claims are owned by the attempt that made them; a stale claim is reclaimed only
  after a window longer than any legitimate invoke, and a late finish from the dead attempt
  is ignored.
- `GateService` now requires executor public keys; receipt verification cannot be disabled.
- Expired `issued` authorizations could pin budget reservations forever.
- Lost intent-state updates under concurrent requests on one task tree (per-tree serialization).
- A forged or stripped executor response could release or commit a budget without proof.

## [0.1.0] - 2026-10-10

Initial release: gate, executor, demo SaaS, command table, templates, grants with
attenuation, shared budgets, effect prediction, configuration pinning, single-use signed
authorizations, hash-chained ledger, intent layer (claims, provenance, anytime-valid
supervision), MCP server, CLI, docker compose reference deployment.
