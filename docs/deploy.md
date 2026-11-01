# Deployment

## Reference: docker compose

```bash
make up      # writ keygen → deploy/keys/writ.env, then compose up --build --wait
make demo    # end-to-end scenario against 127.0.0.1:8080
make logs
make down    # removes volumes
```

Networks:

| Network | Members | Egress |
|---|---|---|
| `agents` | gate, agent containers | normal |
| `control` | gate, executor | none (`internal: true`) |
| `upstream` | executor, protected systems (demo SaaS) | none in the demo; in production this is where the executor reaches real APIs |

Containers run read-only, non-root, `cap_drop: ALL`, `no-new-privileges`. State lives in
named volumes (`gate-data`, `executor-data`). The image is built from `uv.lock`
(`--frozen`), so two builds of the same commit install the same dependency set.

Compose variables (environment or `.env`): `WRIT_IMAGE` (default `writ:local`),
`WRIT_BIND` (default `127.0.0.1:8080`), and the gate tunables listed below. To run a second,
independent stack on the same host (for example to test an upgrade) set a different
`COMPOSE_PROJECT_NAME`, `WRIT_IMAGE` and `WRIT_BIND`.

To run an agent inside the segmented topology:

```bash
export WRIT_TASK_TOKEN=$(writ task create -t templates/resolve_duplicate_charge.yaml ... --token-only)
docker compose -f deploy/docker-compose.yml --env-file deploy/keys/writ.env --profile agent up -d agent
docker compose -f deploy/docker-compose.yml exec agent writ agent me
```

From that container the executor and upstream are unreachable by construction.
`scripts/check-isolation.sh` verifies it.

## Environment variables

### Gate (`writ-gate`)

| Variable | Required | Default | Notes |
|---|---|---|---|
| `WRIT_GATE_PRIVATE_KEY` | yes | | base64url raw Ed25519 private key |
| `WRIT_EXECUTOR_PUBLIC_KEY` | yes | | one or more executor public keys, comma separated (rotation) |
| `WRIT_ADMIN_TOKEN` | one of | | single operator credential (≥24 chars); actor recorded as `operator` |
| `WRIT_ADMIN_TOKENS` | one of | | `name:token,name:token` (each ≥24 chars); actor recorded by name |
| `WRIT_INTERNAL_TOKEN` | yes (≥24 chars) | | gate ↔ executor; must differ from admin tokens |
| `WRIT_EXECUTOR_URL` | yes | | e.g. `http://executor:8081` |
| `WRIT_DB_PATH` | | `/var/lib/writ/gate.db` | SQLite, WAL |
| `WRIT_COMMANDS_PATH` | | `config/commands.yaml` | |
| `WRIT_AUTHORIZATION_TTL_SECONDS` | | `60` | lifetime of a signed authorization |
| `WRIT_MAX_TASK_TTL_SECONDS` | | `604800` | |
| `WRIT_MAX_DELEGATION_DEPTH` | | `8` | |
| `WRIT_MAX_TASKS_PER_TREE` | | `256` | breadth cap on delegation |
| `WRIT_MAX_BODY_BYTES` | | `1048576` | 413 above this |
| `WRIT_AGENT_RATE_LIMIT` | | `50` | requests/second per task token (0 disables) |
| `WRIT_AGENT_RATE_BURST` | | `100` | |
| `WRIT_SWEEP_INTERVAL_SECONDS` | | `30` | maintenance pass; 0 disables the thread |
| `WRIT_STALE_CONSUMED_SECONDS` | | `300` | consumed with no outcome after this → `unknown` |
| `WRIT_RECONCILE_AFTER_SECONDS` | | `30` | age before `unknown` outcomes are auto-reconciled |
| `WRIT_ENABLE_DOCS` | | `0` | serve `/docs` and `/openapi.json` |
| `WRIT_CLAIM_EXTRACTOR` | | `rules` | `openai` enables the model-based claim extractor (needs `OPENAI_API_KEY`) |
| `WRIT_HOST`, `WRIT_PORT` | | `0.0.0.0`, `8080` | |
| `WRIT_LOG_LEVEL` | | `INFO` | JSON logs on stdout |

The gate refuses to start on a malformed key, a short token, an admin token equal to the
internal token, an unloadable command table, or a database written by a newer gate.

### Executor (`writ-executor`)

| Variable | Required | Notes |
|---|---|---|
| `WRIT_EXECUTOR_PRIVATE_KEY` | yes | signs receipts |
| `WRIT_GATE_PUBLIC_KEY` | yes | one or more gate public keys, comma separated (rotation) |
| `WRIT_INTERNAL_TOKEN` | yes (≥24 chars) | |
| `WRIT_GATE_URL` | yes | for consume callbacks |
| `WRIT_DEMO_SAAS_URL`, `WRIT_DEMO_SAAS_API_KEY` | yes | the only upstream credential in the reference build |
| `WRIT_EXECUTOR_DB_PATH` | | nonce store, default `/var/lib/writ/executor.db` |
| `WRIT_NONCE_RETENTION_DAYS` | | `30`; nonce records older than this are purged (keep ≥ your reconciliation window) |

### Demo SaaS (`writ-demo-saas`)

`DEMO_SAAS_API_KEY`, `WRIT_PORT` (9000). Test-only endpoints (`/_state`, `/_reset`, `/_chaos`)
are unauthenticated; never expose this service beyond the demo.

## Production notes

- **TLS and identity.** Put the gate behind a TLS-terminating ingress. Prefer mTLS or a mesh
  on the control network. Task tokens are bearer secrets; deliver them to agents over a
  trusted channel and keep leases short. The gate honours `X-Forwarded-*` from the ingress.
- **Keys and rotation.** `writ keygen` is for development. In production generate keys in
  your secrets manager and inject them. To rotate the executor key: add the new public key to
  the gate's `WRIT_EXECUTOR_PUBLIC_KEY` list, restart the gate, switch the executor's private
  key, then remove the old public key. The gate key rotates the same way through the
  executor's `WRIT_GATE_PUBLIC_KEY`. `/v1/keys` on both services shows what is trusted.
- **Operators.** Use `WRIT_ADMIN_TOKENS` so approvals, rejections and revocations in the
  ledger name a person. Rotate a single operator's token without touching the others.
- **Backups.** The gate database is the system of record for budgets and the ledger. Back it
  up with SQLite's online backup or snapshot the volume; export the ledger continuously
  (`writ ledger export --after <last seq>`) to immutable storage and verify it there
  (`writ ledger verify --file`).
- **Scaling.** One gate process per database; SQLite with `BEGIN IMMEDIATE` gives atomic
  reservations with no coordination service, and decisions for one task tree are serialized
  in-process. A single gate comfortably handles thousands of decisions per second because the
  hot path is local; the executor and upstream dominate latency. Horizontal scaling means
  moving the store to Postgres with row locks on `budget_usage` and an advisory lock per
  root task; the store interface is isolated in `gate/store.py` for that purpose. Executors
  are stateless apart from the nonce store and can be scaled per integration.
- **Observability.** Prometheus at `/metrics` on both services:
  `writ_gate_invocations_total{command,decision,reason}` (unknown commands are labelled
  `<unknown>`), `writ_gate_denials_total{reason}`, `writ_gate_holds_total{reason}`,
  `writ_gate_held_authorizations`, `writ_gate_rate_limited_total`,
  `writ_gate_sweep_actions_total{action}`, `writ_gate_invoke_seconds`,
  `writ_executor_executions_total{adapter,operation,status}`,
  `writ_executor_rejections_total{reason}`. Logs are JSON lines and never contain tokens.
- **Alerts.** `status="unknown"` authorizations older than a few minutes (auto-reconcile is
  failing); `writ_gate_sweep_actions_total{action="marked_unknown"}` increasing (the gate is
  losing outcomes mid-flight); `CONFIG_CHANGED` denials (someone changed a target system);
  denial spikes per task; `writ_gate_held_authorizations` above your review capacity;
  `/readyz` failing.
- **Upgrades.** The gate records a schema version and applies additive migrations on start;
  it refuses a database written by a newer version. Stop the gate before upgrading;
  in-flight authorizations expire harmlessly and the sweep releases their reservations.
- **Ledger retention.** Ledger payloads include the arguments of every attempt (which may
  contain personal data such as email bodies). Treat the gate database and ledger exports
  with the same classification as the protected systems.
