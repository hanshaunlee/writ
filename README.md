# Writ

**An execution authority for AI agents.**

Writ sits between agents and the systems they act on. Agents hold no credentials and no
upstream access. They request *commands* from a fixed table; Writ checks each request
against a bounded, expiring, revocable **task contract**, evaluates what the action will
*cause* under the current configuration of the target system, reserves budgets across the
whole delegation tree, and only then issues a single-use, signed authorization to an
isolated executor that holds the credentials and performs exactly that operation.

The model is the operating system trap table: user code cannot touch hardware, it asks the
kernel to do a specific, checked thing on its behalf. The agent's reasoning is untrusted; the
boundary is enforced by code it cannot change.

```
 agent / sub-agents                 gate (authority)                      executor (credentials)         protected systems
 ───────────────────   invoke   ────────────────────────────  authorize  ────────────────────────  act  ─────────────────
 no credentials       ───────►  task contract · grants       ─────────►  verify signature         ────►  CRM, billing,
 no upstream route              constraints · budgets                    consume (single use)            email, ...
 MCP or HTTP          ◄───────  effect prediction · pin      ◄─────────  re-check config                 predicted effects
                      result    ledger · revocation · leases  receipt    idempotent execute
```

## What it enforces

| Property | How |
|---|---|
| Least authority | Operators create task contracts from templates. Agents can only attenuate (delegate narrower), never widen. |
| Exact binding | Each authorization is bound to the task, the command, a hash of the exact arguments, and the integration's configuration version. |
| Single use, short lived | Authorizations expire in seconds and are consumed atomically at the moment of action. Replays are rejected at both the gate and the executor. |
| Shared budgets | Money, sends, writes and refund counts are reserved atomically across a task and all its ancestors. Two sub-agents cannot each spend the whole budget. |
| Consequence awareness | Before authorizing a write, the gate asks the executor what the operation will cause under the *current* configuration (e.g. a CRM tag that triggers an external export). Forbidden effects are denied. |
| Configuration drift | A change to the target system's configuration after approval denies further mutating actions until an operator re-pins. A change between authorization and execution makes the executor refuse. |
| Revocation and leases | Revoking a task voids every descendant and every outstanding authorization. Leases expire; only operators can extend them, and never beyond a hard cap. A global halt stops everything. |
| Ambiguous outcomes | Timeouts and 5xx responses leave budgets reserved and require reconciliation against the upstream idempotency record. No blind retries. |
| Evidence | Every decision, denial, authorization, outcome and operator action is appended to a hash-chained ledger that can be exported and verified offline. Executors return signed receipts. |
| Fail closed | Unknown commands, unpredictable consequences, missing budgets, unreachable executor: all deny. |
| Proof of outcome | Every executor response is signed; the gate settles a budget only on a receipt that verifies and names the same authorization, status and result. Anything else is `unknown` and reconciled automatically. |

## Intent: outcomes, not just operations

A grant bounds what an agent may *do*. The intent layer bounds what a task may *cause*,
including through permitted channels. In a live run, a model that was denied a CRM change
asked the legitimate recipient of its (permitted) email to make the change for it. Writ now
catches this three ways, in order: content claims (the email asks for a non-goal), provenance
(the address came from nowhere the task was allowed to read), and a probabilistic intent model
that treats every denied attempt as evidence and places the task under supervision before the
next consequential action. Supervised sends and payments are held for an operator. See
[docs/intent.md](docs/intent.md) and the paper in `paper/`.

## Quick start

Requirements: Python 3.12+, [uv](https://docs.astral.sh/uv/), Docker (for the reference deployment).

```bash
make install            # venv + deps
make test               # 89 unit, scenario and adversarial tests, no network
make up                 # keys + docker compose (gate, executor, demo SaaS) on 127.0.0.1:8080
make demo               # walks the duplicate-charge scenario end to end
```

The demo creates a task from `templates/resolve_duplicate_charge.yaml`, then as the agent:
reads the customer and charges, refunds the duplicate (permitted), tries to redirect the
billing contact, email an outsider, trigger a hidden export automation and overspend
(all denied), completes the permitted path, delegates to a sub-agent that shares the budget,
and finally gets killed by the operator. It ends by verifying the ledger.

### Without Docker

```bash
.venv/bin/writ keygen --out keys && set -a && source keys/writ.env && set +a
DEMO_SAAS_API_KEY=$WRIT_DEMO_SAAS_API_KEY WRIT_PORT=9000 writ-demo-saas &
WRIT_PORT=8081 WRIT_GATE_URL=http://127.0.0.1:8080 WRIT_DEMO_SAAS_URL=http://127.0.0.1:9000 WRIT_EXECUTOR_DB_PATH=./executor.db writ-executor &
WRIT_PORT=8080 WRIT_EXECUTOR_URL=http://127.0.0.1:8081 WRIT_DB_PATH=./gate.db writ-gate &
WRIT_ENV_FILE=keys/writ.env scripts/demo.sh
```

## Using it from an agent

**MCP.** `writ-mcp` exposes exactly the commands a task holds as MCP tools, with the task's
constraints in each tool description, plus `writ_task_status` and `writ_delegate`.

```json
{ "mcpServers": { "writ": { "command": "writ-mcp",
    "env": { "WRIT_GATE_URL": "http://gate:8080", "WRIT_TASK_TOKEN": "wt_..." } } } }
```

**HTTP.** `GET /v1/me`, `POST /v1/invoke {command, args}`, `POST /v1/delegate {name, grant}`
with `Authorization: Bearer <task token>`. Send an `Idempotency-Key` on invoke so a retried request
replays instead of acting twice. Agents receive decisions, claims and provenance, never the
detector's statistics. See [docs/api.md](docs/api.md).

**Example agents.** `examples/agent.py` (Anthropic SDK) and `examples/agent_openai.py`
(OpenAI SDK) build their tool list from the gate and work the scenario. Denials are returned
to the model as tool results so it can find the permitted path. Set `WRIT_EXAMPLE_MODEL` to
pick the model.

## Operating it

```bash
writ task create -t templates/resolve_duplicate_charge.yaml -p customer_id=cus_123 \
   -p billing_contact=ap@acme.example -p max_refund_cents=20000 -p 'charge_ids=["ch_1001","ch_1002"]'
writ task show <task_id>            # grant, pinned config versions, budget usage, lease
writ task revoke <task_id>          # cascades to all descendants, voids outstanding authorizations
writ task renew <task_id> 1800      # operators only, capped
writ task repin <task_id>           # re-approve after a target system's configuration changed
writ task explain <task_id>         # intent: every attempt and the evidence after it
writ auth list --status held        # held for operator review; approve / reject
writ halt --reason "incident"       # global stop
writ auth list --status unknown     # ambiguous outcomes awaiting reconciliation
writ sweep                          # run maintenance now: expire leases, release orphaned authorizations, auto-reconcile
writ auth reconcile <auth_id>
writ ledger verify; writ ledger export; writ ledger verify --file ledger.jsonl
```

## Repository layout

```
src/writ/grant.py          grant language: constraints, evaluation, attenuation rules
src/writ/commands.py       command table (YAML), schema validation, budget charges
src/writ/gate/             authority: store (SQLite), service (pipeline), HTTP API
src/writ/executor/         credential holder: verification, nonces, adapters, receipts
src/writ/demosaas/         stand-in upstream with automations, idempotency, chaos
src/writ/mcp_server.py     MCP stdio server
src/writ/cli.py            `writ` operator / agent CLI
config/commands.yaml       the shipped command table
templates/                 task contract templates
tests/                     scenario + adversarial suite (in-process, no network)
tests/test_hardening.py    settlement, sweeps, receipts, key rotation, limits, concurrency
CHANGELOG.md CONTRIBUTING.md LICENSE uv.lock
deploy/                    Dockerfile, docker-compose with segmented networks
docs/                      architecture, API, deployment
SECURITY.md                threat model, assumptions, what is not covered
```

## Status and honest limits

This is version 0.2.0 (see `CHANGELOG.md`): a complete, tested control plane with an intent layer and a reference integration. Read
[SECURITY.md](SECURITY.md) before relying on it. In particular: Writ constrains what passes
through it. An agent that holds other credentials or another network path to the same
resource is not contained by Writ, and that is a deployment property you must verify. Effect
prediction is as good as the adapters; the shipped adapters cover the demo SaaS and are the
pattern for real integrations. The gate is a single-writer SQLite service by design for v0.1
(see docs/deploy.md for scaling notes).

License: Apache-2.0.
