# Architecture

## Components

**Gate** (`src/writ/gate/`). The authority. Owns task contracts, budgets, authorizations and
the ledger. Exposes three APIs on one port with three credentials: agent (task token),
operator (admin token or named admin tokens), executor callback (internal token). Holds the
gate signing key and no upstream credentials.

**Executor** (`src/writ/executor/`). The credential holder. Verifies the gate's signature on
each authorization, claims the authorization locally (single use), consumes it at the gate
(which re-checks halt/revocation/expiry at the moment of action), re-reads the integration's
configuration version, performs the operation idempotently, and returns a signed receipt.
Every response, including a refusal before any work, is receipted. Adapters
(`executor/adapters/`) implement `predict`, `execute`, `reconcile` and `config_version` for
one integration each.

**Command table** (`config/commands.yaml`). The agent system-call table. Each entry names an
adapter operation, declares a JSON Schema for arguments (unknown keys rejected), an effect
class (`read`, `write`, `send`, `money`, `control`), and budget charges computed from the
arguments. Immutable at runtime.

**Templates** (`templates/`). Operator-approved grant shapes with typed parameters. The acting
agent never fills a template.

**MCP server / CLI / client.** Thin. All policy lives in the gate.

## Data model

```
tasks               id, parent_id, root_id, depth, status, token_hash, grant_json,
                    config_versions_json, intent_json (root only), created/expires/max_expires
budget_usage        task_id, dimension, reserved, committed
authorizations      id, task_id, command, args_json, args_hash, charges_json, integration,
                    config_version, effects_json, envelope_json, status, intent_json, hold_json,
                    issued/expires/consumed/finalized, outcome_json, receipt_json
ledger              seq, ts, task_id, type, payload_json, prev_hash, hash
settings            halt flag, schema_version
intent_state        root_id, state_json (shared by the whole tree)
trusted_atoms       root_id, atom, source
invoke_idempotency  task_id, key, request_hash, state, result_json
```

Authorization status machine:

```
issued ──consume──► consumed ──ok──► committed
   │                    ├──failed──► failed      (budget released)
   │                    ├──rejected─► released    (budget released)
   │                    └──?──────► unknown      (budget stays reserved) ──reconcile──► committed | failed | released
   ├──revoked/expired──► released
   └──expired unconsumed (sweep)──► released
held ──approve──► issued (fresh envelope)      held ──reject/revoke/expire──► released
consumed with no outcome for WRIT_STALE_CONSUMED_SECONDS (sweep) ──► unknown
```

Every terminal transition is a conditional update (`WHERE status IN (...)`), and budgets are
settled in the same transaction only when that update changed a row. Revocation, the
sweeper and the outcome path can race freely; at most one of them moves the budget.

## The invoke pipeline

`GateService.invoke(token, command, args, idempotency_key=None)`:

0. If an `Idempotency-Key` is present, claim it for this task: a recorded result is replayed,
   a mismatch or a concurrent duplicate is refused.
1. Resolve the task by token hash. Take the task tree's lock (decisions for one tree are
   serialized; different trees run in parallel). Deny if the gate is halted.
2. Walk the task's ancestor chain; every ancestor must be active and within its lease.
3. The command must exist in the table and be held in the task's grant.
4. Validate arguments against the command's JSON Schema.
5. Evaluate the grant's constraints on argument paths (`eq`, `in`, `max`, `min`, `matches`,
   `keys_subset`). A constrained path that is missing is a violation.
6. Compute budget charges from the arguments.
7. For mutating commands, ask the executor to predict effects. Deny if prediction is
   unavailable or malformed, if the integration's configuration version differs from the one
   pinned on the task, or if any predicted effect is in the grant's `forbidden_effects`.
8. Intent layer (when the root task carries an intent spec): content claims, provenance,
   probabilistic assessment. Deny, hold, or continue.
9. Reserve budgets against the task and every ancestor and mint the authorization (bound to
   task, command, args hash, integration, config version and a short expiry; signed; recorded
   as `AUTHORIZATION_ISSUED` with the intent summary) in one SQLite `BEGIN IMMEDIATE`
   transaction, so a reservation never exists without its authorization row. Release the
   tree lock.
10. Dispatch to the executor. The executor calls back to consume before acting.
11. Verify the receipt: signature under a trusted executor key, same authorization id, same
    status as the response, and for `ok` the hash of the returned result. Settle budgets:
    commit on `ok`, release on `failed`, release on `rejected` only if the row was never
    consumed or the executor's reason is a post-consume refusal (`config_changed`,
    `config_unverifiable`), keep reserved on `unknown`. Any failure of the receipt check,
    and any other rejection on a consumed row, is `unknown`.

Every denial is a ledger entry with the attempted command and arguments. Denials that say
something about the agent (constraint, schema, forbidden effect, budget) are also fed to the
intent model as evidence.

## Delegation (attenuation)

`attenuate(parent, requested)` in `grant.py` returns the effective child grant or raises:

- Each child command must be held by the parent.
- For each parent constraint on a path, the child must have a constraint on the same path
  that *implies* it: `eq` must match; `in` must be a subset; `max`/`min` must be at least as
  tight; `matches` must be the identical pattern or an enumeration whose members all match;
  `keys_subset` must be a subset. Children may add `eq`/`in`/`max`/`min`/`keys_subset`
  constraints on new paths but may not introduce `matches` patterns.
- Budgets: a child limit may not exceed the parent's; omitted dimensions inherit.
- Forbidden effects: union.
- Expiry: clamped to the parent's. Depth is capped (`WRIT_MAX_DELEGATION_DEPTH`) and so is
  the number of tasks in a tree (`WRIT_MAX_TASKS_PER_TREE`).
- Children inherit the parent's pinned configuration and cannot re-pin or renew. Intent
  state lives on the root and is shared by the whole tree.

Budget charges are applied to the whole chain, so sibling sub-agents draw from one pool.

## Revocation, leases, halt

- `revoke(task)` marks the subtree revoked, releases every `issued` and `held`
  authorization in it and records the voided ids. In-flight consumes fail with `TASK_INACTIVE`.
- Leases: `expires_at` is checked lazily on every request and swept periodically, which
  also voids the expired task's outstanding authorizations. `renew` is operator-only,
  capped by `max_expires_at` and the parent's lease.
- `halt` is a stored flag checked at invoke, at approve and at consume (inside the consume
  transaction).

## Background maintenance

A sweeper thread (or `POST /v1/admin/sweep`) runs every `WRIT_SWEEP_INTERVAL_SECONDS`:
expire lapsed leases; release `issued` authorizations past their expiry (nobody can consume
them: both gate and executor check expiry); mark `consumed` authorizations with no outcome
after `WRIT_STALE_CONSUMED_SECONDS` as `unknown`; reconcile `unknown` outcomes older than
`WRIT_RECONCILE_AFTER_SECONDS` with exponential backoff. Reconciliation never re-executes.

## Configuration pinning

At task creation the gate records each mutating integration's configuration version (from
the executor). On invoke the version must still match (`CONFIG_CHANGED` otherwise). The
authorization carries the version; the executor re-reads it immediately before acting and
refuses on drift. Operators re-approve with `repin`, which updates the whole subtree.
Approving a held authorization re-predicts effects and re-checks both the pin and the
forbidden-effect list.

## Reconciliation

An `unknown` outcome (timeout, 5xx, missing or unverifiable receipt) keeps its budget
reserved. `reconcile` asks the executor, which first checks its local nonce record (never
seen means it cannot have executed through this executor) and then the upstream idempotency
record. The result settles the authorization. No automatic retry ever re-executes a mutating
operation.

## Ledger

Append-only, hash-chained: `hash = sha256(canonical({seq, ts, task_id, type, payload, prev}))`.
`GET /v1/admin/ledger/verify` recomputes the chain page by page; `writ ledger verify --file`
does it offline on an export. Ledger payloads carry the full intent summary (statistics
included) so an operator can audit why something was denied or held.

## What the agent can see

Everything returned under a task token is designed to be safe to show an adversary: the
grant it holds, its budgets, denial reasons with the evidence that triggered them (its own
claims, the identifiers it introduced), and whether its tree is supervised. It cannot see
the e-value, forecast, posterior mass or abstract-action mapping, other tasks, operator
names, or the intent specification itself.

## Extending

Add a command: a YAML entry plus an adapter operation (`predict`, `execute`, `reconcile`).
Add an integration: an `Adapter` subclass with a real `config_version` (hash of whatever
configuration your predictions depend on) and register it in `executor/main.py`. See
`CONTRIBUTING.md`.
