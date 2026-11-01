# Security model

Writ's claim is specific: **every path from an agent to a protected resource that goes
through Writ is checked against a task contract the agent cannot widen, and that check
survives the compromise of the agent's reasoning, prompts, tool arguments and generated code.**

What it does *not* claim is equally specific, and is listed below.

## Trust boundaries

| Component | Trusted? | Holds |
|---|---|---|
| Agent runtime (model, prompts, orchestration, sub-agents) | **No** | A task token. Nothing else. |
| Gate | Yes | Task contracts, budgets, ledger, gate signing key. No upstream credentials. |
| Executor | Yes | Upstream credentials, executor signing key, trusted gate public keys. No policy. |
| Protected systems | Trusted to enforce their own authorization; Writ narrows, never widens | |
| Operator | Yes (admin token, optionally named) | Creates/revokes/renews/re-pins tasks, approves and rejects holds, halts the gate. |

Three separate credentials: task tokens (agents), admin tokens (operators), the internal
token (gate ↔ executor), plus Ed25519 signatures on authorizations (gate → executor) and
receipts (executor → gate). Compromising a task token yields exactly that task's authority
for the remainder of its lease, and the operator can revoke it.

## What survives which compromise

| Assume this is compromised | What still holds |
|---|---|
| Model reasoning, prompt injection, hostile tool arguments | Command table is fixed. Args are schema-validated with `additionalProperties: false`. Constraints, budgets, forbidden effects, config pins and leases are enforced by the gate. Every attempt is in the ledger and is evidence for the intent layer. |
| A sub-agent | It holds a strictly narrower grant and shares the parent's budgets and intent state. It cannot renew, re-pin, widen, or hand the gate a regular expression. Revoking the parent kills it. Tree depth and size are capped. |
| The agent container (escape to the host it runs on) | It still has no credentials and, in the reference deployment, no route to the executor or upstream networks. It can only present task tokens to the gate, at a bounded rate and body size. |
| Gate ↔ executor transport (replay, injection, stripping) | Authorizations are single-use at the gate *and* the executor, expire in seconds, and are bound to an argument hash. Every executor response is signed; a response without a receipt that verifies, names the same authorization, agrees with the reported status and covers the result is treated as `unknown` and the budget stays reserved. A forged "rejected" or "ok" cannot free or commit a budget, and a *genuine* rejection replayed for an authorization that was already consumed (the executor's `replay` answer) is treated as `unknown`, not as proof of inaction. |
| Executor reports success dishonestly | Same as above: no verifiable receipt, no settlement. (A fully compromised executor can act with its credentials; see below.) |
| Gate database tampering after the fact | The hash chain breaks; `writ ledger verify` reports the first bad entry. |
| Target system reconfigured after approval | Mutating commands are denied with `CONFIG_CHANGED` until an operator re-pins; approvals of held actions re-check; the executor independently refuses if the version moved between authorization and execution. |
| Gate process crash at any point of the pipeline | Budgets move at most once per authorization (conditional transitions). The sweeper releases authorizations that expired unconsumed, turns consumed-but-lost outcomes into `unknown`, and reconciles them against the executor's nonce record and the upstream's idempotency record. Nothing is ever re-executed automatically. |
| Agent retries after a network timeout | With `Idempotency-Key` the retry replays the recorded result; without it, the second request is a second decision against the same budgets. |

## The intent layer

The intent layer (docs/intent.md, paper/) adds three controls on top of the grant: content
claims, identifier provenance, and a sequential probabilistic test. Its guarantees are relative
to its model classes: a benign agent whose behaviour lies in the modelled benign mixture is
held by the e-rule with probability at most α over its whole trajectory; an adversary in the
modelled compromised class realises a non-goal without supervision only as often as a benign
agent would have produced the same trajectory, inflated by the class size over α. A single
disguised deviation with no other signal is caught only by the claim extractor and provenance.
Intent state is per task tree, so delegation cannot reset it, and updates for one tree are
serialized so parallel probes cannot race each other out of the evidence. Operators review
held authorizations; approving one re-checks consequences and executes it with a fresh
signed single-use authorization.

The agent is told decisions and the evidence it produced (its claims, the identifiers of
unknown provenance), never the test statistic, the forecast or the posterior: an adaptive
adversary must not be able to watch the detector.

## Explicit non-goals and assumptions (read these)

1. **Bypass paths.** If the agent has any credential or network route to a protected system
   that does not pass through the executor, Writ does not contain it. The reference compose
   file segments networks (`agents`, `control`, `upstream`); you must reproduce that property
   in your infrastructure and verify it, for example by running `scripts/check-isolation.sh`
   from the agent's network position.
2. **A compromised executor** can do whatever its credentials allow. Mitigations are
   operational: minimal upstream scopes per executor, one executor per integration, no
   policy logic in the executor, receipts signed with a key the gate verifies.
3. **A compromised gate host** can mint authorizations. Protect the gate's private key (HSM or
   KMS-backed signing is the intended path; the code isolates signing in `signing.py`).
   Applications that verify receipts and authorizations directly (future work) reduce the
   blast radius.
4. **Effect prediction is bounded by adapters.** The gate denies mutating commands whose
   consequences cannot be predicted (`PREDICTION_UNAVAILABLE`), but a prediction is only as
   complete as the adapter's model of the target system. Treat adapter coverage as an
   auditable claim, not a guarantee.
5. **Committed effects are committed.** Revocation stops future actions and voids unconsumed
   authorizations. It cannot unsend an email.
6. **Clock.** Leases and authorization expiry use the gate's clock. Run NTP.
7. **Single-writer gate.** SQLite with serialized writes. This is what makes budget
   reservation trivially atomic; it also means one gate process per database. See
   `docs/deploy.md`.
8. **Denial-of-service.** The gate bounds request bodies, rate-limits per task token, caps
   enumeration sizes, pattern lengths, tree size and depth, and refuses agent-supplied
   regular expressions. It does not defend against volumetric attacks; put it behind an
   ingress that does.
9. **Operator-authored regular expressions** in templates are evaluated by Python's
   backtracking engine. Keep them simple and anchored; the gate caps pattern and input
   length but cannot detect every pathological pattern.
10. **Ledger contents.** Ledger payloads contain the arguments of every attempt, including
    free text. The ledger is as sensitive as the systems it protects.
11. **No formal verification yet.** The attenuation and budget rules are small, deterministic
    and covered by tests (`tests/test_grant.py`, `tests/test_delegation.py`,
    `tests/test_integrity.py`, `tests/test_hardening.py`). They are written to be
    reimplementable in a verified core.

## Hardening checklist for a real deployment

- Terminate TLS in front of the gate; use mTLS or a service mesh between gate and executor.
- Use named operator tokens (`WRIT_ADMIN_TOKENS`); rotate them and the internal token; store
  the gate and executor keys in a secrets manager; rotate keys with the key-list mechanism.
- One executor per integration, with the minimum upstream scopes.
- Keep `WRIT_AUTHORIZATION_TTL_SECONDS` short (default 60).
- Leave `WRIT_ENABLE_DOCS` off; keep the demo SaaS's test endpoints off any real network.
- Export the ledger continuously to write-once storage and verify it there.
- Alert on `writ_gate_denials_total` spikes, on `status=unknown` authorizations older than a
  few minutes, on `marked_unknown` sweep actions, and on `CONFIG_CHANGED`.
- Test containment from the agent's position: with root inside the agent container, confirm
  you cannot reach the executor, the upstream network, or any credential.
- Run `pip-audit` against `uv.lock` in CI (the shipped workflow does).

## Reporting

Open a private security advisory on the repository or contact the maintainers directly.
Please include the ledger entries for the behaviour you observed.
