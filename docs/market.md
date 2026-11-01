# Writ: market positioning

## One sentence

Writ is the execution authority for AI agents: it bounds what an agent's task may *cause*,
not just which tools it may call, and it proves it with signed, auditable evidence.

## The gap

Every serious agent deployment hits the same wall. Teams get an agent to recommend actions
quickly. Letting it *take* actions on CRM, billing, ticketing or email stalls for months,
because the only control anyone has is a tool allowlist, and the people accountable for the
systems know an allowlist bounds operations, not outcomes. The failure we reproduced with a
frontier model (denied a CRM change, it asked the recipient of its permitted email to make the
change) is the one security reviewers fear and cannot currently rule out.

Existing products in the space are gateways: tool aggregation, scopes, credential brokering,
logging, sometimes a model that scores "intent" per call. None of them give an operator a
guarantee they can set, and none treat the trajectory as the unit of control.

## What is new

| Capability | Why it matters to a buyer |
|---|---|
| Contracts over outcomes (non-goals) | The security review becomes "list what this task must never cause" instead of "argue about every tool". |
| Deterministic content and provenance layers | Two classes of laundering are closed by definitions, with no false-positive rate to tune. |
| Anytime-valid intent testing | The operator sets α; a benign task is interrupted with probability at most α over its whole life. This is a promise you can write into an SLA. |
| Lookahead supervision and held authorizations | Consequential actions are held *before* the harmful step, reviewed in minutes, executed with a signed single-use authorization on approval. |
| Tree-scoped evidence and shared budgets | Sub-agents cannot launder authority or evidence by spawning. |
| Hash-chained ledger, signed receipts | Audit and incident response get a tamper-evident record of what was attempted, denied, held and done. |

## Who buys it

Engineering or product leads who own an agent deployment that is blocked at the "take action"
step, in B2B customer operations first (support, billing, success), with security as the
necessary partner. The purchase case is unblocking automation that previously required a
human to supervise every consequential step.

## Wedge, expansion, dependence

1. **Wedge**: one workflow, three integrations, deployed on the customer's infrastructure.
   Success is measured as authorized tasks completed autonomously at an agreed risk budget.
2. **Expansion**: more workflows reuse the same integrations, effect adapters and non-goal
   vocabulary; each deployment grows the labelled corpus of trajectories.
3. **Dependence**: agent platforms embed Writ for protected execution; receiving applications
   begin to verify Writ authorizations and receipts directly. The evidence format and verifier
   are published; the maintained adapters, effect models, extractors and the trajectory corpus
   are the paid product.

## Why this is defensible

Anyone can build a gateway. The durable assets are (a) tested effect models under real
customer configurations, (b) the non-goal vocabulary and claim extractors per domain, (c) a
corpus of paired benign and adversarial trajectories from enforcement, not from demos, and
(d) the guarantee itself, which requires the sequential-testing design to be in the critical
path, which is where Writ already is.

## Pricing shape

Platform fee per environment plus per-integration adapter maintenance, with usage tiers on
authorized actions. Supervision review tooling and the research-grade evaluation harness are
the enterprise tier.

## Risks

Operators must write non-goals; the first-run experience must make that a ten-minute task
(templates ship for common workflows). Effect adapters are real engineering per integration.
A cloud or model vendor can build the gateway; they are less likely to publish and stand
behind a false-hold guarantee, and the adapter and corpus moat compounds with deployments.
