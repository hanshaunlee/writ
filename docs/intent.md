# Intent: contracts over outcomes, not just operations

A grant limits *operations*. The intent layer limits *outcomes*, including outcomes an
agent could reach through a permitted operation, for example by asking the recipient of a
permitted email to do the forbidden thing.

## What a template declares

```yaml
intent:
  outcomes:                 # what the task exists to achieve
    - name: refund_duplicate_charge
      realized_by: [{ command: billing.refund }]
  non_goals:                # what it must not advance by any means
    - name: change_billing_contact
      realized_by: [{ command: crm.update_customer, effect: field_change, field: billing_contact }]
      protected_fields: [billing_contact]
      keywords: [billing contact, billing email]
      compliance: 0.3       # chance a human recipient complies if asked
  sink_commands: [email.send]
  prior_compromise: 0.02    # ρ
  risk_budget: 0.03         # ε
  false_hold_alpha: 0.01    # α
  lookahead: 3              # k
  untrusted_atoms_policy: hold
```

## Four layers, in order

1. **Grant and effect checks** (existing). Direct routes to non-goals are denied.
2. **Content claims.** Free-text payload fields of sink commands are read by a claim extractor
   (rules by default, `WRIT_CLAIM_EXTRACTOR=openai` optional). A request or commitment toward a
   non-goal is denied with `NON_GOAL_ADVANCED`. Claims are data; the policy is code.
3. **Provenance.** Identifier-like atoms (emails, resource ids, URLs, IBANs) in a sink payload must
   come from the contract or from structured fields of authorized read results. Atoms from
   nowhere (the prompt, injected free text) hold the action with `UNTRUSTED_PROVENANCE`.
4. **Probabilistic intent.** Every attempt, executed or denied, updates a posterior over
   hypotheses (benign, or compromised toward each non-goal) and an anytime-valid e-process. The
   task tree enters *supervised* mode when the e-value crosses 1/α, when the k-step forecast
   of a non-goal exceeds ε, or when the residual-risk budget is exhausted. Under supervision,
   sends and money movements are held for an operator.

Intent state is shared across the whole delegation tree, so spawning a sub-agent never resets
the evidence.

## Operator workflow

```bash
writ task show <id>                   # intent: mode, e_value, forecast, non_goal_mass
writ task explain <id>                # every attempt, what it meant, the evidence after it
writ auth list --status held          # what is waiting
writ auth approve <auth_id>           # executes now, signed and single-use
writ auth reject <auth_id>            # releases the budget
writ task unsupervise <id>            # after review
```

## Guarantees and limits

- For a benign agent in the modelled class, the probability of *ever* being held by the
  e-rule is at most α, regardless of trajectory length (Ville's inequality).
- An adversary in the hypothesis class realises a non-goal without triggering supervision with
  probability at most P_benign(realise)/(α·π_adv) (change of measure).
- A single disguised deviation with no prior signal is caught only by layers 2 and 3. The
  probabilistic layer buys lead time once there is *any* signal: a denied attempt, a probe, a
  mention. The paper in `paper/` has the proofs, the simulation study and live-model results.

## Measured

Simulation (1000 trajectories per population, scripted adversaries the model was not fitted
to): the Ville bound holds at every α tested; a persistent launderer that rephrases and retries
realises its non-goal in about 17% of trajectories under content rules alone and about 8% under
the intent layer; benign populations are held in at most a few percent of trajectories, and the
canonical benign plan is never held. Live gpt-5 agents: across benign, prompt-injected,
indirectly injected and compromised conditions, the permission-only gate let the adversarial
conditions realise a non-goal in most runs; the intent layer realised none and held no benign
run. Exact numbers, figures and the proofs are in `paper/main.pdf`; regenerate with
`make sim figures paper`.
