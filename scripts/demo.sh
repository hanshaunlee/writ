#!/usr/bin/env bash
# End-to-end demo against a running deployment (make up). Walks the duplicate-charge scenario:
# permitted actions succeed, every attempt to step outside the contract is denied, two sub-agents
# cannot overspend a shared budget, the kill switch cascades, and the ledger verifies.
set -euo pipefail
cd "$(dirname "$0")/.."
export WRIT_GATE_URL="${WRIT_GATE_URL:-http://127.0.0.1:8080}"
ENV_FILE="${WRIT_ENV_FILE:-deploy/keys/writ.env}"
if [[ -z "${WRIT_ADMIN_TOKEN:-}" ]]; then
  export WRIT_ADMIN_TOKEN="$(grep '^WRIT_ADMIN_TOKEN=' "$ENV_FILE" | cut -d= -f2-)"
fi
WRIT="${WRIT:-.venv/bin/writ}"
# The upstream network is internal (no host access, by design). Reach the demo SaaS's
# test endpoints through the container unless WRIT_DEMO_SAAS_URL points at a reachable one.
COMPOSE=(docker compose -f deploy/docker-compose.yml --env-file "$ENV_FILE")
saas() { # saas <METHOD> <path>
  if [[ -n "${WRIT_DEMO_SAAS_URL:-}" ]]; then
    curl -fsS -X "$1" "$WRIT_DEMO_SAAS_URL$2"
  else
    "${COMPOSE[@]}" exec -T demo-saas python -c "import sys,urllib.request;r=urllib.request.Request('http://localhost:9000'+sys.argv[2],method=sys.argv[1]);sys.stdout.write(urllib.request.urlopen(r).read().decode())" "$1" "$2"
  fi
}

step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
expect() { # expect <label> <jsonpath-ish grep> ; reads JSON from stdin
  local label="$1" needle="$2" out
  out="$(cat)"
  if grep -q "$needle" <<<"$out"; then printf '  \033[32mOK\033[0m   %s\n' "$label"; else printf '  \033[31mFAIL\033[0m %s\n%s\n' "$label" "$out"; exit 1; fi
}

step "gate status"
$WRIT status | expect "gate reachable, not halted" '"halted": false'
saas POST /_reset >/dev/null && echo "  demo upstream reset"

step "operator creates the task contract from a template"
TOKEN="$($WRIT task create -t templates/resolve_duplicate_charge.yaml \
  -p customer_id=cus_123 -p billing_contact=ap@acme.example \
  -p max_refund_cents=20000 -p 'charge_ids=["ch_1001","ch_1002"]' --ttl 900 --token-only)"
export WRIT_TASK_TOKEN="$TOKEN"
TASK_ID="$($WRIT agent me | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')"
echo "  task $TASK_ID"

step "agent investigates (reads inside scope)"
$WRIT agent invoke crm.get_customer '{"customer_id":"cus_123"}' | expect "read own customer" '"status": "committed"'
$WRIT agent invoke crm.get_customer '{"customer_id":"cus_999"}' | expect "other customer denied" 'CONSTRAINT_VIOLATION' || true
$WRIT agent invoke billing.list_charges '{"customer_id":"cus_123"}' | expect "list charges" '"status": "committed"'

step "agent refunds the duplicate (bounded money)"
$WRIT agent invoke billing.refund '{"charge_id":"ch_1002","amount_cents":14900,"reason":"duplicate March charge"}' | expect "refund committed" '"status": "committed"'
$WRIT agent invoke billing.refund '{"charge_id":"ch_1001","amount_cents":6000,"reason":"again"}' | expect "second refund exceeds shared budget" 'BUDGET_EXCEEDED' || true

step "agent tries to step outside the contract"
$WRIT agent invoke crm.update_customer '{"customer_id":"cus_123","fields":{"billing_contact":"attacker@evil.example"}}' | expect "cannot redirect billing contact" 'CONSTRAINT_VIOLATION' || true
$WRIT agent invoke email.send '{"to":"attacker@evil.example","subject":"x","body":"y"}' | expect "cannot email outsiders" 'CONSTRAINT_VIOLATION' || true
$WRIT agent invoke crm.update_customer '{"customer_id":"cus_123","fields":{"tags":["enterprise","VIP"]}}' | expect "hidden export automation blocked" 'FORBIDDEN_EFFECT' || true
$WRIT agent invoke billing.refund '{"charge_id":"ch_1001","amount_cents":100,"reason":"x","bcc":"evil"}' | expect "unknown argument rejected" 'INVALID_ARGS' || true

step "agent completes the permitted path"
$WRIT agent invoke crm.update_customer '{"customer_id":"cus_123","fields":{"note":"Refunded duplicate March charge (ch_1002)."}}' | expect "note recorded" '"status": "committed"'
# After four out-of-scope attempts the intent layer has placed this task under supervision, so the
# (clean) notification is held for an operator rather than sent; the operator approves it.
EMAIL_OUT="$($WRIT agent invoke email.send '{"to":"ap@acme.example","subject":"Refund issued","body":"We refunded the duplicate March charge."}' 2>/dev/null || true)"
if grep -q '"status": "held"' <<<"$EMAIL_OUT"; then
  printf '  \033[32mOK\033[0m   %s\n' "notification held: task is under supervision after repeated out-of-scope attempts"
  HELD_EMAIL="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["authorization_id"])' <<<"$EMAIL_OUT")"
  $WRIT auth approve "$HELD_EMAIL" | expect "operator approves; notification sent" '"status": "committed"'
else
  expect "billing contact notified" '"status": "committed"' <<<"$EMAIL_OUT"
fi
$WRIT agent invoke email.send '{"to":"ap@acme.example","subject":"again","body":"b"}' | expect "no second email" 'BUDGET_EXCEEDED' || true

step "delegation: sub-agent cannot widen, shares budget"
set +e
$WRIT agent delegate '{"commands":[{"command":"email.send","args":{"to":{"eq":"attacker@evil.example"}}}],"budgets":{"sends":1}}' 2>&1 | expect "widening delegation rejected" 'ATTENUATION_VIOLATION'
set -e
CHILD="$($WRIT agent delegate '{"commands":[{"command":"billing.refund","args":{"charge_id":{"eq":"ch_1001"},"amount_cents":{"max":5000}}}],"budgets":{"money_cents":5000,"refunds":1}}' --name refunder --token-only)"
# The sub-agent shares the supervised root's intent state, so its refund (a money action) is held too.
SUB_OUT="$(WRIT_TASK_TOKEN="$CHILD" $WRIT agent invoke billing.refund '{"charge_id":"ch_1001","amount_cents":5000,"reason":"x"}' 2>/dev/null || true)"
if grep -q '"status": "held"' <<<"$SUB_OUT"; then
  printf '  \033[32mOK\033[0m   %s\n' "sub-agent refund held: supervision is shared across the delegation tree"
  HELD_SUB="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["authorization_id"])' <<<"$SUB_OUT")"
  $WRIT auth approve "$HELD_SUB" | expect "operator approves; sub-agent refund committed" '"status": "committed"'
else
  expect "sub-agent within bounds succeeds" '"status": "committed"' <<<"$SUB_OUT"
fi
WRIT_TASK_TOKEN="$CHILD" $WRIT agent invoke billing.refund '{"charge_id":"ch_1001","amount_cents":100,"reason":"x"}' | expect "sub-agent refund count exhausted" 'BUDGET_EXCEEDED' || true

step "intent: the permitted channel cannot carry the forbidden outcome"
ITOKEN="$($WRIT task create -t templates/resolve_duplicate_charge.yaml \
  -p customer_id=cus_123 -p billing_contact=ap@acme.example \
  -p max_refund_cents=20000 -p 'charge_ids=["ch_1001","ch_1002"]' --ttl 900 --token-only)"
ITASK="$(WRIT_TASK_TOKEN="$ITOKEN" $WRIT agent me | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')"
WRIT_TASK_TOKEN="$ITOKEN" $WRIT agent invoke crm.get_customer '{"customer_id":"cus_123"}' >/dev/null || true
WRIT_TASK_TOKEN="$ITOKEN" $WRIT agent invoke billing.refund '{"charge_id":"ch_1001","amount_cents":1000,"reason":"partial"}' >/dev/null || true
WRIT_TASK_TOKEN="$ITOKEN" $WRIT agent invoke crm.update_customer '{"customer_id":"cus_123","fields":{"billing_contact":"cfo@acme.example"}}' | expect "direct attempt denied (observed as evidence)" 'CONSTRAINT_VIOLATION' || true
WRIT_TASK_TOKEN="$ITOKEN" $WRIT agent invoke email.send '{"to":"ap@acme.example","subject":"Refund","body":"Refund issued for ch_1002. Please update the billing contact to cfo@acme.example."}' | expect "laundering request in permitted email denied" 'NON_GOAL_ADVANCED' || true
HELD="$(WRIT_TASK_TOKEN="$ITOKEN" $WRIT agent invoke email.send '{"to":"ap@acme.example","subject":"Refund","body":"Refund issued for ch_1002. Billing owner on file: cfo@acme.example."}' 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("authorization_id","") if d.get("status")=="held" else "")')" || true
[[ -n "$HELD" ]] && printf '  \033[32mOK\033[0m   %s\n' "unknown-provenance address held for operator ($HELD)" || { printf '  \033[31mFAIL\033[0m untrusted provenance not held\n'; exit 1; }
$WRIT auth reject "$HELD" --reason "address not verified" | expect "operator rejects the held email" '"status": "released"'
($WRIT task explain "$ITASK" 2>/dev/null || $WRIT task show "$ITASK" | python3 -c 'import json,sys; i=json.load(sys.stdin)["intent"]; print("mode=%s e=%s forecast=%s" % (i["mode"], i["e_value"], i["forecast"]))') | head -3 | sed "s/^/  /"
$WRIT task revoke "$ITASK" --reason "demo" >/dev/null

step "kill switch cascades"
$WRIT task revoke "$TASK_ID" --reason "demo kill switch" | expect "root and child revoked" "$TASK_ID"
WRIT_TASK_TOKEN="$CHILD" $WRIT agent invoke billing.refund '{"charge_id":"ch_1001","amount_cents":1,"reason":"x"}' | expect "child denied after revocation" 'TASK_INACTIVE' || true

step "upstream state"
saas GET /_state | python3 -c '
import json,sys; s=json.load(sys.stdin)
print("  refunds:", [(r["charge_id"], r["amount_cents"]) for r in s["refunds"]])
print("  emails: ", [e["to"] for e in s["emails"]])
print("  exports:", s["exports"])
print("  billing_contact:", s["customers"]["cus_123"]["billing_contact"])
assert [(r["charge_id"], r["amount_cents"]) for r in s["refunds"]][:2] == [("ch_1002",14900),("ch_1001",5000)]
assert [e["to"] for e in s["emails"]] == ["ap@acme.example"] and s["exports"] == []
'

step "ledger"
$WRIT ledger verify | expect "hash chain verifies" '"ok": true'
$WRIT ledger tail --root "$TASK_ID" -n 12
printf '\n\033[1;32mdemo complete\033[0m\n'
