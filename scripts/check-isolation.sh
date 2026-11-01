#!/usr/bin/env bash
# Verifies the containment properties of the compose deployment from the agent's position:
# the agent container can reach only the gate, and holds no secret other than its task token.
set -euo pipefail
cd "$(dirname "$0")/.."
ENV_FILE="${WRIT_ENV_FILE:-deploy/keys/writ.env}"
COMPOSE=(docker compose -f deploy/docker-compose.yml --env-file "$ENV_FILE" --profile agent)
"${COMPOSE[@]}" up -d agent >/dev/null
"${COMPOSE[@]}" exec -T agent python - <<'PY'
import os, socket, sys
fail = False
def reach(host, port):
    try:
        socket.create_connection((host, port), timeout=2).close(); return True
    except OSError:
        return False
for host, port, want in (("gate", 8080, True), ("executor", 8081, False), ("demo-saas", 9000, False)):
    got = reach(host, port)
    ok = got == want
    fail |= not ok
    print(f"  {'OK  ' if ok else 'FAIL'} {host}:{port} {'reachable' if got else 'unreachable'} (expected {'reachable' if want else 'unreachable'})")
secrets = [k for k in os.environ if k.startswith("WRIT_") and k not in ("WRIT_GATE_URL", "WRIT_TASK_TOKEN", "WRIT_COMMANDS_PATH")]
ok = not secrets
fail |= not ok
print(f"  {'OK  ' if ok else 'FAIL'} agent environment holds no gate/executor/upstream secrets {secrets or ''}")
sys.exit(1 if fail else 0)
PY
echo "isolation check passed"
