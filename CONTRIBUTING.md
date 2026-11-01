# Contributing to Writ

Writ is a security boundary. Changes are judged first on whether they keep the properties
in `SECURITY.md` true, then on everything else.

## Ground rules

- **Fail closed.** Anything the gate cannot evaluate is denied. A new branch that returns
  "allowed" by default is a bug, even if the tests pass.
- **Policy lives in the gate.** The executor verifies and performs; it does not decide. The
  agent-facing surface (MCP, CLI, client) is thin.
- **Budgets move once.** Any new path that settles an authorization must go through
  `GateService._settle` with an explicit `expected` status set.
- **Agents learn decisions, not statistics.** Do not add detector internals to anything
  returned under a task token. Operator views and the ledger are the place for them.
- **Every denial is evidence.** If you add a denial reason that reflects agent behaviour,
  consider whether it belongs in `OBSERVABLE_DENIALS`.

## Development

```bash
make install      # uv venv + editable install with dev extras
make test         # in-process suite (gate, executor, demo SaaS, no network)
make lint         # ruff check + format --check
make up && make demo && make check-isolation   # docker compose end to end
```

Tests run the real gate, executor and demo SaaS wired through ASGI test clients, so a
scenario test is also an integration test. Add a test for every behavioural change:

- `tests/test_grant.py`: constraint evaluation and attenuation.
- `tests/test_scenario.py`, `tests/test_delegation.py`, `tests/test_control.py`: the
  contract from the agent's and operator's point of view.
- `tests/test_integrity.py`, `tests/test_hardening.py`: replay, tampering, receipts,
  settlement, sweeps, limits, concurrency.
- `tests/test_intent.py`: the intent layer.

## Adding an integration

1. Implement an `Adapter` (`src/writ/executor/adapters/base.py`): `predict`, `execute`
   (idempotent by key), `reconcile`, `config_version`. `config_version` must change whenever
   anything your predictions depend on changes.
2. Register it in `src/writ/executor/main.py`.
3. Add commands to `config/commands.yaml` with a strict JSON Schema
   (`additionalProperties: false` is applied automatically) and budget charges.
4. Write a template in `templates/` and a scenario test.

## Dependency changes

`uv.lock` is the source of truth. After editing `pyproject.toml`, run `uv lock` and commit
the lockfile. CI installs with `--frozen`.

## Releasing

1. Update `CHANGELOG.md` and bump `version` in `pyproject.toml` and `src/writ/__init__.py`.
2. `make test && make lint`, then the compose end-to-end run.
3. Tag `vX.Y.Z`.

## Security issues

Do not open a public issue. See the Reporting section of `SECURITY.md`.
