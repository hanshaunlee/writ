.PHONY: install test lint keys up down logs demo build clean sim bench figures paper lock audit

PY := .venv/bin/python
WRIT := .venv/bin/writ

install:
	uv venv -q --python 3.13 || true
	uv sync --frozen --all-extras

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check src tests examples
	$(PY) -m ruff format --check src tests examples

keys:
	@test -f deploy/keys/writ.env && echo "deploy/keys/writ.env exists; not overwriting" || $(WRIT) keygen --out deploy/keys

build: keys
	docker compose -f deploy/docker-compose.yml --env-file deploy/keys/writ.env build

up: keys
	docker compose -f deploy/docker-compose.yml --env-file deploy/keys/writ.env up -d --build --wait

down:
	docker compose -f deploy/docker-compose.yml --env-file deploy/keys/writ.env down -v

logs:
	docker compose -f deploy/docker-compose.yml --env-file deploy/keys/writ.env logs -f

check-isolation:
	scripts/check-isolation.sh

demo:
	WRIT_GATE_URL=http://127.0.0.1:8080 scripts/demo.sh

clean:
	rm -rf .venv .pytest_cache .ruff_cache dist

sim:
	$(PY) research/sim.py --n 1000 --out paper/results/sim.json

bench:
	$(PY) research/bench.py

figures:
	$(PY) research/plots.py

paper: figures
	cd paper && tectonic main.tex

lock:
	uv lock

audit:
	uv export --frozen --no-dev --no-emit-project --no-hashes -o /tmp/writ-req.txt && $(PY) -m pip_audit -r /tmp/writ-req.txt
