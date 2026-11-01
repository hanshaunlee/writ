"""Micro-benchmark: cost of the intent assessment on the hot path (model observe + assess)."""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import research.sim as S  # noqa: E402
from writ.intent.abstract import AbstractAction, Observation  # noqa: E402


def main() -> None:
    model = S.build_model()
    plan = S.scripted_job(model)
    # warm caches as the gate would after the first request on a template
    st = model.initial_state()
    for a in plan:
        st = model.observe(st, Observation(a, True))
        model.assess(st, a)
    times = []
    for _ in range(200):
        st = model.initial_state()
        for a in plan:
            t0 = time.perf_counter()
            st = model.observe(st, Observation(a, True))
            model.assess(st, a)
            times.append((time.perf_counter() - t0) * 1000)
    cold = []
    for _ in range(20):
        m2 = S.build_model()
        st = m2.initial_state()
        a = AbstractAction("crm.get_customer")
        t0 = time.perf_counter()
        st = m2.observe(st, Observation(a, True))
        m2.assess(st, a)
        cold.append((time.perf_counter() - t0) * 1000)
    out = {
        "warm_median_ms": statistics.median(times),
        "warm_p95_ms": sorted(times)[int(0.95 * len(times))],
        "cold_median_ms": statistics.median(cold),
        "n": len(times),
    }
    res = Path(__file__).resolve().parents[1] / "paper/results/bench.json"
    res.write_text(json.dumps(out, indent=1))
    print(json.dumps(out))


if __name__ == "__main__":
    main()
