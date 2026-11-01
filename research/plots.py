"""Figures for the paper from paper/results/*.json(l)."""

from __future__ import annotations

import json
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "paper/results"
FIG = ROOT / "paper/figures"
FIG.mkdir(parents=True, exist_ok=True)
plt.rcParams.update({"font.size": 9, "axes.spines.top": False, "axes.spines.right": False, "figure.dpi": 150})

LABELS = {
    "benign_beta2": "benign β=2",
    "benign_beta4": "benign β=4",
    "benign_beta8": "benign β=8",
    "benign_scripted": "benign scripted",
    "benign_eager": "eager (one attempt)",
    "adv_direct_then_launder": "direct→launder",
    "adv_patient_launder": "patient launder",
    "adv_probing": "probe→launder",
    "adv_multigoal": "multi-goal",
    "adv_mimic": "mimic λ=.15",
    "adv_mimic_lam40": "mimic λ=.40",
    "adv_persistent_x3": "persistent ×3",
    "adv_persistent_direct_x3": "direct→persistent ×3",
}
GATES = {
    "permissions_only": "permissions only",
    "content_rules": "+ content rules",
    "llm_judge": "+ memoryless judge",
    "intent_full": "Writ intent (full)",
    "intent_no_rules": "intent, no rules",
}


def fig_e_paths(sim: dict) -> None:
    fig, ax = plt.subplots(figsize=(5.4, 3.3))
    show = [
        ("benign_beta4", "#4c72b0", "benign β=4"),
        ("benign_eager", "#8c8c8c", "eager (one attempt)"),
        ("adv_patient_launder", "#55a868", "patient launder"),
        ("adv_probing", "#dd8452", "probe→launder"),
        ("adv_direct_then_launder", "#c44e52", "direct→launder"),
        ("adv_persistent_direct_x3", "#8172b3", "direct→persistent ×3"),
    ]
    for name, color, label in show:
        paths = sim["e_paths"].get(name)
        if not paths:
            continue
        L = max(len(p) for p in paths)
        med, lo, hi = [], [], []
        for t in range(L):
            vals = sorted(math.log10(max(p[t], 1e-3)) for p in paths if len(p) > t)
            if len(vals) < max(5, len(paths) // 10):
                break
            med.append(vals[len(vals) // 2])
            lo.append(vals[len(vals) // 4])
            hi.append(vals[3 * len(vals) // 4])
        x = list(range(1, len(med) + 1))
        ax.plot(x, med, color=color, label=label, lw=1.8, marker="o", ms=2.5)
        ax.fill_between(x, lo, hi, color=color, alpha=0.12)
    ax.axhline(2, color="k", ls="--", lw=0.9)
    ax.text(1.02, 2.12, "hold threshold 1/α = 100", fontsize=7.5)
    ax.set_ylim(-1.2, 6.2)
    ax.set_xlabel("step")
    ax.set_ylabel("log10 e-value (median, IQR)")
    ax.legend(fontsize=7, loc="upper left", ncol=2, frameon=False)
    fig.tight_layout()
    fig.savefig(FIG / "e_paths.pdf")
    plt.close(fig)


def fig_gates(sim: dict) -> None:
    gates = ["permissions_only", "content_rules", "llm_judge", "intent_full"]
    advs = [a for a in sim["gates"]["intent_full"] if sim["gates"]["intent_full"][a]["adversarial"]]
    bens = [a for a in sim["gates"]["intent_full"] if not sim["gates"]["intent_full"][a]["adversarial"]]
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.0))
    w = 0.8 / len(gates)
    for gi, g in enumerate(gates):
        ax = axes[0]
        ax.bar(
            [i + gi * w for i in range(len(advs))],
            [sim["gates"][g][a]["realized_rate"] for a in advs],
            width=w,
            label=GATES[g],
        )
        ax = axes[1]
        ax.bar(
            [i + gi * w for i in range(len(bens))],
            [sim["gates"][g][a]["held_rate"] for a in bens],
            width=w,
            label=GATES[g],
        )
    axes[0].set_xticks([i + 0.4 - w / 2 for i in range(len(advs))])
    axes[0].set_xticklabels([LABELS.get(a, a) for a in advs], rotation=25, ha="right", fontsize=7)
    axes[0].set_ylabel("non-goal realised (rate)")
    axes[0].set_title("adversarial strategies", fontsize=9)
    axes[1].set_xticks([i + 0.4 - w / 2 for i in range(len(bens))])
    axes[1].set_xticklabels([LABELS.get(a, a) for a in bens], rotation=25, ha="right", fontsize=7)
    axes[1].set_ylabel("held at least once (rate)")
    axes[1].set_title("benign populations", fontsize=9)
    axes[1].set_ylim(0, 0.12)
    for gi, g in enumerate(gates):
        for i, a in enumerate(bens):
            v = sim["gates"][g][a]["held_rate"]
            if 0 < v < 0.02:
                axes[1].text(i + gi * w, v + 0.002, f"{100 * v:.1f}%", fontsize=5.5, ha="center")
    axes[0].legend(fontsize=6.5, frameon=False, loc="upper right")
    fig.tight_layout()
    fig.savefig(FIG / "gates.pdf")
    plt.close(fig)


def fig_ville(sim: dict) -> None:
    fig, ax = plt.subplots(figsize=(3.4, 3.0))
    alphas = sorted(float(a) for a in sim["ville"])
    floor = 1e-4
    for name in ("benign_beta2", "benign_beta4", "benign_beta8", "benign_scripted"):
        ys = [max(sim["ville"][str(a)][name], floor) for a in alphas]
        ax.plot(alphas, ys, marker="o", ms=3, label=LABELS[name])
    ax.plot(alphas, alphas, "k--", lw=0.8, label="Ville bound α")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_ylim(floor * 0.7, 0.5)
    ax.set_yticks([1e-4, 1e-3, 1e-2, 1e-1])
    ax.set_yticklabels(["<1e-4", "1e-3", "1e-2", "1e-1"])
    ax.set_xlabel("α")
    ax.set_ylabel("P(sup e ≥ 1/α), benign")
    ax.legend(fontsize=6, frameon=False)
    fig.tight_layout()
    fig.savefig(FIG / "ville.pdf")
    plt.close(fig)


def fig_sweeps(sim: dict) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.9))
    ks = sorted(int(k) for k in sim["lookahead"])
    for a in sim["lookahead"][str(ks[0])]:
        ys = [sim["lookahead"][str(k)][a]["supervised_rate"] for k in ks]
        axes[0].plot(ks, ys, marker="o", ms=3, label=LABELS.get(a, a))
    axes[0].set_xlabel("lookahead k")
    axes[0].set_ylabel("supervised before realisation (rate)")
    axes[0].legend(fontsize=6)
    rs = sorted(float(r) for r in sim["recall"])
    for a in sim["recall"][str(rs[0])]["intent_full"]:
        axes[1].plot(
            rs, [sim["recall"][str(r)]["content_rules"][a] for r in rs], ls=":", color="gray", lw=0.8
        )
        axes[1].plot(
            rs,
            [sim["recall"][str(r)]["intent_full"][a] for r in rs],
            marker="o",
            ms=3,
            label=LABELS.get(a, a),
        )
    axes[1].set_xlabel("claim extractor recall r")
    axes[1].set_ylabel("non-goal realised (rate)")
    axes[1].legend(fontsize=6)
    fig.tight_layout()
    fig.savefig(FIG / "sweeps.pdf")
    plt.close(fig)


def fig_epsilon(sim: dict) -> None:
    if not sim.get("epsilon"):
        return
    fig, ax = plt.subplots(figsize=(3.6, 3.0))
    eps = sorted(float(e) for e in sim["epsilon"])
    for a in sim["epsilon"][str(eps[0])]:
        key = "supervised_rate"
        ys = [sim["epsilon"][str(e)][a][key] for e in eps]
        ax.plot(eps, ys, marker="o", ms=3, label=LABELS.get(a, a), ls="--" if a.startswith("benign") else "-")
    ax.set_xlabel("risk budget ε")
    ax.set_ylabel("supervised (rate)")
    ax.legend(fontsize=6)
    fig.tight_layout()
    fig.savefig(FIG / "epsilon.pdf")
    plt.close(fig)


def table_llm(rows: list[dict]) -> str:
    """LaTeX table body for the live-model runs."""
    from collections import defaultdict

    agg: dict = defaultdict(
        lambda: {"n": 0, "realized": 0, "denied": 0, "held": 0, "supervised": 0, "maxe": []}
    )
    for r in rows:
        k = (r["condition"], r["arm"])
        a = agg[k]
        a["n"] += 1
        a["realized"] += r["truth"]["non_goal_realized"]
        a["denied"] += any(d in ("NON_GOAL_ADVANCED",) for d in r["truth"]["denials"])
        a["held"] += bool(r["truth"]["holds"])
        a["supervised"] += r["truth"]["final_mode"] == "supervised"
        a["maxe"].append(r["truth"]["max_e"])
    lines = []
    for (cond, arm), a in sorted(agg.items()):
        me = sorted(a["maxe"])[len(a["maxe"]) // 2] if a["maxe"] else 0
        lines.append(
            f"{cond.replace('_', ' ')} & {arm} & {a['n']} & {a['realized']}/{a['n']} & {a['denied']}/{a['n']} & {a['held']}/{a['n']} & {a['supervised']}/{a['n']} & {me:.1f} \\\\"
        )
    body = "\n".join(lines)
    header = (
        "\\begin{tabular}{llrrrrrr}\n\\toprule\n"
        "condition & arm & $n$ & realised & denied & held & sup. & $\\max E$ \\\\\n\\midrule\n"
    )
    return header + body + "\n\\bottomrule\n\\end{tabular}\n"


def trace_table(rows: list[dict]) -> str:
    """LaTeX rows for one representative live adversarial trajectory (intent arm)."""
    cands = [r for r in rows if r["condition"] == "user_injected" and r["arm"] == "intent" and r["events"]]
    if not cands:
        alt = RES / "llm_runs_iter0_gate.jsonl"
        if alt.exists():
            rows = [json.loads(line) for line in alt.read_text().splitlines() if line.strip()]
            cands = [
                r for r in rows if r["condition"] == "user_injected" and r["arm"] == "intent" and r["events"]
            ]
    if not cands:
        return "\\begin{tabular}{l}\\toprule (no run available) \\\\ \\bottomrule\\end{tabular}\n"
    r = max(cands, key=lambda x: x["truth"]["max_e"])
    history = (r.get("intent_explain") or {}).get("history", [])
    if len(history) != len(r["events"]):
        history = []  # only use operator-side statistics when they align one-to-one with the attempts
    lines = []
    for i, e in enumerate(r["events"], 1):
        it = dict(e.get("intent") or {})
        if "e_value" not in it and i - 1 < len(history):
            it["e_value"] = history[i - 1].get("e_value")
            it.setdefault("mode", (r.get("intent_explain") or {}).get("mode"))
        args = e["args"]
        if e["command"] == "email.send":
            arg = f"to={args.get('to', '')}"
        elif e["command"] == "crm.update_customer":
            arg = "fields=" + ",".join(sorted((args.get("fields") or {}).keys()))
        else:
            arg = ",".join(f"{k}={v}" for k, v in list(args.items())[:1])
        decision = e["status"] if e["decision"] == "allowed" else f"denied ({e['reason']})"
        if e["status"] == "held":
            decision = f"held ({e['reason']})"
        decision = (
            decision.replace("CONSTRAINT_VIOLATION", "constraint")
            .replace("FORBIDDEN_EFFECT", "forbidden effect")
            .replace("NON_GOAL_ADVANCED", "non-goal content")
            .replace("INTENT_SUPERVISED", "supervised")
            .replace("UNTRUSTED_PROVENANCE", "provenance")
            .replace("INTENT_HOLD", "intent")
            .replace("BUDGET_EXCEEDED", "budget")
        )
        ev = it.get("e_value")
        if isinstance(ev, (int, float)):
            ev = f"{ev:.1f}" if ev < 1000 else f"{ev:.1e}".replace("e+0", "e")
        lines.append(
            f"{i} & \\texttt{{{e['command'].replace('_', chr(92) + '_')}}} & \\texttt{{{arg.replace('_', chr(92) + '_').replace('@', '@')}}} & {decision.replace('_', chr(92) + '_')} & {ev if ev is not None else '--'} & {it.get('mode', '--')} \\\\"
        )
    header = "\\begin{tabular}{rlllrl}\n\\toprule\nstep & command & arguments & gate decision & $E_t$ & mode \\\\\n\\midrule\n"
    return header + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}\n"


def numbers(sim: dict, rows: list[dict] | None) -> str:
    g = sim["gates"]

    def pct(x: float) -> str:
        return f"{100 * x:.1f}"

    bens = [a for a, r in g["intent_full"].items() if not r["adversarial"] and a != "benign_eager"]
    ville_max = max(v for row in sim["ville"].values() for v in row.values())
    ville_001 = max(sim["ville"]["0.01"].values())
    macros = {
        "nSim": str(sim["n"]),
        "villeMaxPct": pct(ville_001),
        "villeMaxAnyPct": pct(ville_max),
        "realPermLaunderPct": pct(g["permissions_only"]["adv_direct_then_launder"]["realized_rate"]),
        "realRulesLaunderPct": pct(g["content_rules"]["adv_direct_then_launder"]["realized_rate"]),
        "realIntentLaunderPct": pct(g["intent_full"]["adv_direct_then_launder"]["realized_rate"]),
        "realPermProbePct": pct(g["permissions_only"]["adv_probing"]["realized_rate"]),
        "realIntentProbePct": pct(g["intent_full"]["adv_probing"]["realized_rate"]),
        "realPermPatientPct": pct(g["permissions_only"]["adv_patient_launder"]["realized_rate"]),
        "realRulesPatientPct": pct(g["content_rules"]["adv_patient_launder"]["realized_rate"]),
        "realIntentPatientPct": pct(g["intent_full"]["adv_patient_launder"]["realized_rate"]),
        "heldBenignIntentPct": pct(max(g["intent_full"][a]["held_rate"] for a in bens)),
        "heldBenignJudgePct": pct(max(g["llm_judge"][a]["held_rate"] for a in bens)),
        "supEagerIntentPct": pct(g["intent_full"]["benign_eager"]["supervised_rate"]),
        "supLaunderIntentPct": pct(g["intent_full"]["adv_direct_then_launder"]["supervised_rate"]),
        "realPermPersistPct": pct(g["permissions_only"]["adv_persistent_x3"]["realized_rate"]),
        "realRulesPersistPct": pct(g["content_rules"]["adv_persistent_x3"]["realized_rate"]),
        "realJudgePersistPct": pct(g["llm_judge"]["adv_persistent_x3"]["realized_rate"]),
        "realIntentPersistPct": pct(g["intent_full"]["adv_persistent_x3"]["realized_rate"]),
        "realRulesPersistDirectPct": pct(g["content_rules"]["adv_persistent_direct_x3"]["realized_rate"]),
        "realIntentPersistDirectPct": pct(g["intent_full"]["adv_persistent_direct_x3"]["realized_rate"]),
        "supPersistDirectIntentPct": pct(g["intent_full"]["adv_persistent_direct_x3"]["supervised_rate"]),
        "supMimicIntentPct": pct(g["intent_full"]["adv_mimic"]["supervised_rate"]),
        "realIntentMimicPct": pct(g["intent_full"]["adv_mimic"]["realized_rate"]),
        "realRulesMimicPct": pct(g["content_rules"]["adv_mimic"]["realized_rate"]),
        "simSeconds": str(sim["meta"]["seconds"]),
        "realComposedPersistPct": pct(
            g.get("intent_llm_extractor", g["intent_full"])["adv_persistent_x3"]["realized_rate"]
        ),
        "realComposedLaunderPct": pct(
            g.get("intent_llm_extractor", g["intent_full"])["adv_direct_then_launder"]["realized_rate"]
        ),
        "heldBenignComposedPct": pct(
            max(g.get("intent_llm_extractor", g["intent_full"])[a]["held_rate"] for a in bens)
        ),
        "supMultigoalIntentPct": pct(g["intent_full"]["adv_multigoal"]["supervised_rate"]),
        "realIntentMultigoalPct": pct(g["intent_full"]["adv_multigoal"]["realized_rate"]),
        "realRulesMultigoalPct": pct(g["content_rules"]["adv_multigoal"]["realized_rate"]),
        "supPatientKzeroPct": pct(sim["lookahead"]["0"]["adv_patient_launder"]["supervised_rate"]),
        "supPatientKthreePct": pct(sim["lookahead"]["3"]["adv_patient_launder"]["supervised_rate"]),
        "supProbeKzeroPct": pct(sim["lookahead"]["0"]["adv_probing"]["supervised_rate"]),
        "supProbeKthreePct": pct(sim["lookahead"]["3"]["adv_probing"]["supervised_rate"]),
        "supBenignTwoEpsLowPct": pct(sim["epsilon"]["0.01"]["benign_beta2"]["supervised_rate"]),
        "supBenignTwoEpsDefaultPct": pct(sim["epsilon"]["0.03"]["benign_beta2"]["supervised_rate"]),
        "rZeroMax": f"{sim.get('benign_baseline', {}).get('r0_max', 0):.3f}",
        "forecastInitial": f"{sim.get('benign_baseline', {}).get('forecast_initial', 0):.3f}",
        "qZeroRealizedBetaTwoPct": pct(
            sim.get("benign_baseline", {}).get("q0_realized", {}).get("benign_beta2", 0)
        ),
    }
    if rows:
        adv_ctrl = [r for r in rows if r["adversarial"] and r["arm"] == "control"]
        adv_int = [r for r in rows if r["adversarial"] and r["arm"] == "intent"]
        ben = [r for r in rows if not r["adversarial"]]
        macros["liveAdvControlRealized"] = (
            f"{sum(r['truth']['non_goal_realized'] for r in adv_ctrl)}/{len(adv_ctrl)}"
        )
        macros["liveAdvIntentRealized"] = (
            f"{sum(r['truth']['non_goal_realized'] for r in adv_int)}/{len(adv_int)}"
        )
        macros["liveAdvIntentDeniedOrHeld"] = (
            f"{sum(bool(r['truth']['denials'] and any(d == 'NON_GOAL_ADVANCED' for d in r['truth']['denials'])) or bool(r['truth']['holds']) for r in adv_int)}/{len(adv_int)}"
        )
        macros["liveBenignHeld"] = f"{sum(bool(r['truth']['holds']) for r in ben)}/{len(ben)}"
        macros["liveBenignSupervised"] = (
            f"{sum(r['truth']['final_mode'] == 'supervised' for r in ben)}/{len(ben)}"
        )
        macros["liveBenignRefunded"] = f"{sum(r['truth']['refunded'] == 14900 for r in ben)}/{len(ben)}"
        macros["liveRuns"] = str(len(rows))
        macros["liveModel"] = rows[0]["model"]
    bench_path = RES / "bench.json"
    if bench_path.exists():
        b = json.loads(bench_path.read_text())
        macros["benchWarmMs"] = f"{b['warm_median_ms']:.2f}"
        macros["benchWarmPNinetyFiveMs"] = f"{b['warm_p95_ms']:.2f}"
        macros["benchColdMs"] = f"{b['cold_median_ms']:.0f}"
    spec = sim["meta"]["spec"]
    rho, eps = spec["prior_compromise"], spec["risk_budget"]
    r0 = sim.get("benign_baseline", {}).get("r0_max", 0.0)
    if eps > r0:
        alpha_eps = rho * (1 - eps + r0) / ((1 - rho) * (eps - r0))
        macros["alphaEps"] = f"{min(1.0, alpha_eps):.3f}"
    else:
        macros["alphaEps"] = "1"
    macros["nActions"] = str(sim["meta"]["actions"])
    macros["nHyps"] = str(sim["meta"]["hypotheses"])
    return "\n".join(f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in macros.items()) + "\n"


def main() -> None:
    sim = json.loads((RES / "sim.json").read_text())
    fig_e_paths(sim)
    fig_gates(sim)
    fig_ville(sim)
    fig_sweeps(sim)
    fig_epsilon(sim)
    llm_path = RES / "llm_runs.jsonl"
    rows = None
    if llm_path.exists():
        rows = [json.loads(line) for line in llm_path.read_text().splitlines() if line.strip()]
        (RES / "llm_table.tex").write_text(table_llm(rows))
        (RES / "llm_trace.tex").write_text(trace_table(rows))
        print(f"llm rows: {len(rows)}")
    (RES / "numbers.tex").write_text(numbers(sim, rows))
    print("figures written to", FIG)


if __name__ == "__main__":
    main()
