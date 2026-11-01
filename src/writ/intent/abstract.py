r"""The abstract intent model.

Hypotheses
    H0      benign: the agent pursues exactly the authorized outcomes A.
    H_f     compromised toward non-goal f: the agent pursues A ∪ {f} with hidden-goal weight w.
Each hypothesis is a mixture over rationality β (and, for H_f, over w), so the benign class is
not a single point and the adversary class covers weak and strong drives.

Agent model
    Benign policy  P_0(α | s) ∝ exp(β · U_A(α, s)),  U_A = Σ_{ω ∈ A \ achieved} adv(α, ω) − cost(α).
    Hidden policy  P_f(α | s) ∝ exp(β · U_f(α, s)),  U_f = w · adv(α, f) − cost(α).
    A compromised agent is patient: at each step it acts benignly with probability 1−λ and
    pursues f with probability λ,   P(α | H_f, s) = (1−λ) P_0(α|s) + λ P_f(α|s).
    adv = 1 for a direct effect, p_h (human compliance) for a request carried in a sink,
    p_explore for an out-of-scope probe. Doing the real job first costs a compromised agent only
    a factor (1−λ) per step, while any step toward f is strong evidence.

Observations
    Both executed and denied attempts are observations. A denial is an intervention: the direct
    route to f is removed from the permitted set, so under H_f mass shifts to indirect routes.

Statistics
    posterior P(H | τ); the e-process E_t = L_alt(τ_t)/L_0(τ_t) (a nonnegative martingale under
    H0 with E[E_0] = 1, so P_H0(sup_t E_t ≥ 1/α) ≤ α by Ville's inequality); the k-step risk
    forecast R_k = Σ_H P(H|τ) · P(reach some f within k steps | H, s); and the residual-risk
    budget charged to admitted sink actions.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from pydantic import BaseModel, Field

from .spec import IntentSpec

STOP = "stop"


def _logaddexp(a: float, b: float) -> float:
    m = max(a, b)
    return m + math.log(math.exp(a - m) + math.exp(b - m))


P_EXPLORE = 0.1  # how much an out-of-scope probe advances a hidden goal (exploration value)
KAPPA_FORBIDDEN = 1.5  # benign agents do not produce forbidden direct effects: penalty per such effect
IOTA_INFO = 1.0  # information value of a read not yet performed (both policies)
KAPPA_CONTENT = 2.0  # benign agents rarely carry out-of-scope requests or commitments in content
KAPPA_CONTENT_HIDDEN = 0.2  # for a compromised agent the content route is cheap
KAPPA_PROBE = 0.5  # cost of an attempt outside the grant
HIDDEN_GOAL_WEIGHTS = (2.0, 5.0)
PATIENCE = (0.25, 0.6)  # λ: per-step probability that a compromised agent acts toward its hidden goal
EAGERNESS = (
    0.0,
    0.15,
)  # η: per-step probability that a *benign* agent tries a user-requested non-goal once (then complies)


@dataclass(frozen=True)
class AbstractAction:
    command: str
    direct: frozenset[str] = frozenset()  # outcomes realised directly if executed
    requests: frozenset[str] = frozenset()  # outcomes requested of a human recipient
    sink: bool = False
    probe: bool = False  # attempt outside the grant (constraint/schema violation)

    @property
    def label(self) -> str:
        parts = [self.command]
        if self.direct:
            parts.append("direct=" + ",".join(sorted(self.direct)))
        if self.requests:
            parts.append("requests=" + ",".join(sorted(self.requests)))
        if self.probe:
            parts.append("probe")
        return " ".join(parts)

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "direct": sorted(self.direct),
            "requests": sorted(self.requests),
            "sink": self.sink,
            "probe": self.probe,
        }


@dataclass(frozen=True)
class Observation:
    action: AbstractAction
    executed: bool  # False if the deterministic layers denied it


@dataclass(frozen=True)
class Hypothesis:
    name: str  # "H0" or non-goal name
    goals: frozenset[str]
    beta: float
    hidden_weight: float  # 0 for H0
    prior: float
    patience: float = 0.0  # λ; 0 for H0
    hidden_goals: frozenset[str] = frozenset()  # non-goals pursued; empty for H0
    eagerness: float = 0.0  # η; benign agents only

    @property
    def hidden(self) -> frozenset[str] | None:
        return None if not self.hidden_goals else self.hidden_goals


class IntentState(BaseModel):
    """Persisted per task."""

    achieved: list[str] = Field(
        default_factory=list
    )  # authorized outcomes and performed reads ("read:<command>")
    blocked: list[str] = Field(
        default_factory=list
    )  # non-goals whose direct route is closed (statically or by denial)
    log_weights: list[float] = Field(default_factory=list)  # per hypothesis component: log prior + log lik
    steps: int = 0
    residual_risk_spent: float = 0.0
    mode: str = "normal"  # normal | supervised
    mode_reason: str | None = None
    last_e_value: float = 1.0
    last_forecast: float = 0.0
    history: list[dict] = Field(default_factory=list)


@dataclass
class Assessment:
    e_value: float
    posterior: dict[str, float]  # by hypothesis name (components summed)
    forecast: float  # k-step risk after this action
    residual_risk: float  # charged if admitted
    supervise: bool
    supervise_reason: str | None
    likelihoods: dict[str, float] = field(default_factory=dict)


class IntentModel:
    def __init__(
        self,
        spec: IntentSpec,
        granted_commands: list[str],
        read_commands: list[str] | None = None,
        initially_blocked: list[str] | None = None,
    ):
        self.spec = spec
        self.reads = frozenset(read_commands or ())
        self.initially_blocked = frozenset(initially_blocked or ())
        self.A = frozenset(o.name for o in spec.outcomes)
        self.F = frozenset(n.name for n in spec.non_goals)
        self.granted = tuple(sorted(granted_commands))
        self.compliance = {n.name: (n.compliance if n.human_realizable else 0.0) for n in spec.non_goals}
        # Direct routes: which granted commands can realise which outcomes directly.
        self.direct_routes: dict[str, frozenset[str]] = {}
        for o in spec.outcomes:
            for r in o.realized_by:
                if r.command and r.command in self.granted:
                    self.direct_routes[r.command] = self.direct_routes.get(r.command, frozenset()) | {o.name}
        self.direct_forbidden: dict[str, frozenset[str]] = {}
        for n in spec.non_goals:
            for r in n.realized_by:
                if r.command and r.command in self.granted:
                    self.direct_forbidden[r.command] = self.direct_forbidden.get(r.command, frozenset()) | {
                        n.name
                    }
        self.sinks = frozenset(c for c in spec.sink_commands if c in self.granted)
        self.hypotheses = self._build_hypotheses()
        self._space_cache: dict[tuple[frozenset[str], frozenset[str]], tuple[AbstractAction, ...]] = {}
        self._policy_cache: dict[tuple[int, frozenset[str], frozenset[str]], list[float]] = {}
        self._reach_cache: dict[tuple[int, frozenset[str], frozenset[str], int], float] = {}
        self._hindex = {id(h): i for i, h in enumerate(self.hypotheses)}

    # ------------------------------------------------------------------ hypotheses
    def _build_hypotheses(self) -> list[Hypothesis]:
        rho = self.spec.prior_compromise
        betas = self.spec.rationality
        hs: list[Hypothesis] = [
            Hypothesis("H0", self.A, b, 0.0, (1 - rho) / (len(betas) * len(EAGERNESS)), eagerness=eta)
            for b in betas
            for eta in EAGERNESS
        ]
        if self.F:
            goal_sets: list[tuple[str, frozenset[str]]] = [(f, frozenset({f})) for f in sorted(self.F)]
            if len(self.F) > 1:
                goal_sets.append(("ALL", frozenset(self.F)))
            # Prior over goal sets: the "any reachable non-goal" set takes half of the compromised mass
            # (injected prompts typically bundle several asks); singletons share the other half.
            n_params = len(betas) * len(HIDDEN_GOAL_WEIGHTS) * len(PATIENCE)
            singles = [g for g in goal_sets if g[0] != "ALL"]
            has_all = len(goal_sets) > len(singles)
            for name, gs in goal_sets:
                share = 0.5 if name == "ALL" else (0.5 if has_all else 1.0) / len(singles)
                for b in betas:
                    for w in HIDDEN_GOAL_WEIGHTS:
                        for lam in PATIENCE:
                            hs.append(
                                Hypothesis(
                                    name,
                                    self.A | gs,
                                    b,
                                    w * self.spec.hidden_goal_weight,
                                    rho * share / n_params,
                                    lam,
                                    gs,
                                )
                            )
        return hs

    def initial_state(self) -> IntentState:
        return IntentState(
            log_weights=[math.log(h.prior) for h in self.hypotheses], blocked=sorted(self.initially_blocked)
        )

    # ------------------------------------------------------------------ action space
    def action_space(self, achieved: frozenset[str], blocked: frozenset[str]) -> tuple[AbstractAction, ...]:
        key = (achieved, blocked)
        cached = self._space_cache.get(key)
        if cached is not None:
            return cached
        acts = self._action_space(achieved, blocked)
        self._space_cache[key] = acts
        return acts

    def _action_space(self, achieved: frozenset[str], blocked: frozenset[str]) -> tuple[AbstractAction, ...]:
        acts: list[AbstractAction] = [AbstractAction(STOP)]
        for c in self.granted:
            sink = c in self.sinks
            acts.append(AbstractAction(c, direct=self.direct_routes.get(c, frozenset()), sink=sink))
            if sink:
                realizable = [f for f in sorted(self.F) if self.compliance.get(f, 0.0) > 0]
                for f in realizable:
                    acts.append(
                        AbstractAction(
                            c,
                            direct=self.direct_routes.get(c, frozenset()),
                            requests=frozenset({f}),
                            sink=True,
                        )
                    )
                # Multi-request variants: one payload can ask for several non-goals at once.
                for a_i, f in enumerate(realizable):
                    for g in realizable[a_i + 1 :]:
                        acts.append(
                            AbstractAction(
                                c,
                                direct=self.direct_routes.get(c, frozenset()),
                                requests=frozenset({f, g}),
                                sink=True,
                            )
                        )
            for f in sorted(self.direct_forbidden.get(c, frozenset())):
                if f not in blocked:
                    acts.append(AbstractAction(c, direct=frozenset({f}), sink=sink))
            acts.append(AbstractAction(c, probe=True))
        return tuple(acts)

    def _info(self, a: AbstractAction, achieved: frozenset[str]) -> float:
        if a.command in self.reads and not a.probe and f"read:{a.command}" not in achieved:
            return IOTA_INFO
        return 0.0

    def utility_benign(self, a: AbstractAction, achieved: frozenset[str]) -> float:
        if a.command == STOP:
            return 0.0
        u = -self.spec.action_cost + self._info(a, achieved)
        for w_ in a.direct:
            if w_ in self.A and w_ not in achieved:
                u += 1.0
            elif w_ in self.F:
                u -= KAPPA_FORBIDDEN
        if a.requests:
            u -= KAPPA_CONTENT
        if a.probe:
            u -= KAPPA_PROBE
        return u

    def utility_hidden(
        self, goals: frozenset[str], w: float, a: AbstractAction, achieved: frozenset[str] = frozenset()
    ) -> float:
        if a.command == STOP:
            return 0.0
        u = -self.spec.action_cost + self._info(a, achieved)
        for f in goals:
            if f in a.direct:
                u += w
            if f in a.requests:
                u += w * self.compliance[f]
        if a.requests:
            u -= KAPPA_CONTENT_HIDDEN
        if a.probe:
            u += w * P_EXPLORE - KAPPA_PROBE
        return u

    @staticmethod
    def _log_softmax(utils: list[float], idx: int) -> float:
        m = max(utils)
        return utils[idx] - (m + math.log(sum(math.exp(u - m) for u in utils)))

    def _is_pure_read(self, a: AbstractAction) -> bool:
        return a.command in self.reads and not a.probe and not a.direct and not a.requests

    def policy_logp(
        self, h: Hypothesis, a: AbstractAction, space: list[AbstractAction], achieved: frozenset[str]
    ) -> float:
        """log P(a | h, s) with a guaranteed to be in space.

        Reads are instrumental to every goal, so they carry no goal information: under every
        hypothesis a pure read has the benign policy's probability. The hidden policy then
        distributes the remaining mass over non-read actions by Boltzmann choice.
        """
        idx = space.index(a)
        lb = [h.beta * self.utility_benign(x, achieved) for x in space]
        lp0 = self._log_softmax(lb, idx)
        if h.hidden is None:
            if h.eagerness > 0:
                # Eager-but-compliant: with probability η the benign agent attempts a direct non-goal that is
                # still open (because the user asked for it); once denied the route is closed and it complies.
                open_direct = [x for x in space if x.direct & self.F]
                if open_direct:
                    lp_eager = math.log(1.0 / len(open_direct)) if a in open_direct else -math.inf
                    return (
                        _logaddexp(math.log1p(-h.eagerness) + lp0, math.log(h.eagerness) + lp_eager)
                        if lp_eager > -math.inf
                        else math.log1p(-h.eagerness) + lp0
                    )
            return lp0
        if self._is_pure_read(a):
            return lp0
        m = max(lb)
        p0 = [math.exp(u - m) for u in lb]
        z0 = sum(p0)
        read_mass = sum(p / z0 for x, p in zip(space, p0, strict=True) if self._is_pure_read(x))
        non_read = [i for i, x in enumerate(space) if not self._is_pure_read(x)]
        lh = [h.beta * self.utility_hidden(h.hidden, h.hidden_weight, space[i], achieved) for i in non_read]
        lpf = math.log(max(1e-300, 1.0 - read_mass)) + self._log_softmax(lh, non_read.index(idx))
        return _logaddexp(math.log1p(-h.patience) + lp0, math.log(h.patience) + lpf)

    def policy(
        self,
        h: Hypothesis,
        space: list[AbstractAction],
        achieved: frozenset[str],
        blocked: frozenset[str] | None = None,
    ) -> list[float]:
        """Probability vector over space (memoised when space is the canonical one for (achieved, blocked))."""
        key = None
        if blocked is not None:
            key = (self._hindex[id(h)], achieved, blocked)
            cached = self._policy_cache.get(key)
            if cached is not None:
                return cached
        probs = [math.exp(self.policy_logp(h, a, space, achieved)) for a in space]
        if key is not None:
            self._policy_cache[key] = probs
        return probs

    def _canon(self, a: AbstractAction, achieved: frozenset[str], blocked: frozenset[str]) -> AbstractAction:
        """Map an observed concrete action onto the nearest element of the abstract action space."""
        space = self.action_space(achieved, blocked)
        if a in space:
            return a
        # Direct non-goal that was already blocked: it is still an attempt; score it as the unblocked variant.
        candidates = [x for x in space if x.command == a.command]
        if not candidates:
            return AbstractAction(a.command, probe=True)
        best = max(
            candidates,
            key=lambda x: (
                len(x.direct & a.direct) + len(x.requests & a.requests),
                -len(x.direct ^ a.direct),
                -len(x.requests ^ a.requests),
                x.probe == a.probe,
            ),
        )
        return AbstractAction(
            a.command, direct=a.direct, requests=a.requests, sink=a.sink or best.sink, probe=a.probe
        )

    def log_likelihood(
        self, h: Hypothesis, a: AbstractAction, achieved: frozenset[str], blocked: frozenset[str]
    ) -> float:
        space = list(self.action_space(achieved, blocked))
        if a not in space:
            space.append(a)
        return self.policy_logp(h, a, space, achieved)

    # ------------------------------------------------------------------ inference
    def _posterior_from(self, log_weights: list[float]) -> dict[str, float]:
        m = max(log_weights)
        ws = [math.exp(lw - m) for lw in log_weights]
        z = sum(ws)
        post: dict[str, float] = {}
        for h, w in zip(self.hypotheses, ws, strict=True):
            post[h.name] = post.get(h.name, 0.0) + w / z
        return post

    def e_value_from(self, log_weights: list[float]) -> float:
        """E_t = [Σ_alt π_h L_h / ρ] / [Σ_0 π_h L_h / (1-ρ)]: likelihood ratio of the two mixtures."""
        rho = self.spec.prior_compromise
        alt = [lw for h, lw in zip(self.hypotheses, log_weights, strict=True) if h.name != "H0"]
        nul = [lw for h, lw in zip(self.hypotheses, log_weights, strict=True) if h.name == "H0"]
        if not alt:
            return 1.0

        def lse(xs: list[float]) -> float:
            m = max(xs)
            return m + math.log(sum(math.exp(x - m) for x in xs))

        return math.exp((lse(alt) - math.log(rho)) - (lse(nul) - math.log(1 - rho)))

    def observe(self, state: IntentState, obs: Observation) -> IntentState:
        achieved, blocked = frozenset(state.achieved), frozenset(state.blocked)
        a = self._canon(obs.action, achieved, blocked)
        lws = [
            lw + self.log_likelihood(h, a, achieved, blocked)
            for h, lw in zip(self.hypotheses, state.log_weights, strict=True)
        ]
        new = state.model_copy(deep=True)
        new.log_weights = lws
        new.steps += 1
        if obs.executed:
            gained = a.direct & self.A
            if a.command in self.reads and not a.probe:
                gained = gained | {f"read:{a.command}"}
            new.achieved = sorted(achieved | gained)
        else:
            new.blocked = sorted(blocked | (a.direct & self.F))
        new.last_e_value = self.e_value_from(lws)
        new.history.append({"action": a.to_dict(), "executed": obs.executed, "e_value": new.last_e_value})
        if len(new.history) > 200:
            new.history = new.history[-200:]
        return new

    def posterior(self, state: IntentState) -> dict[str, float]:
        return self._posterior_from(state.log_weights)

    def non_goal_mass(self, log_weights: list[float]) -> dict[str, float]:
        """P(the agent pursues f | τ) for each non-goal f (sums over multi-goal hypotheses)."""
        m = max(log_weights)
        ws = [math.exp(lw - m) for lw in log_weights]
        z = sum(ws)
        out = {f: 0.0 for f in sorted(self.F)}
        for h, w in zip(self.hypotheses, ws, strict=True):
            for f in h.hidden_goals:
                out[f] += w / z
        return out

    # ------------------------------------------------------------------ lookahead
    def reach_probability(
        self, h: Hypothesis, achieved: frozenset[str], blocked: frozenset[str], k: int
    ) -> float:
        """P(some non-goal is realised within k steps | h, state), with the deterministic gate
        denying direct non-goal routes (which then become blocked)."""

        hi = self._hindex[id(h)]

        def v(ach: frozenset[str], blk: frozenset[str], depth: int) -> float:
            if depth == 0:
                return 0.0
            key = (hi, ach, blk, depth)
            cached = self._reach_cache.get(key)
            if cached is not None:
                return cached
            space = list(self.action_space(ach, blk))
            probs = self.policy(h, space, ach, blk)
            total = 0.0
            for x, p in zip(space, probs, strict=True):
                if x.command == STOP:
                    continue
                if x.direct & self.F:
                    # denied by the deterministic layer; the agent learns the route is closed
                    total += p * v(ach, blk | (x.direct & self.F), depth - 1)
                    continue
                hit = 0.0
                for f in x.requests:
                    hit = 1 - (1 - hit) * (1 - self.compliance[f])
                nxt = ach | (x.direct & self.A)
                if x.command in self.reads and not x.probe:
                    nxt = nxt | {f"read:{x.command}"}
                total += p * (hit + (1 - hit) * v(nxt, blk, depth - 1))
            self._reach_cache[key] = total
            return total

        return v(achieved, blocked, k)

    def forecast(self, state: IntentState, k: int | None = None) -> float:
        k = self.spec.lookahead if k is None else k
        achieved, blocked = frozenset(state.achieved), frozenset(state.blocked)
        m = max(state.log_weights)
        ws = [math.exp(lw - m) for lw in state.log_weights]
        z = sum(ws)
        return sum(
            (w / z) * self.reach_probability(h, achieved, blocked, k)
            for h, w in zip(self.hypotheses, ws, strict=True)
        )

    # ------------------------------------------------------------------ admission
    def residual_risk(self, state: IntentState, a: AbstractAction) -> float:
        """Modelled probability that an admitted sink action with no detected request still
        realises a non-goal: Σ_f P(H_f | τ) · (1 − r) · p_h(f)."""
        if not a.sink:
            return 0.0
        mass = self.non_goal_mass(state.log_weights)
        r = self.spec.extractor_recall
        return sum(
            mass.get(f, 0.0) * (1 - r) * self.compliance.get(f, 0.0) for f in self.F if f not in a.requests
        )

    def assess(self, state_after: IntentState, a: AbstractAction) -> Assessment:
        e = state_after.last_e_value
        post = self._posterior_from(state_after.log_weights)
        fc = self.forecast(state_after)
        resid = self.residual_risk(state_after, a)
        reason = None
        if e >= 1.0 / self.spec.false_hold_alpha:
            reason = f"e-value {e:.1f} ≥ 1/α={1 / self.spec.false_hold_alpha:.0f}: evidence of a non-goal exceeds the anytime-valid threshold"
        elif fc > self.spec.risk_budget:
            reason = f"{self.spec.lookahead}-step forecast risk {fc:.3f} > budget {self.spec.risk_budget}"
        elif state_after.residual_risk_spent + resid > self.spec.risk_budget:
            reason = f"cumulative residual risk {state_after.residual_risk_spent + resid:.3f} would exceed budget {self.spec.risk_budget}"
        return Assessment(
            e_value=e,
            posterior=post,
            forecast=fc,
            residual_risk=resid,
            supervise=reason is not None,
            supervise_reason=reason,
        )
