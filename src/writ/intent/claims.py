"""Content claims: what a payload *says*, as structured data a policy can check.

A claim extractor reads the free-text parts of a sink payload (email body, note, reason) and
emits claims such as "this message asks the recipient to change the billing contact".  The
rule extractor here is deterministic and conservative; `claims_llm.py` adds a model-based
extractor. Either way, claims are data: the deterministic policy decides what they mean.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from .spec import IntentSpec

REQUEST_VERBS = (
    r"please\s+(?:\w+\s+){0,3}?(?:update|change|set|switch|move|redirect|forward|send|make|add|grant|mark|upgrade|approve|disable|enable|remove|transfer|wire|pay|refund|cc|share|export)",
    r"(?:can|could|would|will)\s+you\s+(?:\w+\s+){0,3}?(?:update|change|set|switch|move|redirect|forward|send|make|add|grant|mark|upgrade|approve|disable|enable|remove|transfer|wire|pay|refund|cc|share|export)",
    r"(?:you|an?\s+(?:account\s+)?admin(?:istrator)?|your\s+team)\s+(?:should|must|need(?:s)?\s+to|will\s+need\s+to|can)\s+(?:\w+\s+){0,3}?(?:update|change|set|switch|move|redirect|forward|send|make|add|grant|mark|upgrade|approve|disable|enable|remove|transfer|wire|pay|refund|cc|share|export)",
    r"(?:update|change|set|switch|redirect|forward)\s+(?:the\s+|your\s+)?(?:\w+\s+){0,3}?to\s+\S+@\S+",
    r"(?:going\s+forward|from\s+now\s+on|in\s+future)",
)
COMMIT_VERBS = (
    r"(?:we|i)(?:'ve|\s+have)?\s+(?:also\s+)?(?:marked|flagged|upgraded|granted|added|set|changed|updated|moved|switched|redirected|approved|enabled|disabled)",
)

_REQ = [re.compile(p, re.I) for p in REQUEST_VERBS]
_COM = [re.compile(p, re.I) for p in COMMIT_VERBS]


@dataclass
class Claim:
    type: str  # request_of_recipient | commitment | mention
    non_goal: str
    evidence: str
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "non_goal": self.non_goal,
            "evidence": self.evidence[:200],
            "confidence": self.confidence,
        }


@dataclass
class ClaimSet:
    claims: list[Claim] = field(default_factory=list)
    extractor: str = "rules"

    def requests(self) -> set[str]:
        return {c.non_goal for c in self.claims if c.type in ("request_of_recipient", "commitment")}

    def to_dict(self) -> dict:
        return {"extractor": self.extractor, "claims": [c.to_dict() for c in self.claims]}


class ClaimExtractor(Protocol):
    name: str

    def extract(self, texts: list[str], spec: IntentSpec, context: dict[str, Any]) -> ClaimSet: ...


def free_texts(args: Any, spec: IntentSpec) -> list[str]:
    """Collect free-text argument values (by field name) from a payload."""
    out: list[str] = []

    def walk(v: Any, key: str | None) -> None:
        if isinstance(v, dict):
            for k, x in v.items():
                walk(x, k)
        elif isinstance(v, list):
            for x in v:
                walk(x, key)
        elif isinstance(v, str) and key in spec.free_text_fields and len(v) > 0:
            out.append(v)

    walk(args, None)
    return out


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text) if s.strip()]


class RuleClaimExtractor:
    """Keyword + request-verb rules. High precision on explicit asks; recall is measured, not assumed."""

    name = "rules"

    def extract(self, texts: list[str], spec: IntentSpec, context: dict[str, Any]) -> ClaimSet:
        cs = ClaimSet(extractor=self.name)
        denied_values: list[str] = [str(v).lower() for v in context.get("denied_values", []) if str(v)]
        for text in texts:
            for sent in _sentences(text):
                low = sent.lower()
                for ng in spec.non_goals:
                    kws = [k.lower() for k in ng.keywords] + [
                        f.replace("_", " ") for f in ng.protected_fields
                    ]
                    hit_kw = next(
                        (
                            k
                            for k in kws
                            if k and re.search(r"(?<![a-z0-9])" + re.escape(k) + r"(?![a-z0-9])", low)
                        ),
                        None,
                    )
                    hit_denied = next((d for d in denied_values if d in low), None)
                    if not hit_kw and not hit_denied:
                        continue
                    if any(r.search(sent) for r in _REQ):
                        cs.claims.append(Claim("request_of_recipient", ng.name, sent, 0.9))
                    elif any(r.search(sent) for r in _COM):
                        cs.claims.append(Claim("commitment", ng.name, sent, 0.8))
                    else:
                        cs.claims.append(Claim("mention", ng.name, sent, 0.5))
        return cs
