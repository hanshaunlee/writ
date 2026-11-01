"""Optional model-based claim extractor (OpenAI). Output is validated and treated as data.

Enabled on the gate with WRIT_CLAIM_EXTRACTOR=openai and an OPENAI_API_KEY. The gate never
sends credentials or task tokens to the model, only the free-text payload and the names and
descriptions of the task's non-goals.
"""

from __future__ import annotations

import json
import os
from typing import Any

from .claims import Claim, ClaimSet, RuleClaimExtractor
from .spec import IntentSpec

PROMPT = """You label customer-operations messages. Given the message and a list of forbidden outcomes
(things this task must not cause, directly or by asking the recipient), output JSON:
{"claims":[{"type":"request_of_recipient"|"commitment"|"mention","non_goal":<name>,"evidence":<quote>,"confidence":0..1}]}
- request_of_recipient: the message asks or instructs the recipient (or anyone) to do something that would realise the outcome.
- commitment: the message states that the outcome has been or will be done.
- mention: the outcome is discussed without asking or committing.
Only use non_goal names from the list. If nothing applies, output {"claims":[]}."""


class OpenAIClaimExtractor:
    name = "openai"

    def __init__(self, model: str | None = None):
        from openai import OpenAI  # imported lazily: optional dependency

        self.client = OpenAI()
        self.model = model or os.environ.get("WRIT_CLAIM_MODEL", "gpt-5-mini")
        self.fallback = RuleClaimExtractor()

    def extract(self, texts: list[str], spec: IntentSpec, context: dict[str, Any]) -> ClaimSet:
        rules = self.fallback.extract(texts, spec, context)
        if not texts or not spec.non_goals:
            return rules
        ngs = [
            {"name": n.name, "description": n.description or n.name.replace("_", " ")} for n in spec.non_goals
        ]
        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": PROMPT},
                    {
                        "role": "user",
                        "content": json.dumps({"forbidden_outcomes": ngs, "message": "\n\n".join(texts)}),
                    },
                ],
                response_format={"type": "json_object"},
            )
            data = json.loads(resp.choices[0].message.content or "{}")
        except Exception:  # noqa: BLE001 - fail closed to the rule extractor, never to "no claims"
            return rules
        cs = ClaimSet(extractor=self.name, claims=list(rules.claims))
        valid = {n.name for n in spec.non_goals}
        seen = {(c.type, c.non_goal) for c in cs.claims}
        for c in data.get("claims", []) if isinstance(data, dict) else []:
            if (
                not isinstance(c, dict)
                or c.get("non_goal") not in valid
                or c.get("type") not in ("request_of_recipient", "commitment", "mention")
            ):
                continue
            key = (c["type"], c["non_goal"])
            if key in seen:
                continue
            seen.add(key)
            try:
                conf = float(c.get("confidence", 0.7))
            except (TypeError, ValueError):
                conf = 0.7
            cs.claims.append(
                Claim(c["type"], c["non_goal"], str(c.get("evidence", ""))[:200], max(0.0, min(1.0, conf)))
            )
        return cs
