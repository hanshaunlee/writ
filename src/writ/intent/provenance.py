"""Provenance of identifiers.

Every identifier-like atom (email address, resource id, URL, money amount) in a sink payload
has an origin. Atoms that come from the task contract or from structured fields of authorized
read results are trusted for this task. Atoms that appear from nowhere (the prompt, injected
free text, the model's imagination) are untrusted. A sink payload carrying untrusted atoms is
the signature of smuggling an out-of-scope target through a permitted channel.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RES_ID = re.compile(r"\b(?:cus|ch|re|em|exp|inv|acct|txn|sub|pay)_[A-Za-z0-9]{3,}\b")
URL = re.compile(r"https?://[^\s)>\]]+", re.I)
IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")


def extract_atoms(text: str) -> set[str]:
    atoms: set[str] = set()
    for rx in (EMAIL, RES_ID, URL, IBAN):
        atoms.update(m.group(0).lower().rstrip(".,;:") for m in rx.finditer(text))
    return atoms


def atoms_in(
    value: Any, free_text_fields: list[str], key: str | None = None, *, structured_only: bool
) -> set[str]:
    """Atoms in a JSON value. With structured_only, skip free-text fields (untrusted content)."""
    out: set[str] = set()
    if isinstance(value, dict):
        for k, v in value.items():
            out |= atoms_in(v, free_text_fields, k, structured_only=structured_only)
    elif isinstance(value, list):
        for v in value:
            out |= atoms_in(v, free_text_fields, key, structured_only=structured_only)
    elif isinstance(value, str):
        if structured_only and key in free_text_fields:
            return out
        out |= extract_atoms(value)
    return out


@dataclass
class ProvenanceReport:
    trusted: set[str] = field(default_factory=set)
    untrusted: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {"trusted": sorted(self.trusted), "untrusted": sorted(self.untrusted)}


def contract_atoms(grant: dict) -> set[str]:
    out: set[str] = set()

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str):
            out.update(extract_atoms(v))

    walk(grant)
    return out


def classify(payload: Any, trusted: set[str], free_text_fields: list[str]) -> ProvenanceReport:
    found = atoms_in(payload, free_text_fields, structured_only=False)
    rep = ProvenanceReport()
    for a in found:
        (rep.trusted if a in trusted else rep.untrusted).add(a)
    return rep
