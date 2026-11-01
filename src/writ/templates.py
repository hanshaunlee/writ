"""Task contract templates: operator-approved grant shapes with typed parameters."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from .grant import Grant
from .intent.spec import IntentSpec

_PLACEHOLDER = re.compile(r"^\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}$")
_INLINE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


class TemplateError(Exception):
    pass


def _coerce(value: str) -> Any:
    """Parameters arrive as strings from the CLI; parse JSON where it is unambiguous."""
    s = value.strip()
    if s and (s[0] in "[{" or s in ("true", "false", "null") or re.fullmatch(r"-?\d+", s)):
        try:
            return json.loads(s)
        except ValueError:
            return value
    return value


def _subst(node: Any, params: dict[str, Any]) -> Any:
    if isinstance(node, str):
        m = _PLACEHOLDER.match(node)
        if m:
            name = m.group(1)
            if name not in params:
                raise TemplateError(f"missing parameter '{name}'")
            return params[name]

        def rep(mm: re.Match) -> str:
            name = mm.group(1)
            if name not in params:
                raise TemplateError(f"missing parameter '{name}'")
            v = params[name]
            return v if isinstance(v, str) else json.dumps(v)

        return _INLINE.sub(rep, node)
    if isinstance(node, list):
        return [_subst(x, params) for x in node]
    if isinstance(node, dict):
        return {k: _subst(v, params) for k, v in node.items()}
    return node


def load_template(path: str | Path) -> dict:
    data = yaml.safe_load(Path(path).read_text())
    if not isinstance(data, dict) or "grant" not in data:
        raise TemplateError("template must be a mapping with a 'grant' key")
    return data


def render(template: dict, raw_params: dict[str, str]) -> tuple[str, Grant, int, str, IntentSpec | None]:
    declared = template.get("parameters", {}) or {}
    unknown = set(raw_params) - set(declared)
    if unknown:
        raise TemplateError(f"unknown parameters: {sorted(unknown)}")
    params = {k: _coerce(v) if isinstance(v, str) else v for k, v in raw_params.items()}
    grant_raw = _subst(template["grant"], params)
    grant = Grant.model_validate(grant_raw)
    name = template.get("name", "task")
    ttl = int(template.get("ttl_seconds", 3600))
    description = _subst(template.get("description", ""), params)
    intent = IntentSpec.model_validate(_subst(template["intent"], params)) if template.get("intent") else None
    return name, grant, ttl, description, intent
