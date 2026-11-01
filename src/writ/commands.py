"""The command table: the agent "system call table".

Each command names an executor adapter operation, declares its argument schema,
its effect class, and how to compute budget charges from its arguments.  The table
is loaded from YAML at gate start-up and is immutable at runtime: an agent cannot
add, rename or widen a command.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .grant import get_path

EFFECT_CLASSES = ("read", "write", "send", "money", "control")

_BUDGET_REF = re.compile(r"^args\.([A-Za-z0-9_.]+)$")


class CommandDef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    integration: str
    adapter: str
    operation: str
    effect_class: str
    args_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    budgets: dict[str, int | str] = Field(default_factory=dict)
    predict_effects: bool = True
    timeout_seconds: float = 15.0

    @field_validator("effect_class")
    @classmethod
    def _effect_class(cls, v: str) -> str:
        if v not in EFFECT_CLASSES:
            raise ValueError(f"effect_class must be one of {EFFECT_CLASSES}")
        return v

    @field_validator("args_schema")
    @classmethod
    def _schema(cls, v: dict) -> dict:
        Draft202012Validator.check_schema(v)
        # Reject unknown argument keys by default so constraints cannot be bypassed by aliases.
        if v.get("type") == "object" and "additionalProperties" not in v:
            v = {**v, "additionalProperties": False}
        return v

    @field_validator("budgets")
    @classmethod
    def _budgets(cls, v: dict) -> dict:
        for dim, expr in v.items():
            if isinstance(expr, bool) or not (
                isinstance(expr, int) or (isinstance(expr, str) and _BUDGET_REF.match(expr))
            ):
                raise ValueError(f"budget '{dim}' must be an integer or an 'args.<path>' reference")
        return v

    def validate_args(self, args: Any) -> list[str]:
        validator = Draft202012Validator(self.args_schema)
        return [
            f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
            for e in validator.iter_errors(args)
        ]

    def budget_charges(self, args: dict) -> dict[str, int]:
        charges: dict[str, int] = {}
        for dim, expr in self.budgets.items():
            if isinstance(expr, int):
                amt = expr
            else:
                m = _BUDGET_REF.match(expr)
                assert m
                raw = get_path(args, m.group(1))
                if not isinstance(raw, int) or isinstance(raw, bool):
                    raise ValueError(f"budget '{dim}' requires integer argument '{m.group(1)}'")
                amt = raw
            if amt < 0:
                raise ValueError(f"budget charge '{dim}' must be non-negative")
            charges[dim] = amt
        return charges

    def is_mutating(self) -> bool:
        return self.effect_class != "read"


class CommandTable(BaseModel):
    commands: dict[str, CommandDef]

    @classmethod
    def from_yaml(cls, path: str | Path) -> CommandTable:
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> CommandTable:
        cmds: dict[str, CommandDef] = {}
        for raw in data.get("commands", []):
            cd = CommandDef.model_validate(raw)
            if cd.name in cmds:
                raise ValueError(f"duplicate command: {cd.name}")
            cmds[cd.name] = cd
        return cls(commands=cmds)

    def get(self, name: str) -> CommandDef | None:
        return self.commands.get(name)

    def integrations(self) -> set[str]:
        return {c.integration for c in self.commands.values()}
