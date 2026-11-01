"""Task grants: the bounded authority a task holds, and the rules for attenuating it.

A Grant lists the commands a task may invoke, per-argument constraints on each,
shared budgets, and forbidden downstream effects.  Delegation produces a child
grant that must be *at least as narrow* in every dimension.  The checks here are
deterministic and do not consult a model.
"""

from __future__ import annotations

import math
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CONSTRAINT_OPS = ("eq", "in", "max", "min", "matches", "keys_subset")

MAX_ENUM_VALUES = 1000  # values in an `in` constraint
MAX_PATTERN_LENGTH = 512  # characters in a `matches` pattern
MAX_MATCH_INPUT = 20000  # characters a `matches` pattern is applied to
MAX_BUDGET = 2**53  # keep budgets exact in every JSON consumer
MAX_VALUE_LENGTH = 1024  # characters in an `eq` / `in` string value


def _is_number(v: Any) -> bool:
    """A finite int or float. Booleans, NaN and infinities are not numbers for constraint purposes."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    return not isinstance(v, float) or math.isfinite(v)


def _check_value(v: Any, where: str) -> None:
    if isinstance(v, str) and len(v) > MAX_VALUE_LENGTH:
        raise ValueError(f"{where}: string value longer than {MAX_VALUE_LENGTH} characters")
    if isinstance(v, float) and not math.isfinite(v):
        raise ValueError(f"{where}: non-finite number")
    if isinstance(v, (list, dict)):
        raise ValueError(f"{where}: value must be a scalar")


def _same(a: Any, b: Any) -> bool:
    """Equality that never confuses booleans with numbers (`True == 1` in Python)."""
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    return a == b


def _member(v: Any, values: list[Any]) -> bool:
    return any(_same(v, x) for x in values)


class Constraint(BaseModel):
    """Constraints on one argument path. All present operators must hold."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    eq: Any | None = None
    in_: list[Any] | None = Field(default=None, alias="in", max_length=MAX_ENUM_VALUES)
    max: int | float | None = None
    min: int | float | None = None
    matches: str | None = Field(default=None, max_length=MAX_PATTERN_LENGTH)
    keys_subset: list[str] | None = Field(default=None, max_length=MAX_ENUM_VALUES)

    @field_validator("max", "min")
    @classmethod
    def _numeric(cls, v: Any) -> Any:
        if v is not None and not _is_number(v):
            raise ValueError("max/min must be a finite number")
        return v

    @model_validator(mode="after")
    def _non_empty(self) -> Constraint:
        if all(getattr(self, f) is None for f in ("eq", "in_", "max", "min", "matches", "keys_subset")):
            raise ValueError("constraint must specify at least one operator")
        if self.eq is not None:
            _check_value(self.eq, "eq")
        for v in self.in_ or []:
            _check_value(v, "in")
        for k in self.keys_subset or []:
            _check_value(k, "keys_subset")
        if self.matches is not None:
            re.compile(self.matches)
        if self.max is not None and self.min is not None and self.min > self.max:
            raise ValueError("constraint admits no value: min > max")
        return self

    def to_dict(self) -> dict:
        return self.model_dump(by_alias=True, exclude_none=True)


class CommandGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str = Field(min_length=1, max_length=200)
    args: dict[str, Constraint] = Field(default_factory=dict)  # dotted path -> constraint


class Grant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    commands: list[CommandGrant] = Field(default_factory=list, max_length=500)
    budgets: dict[str, int] = Field(default_factory=dict)  # dimension -> limit
    forbidden_effects: list[str] = Field(default_factory=list, max_length=500)

    @field_validator("budgets")
    @classmethod
    def _budgets(cls, v: dict[str, int]) -> dict[str, int]:
        for dim, lim in v.items():
            if isinstance(lim, bool) or not isinstance(lim, int):
                raise ValueError(f"budget '{dim}' must be an integer")
            if lim < 0 or lim > MAX_BUDGET:
                raise ValueError(f"budget '{dim}' must be between 0 and {MAX_BUDGET}")
        return v

    def command_grant(self, name: str) -> CommandGrant | None:
        for cg in self.commands:
            if cg.command == name:
                return cg
        return None

    def to_dict(self) -> dict:
        return self.model_dump(by_alias=True, exclude_none=True)


# ----------------------------------------------------------------------------
# Argument constraint evaluation
# ----------------------------------------------------------------------------


class ConstraintViolation(Exception):
    def __init__(self, path: str, op: str, detail: str):
        super().__init__(f"constraint violated at '{path}' ({op}): {detail}")
        self.path = path
        self.op = op
        self.detail = detail


_MISSING = object()


def get_path(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isascii() and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return _MISSING
    return cur


def check_constraint(path: str, value: Any, c: Constraint) -> None:
    """Raise ConstraintViolation if value does not satisfy c.

    A constrained path that is absent from the arguments is a violation: a grant
    that constrains `to` means the caller must say where it is sending.
    """
    if value is _MISSING:
        raise ConstraintViolation(path, "present", "constrained argument is missing")
    if c.eq is not None and not _same(value, c.eq):
        raise ConstraintViolation(path, "eq", f"value {value!r} != {c.eq!r}")
    if c.in_ is not None and not _member(value, c.in_):
        raise ConstraintViolation(path, "in", f"value {value!r} not in allowed set")
    if c.max is not None:
        if not _is_number(value):
            raise ConstraintViolation(path, "max", "value is not numeric")
        if value > c.max:
            raise ConstraintViolation(path, "max", f"{value} > {c.max}")
    if c.min is not None:
        if not _is_number(value):
            raise ConstraintViolation(path, "min", "value is not numeric")
        if value < c.min:
            raise ConstraintViolation(path, "min", f"{value} < {c.min}")
    if c.matches is not None:
        if not isinstance(value, str):
            raise ConstraintViolation(path, "matches", "value is not a string")
        if len(value) > MAX_MATCH_INPUT:
            raise ConstraintViolation(path, "matches", f"value longer than {MAX_MATCH_INPUT} characters")
        if re.fullmatch(c.matches, value) is None:
            raise ConstraintViolation(path, "matches", f"value {value!r} does not match /{c.matches}/")
    if c.keys_subset is not None:
        if not isinstance(value, dict):
            raise ConstraintViolation(path, "keys_subset", "value is not an object")
        extra = sorted(set(value.keys()) - set(c.keys_subset))
        if extra:
            raise ConstraintViolation(path, "keys_subset", f"keys not permitted: {extra}")


def check_args(args: dict, cg: CommandGrant) -> None:
    for path, c in cg.args.items():
        check_constraint(path, get_path(args, path), c)


# ----------------------------------------------------------------------------
# Attenuation: child grant must be no wider than parent grant
# ----------------------------------------------------------------------------


class AttenuationError(Exception):
    pass


def _values_of(c: Constraint) -> list[Any] | None:
    """Finite enumeration of the values a constraint admits, if known."""
    if c.eq is not None:
        return [c.eq]
    if c.in_ is not None:
        return list(c.in_)
    return None


def constraint_implies(child: Constraint, parent: Constraint, path: str, command: str) -> None:
    """Raise AttenuationError unless every value admitted by child is admitted by parent."""
    cv = _values_of(child)

    def fail(op: str, why: str) -> None:
        raise AttenuationError(f"{command}: child constraint on '{path}' widens parent ({op}): {why}")

    if parent.eq is not None:
        if cv is None or any(not _same(v, parent.eq) for v in cv):
            fail("eq", f"child must fix value to {parent.eq!r}")
    if parent.in_ is not None:
        if cv is None or any(not _member(v, parent.in_) for v in cv):
            fail("in", "child must restrict to a subset of parent's allowed set")
    if parent.max is not None:
        if cv is not None:
            if any(not _is_number(v) or v > parent.max for v in cv):
                fail("max", f"child admits values above {parent.max}")
        elif child.max is None or child.max > parent.max:
            fail("max", f"child max must be <= {parent.max}")
    if parent.min is not None:
        if cv is not None:
            if any(not _is_number(v) or v < parent.min for v in cv):
                fail("min", f"child admits values below {parent.min}")
        elif child.min is None or child.min < parent.min:
            fail("min", f"child min must be >= {parent.min}")
    if parent.matches is not None:
        if cv is not None:
            if any(not isinstance(v, str) or re.fullmatch(parent.matches, v) is None for v in cv):
                fail("matches", "child admits values not matching parent pattern")
        elif child.matches != parent.matches:
            # Regex implication is undecidable in general; require identical pattern.
            fail("matches", "child must keep the identical pattern or enumerate values")
    if parent.keys_subset is not None:
        if child.keys_subset is None or not set(child.keys_subset) <= set(parent.keys_subset):
            fail("keys_subset", "child keys must be a subset of parent's permitted keys")


def attenuate(parent: Grant, requested: Grant) -> Grant:
    """Validate that `requested` is no wider than `parent` and return the effective child grant.

    - Commands: child commands must each exist in parent.
    - Args: every parent constraint must be implied by a child constraint on the same path.
      Child may add constraints on new paths, but may not introduce regular expressions the
      parent did not already carry (patterns are operator-authored; an agent-supplied pattern
      would be evaluated by the gate against agent-supplied input).
    - Budgets: child limit per dimension must be <= parent's.  Omitted dimensions inherit
      the parent's limit.  Dimensions absent from parent are always allowed (narrowing).
    - Forbidden effects: child's set is the union with the parent's.
    """
    parent_cmds = {cg.command: cg for cg in parent.commands}
    child_cmds: list[CommandGrant] = []
    seen: set[str] = set()
    for cg in requested.commands:
        if cg.command in seen:
            raise AttenuationError(f"duplicate command grant: {cg.command}")
        seen.add(cg.command)
        pcg = parent_cmds.get(cg.command)
        if pcg is None:
            raise AttenuationError(f"command not held by parent: {cg.command}")
        for path, pc in pcg.args.items():
            cc = cg.args.get(path)
            if cc is None:
                raise AttenuationError(
                    f"{cg.command}: child drops parent constraint on '{path}'; constraints can only be added"
                )
            constraint_implies(cc, pc, path, cg.command)
        for path, cc in cg.args.items():
            pc = pcg.args.get(path)
            if cc.matches is not None and (pc is None or pc.matches != cc.matches):
                raise AttenuationError(
                    f"{cg.command}: child may not introduce a 'matches' pattern on '{path}'; use eq or in"
                )
        child_cmds.append(cg)

    budgets: dict[str, int] = dict(requested.budgets)
    for dim, plimit in parent.budgets.items():
        if dim not in budgets:
            budgets[dim] = plimit
        elif budgets[dim] > plimit:
            raise AttenuationError(f"budget '{dim}' {budgets[dim]} exceeds parent limit {plimit}")
    for dim, lim in budgets.items():
        if lim < 0:
            raise AttenuationError(f"budget '{dim}' must be non-negative")

    forbidden = sorted(set(parent.forbidden_effects) | set(requested.forbidden_effects))
    return Grant(commands=child_cmds, budgets=budgets, forbidden_effects=forbidden)
