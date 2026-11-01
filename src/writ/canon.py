"""Canonical JSON encoding and hashing.

Every signed object (authorizations, receipts, ledger entries) is hashed over its
canonical encoding: sorted keys, no insignificant whitespace, UTF-8, no NaN/Infinity.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def canonical_bytes(obj: Any) -> bytes:
    return canonical_json(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    """sha256 over the canonical JSON of obj, hex encoded."""
    return sha256_hex(canonical_bytes(obj))
