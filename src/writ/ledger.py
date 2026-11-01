"""Hash-chained, append-only ledger entries.

Each entry's hash covers its sequence number, timestamp, task, type, payload and the
previous entry's hash, so any edit or deletion in the stored history is detectable.
"""

from __future__ import annotations

from typing import Any

from .canon import hash_obj

GENESIS = "0" * 64


def entry_hash(seq: int, ts: str, task_id: str | None, event_type: str, payload: Any, prev_hash: str) -> str:
    return hash_obj(
        {
            "seq": seq,
            "ts": ts,
            "task_id": task_id,
            "type": event_type,
            "payload": payload,
            "prev": prev_hash,
        }
    )


class ChainVerifier:
    """Incremental verifier: feed pages of entries in ascending seq order."""

    def __init__(self) -> None:
        self.prev = GENESIS
        self.expected_seq: int | None = None
        self.count = 0
        self.error: str | None = None
        self.head: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def feed(self, entries: list[dict]) -> bool:
        """Verify the next page. Returns False (and sets `error`) at the first bad entry."""
        if self.error is not None:
            return False
        for e in entries:
            try:
                seq = e["seq"]
                if self.expected_seq is not None and seq != self.expected_seq:
                    self.error = f"gap or reorder at seq {seq}"
                    return False
                if e["prev_hash"] != self.prev:
                    self.error = f"broken link at seq {seq}"
                    return False
                h = entry_hash(seq, e["ts"], e["task_id"], e["type"], e["payload"], e["prev_hash"])
                if h != e["hash"]:
                    self.error = f"hash mismatch at seq {seq}"
                    return False
            except (KeyError, TypeError) as exc:
                self.error = f"malformed entry: {exc!r}"
                return False
            self.prev = h
            self.head = h
            self.expected_seq = seq + 1
            self.count += 1
        return True


def verify_chain(entries: list[dict]) -> tuple[bool, str | None]:
    """entries: dicts with seq, ts, task_id, type, payload, prev_hash, hash, in ascending seq order."""
    v = ChainVerifier()
    v.feed(entries)
    return v.ok, v.error
