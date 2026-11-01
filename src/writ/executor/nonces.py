"""Executor-local single-use record. Defence in depth alongside the gate's consume step."""

from __future__ import annotations

import sqlite3
import threading


class NonceStore:
    def __init__(self, path: str = ":memory:"):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS used (id TEXT PRIMARY KEY, at TEXT NOT NULL, status TEXT NOT NULL)"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS used_at ON used(at)")

    def claim(self, auth_id: str, at: str) -> bool:
        """Return True if this is the first time auth_id is seen."""
        with self._lock:
            try:
                self._conn.execute("INSERT INTO used(id, at, status) VALUES(?,?,?)", (auth_id, at, "claimed"))
                return True
            except sqlite3.IntegrityError:
                return False

    def set_status(self, auth_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE used SET status=? WHERE id=?", (status, auth_id))

    def status(self, auth_id: str) -> str | None:
        with self._lock:
            r = self._conn.execute("SELECT status FROM used WHERE id=?", (auth_id,)).fetchone()
        return r[0] if r else None

    def purge_before(self, cutoff_iso: str) -> int:
        """Delete records first seen before cutoff. Returns the number removed."""
        with self._lock:
            return self._conn.execute("DELETE FROM used WHERE at < ?", (cutoff_iso,)).rowcount

    def count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM used").fetchone()[0])
