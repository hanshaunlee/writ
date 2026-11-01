"""SQLite-backed store for the gate.

All mutations run inside a single serialized writer (BEGIN IMMEDIATE under a process
lock), which is what makes budget reservations atomic across concurrent sub-agents.
The ledger is append-only and hash-chained.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from ..ledger import GENESIS, entry_hash

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  parent_id TEXT REFERENCES tasks(id),
  root_id TEXT NOT NULL,
  depth INTEGER NOT NULL,
  name TEXT NOT NULL,
  principal TEXT NOT NULL,
  status TEXT NOT NULL,
  status_reason TEXT,
  token_hash TEXT NOT NULL UNIQUE,
  grant_json TEXT NOT NULL,
  config_versions_json TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  max_expires_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  intent_json TEXT
);
CREATE INDEX IF NOT EXISTS tasks_parent ON tasks(parent_id);
CREATE INDEX IF NOT EXISTS tasks_root ON tasks(root_id);
CREATE INDEX IF NOT EXISTS tasks_status ON tasks(status);

CREATE TABLE IF NOT EXISTS budget_usage (
  task_id TEXT NOT NULL REFERENCES tasks(id),
  dimension TEXT NOT NULL,
  reserved INTEGER NOT NULL DEFAULT 0,
  committed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (task_id, dimension)
);

CREATE TABLE IF NOT EXISTS authorizations (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(id),
  command TEXT NOT NULL,
  args_json TEXT NOT NULL,
  args_hash TEXT NOT NULL,
  charges_json TEXT NOT NULL,
  integration TEXT NOT NULL,
  config_version TEXT,
  effects_json TEXT NOT NULL,
  envelope_json TEXT NOT NULL,
  status TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  finalized_at TEXT,
  outcome_json TEXT,
  receipt_json TEXT,
  hold_json TEXT,
  intent_json TEXT
);
CREATE INDEX IF NOT EXISTS auth_task ON authorizations(task_id);
CREATE INDEX IF NOT EXISTS auth_status ON authorizations(status);

CREATE TABLE IF NOT EXISTS ledger (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  task_id TEXT,
  type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS ledger_task ON ledger(task_id);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intent_state (
  root_id TEXT PRIMARY KEY REFERENCES tasks(id),
  state_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trusted_atoms (
  root_id TEXT NOT NULL REFERENCES tasks(id),
  atom TEXT NOT NULL,
  source TEXT NOT NULL,
  PRIMARY KEY (root_id, atom)
);

CREATE TABLE IF NOT EXISTS invoke_idempotency (
  task_id TEXT NOT NULL REFERENCES tasks(id),
  key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  state TEXT NOT NULL,
  result_json TEXT,
  created_at TEXT NOT NULL,
  attempt TEXT,
  PRIMARY KEY (task_id, key)
);
"""

# Column additions for databases created by earlier versions. CREATE TABLE IF NOT EXISTS leaves
# existing tables untouched, so each (table, column, ddl) is applied when the column is absent.
MIGRATIONS = [
    ("tasks", "intent_json", "ALTER TABLE tasks ADD COLUMN intent_json TEXT"),
    ("authorizations", "hold_json", "ALTER TABLE authorizations ADD COLUMN hold_json TEXT"),
    ("authorizations", "intent_json", "ALTER TABLE authorizations ADD COLUMN intent_json TEXT"),
    ("invoke_idempotency", "attempt", "ALTER TABLE invoke_idempotency ADD COLUMN attempt TEXT"),
]

# Authorization states from which no budget movement may happen again.
FINAL_AUTH_STATUSES = ("committed", "failed", "released")


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class BudgetExceeded(Exception):
    def __init__(self, task_id: str, dimension: str, limit: int, used: int, requested: int):
        super().__init__(
            f"budget '{dimension}' exceeded on task {task_id}: limit {limit}, used {used}, requested {requested}"
        )
        self.task_id = task_id
        self.dimension = dimension
        self.limit = limit
        self.used = used
        self.requested = requested


class SchemaTooNew(Exception):
    pass


def _row(r: sqlite3.Row | None) -> dict | None:
    return dict(r) if r is not None else None


class Store:
    def __init__(self, path: str = ":memory:"):
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=30000")
        # executescript manages its own transaction.
        self._conn.executescript(SCHEMA)
        for table, column, ddl in MIGRATIONS:
            cols = {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})").fetchall()}
            if column not in cols:
                self._conn.execute(ddl)
        current = int(self.get_setting("schema_version", "0") or 0)
        if current > SCHEMA_VERSION:
            raise SchemaTooNew(
                f"database schema version {current} is newer than this gate supports ({SCHEMA_VERSION}); upgrade the gate"
            )
        if current != SCHEMA_VERSION:
            self.set_setting("schema_version", str(SCHEMA_VERSION))

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Serialized write transaction. Nested calls join the outer transaction."""
        with self._lock:
            if self._conn.in_transaction:
                yield self._conn
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    # ------------------------------------------------------------------ ledger
    def append_ledger(
        self, event_type: str, payload: dict, task_id: str | None = None, ts: str | None = None
    ) -> dict:
        with self.tx() as c:
            last = c.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
            prev_hash = last["hash"] if last else GENESIS
            seq = (last["seq"] + 1) if last else 1
            ts = ts or iso(utcnow())
            h = entry_hash(seq, ts, task_id, event_type, payload, prev_hash)
            c.execute(
                "INSERT INTO ledger(seq, ts, task_id, type, payload_json, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                (seq, ts, task_id, event_type, json.dumps(payload, sort_keys=True), prev_hash, h),
            )
            return {
                "seq": seq,
                "ts": ts,
                "task_id": task_id,
                "type": event_type,
                "payload": payload,
                "prev_hash": prev_hash,
                "hash": h,
            }

    def ledger_entries(
        self, after: int = 0, limit: int = 500, task_id: str | None = None, root_id: str | None = None
    ) -> list[dict]:
        with self._lock:
            if root_id:
                rows = self._conn.execute(
                    "SELECT l.* FROM ledger l LEFT JOIN tasks t ON t.id = l.task_id WHERE l.seq > ? AND (t.root_id = ? OR l.task_id = ?) ORDER BY l.seq LIMIT ?",
                    (after, root_id, root_id, limit),
                ).fetchall()
            elif task_id:
                rows = self._conn.execute(
                    "SELECT * FROM ledger WHERE seq > ? AND task_id = ? ORDER BY seq LIMIT ?",
                    (after, task_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM ledger WHERE seq > ? ORDER BY seq LIMIT ?", (after, limit)
                ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["payload"] = json.loads(d.pop("payload_json"))
            out.append(d)
        return out

    def ledger_head(self) -> dict | None:
        with self._lock:
            r = self._conn.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        return _row(r)

    # ------------------------------------------------------------------ settings
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self._lock:
            r = self._conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default

    def set_setting(self, key: str, value: str) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    # ------------------------------------------------------------------ tasks
    def insert_task(self, t: dict) -> None:
        t = {"intent_json": None, **t}
        with self.tx() as c:
            c.execute(
                """INSERT INTO tasks(id,parent_id,root_id,depth,name,principal,status,status_reason,token_hash,grant_json,
                   config_versions_json,metadata_json,created_at,expires_at,max_expires_at,updated_at,intent_json)
                   VALUES(:id,:parent_id,:root_id,:depth,:name,:principal,:status,:status_reason,:token_hash,:grant_json,
                   :config_versions_json,:metadata_json,:created_at,:expires_at,:max_expires_at,:updated_at,:intent_json)""",
                t,
            )
            for dim in json.loads(t["grant_json"]).get("budgets", {}):
                c.execute("INSERT INTO budget_usage(task_id, dimension) VALUES(?,?)", (t["id"], dim))

    def get_task(self, task_id: str) -> dict | None:
        with self._lock:
            return _row(self._conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())

    def get_task_by_token_hash(self, token_hash: str) -> dict | None:
        with self._lock:
            return _row(
                self._conn.execute("SELECT * FROM tasks WHERE token_hash=?", (token_hash,)).fetchone()
            )

    def task_chain(self, task_id: str) -> list[dict]:
        """The task and its ancestors, nearest first."""
        with self._lock:
            rows = self._conn.execute(
                """WITH RECURSIVE chain(id, parent_id, lvl) AS (
                     SELECT id, parent_id, 0 FROM tasks WHERE id=?
                     UNION ALL
                     SELECT t.id, t.parent_id, c.lvl+1 FROM tasks t JOIN chain c ON t.id = c.parent_id)
                   SELECT t.* FROM chain c JOIN tasks t ON t.id = c.id ORDER BY c.lvl""",
                (task_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def task_subtree_ids(self, task_id: str) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                """WITH RECURSIVE sub(id) AS (
                     SELECT id FROM tasks WHERE id=?
                     UNION ALL
                     SELECT t.id FROM tasks t JOIN sub s ON t.parent_id = s.id)
                   SELECT id FROM sub""",
                (task_id,),
            ).fetchall()
        return [r["id"] for r in rows]

    def count_tree(self, root_id: str) -> int:
        with self._lock:
            r = self._conn.execute("SELECT COUNT(*) AS n FROM tasks WHERE root_id=?", (root_id,)).fetchone()
        return int(r["n"])

    def list_tasks(
        self,
        root_id: str | None = None,
        status: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict]:
        q = "SELECT * FROM tasks WHERE 1=1"
        params: list[Any] = []
        if root_id:
            q += " AND root_id=?"
            params.append(root_id)
        if status:
            q += " AND status=?"
            params.append(status)
        q += " ORDER BY created_at DESC, id LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with self._lock:
            return [dict(r) for r in self._conn.execute(q, params).fetchall()]

    def update_task_status(self, task_id: str, status: str, reason: str | None, now: str) -> None:
        with self.tx() as c:
            c.execute(
                "UPDATE tasks SET status=?, status_reason=?, updated_at=? WHERE id=?",
                (status, reason, now, task_id),
            )

    def update_task_fields(self, task_id: str, now: str, **fields: Any) -> None:
        allowed = {"expires_at", "config_versions_json", "metadata_json", "intent_json"}
        bad = set(fields) - allowed
        if bad:
            raise ValueError(f"cannot update fields {bad}")
        sets = ", ".join(f"{k}=?" for k in fields)
        with self.tx() as c:
            c.execute(f"UPDATE tasks SET {sets}, updated_at=? WHERE id=?", (*fields.values(), now, task_id))

    # ------------------------------------------------------------------ budgets
    def budget_usage(self, task_id: str) -> dict[str, dict[str, int]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM budget_usage WHERE task_id=?", (task_id,)).fetchall()
        return {r["dimension"]: {"reserved": r["reserved"], "committed": r["committed"]} for r in rows}

    def reserve_budgets(self, chain: list[dict], charges: dict[str, int]) -> None:
        """Atomically reserve charges against every task in chain (task + ancestors).

        Each task's grant declares limits for the dimensions it cares about.  A charge for a
        dimension a task does not limit is not checked against that task.
        """
        if not charges:
            return
        with self.tx() as c:
            for t in chain:
                limits = json.loads(t["grant_json"]).get("budgets", {})
                for dim, amt in charges.items():
                    if dim not in limits:
                        continue
                    row = c.execute(
                        "SELECT reserved, committed FROM budget_usage WHERE task_id=? AND dimension=?",
                        (t["id"], dim),
                    ).fetchone()
                    used = (row["reserved"] + row["committed"]) if row else 0
                    if used + amt > limits[dim]:
                        raise BudgetExceeded(t["id"], dim, limits[dim], used, amt)
            for t in chain:
                limits = json.loads(t["grant_json"]).get("budgets", {})
                for dim, amt in charges.items():
                    if dim not in limits:
                        continue
                    c.execute(
                        """INSERT INTO budget_usage(task_id, dimension, reserved, committed) VALUES(?,?,?,0)
                           ON CONFLICT(task_id, dimension) DO UPDATE SET reserved = reserved + excluded.reserved""",
                        (t["id"], dim, amt),
                    )

    def settle_budgets(self, chain: list[dict], charges: dict[str, int], commit: bool) -> None:
        with self.tx() as c:
            for t in chain:
                limits = json.loads(t["grant_json"]).get("budgets", {})
                for dim, amt in charges.items():
                    if dim not in limits:
                        continue
                    if commit:
                        c.execute(
                            "UPDATE budget_usage SET reserved = MAX(0, reserved - ?), committed = committed + ? WHERE task_id=? AND dimension=?",
                            (amt, amt, t["id"], dim),
                        )
                    else:
                        c.execute(
                            "UPDATE budget_usage SET reserved = MAX(0, reserved - ?) WHERE task_id=? AND dimension=?",
                            (amt, t["id"], dim),
                        )

    # ------------------------------------------------------------------ intent
    def get_intent_state(self, root_id: str) -> dict | None:
        with self._lock:
            r = self._conn.execute(
                "SELECT state_json FROM intent_state WHERE root_id=?", (root_id,)
            ).fetchone()
        return json.loads(r["state_json"]) if r else None

    def set_intent_state(self, root_id: str, state: dict, now: str) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO intent_state(root_id, state_json, updated_at) VALUES(?,?,?) ON CONFLICT(root_id) DO UPDATE SET state_json=excluded.state_json, updated_at=excluded.updated_at",
                (root_id, json.dumps(state, sort_keys=True), now),
            )

    def add_trusted_atoms(self, root_id: str, atoms: set[str], source: str) -> None:
        if not atoms:
            return
        with self.tx() as c:
            c.executemany(
                "INSERT OR IGNORE INTO trusted_atoms(root_id, atom, source) VALUES(?,?,?)",
                [(root_id, a, source) for a in atoms],
            )

    def trusted_atoms(self, root_id: str) -> set[str]:
        with self._lock:
            return {
                r["atom"]
                for r in self._conn.execute(
                    "SELECT atom FROM trusted_atoms WHERE root_id=?", (root_id,)
                ).fetchall()
            }

    # ------------------------------------------------------------------ authorizations
    def insert_authorization(self, a: dict) -> None:
        a = {"hold_json": None, "intent_json": None, **a}
        with self.tx() as c:
            c.execute(
                """INSERT INTO authorizations(id,task_id,command,args_json,args_hash,charges_json,integration,config_version,
                   effects_json,envelope_json,status,issued_at,expires_at,hold_json,intent_json)
                   VALUES(:id,:task_id,:command,:args_json,:args_hash,:charges_json,:integration,:config_version,
                   :effects_json,:envelope_json,:status,:issued_at,:expires_at,:hold_json,:intent_json)""",
                a,
            )

    def release_hold(
        self, auth_id: str, envelope_json: str, issued_at: str, expires_at: str, config_version: str | None
    ) -> bool:
        """held -> issued with a fresh envelope. Returns False if the row was no longer held."""
        with self.tx() as c:
            cur = c.execute(
                "UPDATE authorizations SET status='issued', envelope_json=?, issued_at=?, expires_at=?, config_version=? WHERE id=? AND status='held'",
                (envelope_json, issued_at, expires_at, config_version, auth_id),
            )
            return cur.rowcount == 1

    def get_authorization(self, auth_id: str) -> dict | None:
        with self._lock:
            return _row(self._conn.execute("SELECT * FROM authorizations WHERE id=?", (auth_id,)).fetchone())

    def list_authorizations(
        self,
        task_ids: list[str] | None = None,
        status: str | None = None,
        limit: int = 500,
        *,
        expires_before: str | None = None,
        consumed_before: str | None = None,
        finalized_before: str | None = None,
    ) -> list[dict]:
        q = "SELECT * FROM authorizations WHERE 1=1"
        params: list[Any] = []
        if task_ids is not None:
            if not task_ids:
                return []
            q += f" AND task_id IN ({','.join('?' * len(task_ids))})"
            params.extend(task_ids)
        if status:
            q += " AND status=?"
            params.append(status)
        if expires_before:
            q += " AND expires_at <= ?"
            params.append(expires_before)
        if consumed_before:
            q += " AND consumed_at IS NOT NULL AND consumed_at <= ?"
            params.append(consumed_before)
        if finalized_before:
            q += " AND finalized_at IS NOT NULL AND finalized_at <= ?"
            params.append(finalized_before)
        q += " ORDER BY issued_at DESC, id LIMIT ?"
        params.append(limit)
        with self._lock:
            return [dict(r) for r in self._conn.execute(q, params).fetchall()]

    def consume_authorization(self, auth_id: str, now: str) -> dict | None:
        """Atomically move issued -> consumed. Returns the row if consumed, None if not consumable."""
        with self.tx() as c:
            cur = c.execute(
                "UPDATE authorizations SET status='consumed', consumed_at=? WHERE id=? AND status='issued' AND expires_at > ?",
                (now, auth_id, now),
            )
            if cur.rowcount != 1:
                return None
            return _row(c.execute("SELECT * FROM authorizations WHERE id=?", (auth_id,)).fetchone())

    def finalize_authorization(
        self,
        auth_id: str,
        status: str,
        now: str,
        outcome: dict | None,
        receipt: dict | None,
        *,
        expected: tuple[str, ...] | None = None,
    ) -> bool:
        """Set the terminal status. With `expected`, only rows currently in one of those states move;
        the return value says whether the transition happened, so budgets are settled at most once."""
        q = "UPDATE authorizations SET status=?, finalized_at=?, outcome_json=?, receipt_json=? WHERE id=?"
        params: list[Any] = [
            status,
            now,
            json.dumps(outcome, sort_keys=True) if outcome is not None else None,
            json.dumps(receipt, sort_keys=True) if receipt is not None else None,
            auth_id,
        ]
        if expected:
            q += f" AND status IN ({','.join('?' * len(expected))})"
            params.extend(expected)
        with self.tx() as c:
            return c.execute(q, params).rowcount == 1

    # ------------------------------------------------------------------ invoke idempotency
    def idempotency_begin(
        self, task_id: str, key: str, request_hash: str, now: str, stale_before: str, attempt: str
    ) -> tuple[str, dict | None]:
        """Claim an idempotency key for this task on behalf of `attempt`.

        Returns ("new", None) when the caller should proceed, ("done", result) when a result is
        already recorded, ("in_progress", None) when another request with the same key is still
        running, or ("mismatch", None) when the key was used with different arguments. A claim
        whose attempt died (older than `stale_before`, no result) is taken over by the caller.
        """
        with self.tx() as c:
            r = c.execute(
                "SELECT request_hash, state, result_json, created_at FROM invoke_idempotency WHERE task_id=? AND key=?",
                (task_id, key),
            ).fetchone()
            if r is None:
                c.execute(
                    "INSERT INTO invoke_idempotency(task_id, key, request_hash, state, created_at, attempt) VALUES(?,?,?,'in_progress',?,?)",
                    (task_id, key, request_hash, now, attempt),
                )
                return "new", None
            if r["request_hash"] != request_hash:
                return "mismatch", None
            if r["state"] == "done":
                return "done", json.loads(r["result_json"])
            if r["created_at"] <= stale_before:
                c.execute(
                    "UPDATE invoke_idempotency SET created_at=?, attempt=? WHERE task_id=? AND key=?",
                    (now, attempt, task_id, key),
                )
                return "new", None
            return "in_progress", None

    def idempotency_finish(self, task_id: str, key: str, result: dict, attempt: str) -> bool:
        """Record the result; only the attempt that holds the claim may do so."""
        with self.tx() as c:
            cur = c.execute(
                "UPDATE invoke_idempotency SET state='done', result_json=? WHERE task_id=? AND key=? AND attempt=? AND state='in_progress'",
                (json.dumps(result, sort_keys=True), task_id, key, attempt),
            )
            return cur.rowcount == 1

    def idempotency_abandon(self, task_id: str, key: str, attempt: str) -> None:
        with self.tx() as c:
            c.execute(
                "DELETE FROM invoke_idempotency WHERE task_id=? AND key=? AND attempt=? AND state='in_progress'",
                (task_id, key, attempt),
            )
