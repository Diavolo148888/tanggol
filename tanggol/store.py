"""Event store — SQLite, thread-safe, zero config."""

from __future__ import annotations

import datetime as _dt
import json
import pathlib
import sqlite3
import threading

DEFAULT_DB = pathlib.Path(pathlib.Path.home() / ".tanggol" / "events.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  kind TEXT NOT NULL,          -- ssh_auth | portscan | http_hit | feed
  src TEXT NOT NULL,
  dst_port INTEGER,
  detail TEXT NOT NULL DEFAULT '',
  alert INTEGER NOT NULL DEFAULT 0,
  alert_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
"""


def utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class Store:
    def __init__(self, path: pathlib.Path | str | None = None):
        self.path = pathlib.Path(path) if path else DEFAULT_DB
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.Lock()
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def add_event(self, kind: str, src: str, dst_port: int | None = None,
                  detail: str = "", alert: bool = False, alert_reason: str = "") -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO events(ts, kind, src, dst_port, detail, alert, alert_reason)"
                " VALUES (?,?,?,?,?,?,?)",
                (utcnow(), kind, src, dst_port, detail, int(alert), alert_reason),
            )
            self.conn.commit()
        return int(cur.lastrowid)

    def recent(self, limit: int = 100, kind: str | None = None,
               alerts_only: bool = False) -> list[dict]:
        q = "SELECT id, ts, kind, src, dst_port, detail, alert, alert_reason FROM events"
        conds, params = [], []
        if kind:
            conds.append("kind=?"); params.append(kind)
        if alerts_only:
            conds.append("alert=1")
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self.conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        with self._lock:
            total = self.conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
            alerts = self.conn.execute("SELECT COUNT(*) c FROM events WHERE alert=1").fetchone()["c"]
            top = self.conn.execute(
                "SELECT src, COUNT(*) c FROM events GROUP BY src ORDER BY c DESC LIMIT 5"
            ).fetchall()
            by_kind = self.conn.execute(
                "SELECT kind, COUNT(*) c FROM events GROUP BY kind ORDER BY c DESC"
            ).fetchall()
        return {
            "total": total, "alerts": alerts,
            "top_sources": [{"src": r["src"], "count": r["c"]} for r in top],
            "by_kind": [{"kind": r["kind"], "count": r["c"]} for r in by_kind],
        }

    def close(self):
        self.conn.close()
