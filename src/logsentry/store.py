"""SQLite storage. Ingest is idempotent: the same file and line is stored once."""
from __future__ import annotations

import json
import sqlite3
from typing import Iterable, List, Optional, Tuple

from .models import Alert, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY,
    source  TEXT NOT NULL CHECK (source IN ('web', 'auth')),
    epoch   INTEGER NOT NULL,
    ip      TEXT NOT NULL,
    user    TEXT,
    method  TEXT,
    path    TEXT,
    status  INTEGER,
    size    INTEGER,
    ua      TEXT,
    action  TEXT,
    raw     TEXT NOT NULL,
    file    TEXT NOT NULL,
    line    INTEGER NOT NULL,
    UNIQUE (file, line)
);
CREATE INDEX IF NOT EXISTS ix_events_ip_epoch ON events (ip, epoch);
CREATE INDEX IF NOT EXISTS ix_events_source_epoch ON events (source, epoch);

CREATE TABLE IF NOT EXISTS rejects (
    id     INTEGER PRIMARY KEY,
    file   TEXT NOT NULL,
    line   INTEGER NOT NULL,
    reason TEXT NOT NULL,
    raw    TEXT NOT NULL,
    UNIQUE (file, line)
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    ip          TEXT NOT NULL,
    user        TEXT,
    first_epoch INTEGER NOT NULL,
    last_epoch  INTEGER NOT NULL CHECK (last_epoch >= first_epoch),
    count       INTEGER NOT NULL CHECK (count >= 1),
    summary     TEXT NOT NULL,
    evidence    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_alerts_ip ON alerts (ip);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def ingest(conn: sqlite3.Connection, events: Iterable[Event], rejects: Iterable[Tuple[int, str, str]] = (),
           file: str = "") -> Tuple[int, int]:
    """Insert events and rejects. Returns (new events, new rejects); duplicates are skipped."""
    new_events = new_rejects = 0
    with conn:
        for e in events:
            cur = conn.execute(
                "INSERT OR IGNORE INTO events (source, epoch, ip, user, method, path, status, size, ua, action, raw, file, line) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (e.source, e.epoch, e.ip, e.user, e.method, e.path, e.status, e.size, e.ua, e.action, e.raw, e.file, e.line))
            new_events += cur.rowcount
        for line, reason, raw in rejects:
            cur = conn.execute("INSERT OR IGNORE INTO rejects (file, line, reason, raw) VALUES (?,?,?,?)",
                               (file, line, reason, raw))
            new_rejects += cur.rowcount
    return new_events, new_rejects


def load_events(conn: sqlite3.Connection) -> List[Event]:
    rows = conn.execute("SELECT * FROM events ORDER BY epoch, id").fetchall()
    return [Event(source=r["source"], epoch=r["epoch"], ip=r["ip"], user=r["user"], method=r["method"],
                  path=r["path"], status=r["status"], size=r["size"], ua=r["ua"], action=r["action"],
                  raw=r["raw"], file=r["file"], line=r["line"], id=r["id"]) for r in rows]


def replace_alerts(conn: sqlite3.Connection, alerts: Iterable[Alert]) -> int:
    """Alerts are derived data, so each detection run replaces the previous set."""
    n = 0
    with conn:
        conn.execute("DELETE FROM alerts")
        for a in alerts:
            conn.execute(
                "INSERT INTO alerts (rule_id, severity, ip, user, first_epoch, last_epoch, count, summary, evidence) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (a.rule_id, a.severity, a.ip, a.user, a.first_epoch, a.last_epoch, a.count, a.summary,
                 json.dumps(a.evidence)))
            n += 1
    return n


def load_alerts(conn: sqlite3.Connection) -> List[Alert]:
    rows = conn.execute("SELECT * FROM alerts ORDER BY first_epoch, id").fetchall()
    return [Alert(rule_id=r["rule_id"], severity=r["severity"], ip=r["ip"], user=r["user"],
                  first_epoch=r["first_epoch"], last_epoch=r["last_epoch"], count=r["count"],
                  summary=r["summary"], evidence=json.loads(r["evidence"]), id=r["id"]) for r in rows]


def counts(conn: sqlite3.Connection) -> dict:
    one = lambda sql: conn.execute(sql).fetchone()[0]
    return {"events": one("SELECT COUNT(*) FROM events"),
            "web_events": one("SELECT COUNT(*) FROM events WHERE source='web'"),
            "auth_events": one("SELECT COUNT(*) FROM events WHERE source='auth'"),
            "rejects": one("SELECT COUNT(*) FROM rejects"),
            "alerts": one("SELECT COUNT(*) FROM alerts")}
