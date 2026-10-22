import sqlite3

import pytest

from conftest import ssh, web
from logsentry import store
from logsentry.models import Alert


def numbered(events):
    for i, e in enumerate(events, start=1):
        e.file, e.line = "a.log", i
    return events


def test_ingest_is_idempotent():
    conn = store.connect(":memory:")
    events = numbered([web(t=1), web(t=2), ssh(t=3)])
    assert store.ingest(conn, events) == (3, 0)
    assert store.ingest(conn, events) == (0, 0)
    assert store.counts(conn)["events"] == 3


def test_rejects_are_stored_once():
    conn = store.connect(":memory:")
    assert store.ingest(conn, [], [(4, "bad", "junk")], file="a.log") == (0, 1)
    assert store.ingest(conn, [], [(4, "bad", "junk")], file="a.log") == (0, 0)
    assert store.counts(conn)["rejects"] == 1


def test_events_round_trip_in_time_order():
    conn = store.connect(":memory:")
    store.ingest(conn, numbered([web(t=30), web(t=10, path="/x?a=1"), ssh(t=20)]))
    loaded = store.load_events(conn)
    assert [e.epoch - web().epoch for e in loaded] == [10, 20, 30]
    assert loaded[0].path == "/x?a=1" and loaded[1].action == "failed_password"


def test_alerts_are_replaced_not_appended():
    conn = store.connect(":memory:")
    a = Alert("WEB-001", "high", "1.2.3.4", 10, 20, 3, "s", evidence=["x", "y"])
    store.replace_alerts(conn, [a])
    store.replace_alerts(conn, [a, a])
    loaded = store.load_alerts(conn)
    assert len(loaded) == 2 and loaded[0].evidence == ["x", "y"]


def test_schema_constraints_reject_bad_rows():
    conn = store.connect(":memory:")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO events (source, epoch, ip, raw, file, line) VALUES ('mail', 1, 'x', 'r', 'f', 1)")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO alerts (rule_id, severity, ip, first_epoch, last_epoch, count, summary, evidence) "
                     "VALUES ('R', 'severe', 'x', 1, 2, 1, 's', '[]')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO alerts (rule_id, severity, ip, first_epoch, last_epoch, count, summary, evidence) "
                     "VALUES ('R', 'low', 'x', 5, 2, 1, 's', '[]')")
