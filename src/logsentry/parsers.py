"""Parsers that turn raw log lines into Events.

Two formats are supported: the nginx/Apache "combined" access log and OpenSSH
messages in a syslog-style auth.log. A line that does not parse is reported as
a reject with a reason instead of crashing the run or being silently dropped.
"""
from __future__ import annotations

import re
from calendar import timegm
from typing import Iterable, Iterator, List, Optional, Tuple

from .models import Event

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<req>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"\s*$')
WEB_TIME_RE = re.compile(r'^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d\d):(\d\d):(\d\d) ([+-])(\d\d)(\d\d)$')

SYSLOG_RE = re.compile(
    r'^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d\d:\d\d:\d\d) (?P<host>\S+) '
    r'(?P<proc>[\w\-/.]+)(?:\[\d+\])?: (?P<msg>.*)$')
FAILED_RE = re.compile(r'^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+')
ACCEPTED_RE = re.compile(r'^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+')
INVALID_RE = re.compile(r'^Invalid user (?P<user>\S+) from (?P<ip>\S+)')


class ParseError(ValueError):
    pass


def _dash(value: str) -> Optional[str]:
    return None if value == "-" else value


def parse_web_time(text: str) -> int:
    m = WEB_TIME_RE.match(text)
    if not m or m.group(2) not in MONTHS:
        raise ParseError("bad timestamp")
    day, mon, year, hh, mm, ss, sign, oh, om = m.groups()
    try:
        epoch = timegm((int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss), 0, 0, 0))
    except (ValueError, OverflowError):
        raise ParseError("bad timestamp")
    offset = int(oh) * 3600 + int(om) * 60
    return epoch - offset if sign == "+" else epoch + offset


def parse_web_line(line: str) -> Event:
    m = WEB_RE.match(line.rstrip("\n"))
    if not m:
        raise ParseError("not a combined-format access log line")
    epoch = parse_web_time(m.group("time"))
    parts = m.group("req").split(" ")
    method = path = None
    if len(parts) >= 2 and parts[0].isalpha():
        method, path = parts[0].upper(), parts[1]
    else:
        path = m.group("req") or None   # malformed or empty request line, kept for inspection
    size = None if m.group("size") == "-" else int(m.group("size")) if m.group("size").isdigit() else None
    return Event(source="web", epoch=epoch, ip=m.group("ip"), user=_dash(m.group("user")), method=method,
                 path=path, status=int(m.group("status")), size=size, ua=_dash(m.group("ua")),
                 raw=line.rstrip("\n"))


def parse_auth_line(line: str, year: int) -> Event:
    """Parse one sshd line. Syslog timestamps carry no year or zone, so the caller
    supplies the year and times are treated as UTC."""
    m = SYSLOG_RE.match(line.rstrip("\n"))
    if not m or m.group("mon") not in MONTHS:
        raise ParseError("not a syslog line")
    if not m.group("proc").startswith("sshd"):
        raise ParseError("not an sshd message")
    hh, mm, ss = (int(x) for x in m.group("time").split(":"))
    try:
        epoch = timegm((year, MONTHS[m.group("mon")], int(m.group("day")), hh, mm, ss, 0, 0, 0))
    except (ValueError, OverflowError):
        raise ParseError("bad timestamp")
    msg = m.group("msg")
    for regex, action in ((FAILED_RE, "failed_password"), (ACCEPTED_RE, "accepted"), (INVALID_RE, "invalid_user")):
        hit = regex.match(msg)
        if hit:
            return Event(source="auth", epoch=epoch, ip=hit.group("ip"), user=hit.group("user"),
                         action=action, raw=line.rstrip("\n"))
    raise ParseError("sshd message of no interest")


Reject = Tuple[int, str, str]   # line number, reason, raw line


def parse_lines(lines: Iterable[str], kind: str, year: int = 0) -> Tuple[List[Event], List[Reject]]:
    """Parse many lines. Returns (events, rejects). Blank lines are ignored.
    Event.line is the 1-based line number in the input."""
    events: List[Event] = []
    rejects: List[Reject] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = parse_web_line(line) if kind == "web" else parse_auth_line(line, year)
        except ParseError as exc:
            rejects.append((number, str(exc), line.rstrip("\n")[:500]))
            continue
        event.line = number
        events.append(event)
    return events, rejects


def read_file(path: str, kind: str, year: int = 0) -> Tuple[List[Event], List[Reject]]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        events, rejects = parse_lines(handle, kind, year)
    for event in events:
        event.file = path
    return events, rejects
