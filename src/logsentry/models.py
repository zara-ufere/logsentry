"""Plain data types shared by every stage of the pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_rank(name: str) -> int:
    return SEVERITY_RANK[name]


def fmt_epoch(epoch: int) -> str:
    """UTC timestamp as 'YYYY-MM-DD HH:MM:SS'."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class Event:
    """One normalised log record. Web and SSH logs both become Events."""
    source: str                 # 'web' or 'auth'
    epoch: int                  # seconds since 1970, UTC
    ip: str
    raw: str
    user: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None  # request target as logged, query string included
    status: Optional[int] = None
    size: Optional[int] = None
    ua: Optional[str] = None
    action: Optional[str] = None  # auth only: failed_password, accepted, invalid_user
    file: str = ""
    line: int = 0
    id: Optional[int] = None


@dataclass
class Alert:
    rule_id: str
    severity: str
    ip: str
    first_epoch: int
    last_epoch: int
    count: int
    summary: str
    user: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    id: Optional[int] = None
