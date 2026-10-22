import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest

from logsentry.models import Event

T0 = 1_790_000_000  # a fixed instant so tests never depend on the clock


def web(ip="198.51.100.9", t=0, method="GET", path="/", status=200, ua="Mozilla/5.0", user=None):
    raw = '%s - - [t=%d] "%s %s HTTP/1.1" %d 100 "-" "%s"' % (ip, t, method, path, status, ua)
    return Event(source="web", epoch=T0 + t, ip=ip, raw=raw, user=user, method=method, path=path,
                 status=status, size=100, ua=ua)


def ssh(ip="192.0.2.9", t=0, action="failed_password", user="root"):
    raw = "t=%d sshd: %s for %s from %s" % (t, action, user, ip)
    return Event(source="auth", epoch=T0 + t, ip=ip, raw=raw, user=user, action=action)


@pytest.fixture
def make_web():
    return web


@pytest.fixture
def make_ssh():
    return ssh
