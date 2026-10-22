import re

from conftest import web
from logsentry import report
from logsentry.evaluate import evaluate
from logsentry.incidents import build_incidents
from logsentry.models import Alert
from logsentry.rules import run_rules

COUNTS = {"events": 10, "web_events": 7, "auth_events": 3, "rejects": 1, "alerts": 1}
PAYLOAD = '<script>alert("pwned")</script>'


def hostile_alert():
    return Alert("WEB-003", "medium", "203.0.113.9<b>", 1_790_000_000, 1_790_000_005, 1,
                 "summary " + PAYLOAD, evidence=['1.2.3.4 "GET /?q=%s" 200' % PAYLOAD, "<img src=x onerror=alert(1)>"])


def test_attacker_controlled_text_is_escaped_everywhere():
    a = hostile_alert()
    page = report.render(COUNTS, [a], build_incidents([a]), title="<title>x</title>")
    assert "<script>alert" not in page and "<img src=x" not in page
    assert "203.0.113.9<b>" not in page and "203.0.113.9&lt;b&gt;" in page       # the hostile IP field is escaped too
    assert "<title>x</title>" not in page and "&lt;title&gt;x&lt;/title&gt;" in page
    assert "&lt;script&gt;alert(&quot;pwned&quot;)&lt;/script&gt;" in page
    assert page.count("<script") == 0


def test_real_log_lines_with_xss_stay_inert():
    alerts = run_rules([web(path="/s?q=<script>alert(1)</script>")])
    page = report.render(COUNTS, alerts, build_incidents(alerts))
    assert "<script" not in page and "&lt;script&gt;" in page


def test_report_is_self_contained():
    a = hostile_alert()
    page = report.render(COUNTS, [a], build_incidents([a]))
    assert not re.search(r"<[a-z][^>]*\s(?:src|href)\s*=", page, re.I)         # no real tag loads anything
    for token in ("<link", "@import", "url(http", "<iframe", "<script", "<img"):
        assert token not in page


def test_empty_report_renders_and_evaluation_section_is_optional():
    page = report.render(COUNTS, [], [])
    assert "No alerts." in page and "How well did it do?" not in page
    labels = {"campaigns": [{"id": "C1", "name": "<b>x</b>", "ips": ["1.1.1.1"], "expected_rules": ["WEB-001"],
                             "allowed_rules": [], "known_gap": False}], "benign_notes": []}
    page = report.render(COUNTS, [], [], evaluate([], labels))
    assert "How well did it do?" in page and "Missed WEB-001" in page and "<b>x</b>" not in page


def test_percent_formatting():
    assert report.pct(None) == "n/a" and report.pct(0.9411) == "94%" and report.pct(1.0) == "100%"
