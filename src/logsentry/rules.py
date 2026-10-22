"""Detection rules.

Every rule takes the full, time-ordered list of Events and returns Alerts.
Two kinds of rule exist:

* signature rules look inside a single request for a known attack pattern
  (SQL injection, path traversal, and so on);
* behaviour rules count what one source IP does inside a time window
  (many failed logins, many distinct 404s, and so on).

Thresholds live in Config so they can be tuned without touching the logic.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, fields
from typing import Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import unquote_plus

from .models import Alert, Event, fmt_epoch


@dataclass(frozen=True)
class RuleInfo:
    id: str
    name: str
    source: str            # 'web' or 'auth'
    severity: str          # default severity; some rules escalate
    owasp: Optional[str]   # OWASP Top 10 (2021) category, if one applies
    attack: str            # MITRE ATT&CK technique id
    stage: str             # recon, exploit, credential or compromise
    description: str


RULES: List[RuleInfo] = [
    RuleInfo("WEB-001", "SQL injection attempt", "web", "high", "A03:2021 Injection", "T1190", "exploit",
             "Request contains SQL syntax typical of injection: UNION SELECT, tautologies, time delays, schema probing."),
    RuleInfo("WEB-002", "Path traversal or file inclusion attempt", "web", "high",
             "A01:2021 Broken Access Control", "T1190", "exploit",
             "Request tries to read files outside the web root using ../ sequences, system file names or PHP wrappers."),
    RuleInfo("WEB-003", "Cross-site scripting probe", "web", "medium", "A03:2021 Injection", "T1190", "exploit",
             "Request carries script tags, javascript: URLs or event-handler attributes."),
    RuleInfo("WEB-004", "Known attack tool user agent", "web", "medium", None, "T1595.002", "recon",
             "User agent identifies a vulnerability scanner or brute force tool such as sqlmap, nikto or gobuster."),
    RuleInfo("WEB-005", "Forced browsing (many distinct 404s)", "web", "medium",
             "A01:2021 Broken Access Control", "T1595.003", "recon",
             "One IP requested many different missing paths in a short time, which is what wordlist scanners do."),
    RuleInfo("WEB-006", "Web login brute force", "web", "high",
             "A07:2021 Identification and Authentication Failures", "T1110", "credential",
             "Many failed POSTs to a login URL from one IP. Escalates to critical if a successful login follows."),
    RuleInfo("WEB-007", "Sensitive file or admin panel probing", "web", "medium",
             "A05:2021 Security Misconfiguration", "T1595.003", "recon",
             "Requests for .env, .git, backups, config files or admin panels. Critical if the server answered 200."),
    RuleInfo("WEB-008", "Log4Shell JNDI lookup attempt", "web", "high", "A06:2021 Vulnerable and Outdated Components",
             "T1190", "exploit", "A ${jndi:...} style lookup string appears in the request or user agent."),
    RuleInfo("AUTH-001", "SSH brute force", "auth", "high",
             "A07:2021 Identification and Authentication Failures", "T1110.001", "credential",
             "Many failed SSH passwords from one IP in a short window."),
    RuleInfo("AUTH-002", "SSH password spraying", "auth", "high",
             "A07:2021 Identification and Authentication Failures", "T1110.003", "credential",
             "One IP tried many different usernames, which suggests guessing common passwords across accounts."),
    RuleInfo("AUTH-003", "SSH success after repeated failures", "auth", "critical",
             "A07:2021 Identification and Authentication Failures", "T1078", "compromise",
             "A login succeeded from an IP that had just failed repeatedly. Treat the account as possibly compromised."),
    RuleInfo("AUTH-004", "Slow SSH brute force", "auth", "medium",
             "A07:2021 Identification and Authentication Failures", "T1110.001", "credential",
             "Many failures spread over a day, slow enough to slip under the fast-burst rule."),
]
RULE_BY_ID: Dict[str, RuleInfo] = {r.id: r for r in RULES}


@dataclass
class Config:
    burst_gap: int = 900                      # seconds of quiet that ends a signature-rule burst
    login_paths: Tuple[str, ...] = ("/login", "/signin", "/wp-login.php", "/admin/login", "/user/login", "/api/login")
    login_fail_statuses: Tuple[int, ...] = (401, 403)
    login_success_statuses: Tuple[int, ...] = (302, 303)
    web_bruteforce_threshold: int = 10
    web_bruteforce_window: int = 60
    web_success_followup: int = 120
    forced_browsing_threshold: int = 15       # distinct missing paths
    forced_browsing_window: int = 60
    ssh_bruteforce_threshold: int = 8
    ssh_bruteforce_window: int = 120
    ssh_spray_users: int = 5
    ssh_spray_window: int = 600
    ssh_success_failures: int = 5
    ssh_success_lookback: int = 600
    ssh_slow_threshold: int = 30
    ssh_slow_window: int = 86400
    ignore_networks: Tuple[str, ...] = ()     # CIDR ranges to trust, for example internal address space

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ValueError("unknown config keys: " + ", ".join(sorted(unknown)))
        values = {}
        for key, value in data.items():
            values[key] = tuple(value) if isinstance(value, list) else value
        return cls(**values)


# ---------------------------------------------------------------- helpers

def decode_target(text: str) -> str:
    """URL-decode repeatedly so double encoding (%252e) cannot hide a payload."""
    for _ in range(3):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text


def bursts(times: Sequence[int], window: int, threshold: int) -> List[Tuple[int, int]]:
    """Index ranges where `threshold` or more times fall inside `window` seconds.
    Overlapping windows are merged so one attack gives one range, not hundreds."""
    out: List[Tuple[int, int]] = []
    lo = 0
    for hi in range(len(times)):
        while times[hi] - times[lo] >= window:
            lo += 1
        if hi - lo + 1 >= threshold:
            if out and lo <= out[-1][1]:
                out[-1] = (out[-1][0], hi)
            else:
                out.append((lo, hi))
    return out


def distinct_bursts(times: Sequence[int], keys: Sequence[str], window: int, threshold: int) -> List[Tuple[int, int]]:
    """Like bursts() but counts distinct keys (paths, usernames) inside the window."""
    out: List[Tuple[int, int]] = []
    lo = 0
    seen: Dict[str, int] = {}
    for hi in range(len(times)):
        seen[keys[hi]] = seen.get(keys[hi], 0) + 1
        while times[hi] - times[lo] >= window:
            k = keys[lo]
            seen[k] -= 1
            if seen[k] == 0:
                del seen[k]
            lo += 1
        if len(seen) >= threshold:
            if out and lo <= out[-1][1]:
                out[-1] = (out[-1][0], hi)
            else:
                out.append((lo, hi))
    return out


def group_by_ip(events: Sequence[Event]) -> Dict[str, List[Event]]:
    groups: Dict[str, List[Event]] = {}
    for e in events:
        groups.setdefault(e.ip, []).append(e)
    return groups


def split_on_gap(events: List[Event], gap: int) -> List[List[Event]]:
    runs: List[List[Event]] = []
    for e in events:
        if runs and e.epoch - runs[-1][-1].epoch <= gap:
            runs[-1].append(e)
        else:
            runs.append([e])
    return runs


def evidence_of(events: Sequence[Event], limit: int = 5) -> List[str]:
    return [e.raw for e in events[:limit]]


def evidence_ending_with(events: Sequence[Event], limit: int = 5) -> List[str]:
    """Evidence for alerts whose last event is the decisive one (a successful login): keep the
    first few lines and always include that final line."""
    if len(events) <= limit:
        return [e.raw for e in events]
    return [e.raw for e in events[:limit - 1]] + [events[-1].raw]


def make_alert(rule_id: str, ip: str, events: Sequence[Event], summary: str, severity: Optional[str] = None,
               user: Optional[str] = None, decisive_last: bool = False) -> Alert:
    return Alert(rule_id=rule_id, severity=severity or RULE_BY_ID[rule_id].severity, ip=ip,
                 first_epoch=events[0].epoch, last_epoch=events[-1].epoch, count=len(events),
                 summary=summary, user=user,
                 evidence=evidence_ending_with(events) if decisive_last else evidence_of(events))


def signature_rule(rule_id: str, events: Sequence[Event], matcher: Callable[[Event], bool], noun: str,
                   cfg: Config) -> List[Alert]:
    """One alert per burst of matching requests from one IP."""
    hits = [e for e in events if e.source == "web" and e.path and matcher(e)]
    alerts: List[Alert] = []
    for ip, group in group_by_ip(hits).items():
        for run in split_on_gap(group, cfg.burst_gap):
            alerts.append(make_alert(rule_id, ip, run, "%d %s from %s" % (len(run), noun, ip)))
    return alerts


# ---------------------------------------------------------------- web rules

SQLI = [re.compile(p, re.I) for p in (
    r"union(?:\s|/\*.*?\*/)+(?:all\s+)?select",
    r"['\"]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
    r"\b(?:or|and)\s+\d+\s*=\s*\d+",
    r"['\"]\s*(?:--|#|/\*)",
    r"\b(?:sleep|benchmark|pg_sleep|extractvalue|updatexml)\s*\(",
    r"waitfor\s+delay",
    r"information_schema|sqlite_master|pg_catalog|sysobjects|mysql\.user",
    r";\s*(?:drop|insert|update|delete|select|exec)\b",
)]
TRAVERSAL = [re.compile(p, re.I) for p in (
    r"\.\./|\.\.\\",
    r"/etc/(?:passwd|shadow|hosts|group)",
    r"\b(?:boot|win)\.ini\b",
    r"\b(?:php|file|expect|data|zip|phar)://",
    r"/proc/self/",
)]
XSS = [re.compile(p, re.I) for p in (
    r"<\s*script",
    r"javascript\s*:",
    r"\bon(?:error|load|mouseover|focus|click)\s*=",
    r"<\s*(?:img|svg|iframe|body)\b[^>]*>",
    r"document\.cookie|alert\s*\(",
)]
JNDI = re.compile(r"\$\{\s*(?:jndi|env|lower|upper)\s*:", re.I)
SCANNER_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|zgrab|nuclei|acunetix|nessus|openvas|feroxbuster|hydra", re.I)
SECRET_PATHS = [re.compile(p, re.I) for p in (
    r"/\.env(?:[./?]|$)", r"/\.git(?:/|$)", r"/\.svn/", r"/\.aws/", r"/\.ssh/", r"/\.htpasswd",
    r"/wp-config\.php", r"/id_rsa", r"\.(?:sql|bak|old|orig|swp)(?:\?|$)",
    r"/(?:backup|dump|database|site)\.(?:sql|zip|tar\.gz)",
)]
PANEL_PATHS = [re.compile(p, re.I) for p in (
    r"/(?:phpmyadmin|pma)(?:/|$|\?)", r"/server-(?:status|info)(?:/|$|\?)", r"/manager/html", r"/solr/admin",
)]


def _any(patterns, text: str) -> bool:
    return any(p.search(text) for p in patterns)


def rule_sqli(events, cfg):
    return signature_rule("WEB-001", events, lambda e: _any(SQLI, decode_target(e.path)), "SQL injection requests", cfg)


def rule_traversal(events, cfg):
    return signature_rule("WEB-002", events, lambda e: _any(TRAVERSAL, decode_target(e.path)),
                          "path traversal requests", cfg)


def rule_xss(events, cfg):
    return signature_rule("WEB-003", events, lambda e: _any(XSS, decode_target(e.path)), "XSS probe requests", cfg)


def rule_jndi(events, cfg):
    return signature_rule("WEB-008", events,
                          lambda e: bool(JNDI.search(decode_target(e.path)) or (e.ua and JNDI.search(decode_target(e.ua)))),
                          "JNDI lookup requests", cfg)


def rule_scanner_ua(events, cfg):
    hits = [e for e in events if e.source == "web" and e.ua and SCANNER_UA.search(e.ua)]
    alerts = []
    for ip, group in group_by_ip(hits).items():
        tool = SCANNER_UA.search(group[0].ua).group(0).lower()
        alerts.append(make_alert("WEB-004", ip, group, "%d requests from %s using the %s tool" % (len(group), ip, tool)))
    return alerts


def _path_only(e: Event) -> str:
    return decode_target(e.path.split("?", 1)[0]).lower()


def rule_forced_browsing(events, cfg):
    missing = [e for e in events if e.source == "web" and e.status == 404 and e.path]
    alerts = []
    for ip, group in group_by_ip(missing).items():
        times = [e.epoch for e in group]
        keys = [_path_only(e) for e in group]
        for lo, hi in distinct_bursts(times, keys, cfg.forced_browsing_window, cfg.forced_browsing_threshold):
            span = group[lo:hi + 1]
            distinct = len(set(keys[lo:hi + 1]))
            alerts.append(make_alert("WEB-005", ip, span,
                                     "%d distinct missing paths requested by %s" % (distinct, ip)))
    return alerts


def rule_login_bruteforce(events, cfg):
    logins = [e for e in events if e.source == "web" and e.method == "POST" and e.path
              and _path_only(e) in cfg.login_paths]
    alerts = []
    for ip, group in group_by_ip(logins).items():
        failures = [e for e in group if e.status in cfg.login_fail_statuses]
        times = [e.epoch for e in failures]
        for lo, hi in bursts(times, cfg.web_bruteforce_window, cfg.web_bruteforce_threshold):
            span = failures[lo:hi + 1]
            won = [e for e in group if e.status in cfg.login_success_statuses
                   and span[-1].epoch < e.epoch <= span[-1].epoch + cfg.web_success_followup]
            summary = "%d failed logins from %s" % (len(span), ip)
            severity = None
            if won:
                span = span + won[:1]
                summary += ", followed by a successful login"
                severity = "critical"
            alerts.append(make_alert("WEB-006", ip, span, summary, severity, decisive_last=bool(won)))
    return alerts


def _sensitive_kind(e: Event) -> Optional[str]:
    """'secret' for files that should never be served, 'panel' for admin consoles, else None."""
    target = decode_target(e.path or "")
    if _any(SECRET_PATHS, target):
        return "secret"
    if _any(PANEL_PATHS, target):
        return "panel"
    return None


def rule_sensitive_paths(events, cfg):
    hits = [e for e in events if e.source == "web" and e.path and _sensitive_kind(e)]
    alerts = []
    for ip, group in group_by_ip(hits).items():
        for run in split_on_gap(group, cfg.burst_gap):
            secret_served = any(e.status == 200 and _sensitive_kind(e) == "secret" for e in run)
            panel_served = any(e.status == 200 and _sensitive_kind(e) == "panel" for e in run)
            severity = "critical" if secret_served else "high" if panel_served else "medium"
            note = (" and the server answered 200 for a secret file" if secret_served
                    else " and an admin panel answered 200" if panel_served else "")
            alerts.append(make_alert("WEB-007", ip, run,
                                     "%d requests for sensitive paths from %s%s" % (len(run), ip, note), severity))
    return alerts


# ---------------------------------------------------------------- ssh rules

def _failed_by_ip(events) -> Dict[str, List[Event]]:
    return group_by_ip([e for e in events if e.source == "auth" and e.action == "failed_password"])


def rule_ssh_bruteforce(events, cfg):
    alerts = []
    for ip, group in _failed_by_ip(events).items():
        times = [e.epoch for e in group]
        for lo, hi in bursts(times, cfg.ssh_bruteforce_window, cfg.ssh_bruteforce_threshold):
            span = group[lo:hi + 1]
            users = sorted({e.user for e in span if e.user})
            alerts.append(make_alert("AUTH-001", ip, span, "%d failed SSH logins from %s against %s" % (
                len(span), ip, ", ".join(users[:3]) + ("..." if len(users) > 3 else ""))))
    return alerts


def rule_ssh_spray(events, cfg):
    alerts = []
    for ip, group in _failed_by_ip(events).items():
        times = [e.epoch for e in group]
        keys = [e.user or "?" for e in group]
        for lo, hi in distinct_bursts(times, keys, cfg.ssh_spray_window, cfg.ssh_spray_users):
            span = group[lo:hi + 1]
            alerts.append(make_alert("AUTH-002", ip, span, "%s tried %d different usernames" % (
                ip, len(set(keys[lo:hi + 1])))))
    return alerts


def rule_ssh_success_after_failures(events, cfg):
    failures = _failed_by_ip(events)
    alerts: List[Alert] = []
    last_alert: Dict[Tuple[str, str], int] = {}
    for e in events:
        if e.source != "auth" or e.action != "accepted":
            continue
        prior = [f for f in failures.get(e.ip, []) if e.epoch - cfg.ssh_success_lookback <= f.epoch < e.epoch]
        if len(prior) < cfg.ssh_success_failures:
            continue
        key = (e.ip, e.user or "")
        if key in last_alert and e.epoch - last_alert[key] <= cfg.ssh_success_lookback:
            continue
        last_alert[key] = e.epoch
        alerts.append(make_alert("AUTH-003", e.ip, prior + [e], "%s logged in as %s after %d failed attempts" % (
            e.ip, e.user, len(prior)), user=e.user, decisive_last=True))
    return alerts


def rule_ssh_slow(events, cfg):
    alerts = []
    for ip, group in _failed_by_ip(events).items():
        times = [e.epoch for e in group]
        for lo, hi in bursts(times, cfg.ssh_slow_window, cfg.ssh_slow_threshold):
            span = group[lo:hi + 1]
            alerts.append(make_alert("AUTH-004", ip, span, "%d failed SSH logins from %s spread over %s" % (
                len(span), ip, _duration(span[-1].epoch - span[0].epoch))))
    return alerts


def _duration(seconds: int) -> str:
    if seconds >= 3600:
        return "%.1f hours" % (seconds / 3600.0)
    return "%d minutes" % max(1, seconds // 60)


RULE_FUNCS: Dict[str, Callable[[Sequence[Event], Config], List[Alert]]] = {
    "WEB-001": rule_sqli, "WEB-002": rule_traversal, "WEB-003": rule_xss, "WEB-004": rule_scanner_ua,
    "WEB-005": rule_forced_browsing, "WEB-006": rule_login_bruteforce, "WEB-007": rule_sensitive_paths,
    "WEB-008": rule_jndi, "AUTH-001": rule_ssh_bruteforce, "AUTH-002": rule_ssh_spray,
    "AUTH-003": rule_ssh_success_after_failures, "AUTH-004": rule_ssh_slow,
}


def _trusted(ip: str, networks) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def run_rules(events: Sequence[Event], cfg: Optional[Config] = None,
              only: Optional[Sequence[str]] = None) -> List[Alert]:
    cfg = cfg or Config()
    if cfg.ignore_networks:
        networks = [ipaddress.ip_network(n, strict=False) for n in cfg.ignore_networks]
        events = [e for e in events if not _trusted(e.ip, networks)]
    alerts: List[Alert] = []
    for rule_id, func in RULE_FUNCS.items():
        if only and rule_id not in only:
            continue
        alerts.extend(func(events, cfg))
    # The slow-brute-force rule is only interesting when the fast rule did not already fire for that IP.
    fast = {a.ip for a in alerts if a.rule_id == "AUTH-001"}
    alerts = [a for a in alerts if not (a.rule_id == "AUTH-004" and a.ip in fast)]
    alerts.sort(key=lambda a: (a.first_epoch, a.rule_id, a.ip))
    return alerts
