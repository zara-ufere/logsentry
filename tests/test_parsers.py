import pytest

from logsentry.parsers import ParseError, parse_auth_line, parse_lines, parse_web_line, parse_web_time

GOOD = ('203.0.113.5 - bob [10/Oct/2026:13:55:36 -0400] "GET /products?id=3 HTTP/1.1" 200 2326 '
        '"https://shop.example.test/" "Mozilla/5.0 (X11; Linux)"')


def test_web_line_fields():
    e = parse_web_line(GOOD)
    assert (e.source, e.ip, e.user, e.method, e.path, e.status, e.size) == (
        "web", "203.0.113.5", "bob", "GET", "/products?id=3", 200, 2326)
    assert e.ua == "Mozilla/5.0 (X11; Linux)"


def test_timezone_offset_is_converted_to_utc():
    utc = parse_web_time("10/Oct/2026:17:55:36 +0000")
    assert parse_web_time("10/Oct/2026:13:55:36 -0400") == utc
    assert parse_web_time("10/Oct/2026:19:55:36 +0200") == utc


def test_dash_fields_become_none():
    e = parse_web_line('1.2.3.4 - - [10/Oct/2026:00:00:00 +0000] "GET / HTTP/1.1" 304 - "-" "-"')
    assert e.user is None and e.size is None and e.ua is None


def test_malformed_request_line_is_kept_not_dropped():
    e = parse_web_line('1.2.3.4 - - [10/Oct/2026:00:00:00 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"')
    assert e.method is None and e.path == "\\x16\\x03\\x01" and e.status == 400


def test_nginx_escaped_quote_parses():
    e = parse_web_line('1.2.3.4 - - [10/Oct/2026:00:00:00 +0000] "GET /a?q=\\x22x HTTP/1.1" 200 5 "-" "ua"')
    assert e.path == "/a?q=\\x22x"


def test_raw_quote_inside_request_is_rejected():
    with pytest.raises(ParseError):
        parse_web_line('1.2.3.4 - - [10/Oct/2026:00:00:00 +0000] "GET /a?q="x HTTP/1.1" 200 5 "-" "ua"')


@pytest.mark.parametrize("line", ["", "garbage", '1.2.3.4 - - [bad time] "GET / HTTP/1.1" 200 5 "-" "ua"',
                                  '1.2.3.4 - - [32/Foo/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "ua"'])
def test_bad_web_lines_raise(line):
    with pytest.raises(ParseError):
        parse_web_line(line)


def test_auth_failed_password_valid_and_invalid_user():
    a = parse_auth_line("Oct  2 03:14:07 web01 sshd[1234]: Failed password for root from 192.0.2.7 port 51234 ssh2", 2026)
    assert (a.action, a.user, a.ip) == ("failed_password", "root", "192.0.2.7")
    b = parse_auth_line("Oct 22 03:14:07 web01 sshd[1234]: Failed password for invalid user admin from 192.0.2.7 port 1 ssh2", 2026)
    assert (b.action, b.user) == ("failed_password", "admin")


def test_auth_accepted_and_invalid_user_actions():
    a = parse_auth_line("Oct 22 03:14:07 web01 sshd[1]: Accepted publickey for alice from 10.0.0.5 port 22 ssh2", 2026)
    assert (a.action, a.user) == ("accepted", "alice")
    i = parse_auth_line("Oct 22 03:14:07 web01 sshd[1]: Invalid user oracle from 192.0.2.7 port 40000", 2026)
    assert i.action == "invalid_user"


def test_auth_ipv6_and_year_argument():
    a = parse_auth_line("Jan  5 00:00:01 h sshd[9]: Failed password for root from 2001:db8::1 port 22 ssh2", 2024)
    assert a.ip == "2001:db8::1"
    b = parse_auth_line("Jan  5 00:00:01 h sshd[9]: Failed password for root from 2001:db8::1 port 22 ssh2", 2025)
    assert b.epoch - a.epoch == 366 * 86400   # 2024 is a leap year


@pytest.mark.parametrize("line", [
    "Oct 22 03:14:07 web01 CRON[1]: pam_unix(cron:session): session opened",
    "Oct 22 03:14:07 web01 sshd[1]: Connection closed by 192.0.2.7 port 1 [preauth]",
    "not syslog at all"])
def test_uninteresting_auth_lines_are_rejected(line):
    with pytest.raises(ParseError):
        parse_auth_line(line, 2026)


def test_parse_lines_counts_rejects_and_skips_blanks():
    events, rejects = parse_lines([GOOD + "\n", "\n", "junk\n", GOOD], "web")
    assert len(events) == 2 and [e.line for e in events] == [1, 4]
    assert len(rejects) == 1 and rejects[0][0] == 3 and rejects[0][2] == "junk"
