from conftest import ssh
from logsentry.rules import Config, bursts, distinct_bursts, run_rules


def fire(events, rule, cfg=None):
    return run_rules(events, cfg, only=[rule])


def fails(n, spacing=1, ip="192.0.2.9", user="root", start=0):
    return [ssh(ip=ip, t=start + i * spacing, user=user) for i in range(n)]


def test_bursts_threshold_and_exclusive_window_edge():
    assert bursts([0, 1, 2], window=10, threshold=4) == []
    assert bursts([0, 1, 2, 3], window=10, threshold=4) == [(0, 3)]
    assert bursts([0, 10], window=10, threshold=2) == []          # exactly `window` apart is outside
    assert bursts([0, 9], window=10, threshold=2) == [(0, 1)]


def test_bursts_merge_overlaps_and_keep_separate_attacks_apart():
    assert bursts(list(range(20)), window=5, threshold=3) == [(0, 19)]
    assert bursts([0, 1, 2, 100, 101, 102], window=5, threshold=3) == [(0, 2), (3, 5)]


def test_distinct_bursts_count_unique_keys():
    assert distinct_bursts([0, 1, 2, 3], ["a", "a", "a", "a"], 10, 2) == []
    assert distinct_bursts([0, 1, 2, 3], ["a", "b", "a", "c"], 10, 3) == [(0, 3)]
    assert distinct_bursts([0, 20, 40], ["a", "b", "c"], 30, 3) == []


def test_ssh_bruteforce_boundary():
    assert fire(fails(7), "AUTH-001") == []
    alerts = fire(fails(8), "AUTH-001")
    assert len(alerts) == 1 and alerts[0].count == 8 and alerts[0].severity == "high"


def test_ssh_bruteforce_ignores_slow_attempts_other_ips_and_invalid_user_notices():
    assert fire(fails(8, spacing=20), "AUTH-001") == []                     # 8 over 140s
    mixed = fails(5, ip="1.1.1.1") + fails(5, ip="2.2.2.2")
    assert fire(mixed, "AUTH-001") == []
    notices = [ssh(t=i, action="invalid_user") for i in range(20)]         # sshd logs these in addition to the failure
    assert fire(notices, "AUTH-001") == []


def test_spray_needs_distinct_usernames():
    users = ["a", "b", "c", "d", "e"]
    assert len(fire([ssh(t=i * 30, user=u) for i, u in enumerate(users)], "AUTH-002")) == 1
    assert fire([ssh(t=i * 30, user=u) for i, u in enumerate(users[:4])], "AUTH-002") == []
    assert fire([ssh(t=i * 30, user="root") for i in range(10)], "AUTH-002") == []
    assert fire([ssh(t=i * 200, user=u) for i, u in enumerate(users)], "AUTH-002") == []   # too spread out


def test_success_after_failures_boundary_and_evidence():
    ok = fails(5) + [ssh(t=30, action="accepted", user="deploy")]
    alert = fire(ok, "AUTH-003")[0]
    assert alert.severity == "critical" and alert.user == "deploy" and "Accepted" not in alert.summary
    assert "accepted" in alert.evidence[-1]
    assert fire(fails(4) + [ssh(t=30, action="accepted")], "AUTH-003") == []


def test_success_after_failures_respects_lookback_and_source_ip():
    assert fire(fails(6) + [ssh(t=5000, action="accepted")], "AUTH-003") == []
    assert fire(fails(6, ip="1.1.1.1") + [ssh(ip="2.2.2.2", t=30, action="accepted")], "AUTH-003") == []


def test_repeated_successes_do_not_repeat_the_alert():
    events = fails(6) + [ssh(t=30 + i * 60, action="accepted", user="deploy") for i in range(4)]
    assert len(fire(events, "AUTH-003")) == 1


def test_slow_bruteforce_and_suppression_by_fast_rule():
    slow = fails(30, spacing=1200)                                           # 30 failures over about 10 hours
    assert len(fire(slow, "AUTH-004")) == 1
    assert fire(fails(29, spacing=1200), "AUTH-004") == []
    both = fails(40, spacing=1)                                              # fast attack also exceeds the slow threshold
    ids = {a.rule_id for a in run_rules(both)}
    assert ids == {"AUTH-001"}


def test_config_from_dict_validates_and_converts():
    cfg = Config.from_dict({"ssh_bruteforce_threshold": 3, "ignore_networks": ["10.0.0.0/8"]})
    assert cfg.ssh_bruteforce_threshold == 3 and cfg.ignore_networks == ("10.0.0.0/8",)
    try:
        Config.from_dict({"nonsense": 1})
        assert False, "should have raised"
    except ValueError as exc:
        assert "nonsense" in str(exc)


def test_threshold_override_changes_behaviour():
    assert len(fire(fails(3), "AUTH-001", Config(ssh_bruteforce_threshold=3))) == 1
