from conftest import ssh, web
from logsentry.incidents import build_incidents
from logsentry.rules import run_rules


def test_alerts_group_into_one_incident_per_ip_with_stage_order():
    ip = "203.0.113.50"
    events = [web(ip=ip, t=i, path="/x%d" % i, status=404) for i in range(20)]
    events += [web(ip=ip, t=100 + i, path="/p?id=1 OR 1=1") for i in range(3)]
    events += [web(ip="198.51.100.1", path="/p?id=1 OR 1=1")]
    incidents = build_incidents(run_rules(events))
    assert len(incidents) == 2
    mine = [i for i in incidents if i.ip == ip][0]
    assert mine.stages == ["recon", "exploit"] and mine.multi_stage and not mine.compromised


def test_compromise_makes_the_incident_critical():
    events = [ssh(t=i) for i in range(10)] + [ssh(t=60, action="accepted", user="deploy")]
    inc = build_incidents(run_rules(events))[0]
    assert inc.compromised and inc.severity == "critical" and inc.stages[-1] == "compromise"


def test_three_stages_escalate_to_critical():
    ip = "203.0.113.60"
    events = [web(ip=ip, t=i, path="/q%d" % i, status=404) for i in range(20)]
    events += [web(ip=ip, t=100 + i, path="/p?id=1 OR 1=1") for i in range(2)]
    events += [web(ip=ip, t=200 + i, method="POST", path="/login", status=401) for i in range(12)]
    inc = build_incidents(run_rules(events))[0]
    assert len(inc.stages) == 3 and inc.severity == "critical" and not inc.compromised


def test_incidents_sorted_most_serious_first_and_empty_input_ok():
    assert build_incidents([]) == []
    events = [web(ip="1.1.1.1", path="/s?q=<script>")] + [ssh(ip="2.2.2.2", t=i) for i in range(10)]
    assert [i.ip for i in build_incidents(run_rules(events))] == ["2.2.2.2", "1.1.1.1"]
