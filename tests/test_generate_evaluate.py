import json
import os

import pytest

from logsentry import generate, parsers, store
from logsentry.evaluate import evaluate
from logsentry.models import Alert
from logsentry.rules import Config, run_rules

HERE = os.path.dirname(__file__)


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    out = tmp_path_factory.mktemp("sample")
    labels = generate.generate(str(out), seed=7)
    web, web_rejects = parsers.read_file(str(out / "access.log"), "web")
    auth, auth_rejects = parsers.read_file(str(out / "auth.log"), "auth", labels["year"])
    events = sorted(web + auth, key=lambda e: e.epoch)
    return {"dir": out, "labels": labels, "events": events, "rejects": web_rejects + auth_rejects}


def test_generator_is_deterministic_and_seed_sensitive(tmp_path):
    a, b, c = (tmp_path / n for n in "abc")
    generate.generate(str(a), seed=3)
    generate.generate(str(b), seed=3)
    generate.generate(str(c), seed=4)
    for name in ("access.log", "auth.log", "labels.json"):
        assert (a / name).read_bytes() == (b / name).read_bytes()
    assert (a / "access.log").read_bytes() != (c / "access.log").read_bytes()


def test_every_generated_line_parses(sample):
    assert sample["rejects"] == []
    assert len(sample["events"]) > 4000


def test_labels_are_well_formed(sample):
    ids = [c["id"] for c in sample["labels"]["campaigns"]]
    assert len(ids) == len(set(ids)) == 13
    assert sum(1 for c in sample["labels"]["campaigns"] if c["known_gap"]) == 1
    attacker_ips = [ip for c in sample["labels"]["campaigns"] for ip in c["ips"]]
    assert all(ip.startswith(("203.0.113.", "198.51.100.", "192.0.2.")) for ip in attacker_ips)   # RFC 5737 ranges only


def test_pipeline_scores_on_the_sample_data(sample):
    ev = evaluate(run_rules(sample["events"]), sample["labels"])
    assert (ev.tp, ev.fn) == (16, 0)                                  # every expected detection fires
    assert [(f["ip"], f["rule_id"]) for f in ev.false_positives] == [("10.20.5.7", "AUTH-003")]
    gap = [c for c in ev.campaigns if c.known_gap][0]
    assert gap.id == "C12" and not gap.any_alert
    assert all(not c.missed for c in ev.campaigns)
    assert ev.campaigns_detected == 12


def test_hard_negatives_stay_quiet(sample):
    alerts = run_rules(sample["events"])
    quiet = {"10.20.9.1", "66.249.66.1", "10.20.5.6", "10.20.0.5"}      # password manager, crawler, slow typos, health check
    assert quiet.isdisjoint({a.ip for a in alerts})


def test_trusting_the_internal_network_removes_the_false_positive(sample):
    with open(os.path.join(HERE, "..", "examples", "trusted_internal.json")) as handle:
        cfg = Config.from_dict(json.load(handle))
    ev = evaluate(run_rules(sample["events"], cfg), sample["labels"])
    assert ev.fp == 0 and ev.precision == 1.0 and ev.recall == 1.0


def test_lowering_a_threshold_trades_precision_for_recall(sample):
    ev = evaluate(run_rules(sample["events"], Config(web_bruteforce_threshold=9, forced_browsing_threshold=12)), sample["labels"])
    noisy = {f["ip"] for f in ev.false_positives}
    assert "10.20.9.1" in noisy and "66.249.66.1" in noisy


def labels_for(*campaigns):
    return {"campaigns": list(campaigns), "benign_notes": [{"ip": "9.9.9.9", "note": "known noisy host"}]}


def campaign(cid, ips, expected, allowed=(), gap=False):
    return {"id": cid, "name": cid, "ips": ips, "expected_rules": expected, "allowed_rules": list(allowed), "known_gap": gap}


def alert(ip, rule):
    return Alert(rule, "high", ip, 1, 2, 1, "s")


def test_evaluate_counts_tp_fp_fn():
    labels = labels_for(campaign("A", ["1.1.1.1"], ["WEB-001", "WEB-004"]))
    ev = evaluate([alert("1.1.1.1", "WEB-001"), alert("9.9.9.9", "WEB-002")], labels)
    assert (ev.tp, ev.fp, ev.fn) == (1, 1, 1)
    assert ev.rules["WEB-004"].fn == 1 and ev.rules["WEB-002"].fp == 1
    assert ev.false_positives == [{"ip": "9.9.9.9", "rule_id": "WEB-002", "note": "known noisy host"}]
    assert ev.campaigns[0].missed == ["WEB-004"] and ev.campaigns[0].fired == ["WEB-001"]


def test_allowed_rules_are_not_false_positives_and_duplicates_count_once():
    labels = labels_for(campaign("A", ["1.1.1.1"], ["WEB-001"], allowed=["WEB-004"]))
    ev = evaluate([alert("1.1.1.1", "WEB-001"), alert("1.1.1.1", "WEB-001"), alert("1.1.1.1", "WEB-004")], labels)
    assert (ev.tp, ev.fp, ev.fn) == (1, 0, 0)


def test_precision_and_recall_are_none_when_undefined():
    ev = evaluate([], labels_for(campaign("G", ["1.1.1.1"], [], gap=True)))
    assert ev.precision is None and ev.recall is None and ev.campaigns_detected == 0
    assert ev.rules["WEB-001"].precision is None
