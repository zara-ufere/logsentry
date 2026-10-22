"""Score detections against the generator's ground-truth labels.

An alert is identified by (source IP, rule id). For each labelled campaign:
  * every expected (ip, rule) pair that fired is a true positive;
  * every expected pair that did not fire is a false negative;
  * an alert on a pair that is neither expected nor explicitly allowed is a false positive.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .models import Alert
from .rules import RULES

Pair = Tuple[str, str]


@dataclass
class RuleScore:
    rule_id: str
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> Optional[float]:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else None

    @property
    def recall(self) -> Optional[float]:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else None


@dataclass
class CampaignResult:
    id: str
    name: str
    known_gap: bool
    expected: List[str]
    fired: List[str]        # expected rules that fired
    missed: List[str]       # expected rules that did not fire
    any_alert: bool         # did any rule fire for any of this campaign's IPs
    description: str = ""


@dataclass
class Evaluation:
    rules: Dict[str, RuleScore]
    campaigns: List[CampaignResult]
    false_positives: List[dict] = field(default_factory=list)
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> Optional[float]:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else None

    @property
    def recall(self) -> Optional[float]:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else None

    @property
    def campaigns_detected(self) -> int:
        return sum(1 for c in self.campaigns if c.any_alert)


def evaluate(alerts: Sequence[Alert], labels: dict) -> Evaluation:
    fired: Set[Pair] = {(a.ip, a.rule_id) for a in alerts}
    expected: Set[Pair] = set()
    allowed: Set[Pair] = set()
    campaign_ips: Dict[str, List[str]] = {}
    for c in labels["campaigns"]:
        campaign_ips[c["id"]] = c["ips"]
        for ip in c["ips"]:
            expected.update((ip, r) for r in c["expected_rules"])
            allowed.update((ip, r) for r in c.get("allowed_rules", []))
    notes = {n["ip"]: n["note"] for n in labels.get("benign_notes", [])}

    scores = {r.id: RuleScore(r.id) for r in RULES}
    for ip, rule in expected:
        scores[rule].tp += (ip, rule) in fired
        scores[rule].fn += (ip, rule) not in fired
    false_positives = []
    for ip, rule in sorted(fired - expected - allowed):
        scores[rule].fp += 1
        false_positives.append({"ip": ip, "rule_id": rule, "note": notes.get(ip, "no label for this address")})

    campaigns: List[CampaignResult] = []
    ips_with_alerts = {a.ip for a in alerts}
    for c in labels["campaigns"]:
        want = c["expected_rules"]
        hit = sorted({r for r in want for ip in c["ips"] if (ip, r) in fired})
        miss = sorted({r for r in want for ip in c["ips"] if (ip, r) not in fired})
        campaigns.append(CampaignResult(
            id=c["id"], name=c["name"], known_gap=c.get("known_gap", False), expected=want,
            fired=hit, missed=[r for r in miss if r not in hit], any_alert=any(ip in ips_with_alerts for ip in c["ips"]),
            description=c.get("description", "")))

    result = Evaluation(rules=scores, campaigns=campaigns, false_positives=false_positives)
    result.tp = sum(s.tp for s in scores.values())
    result.fp = sum(s.fp for s in scores.values())
    result.fn = sum(s.fn for s in scores.values())
    return result
