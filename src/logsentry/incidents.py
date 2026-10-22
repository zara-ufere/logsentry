"""Group alerts by source IP into incidents, so an analyst reads one story per attacker
instead of a flat list of alerts."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from .models import Alert, severity_rank
from .rules import RULE_BY_ID

STAGE_ORDER = ["recon", "exploit", "credential", "compromise"]
STAGE_LABEL = {"recon": "Reconnaissance", "exploit": "Exploitation attempts",
               "credential": "Credential attacks", "compromise": "Possible compromise"}


@dataclass
class Incident:
    ip: str
    alerts: List[Alert]
    severity: str
    first_epoch: int
    last_epoch: int
    stages: List[str] = field(default_factory=list)   # in the order they first appeared
    compromised: bool = False

    @property
    def multi_stage(self) -> bool:
        return len(self.stages) >= 2


def build_incidents(alerts: Sequence[Alert]) -> List[Incident]:
    by_ip: Dict[str, List[Alert]] = {}
    for a in alerts:
        by_ip.setdefault(a.ip, []).append(a)
    incidents: List[Incident] = []
    for ip, group in by_ip.items():
        group = sorted(group, key=lambda a: (a.first_epoch, STAGE_ORDER.index(RULE_BY_ID[a.rule_id].stage), a.rule_id))
        stages: List[str] = []
        for a in group:
            stage = RULE_BY_ID[a.rule_id].stage
            if stage not in stages:
                stages.append(stage)
        compromised = any(a.rule_id == "AUTH-003" or (a.rule_id == "WEB-006" and "successful login" in a.summary)
                          for a in group)
        top = max(group, key=lambda a: severity_rank(a.severity)).severity
        # An attacker who moves from probing to a real attempt, or gets in, is worse than any single alert says.
        if compromised:
            top = "critical"
        elif len(stages) >= 3 and severity_rank(top) < severity_rank("critical"):
            top = "critical"
        incidents.append(Incident(ip=ip, alerts=group, severity=top, first_epoch=group[0].first_epoch,
                                  last_epoch=max(a.last_epoch for a in group), stages=stages,
                                  compromised=compromised))
    incidents.sort(key=lambda i: (-severity_rank(i.severity), -len(i.alerts), i.first_epoch))
    return incidents
