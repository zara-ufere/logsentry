"""Self-contained HTML report.

Log lines are attacker-controlled: a request can contain <script> tags. Every dynamic
value therefore goes through esc() before it reaches the page, and the report loads
no external scripts, styles or fonts.
"""
from __future__ import annotations

import html
from typing import Dict, List, Optional, Sequence

from .evaluate import Evaluation
from .incidents import STAGE_LABEL, Incident
from .models import Alert, fmt_epoch
from .rules import RULES, RULE_BY_ID

CSS = """
:root{--bg:#F5F3FC;--surface:#fff;--ink:#221A44;--muted:#5F5681;--line:#E2DCF3;--soft:#EFEBFA;--accent:#5B3FD1;
--crit:#B3261E;--crit-bg:#FCE9E7;--high:#B8500A;--high-bg:#FDEDDC;--med:#7A6200;--med-bg:#FBF3CF;--low:#2F6B3A;--low-bg:#E3F3E4;
--ok:#1F7A4D;--ok-bg:#DFF3E8;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#14102A;--surface:#1D1839;--ink:#EFEBFF;--muted:#B0A6D8;--line:#362F60;--soft:#262046;
--accent:#A999FF;--crit:#FF9C94;--crit-bg:#3E1D26;--high:#FFB77A;--high-bg:#3F2A1B;--med:#EBCD54;--med-bg:#383119;--low:#98D69B;--low-bg:#1F3622;
--ok:#78D6A5;--ok-bg:#183626;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:0 20px 60px}
header{padding:30px 0 6px}h1{font-size:1.7rem;margin:0 0 4px}header p{margin:0;color:var(--muted)}
h2{font-size:1.15rem;margin:34px 0 4px}.sub{color:var(--muted);font-size:.93rem;margin:0 0 12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}
.stat{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:14px 16px}
.stat .v{font-size:1.7rem;font-weight:700;line-height:1.2}.stat .l{color:var(--muted);font-size:.88rem}
.stat.bad .v{color:var(--crit)}.stat.good .v{color:var(--ok)}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:.76rem;font-weight:700;letter-spacing:.02em;text-transform:uppercase}
.pill.critical{background:var(--crit-bg);color:var(--crit)}.pill.high{background:var(--high-bg);color:var(--high)}
.pill.medium{background:var(--med-bg);color:var(--med)}.pill.low{background:var(--low-bg);color:var(--low)}
.pill.plain{background:var(--soft);color:var(--muted);text-transform:none;font-weight:600}
.pill.ok{background:var(--ok-bg);color:var(--ok)}
details.inc{background:var(--surface);border:1px solid var(--line);border-left:6px solid var(--line);border-radius:14px;margin-bottom:10px;padding:0}
details.inc.critical{border-left-color:var(--crit)}details.inc.high{border-left-color:var(--high)}
details.inc.medium{border-left-color:var(--med)}details.inc.low{border-left-color:var(--low)}
details.inc>summary{cursor:pointer;padding:14px 16px;list-style:none}
details.inc>summary::-webkit-details-marker{display:none}
.ip{font-weight:700;font-family:ui-monospace,Menlo,Consolas,monospace}
.chain{color:var(--muted);font-size:.9rem;margin-top:4px}
.body{padding:0 16px 14px}
.alert{border-top:1px solid var(--line);padding:12px 0}
.alert h4{margin:0 0 2px;font-size:.98rem}.meta{color:var(--muted);font-size:.88rem}
pre{background:var(--soft);border-radius:10px;padding:10px 12px;overflow-x:auto;font-size:.8rem;margin:8px 0 0;white-space:pre-wrap;word-break:break-all}
table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line);border-radius:14px;overflow:hidden;font-size:.92rem}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;background:var(--soft)}
tr:last-child td{border-bottom:0}td:first-child{white-space:nowrap}.num{text-align:right;font-variant-numeric:tabular-nums}
.scroll{overflow-x:auto}
.bar{height:8px;border-radius:99px;background:var(--soft);min-width:80px}.bar i{display:block;height:100%;border-radius:99px;background:var(--accent)}
.note{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:12px 16px;margin:8px 0;color:var(--muted);font-size:.92rem}
footer{color:var(--muted);font-size:.85rem;text-align:center;margin-top:40px}
"""


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def pill(sev: str) -> str:
    return '<span class="pill %s">%s</span>' % (esc(sev) if sev in ("low", "medium", "high", "critical") else "plain", esc(sev))


def pct(x: Optional[float]) -> str:
    return "n/a" if x is None else "%d%%" % round(100 * x)


def incident_html(inc: Incident) -> str:
    stages = " &rarr; ".join(esc(STAGE_LABEL[s]) for s in inc.stages)
    flags = ' <span class="pill critical">Possible compromise</span>' if inc.compromised else ""
    head = ('<summary><span class="ip">%s</span> %s%s <span class="meta">&middot; %d alert%s &middot; %s to %s UTC</span>'
            '<div class="chain">%s</div></summary>') % (
        esc(inc.ip), pill(inc.severity), flags, len(inc.alerts), "" if len(inc.alerts) == 1 else "s",
        esc(fmt_epoch(inc.first_epoch)), esc(fmt_epoch(inc.last_epoch)[11:]), stages)
    rows = []
    for a in inc.alerts:
        info = RULE_BY_ID[a.rule_id]
        tags = '<span class="pill plain">%s</span> <span class="pill plain">ATT&amp;CK %s</span>' % (
            esc(info.owasp or "No OWASP category"), esc(info.attack))
        evidence = "\n".join(esc(line) for line in a.evidence)
        rows.append('<div class="alert"><h4>%s %s &middot; %s</h4><div class="meta">%s</div><div style="margin-top:6px">%s</div>'
                    '<pre>%s</pre></div>' % (pill(a.severity), esc(a.rule_id), esc(info.name), esc(a.summary), tags, evidence))
    return '<details class="inc %s">%s<div class="body">%s</div></details>' % (esc(inc.severity), head, "".join(rows))


def coverage_html(alerts: Sequence[Alert]) -> str:
    counts: Dict[str, int] = {}
    for a in alerts:
        counts[a.rule_id] = counts.get(a.rule_id, 0) + 1
    top = max(list(counts.values()) + [1])
    rows = []
    for r in RULES:
        n = counts.get(r.id, 0)
        rows.append('<tr><td><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class="num">%d</td>'
                    '<td><div class="bar"><i style="width:%d%%"></i></div></td></tr>' % (
                        esc(r.id), esc(r.name), esc(r.owasp or "None"), esc(r.attack), esc(r.source), n, round(100 * n / top)))
    return ('<div class="scroll"><table><thead><tr><th>Rule</th><th>What it detects</th><th>OWASP Top 10</th><th>ATT&amp;CK</th>'
            '<th>Log</th><th class="num">Alerts</th><th></th></tr></thead><tbody>%s</tbody></table></div>') % "".join(rows)


def evaluation_html(ev: Evaluation) -> str:
    out = ['<h2>How well did it do?</h2><p class="sub">Scored against the labelled synthetic data. Because the same person wrote the '
           'generator and the rules, this shows the pipeline works and where it is blind. It does not predict accuracy on real traffic.</p>']
    out.append('<div class="stats"><div class="stat"><div class="v">%s</div><div class="l">Recall: expected detections found (%d of %d)</div></div>'
               '<div class="stat"><div class="v">%s</div><div class="l">Precision: alerts that were real (%d of %d)</div></div>'
               '<div class="stat"><div class="v">%d of %d</div><div class="l">Attack campaigns noticed at all</div></div></div>' % (
                   pct(ev.recall), ev.tp, ev.tp + ev.fn, pct(ev.precision), ev.tp, ev.tp + ev.fp,
                   ev.campaigns_detected, len(ev.campaigns)))
    rows = []
    for c in ev.campaigns:
        if c.known_gap:
            status = '<span class="pill high">Known gap</span>'
        elif c.missed:
            status = '<span class="pill critical">Missed %s</span>' % esc(", ".join(c.missed))
        else:
            status = '<span class="pill ok">Detected</span>'
        rows.append("<tr><td>%s</td><td><b>%s</b><div class=\"meta\">%s</div></td><td>%s</td><td>%s</td></tr>" % (
            esc(c.id), esc(c.name), esc(c.description), esc(", ".join(c.fired) or "none"), status))
    out.append('<div class="scroll"><table><thead><tr><th>ID</th><th>Planted attack</th><th>Rules that fired</th><th>Result</th></tr></thead>'
               '<tbody>%s</tbody></table></div>' % "".join(rows))
    if ev.false_positives:
        items = "".join("<li><b>%s</b> %s: %s</li>" % (esc(f["ip"]), esc(f["rule_id"]), esc(f["note"])) for f in ev.false_positives)
        out.append('<div class="note"><b>False positives</b><ul>%s</ul></div>' % items)
    else:
        out.append('<div class="note"><b>False positives:</b> none.</div>')
    return "".join(out)


def render(counts: dict, alerts: Sequence[Alert], incidents: Sequence[Incident],
           evaluation: Optional[Evaluation] = None, title: str = "logsentry report") -> str:
    crit = sum(1 for i in incidents if i.severity == "critical")
    stats = [("Log events analysed", "{:,}".format(counts["events"]), ""),
             ("Alerts raised", str(len(alerts)), ""),
             ("Incidents (one per source IP)", str(len(incidents)), ""),
             ("Critical incidents", str(crit), "bad" if crit else "good"),
             ("Lines that failed to parse", str(counts["rejects"]), "")]
    cards = "".join('<div class="stat %s"><div class="v">%s</div><div class="l">%s</div></div>' % (c, esc(v), esc(l))
                    for l, v, c in stats)
    parts = ["<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
             "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
             "<title>%s</title><style>%s</style></head><body><div class=\"wrap\">" % (esc(title), CSS),
             "<header><h1>%s</h1><p>%s web events and %s SSH events. Times are UTC.</p></header>" % (
                 esc(title), esc("{:,}".format(counts["web_events"])), esc("{:,}".format(counts["auth_events"]))),
             '<div class="stats">%s</div>' % cards,
             "<h2>Incidents</h2><p class=\"sub\">Alerts grouped by attacker address, most serious first. "
             "Open one to see each alert and the log lines behind it.</p>"]
    parts.extend(incident_html(i) for i in incidents) if incidents else parts.append('<div class="note">No alerts.</div>')
    parts.append("<h2>What the rules look for</h2><p class=\"sub\">Each rule is mapped to an OWASP Top 10 (2021) category and a MITRE ATT&amp;CK technique.</p>")
    parts.append(coverage_html(alerts))
    if evaluation is not None:
        parts.append(evaluation_html(evaluation))
    parts.append("<footer>Generated by logsentry</footer></div></body></html>")
    return "".join(parts)
