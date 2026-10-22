"""Command line interface: generate, ingest, detect, alerts, report, evaluate, rules, demo."""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import List, Optional

from . import __version__, generate as gen, parsers, report as reportmod, store
from .evaluate import evaluate
from .incidents import build_incidents
from .models import fmt_epoch, severity_rank
from .rules import RULES, Config, run_rules


def load_config(path: Optional[str]) -> Config:
    if not path:
        return Config()
    with open(path, "r", encoding="utf-8") as handle:
        return Config.from_dict(json.load(handle))


def load_labels(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def do_ingest(db: str, web: List[str], auth: List[str], year: int) -> None:
    conn = store.connect(db)
    for kind, files in (("web", web), ("auth", auth)):
        for path in files:
            events, rejects = parsers.read_file(path, kind, year)
            new_e, new_r = store.ingest(conn, events, rejects, file=path)
            print("%s: %d lines parsed (%d new), %d rejected (%d new)" % (
                path, len(events), new_e, len(rejects), new_r))


def do_detect(db: str, cfg: Config) -> int:
    conn = store.connect(db)
    alerts = run_rules(store.load_events(conn), cfg)
    store.replace_alerts(conn, alerts)
    by_sev = {}
    for a in alerts:
        by_sev[a.severity] = by_sev.get(a.severity, 0) + 1
    print("%d alerts: %s" % (len(alerts), ", ".join("%d %s" % (by_sev[s], s) for s in
                                                    ("critical", "high", "medium", "low") if s in by_sev) or "none"))
    return len(alerts)


def print_alerts(db: str, minimum: str) -> None:
    conn = store.connect(db)
    alerts = [a for a in store.load_alerts(conn) if severity_rank(a.severity) >= severity_rank(minimum)]
    alerts.sort(key=lambda a: (-severity_rank(a.severity), a.first_epoch))
    for a in alerts:
        print("%-8s %-8s %-16s %s  %s" % (a.severity.upper(), a.rule_id, a.ip, fmt_epoch(a.first_epoch), a.summary))
    if not alerts:
        print("No alerts at or above %s." % minimum)


def print_evaluation(ev) -> None:
    print("%-9s %5s %5s %5s %10s %8s" % ("Rule", "TP", "FP", "FN", "Precision", "Recall"))
    for rule in RULES:
        s = ev.rules[rule.id]
        fmt = lambda x: "n/a" if x is None else "%.2f" % x
        print("%-9s %5d %5d %5d %10s %8s" % (rule.id, s.tp, s.fp, s.fn, fmt(s.precision), fmt(s.recall)))
    print("\nOverall: precision %s, recall %s, %d of %d campaigns noticed" % (
        reportmod.pct(ev.precision), reportmod.pct(ev.recall), ev.campaigns_detected, len(ev.campaigns)))
    for c in ev.campaigns:
        if c.known_gap:
            print("  Known gap: %s %s (%s)" % (c.id, c.name, "noticed anyway" if c.any_alert else "not detected"))
        elif c.missed:
            print("  MISSED: %s %s did not trigger %s" % (c.id, c.name, ", ".join(c.missed)))
    for f in ev.false_positives:
        print("  False positive: %s %s. %s" % (f["ip"], f["rule_id"], f["note"]))


def do_report(db: str, out: str, labels_path: Optional[str], title: str, cfg: Config) -> None:
    conn = store.connect(db)
    alerts = store.load_alerts(conn)
    ev = evaluate(alerts, load_labels(labels_path)) if labels_path else None
    page = reportmod.render(store.counts(conn), alerts, build_incidents(alerts), ev, title)
    with open(out, "w", encoding="utf-8") as handle:
        handle.write(page)
    print("Wrote %s" % out)


def do_demo(out: str, seed: int, cfg: Config) -> None:
    labels = gen.generate(out, seed)
    print("Generated sample logs and labels in %s/" % out)
    db = os.path.join(out, "logsentry.db")
    if os.path.exists(db):
        os.remove(db)
    do_ingest(db, [os.path.join(out, "access.log")], [os.path.join(out, "auth.log")], labels["year"])
    do_detect(db, cfg)
    conn = store.connect(db)
    ev = evaluate(store.load_alerts(conn), labels)
    print()
    print_evaluation(ev)
    do_report(db, os.path.join(out, "report.html"), os.path.join(out, "labels.json"), "logsentry demo report", cfg)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logsentry", description="Detect attacks in web and SSH logs and measure how well.")
    p.add_argument("--version", action="version", version="logsentry " + __version__)
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="write sample logs and a labels file")
    g.add_argument("--out", default="sample")
    g.add_argument("--seed", type=int, default=7)

    i = sub.add_parser("ingest", help="parse log files into the database")
    i.add_argument("--db", default="logsentry.db")
    i.add_argument("--web", action="append", default=[], help="nginx/Apache combined access log (repeatable)")
    i.add_argument("--auth", action="append", default=[], help="sshd auth.log (repeatable)")
    i.add_argument("--year", type=int, default=datetime.now(timezone.utc).year, help="year for auth.log, whose timestamps have none")

    d = sub.add_parser("detect", help="run the detection rules")
    d.add_argument("--db", default="logsentry.db")
    d.add_argument("--config", help="JSON file overriding thresholds")

    a = sub.add_parser("alerts", help="list alerts in the terminal")
    a.add_argument("--db", default="logsentry.db")
    a.add_argument("--min-severity", default="low", choices=["low", "medium", "high", "critical"])

    r = sub.add_parser("report", help="write the HTML report")
    r.add_argument("--db", default="logsentry.db")
    r.add_argument("--out", default="report.html")
    r.add_argument("--labels", help="labels.json, to include the accuracy section")
    r.add_argument("--title", default="logsentry report")

    e = sub.add_parser("evaluate", help="score alerts against a labels file")
    e.add_argument("--db", default="logsentry.db")
    e.add_argument("--labels", required=True)

    sub.add_parser("rules", help="list the detection rules")

    m = sub.add_parser("demo", help="generate sample data, detect, score and write a report in one step")
    m.add_argument("--out", default="demo_output")
    m.add_argument("--seed", type=int, default=7)
    m.add_argument("--config", help="JSON file overriding thresholds")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "generate":
            labels = gen.generate(args.out, args.seed)
            print("Wrote access.log, auth.log and labels.json to %s/ (%d campaigns)" % (args.out, len(labels["campaigns"])))
        elif args.command == "ingest":
            if not (args.web or args.auth):
                print("Give at least one --web or --auth file.", file=sys.stderr)
                return 2
            do_ingest(args.db, args.web, args.auth, args.year)
        elif args.command == "detect":
            do_detect(args.db, load_config(args.config))
        elif args.command == "alerts":
            print_alerts(args.db, args.min_severity)
        elif args.command == "report":
            do_report(args.db, args.out, args.labels, args.title, Config())
        elif args.command == "evaluate":
            print_evaluation(evaluate(store.load_alerts(store.connect(args.db)), load_labels(args.labels)))
        elif args.command == "rules":
            for r in RULES:
                print("%-9s %-8s %-9s %-34s %s" % (r.id, r.severity, r.attack, (r.owasp or "-")[:34], r.name))
        elif args.command == "demo":
            do_demo(args.out, args.seed, load_config(args.config))
    except (OSError, ValueError, KeyError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    return 0
