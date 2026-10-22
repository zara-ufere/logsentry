import json
import os

from logsentry.cli import main


def test_demo_end_to_end(tmp_path, capsys):
    out = tmp_path / "demo"
    assert main(["demo", "--out", str(out)]) == 0
    text = capsys.readouterr().out
    assert "precision 94%, recall 100%, 12 of 13 campaigns noticed" in text
    assert "Known gap: C12" in text and "False positive: 10.20.5.7" in text
    page = (out / "report.html").read_text()
    assert "<script" not in page and "AUTH-003" in page
    assert (out / "logsentry.db").exists()


def test_demo_with_trusted_network_config(tmp_path, capsys):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"ignore_networks": ["10.20.0.0/16"]}))
    assert main(["demo", "--out", str(tmp_path / "d"), "--config", str(cfg)]) == 0
    assert "precision 100%, recall 100%" in capsys.readouterr().out


def test_step_by_step_commands_and_idempotent_ingest(tmp_path, capsys):
    d, db = str(tmp_path / "s"), str(tmp_path / "x.db")
    assert main(["generate", "--out", d]) == 0
    args = ["ingest", "--db", db, "--web", d + "/access.log", "--auth", d + "/auth.log", "--year", "2026"]
    assert main(args) == 0 and "(4089 new)" in capsys.readouterr().out
    assert main(args) == 0 and "(0 new)" in capsys.readouterr().out
    assert main(["detect", "--db", db]) == 0 and "17 alerts: 4 critical" in capsys.readouterr().out
    assert main(["alerts", "--db", db, "--min-severity", "critical"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 4 and all(l.startswith("CRITICAL") for l in lines)
    assert main(["evaluate", "--db", db, "--labels", d + "/labels.json"]) == 0
    assert "Overall: precision 94%" in capsys.readouterr().out
    assert main(["report", "--db", db, "--out", str(tmp_path / "r.html"), "--labels", d + "/labels.json"]) == 0
    assert os.path.exists(tmp_path / "r.html")


def test_rules_command_lists_every_rule(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert len(out.strip().splitlines()) == 12 and "T1110.003" in out


def test_errors_exit_with_code_2_and_a_message(tmp_path, capsys):
    assert main(["ingest", "--db", str(tmp_path / "x.db")]) == 2
    assert main(["ingest", "--db", str(tmp_path / "x.db"), "--web", str(tmp_path / "missing.log")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text('{"nonsense": 1}')
    db = str(tmp_path / "y.db")
    (tmp_path / "a.log").write_text('1.2.3.4 - - [10/Oct/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "ua"\n')
    assert main(["ingest", "--db", db, "--web", str(tmp_path / "a.log")]) == 0
    assert main(["detect", "--db", db, "--config", str(bad)]) == 2
    assert "nonsense" in capsys.readouterr().err


def test_bad_lines_are_counted_not_fatal(tmp_path, capsys):
    log = tmp_path / "a.log"
    log.write_text('garbage\n1.2.3.4 - - [10/Oct/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "ua"\n')
    assert main(["ingest", "--db", str(tmp_path / "z.db"), "--web", str(log)]) == 0
    assert "1 lines parsed (1 new), 1 rejected (1 new)" in capsys.readouterr().out
