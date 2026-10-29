# -*- coding: utf-8 -*-
"""Tests for the structured diagnostic logging layer (phpscan.log).

Covers: obtaining/naming the logger, log-level configuration (including
rejection of invalid levels), emission of internal diagnostics at the
expected level, and -- crucially -- that findings, terminal reports,
JSON and SARIF output are untouched by logging.
"""

import json
import logging
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phpscan import cli, host, live, log  # noqa: E402

# A log line as produced by log.FORMAT: "05:09:29 WARNING phpscan.host: ..."
_LOG_LINE = re.compile(r"\d\d:\d\d:\d\d (DEBUG|INFO|WARNING|ERROR|CRITICAL) phpscan\b")


@pytest.fixture(autouse=True)
def restore_default_log_level():
    """Never leak one test's log level into the next one."""
    yield
    log.configure(log.DEFAULT_LEVEL)


def _target(tmp_path):
    """Small scan target with one finding."""
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / "vuln.php").write_text("<?php echo $_GET['x']; ?>", encoding="utf-8")
    return str(src)


# ------------------------------------------------------------ 1/2: identity


def test_logger_can_be_obtained():
    logger = log.get_logger()
    assert isinstance(logger, logging.Logger)
    assert log.get_logger("live") is not None
    assert log.get_logger("host") is not None


def test_logger_has_expected_phpscan_name():
    assert log.get_logger().name == "phpscan"
    assert log.get_logger("live").name == "phpscan.live"
    assert log.get_logger("host").name == "phpscan.host"
    assert log.get_logger("live").parent is log.get_logger()


# ------------------------------------------------------------ 3: configuration


def test_log_level_configuration_works(caplog):
    log.configure("DEBUG")
    assert log.get_logger().level == logging.DEBUG
    assert log.get_logger("host").getEffectiveLevel() == logging.DEBUG

    caplog.clear()
    log.get_logger("probe").debug("debug-seen")
    assert [r for r in caplog.records if r.getMessage() == "debug-seen"]

    log.configure("INFO")  # case-insensitive names are accepted
    assert log.get_logger().level == logging.INFO
    caplog.clear()
    log.get_logger("probe").debug("debug-hidden")
    log.get_logger("probe").info("info-seen")
    assert not [r for r in caplog.records if r.getMessage() == "debug-hidden"]
    assert [r for r in caplog.records if r.getMessage() == "info-seen"]


def test_configure_is_idempotent(caplog):
    for _ in range(3):
        log.configure("WARNING")
    log.configure("DEBUG")
    caplog.clear()
    log.get_logger("probe").debug("once-only")
    assert len([r for r in caplog.records if r.getMessage() == "once-only"]) == 1


# ------------------------------------------------------------ 4: invalid level


def test_invalid_log_level_is_rejected(capsys):
    with pytest.raises(ValueError):
        log.configure("VERBOSE")
    capsys.readouterr()

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--log-level", "BOGUS", "scan", "target"])
    assert excinfo.value.code == 2
    capsys.readouterr()

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["scan", "target", "--log-level", "BOGUS"])
    assert excinfo.value.code == 2
    capsys.readouterr()


# ------------------------------------------------------------ 5: real diagnostics


def test_host_diagnostic_emitted_at_debug(caplog):
    log.configure("DEBUG")
    caplog.clear()
    host.walk_all(os.path.join(str(os.path.dirname(__file__)), "no-such-directory"))
    recs = [r for r in caplog.records if r.name == "phpscan.host"]
    assert recs, "an unreadable directory should be observable"
    assert recs[0].levelno == logging.DEBUG
    assert recs[0].getMessage().startswith("skipping unreadable directory")


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory permissions")
def test_host_permission_denied_warns_at_default_level(tmp_path, capsys):
    locked = tmp_path / "locked"
    locked.mkdir()
    os.chmod(str(locked), 0o000)
    if os.access(str(locked), os.R_OK | os.X_OK):
        os.chmod(str(locked), 0o755)
        pytest.skip("directory permissions not enforced for this user")
    log.configure(log.DEFAULT_LEVEL)
    capsys.readouterr()
    try:
        host.walk_all(str(tmp_path))
    finally:
        os.chmod(str(locked), 0o755)
    err = capsys.readouterr().err
    assert "WARNING phpscan.host" in err
    assert "permission denied" in err


def test_live_probe_diagnostic_emitted_at_debug(caplog):
    log.configure("DEBUG")
    caplog.clear()
    scope = live.Scope(allow_hosts=("example.test",), max_requests=0)
    resp = live.fetch("http://example.test/index.php?token=hunter2token&keep=1", scope)
    assert resp["status"] == 0 and "budget" in resp["error"]
    recs = [r for r in caplog.records if r.name == "phpscan.live"]
    assert recs and recs[0].levelno == logging.DEBUG
    msg = recs[0].getMessage()
    assert "hunter2token" not in msg  # credentials never reach a log line
    assert "keep=1" in msg


@pytest.mark.network
def test_live_connection_failure_emitted_at_info(caplog):
    log.configure("INFO")
    caplog.clear()
    scope = live.Scope(allow_hosts=("127.0.0.1",), timeout=2.0)
    resp = live.fetch("http://127.0.0.1:1/unreachable", scope)
    assert resp["status"] == 0 and resp.get("error")
    recs = [r for r in caplog.records if r.name == "phpscan.live" and r.levelno == logging.INFO]
    assert recs and "request failed" in recs[0].getMessage()


# ------------------------------------------------------------ 6: report unchanged


def test_findings_report_output_unchanged(tmp_path, capsys):
    target = _target(tmp_path)
    log.configure("DEBUG")
    rc = cli.main(["scan", target, "--no-baseline"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "deterministic PHP security scan" in out
    assert "Findings by status:" in out
    assert "Findings by severity:" in out
    assert not _LOG_LINE.search(out), "log lines must never reach report output"


# ------------------------------------------------------------ 7: machine output


def test_json_and_sarif_output_not_polluted(tmp_path, capsys):
    target = _target(tmp_path)
    json_out = str(tmp_path / "out.json")
    sarif_out = str(tmp_path / "out.sarif")
    log.configure("DEBUG")
    log.get_logger("test").debug("SENTINEL-DIAGNOSTIC-LINE")

    rc = cli.main(
        [
            "scan",
            target,
            "--json",
            "--quiet",
            "--no-baseline",
            "--out",
            json_out,
            "--sarif-out",
            sarif_out,
        ]
    )
    cap = capsys.readouterr()
    assert rc == 0
    payload = json.loads(cap.out)  # stdout is pure JSON
    assert payload["meta"]["version"]
    assert "SENTINEL-DIAGNOSTIC-LINE" in cap.err  # diagnostics go to stderr
    assert "SENTINEL-DIAGNOSTIC-LINE" not in cap.out

    for path in (json_out, sarif_out):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        json.loads(text)  # report files parse as JSON
        assert "SENTINEL-DIAGNOSTIC-LINE" not in text
    with open(sarif_out, encoding="utf-8") as fh:
        assert json.load(fh)["runs"]


# ------------------------------------------------------------ 8: default quiet


def test_default_cli_level_stays_quiet(tmp_path, capsys):
    target = _target(tmp_path)
    rc = cli.main(["scan", target, "--quiet", "--no-baseline"])
    cap = capsys.readouterr()
    assert rc == 0
    assert "findings" in cap.out
    assert log.get_logger().getEffectiveLevel() == logging.WARNING

    log.get_logger("test").debug("HIDDEN-DEBUG-LINE")
    log.get_logger("test").info("HIDDEN-INFO-LINE")
    log.get_logger("test").warning("SHOWN-WARNING-LINE")
    cap2 = capsys.readouterr()
    assert "HIDDEN-DEBUG-LINE" not in cap2.err
    assert "HIDDEN-INFO-LINE" not in cap2.err
    assert "SHOWN-WARNING-LINE" in cap2.err
    assert cap2.out == "", "logging must never write to stdout"


# ------------------------------------------------------------ security


def test_redact_url_masks_credentials():
    url = "http://user:hunter2@10.0.0.1:8080/a.php?token=s3cr3t&plain=ok"
    safe = log.redact_url(url)
    assert "hunter2" not in safe
    assert "s3cr3t" not in safe
    assert "10.0.0.1" in safe
    assert "plain=ok" in safe
    plain = "http://example.test/a.php?x=1"
    assert log.redact_url(plain) == plain


def test_configure_leaves_root_logger_alone():
    """Embedding phpscan must not reconfigure the host application's logging."""
    root_before = list(logging.getLogger().handlers)
    log.get_logger()
    log.configure("DEBUG")
    assert list(logging.getLogger().handlers) == root_before
    assert any(h.__class__.__name__ == "NullHandler" for h in log.get_logger().handlers)
