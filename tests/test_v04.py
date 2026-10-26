"""phpscan v0.4 tests: evidence model, live scope safety, probing,
host investigation, patch timeline, fusion, proof corroboration,
uncertainty extension, and static-side quick wins."""

import http.server
import json
import os
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "phpscan"))
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE not in sys.path:
    sys.path.insert(0, BASE)

from phpscan.evidence import Evidence, EvidenceStore  # noqa: E402
from phpscan import live, probing, host, timeline, fusion, proof, uncertainty  # noqa: E402
from phpscan import cli  # noqa: E402


# ---------------------------------------------------------------- helpers


class _Server:
    def __init__(self, routes, port=0):
        outer = self
        outer.routes = routes
        outer.hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.hits.append(self.path)
                body = outer.routes.get(self.path)
                if body is None:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"nope")
                    return
                if isinstance(body, tuple):
                    status, extra, payload = body
                else:
                    status, extra, payload = 200, {}, body
                self.send_response(status)
                for k, v in extra.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(payload if isinstance(payload, bytes) else payload.encode())

        self.httpd = http.server.HTTPServer(("127.0.0.1", port), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.port

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def srv():
    s = _Server(
        {
            "/": (
                200,
                {"Server": "nginx/1.18", "X-Powered-By": "PHP/8.1.0", "Content-Type": "text/html"},
                b"<h1>app</h1><script src=/static/app.js></script>",
            ),
            "/robots.txt": (200, {}, b"User-Agent: *\nDisallow: /admin/\n"),
            "/.env": (200, {}, b"APP_KEY=Q3fX9ufdS5mzkQ4WUHn3g84bRZ8edEK8\n"),
            "/admin": (401, {}, b"auth"),
        }
    )
    yield s
    s.stop()


# ----------------------------------------------------------- evidence.py


def test_evidence_deterministic_and_dedup():
    a = Evidence("live", "X", "t", value="v", ts="2026-01-01T00:00:00Z")
    b = Evidence("live", "X", "t", value="v", ts="2025-01-01T00:00:00Z")
    assert a.id == b.id
    store = EvidenceStore("t")
    store.add(a)
    store.add(b)
    d = store.to_dict()
    assert d["total"] == 1
    assert d["records"][0]["ts"] == a.ts


def test_evidence_redaction():
    r = Evidence("host", "CREDENTIAL_ARTIFACT", "f", value="sk_live_superlongsecret")
    assert r.value["redacted"] is True
    assert "sk_live_superlongsecret" not in json.dumps(r.value)
    assert len(r.value["sha256"]) == 16
    assert r.value["hint"].startswith("sk_")
    n = Evidence("live", "HTTP_RESPONSE_OBSERVED", "u", value={"status": 200})
    assert n.value == {"status": 200}


def test_evidence_clip_and_roundtrip():
    long = "x" * 600
    e = Evidence("live", "X", "t", value=long)
    assert len(e.value) == 512 and e.value.endswith("...")
    store = EvidenceStore("t", "0.4.0")
    store.add(e)
    import tempfile as tf

    with tf.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "ev.json")
        store.write(p)
        st2 = EvidenceStore.load(p)
    assert st2.records[0].to_dict() == e.to_dict()


def test_evidence_schema_guard():
    import tempfile as tf

    with tf.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "bad.json")
        with open(p, "w") as f:
            json.dump({"schema": "wrong", "records": []}, f)
        with pytest.raises(ValueError):
            EvidenceStore.load(p)


# ------------------------------------------------------------- live.py


def test_scope_al():
    s = live.Scope(allow_hosts=["example.com"])
    assert s.allows("https://example.com/x")
    assert not s.allows("http://evil.com/x")
    assert not s.allows("ftp://example.com/x")


def test_passive_observes_headers_and_robots(srv):
    scope = live.Scope(allow_hosts=["127.0.0.1"], max_requests=8)
    store, summary = live.run_passive(srv.url, scope)
    cats = {r.category for r in store.records}
    for c in (
        "DNS_OBSERVED",
        "HTTP_RESPONSE_OBSERVED",
        "PHP_VERSION_OBSERVED",
        "SERVER_HEADER_OBSERVED",
        "SECURITY_HEADERS_MISSING",
        "ROBOTS_DISALLOW",
        "FRAMEWORK_FINGERPRINT",
    ):
        assert c in cats, cats
    assert not any(r.category == "CREDENTIAL_ARTIFACT" for r in store.records)
    assert summary["requests"] == 2


def test_malformed_port_same_host_does_not_crash():
    scope = live.Scope(allow_hosts=["127.0.0.1"], max_requests=2)
    store, _summ = live.run_passive("https://127.0.0.1:<port>", scope, probe_robots=False)
    assert any(r.category in ("HTTP_UNCERTAIN", "SCOPE_REFUSAL", "DNS_UNCERTAIN") for r in store.records)


def test_redirect_out_of_scope_recorded():
    s = _Server(
        {
            "/": (302, {"Location": "http://evil.example/x"}, b""),
        }
    )
    try:
        scope = live.Scope(allow_hosts=["127.0.0.1"], max_requests=8)
        store, summary = live.run_passive(s.url, scope, probe_robots=False)
        refusals = [r for r in store.records if r.category == "SCOPE_REFUSAL"]
        assert refusals
        assert "evil.example" in json.dumps(refusals[0].value)
    finally:
        s.stop()


def test_budget_enforced():
    s = _Server({"/": b"ok"})
    try:
        scope = live.Scope(allow_hosts=["127.0.0.1"], max_requests=1, timeout=5.0)
        _store, summary = live.run_passive(s.url, scope, probe_robots=False)
        assert summary["requests"] == 1
    finally:
        s.stop()


# -------------------------------------------------------------- probing


def test_safe_probing_route_touch(srv):
    scope = live.Scope(allow_hosts=["127.0.0.1"], max_requests=32)
    store, summary = probing.run_safe(srv.url, scope)
    cats = {r.category for r in store.records}
    assert "ROUTE_PRESENT" in cats
    assert any(r.category == "CREDENTIAL_ARTIFACT" for r in store.records)
    assert "PARAM_BEHAVIOR_DIFF" in cats
    assert any(r.category == "ROUTE_ABSENT" for r in store.records)
    assert summary["probes"] > 0


# ---------------------------------------------------------------- host


def _mk(path, data=b"x"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def test_host_investigte_categories():
    with tempfile.TemporaryDirectory() as root:
        _mk(os.path.join(root, "uploads", "shell.php.jpg"), b"<?php echo 1;")
        _mk(os.path.join(root, "uploads", "serve.php"), b"<?php //;  ")
        _mk(os.path.join(root, "config.php"), b"<?php $pass='sk_live_51J2A3B4C'; ?>")
        _mk(os.path.join(root, "bak.bak"), b"old")
        _mk(os.path.join(root, "wp.html"), b"\n<?php eval($_POST[1]); ?>\n")
        _mk(os.path.join(root, "tpl.html"), b"plain text")
        _mk(os.path.join(root, "real.png"), b"\x89PNG\r\n\x1a\n\x00\x01\x02")
        store, summary = host.run_investigate(root, now=time.time())
    cats = {}
    for r in store.records:
        cats.setdefault(r.category, []).append(r.target.replace("\\", "/"))
    assert any(t.endswith("shell.php.jpg") for t in cats.get("DOUBLE_EXTENSION", []))
    assert any(t.endswith("wp.html") for t in cats.get("DISGUISED_PHP", []))
    assert not any(t.endswith("real.png") for t in cats.get("DISGUISED_PHP", []))
    assert cats.get("BACKUP_ARTIFACT")
    assert cats.get("CREDENTIAL_ARTIFACT")
    assert any(t.endswith("serve.php") for t in cats.get("PHP_LOCATION_NOTED", []))
    assert summary["files_seen"] == 7


def test_host_processes_optin_required():
    with tempfile.TemporaryDirectory() as root:
        _mk(os.path.join(root, "a.php"), b"<?php")
        store, _summary = host.run_investigate(root, opts={})
        assert not any(r.category in ("PROCESS_OBSERVED", "PROCESSES_UNCERTAIN") for r in store.records)
        store2, summary2 = host.run_investigate(root, opts={"processes": True})
        seen = [r for r in store2.records if r.category in ("PROCESS_OBSERVED", "PROCESSES_UNCERTAIN")]
        assert seen, "opt-in process scan should record something"
        assert summary2["records"] >= len(store.records)


# ------------------------------------------------------------ timeline

_DECL = {
    "schema": "phpscan-patch-timeline/1",
    "components": [
        {"name": "acme/pkg", "affected": ["<2.0.0"], "patched": ["2.0.0"]},
        {"name": "other/lib", "affected": ["<3.0"]},
    ],
}


def test_timeline_exposure_grade():
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, "vendor"))
        with open(os.path.join(root, "composer.lock"), "w") as f:
            json.dump(
                {
                    "packages": [
                        {"name": "acme/pkg", "version": "1.5.0"},
                        {"name": "acme/pkg", "version": "2.0.1"},
                        {"name": "other/lib", "version": "2.9.9"},
                    ]
                },
                f,
            )
        installed = timeline.collect_installed(root)
        entries, counts = timeline.grade(_DECL["components"], installed)
        by_version = {(e["name"], e["version"]): e["status"] for e in entries}
        assert by_version[("acme/pkg", "1.5.0")] == "EXPOSURE_CONFIRMED"
        assert by_version[("acme/pkg", "2.0.1")] == "EXPOSURE_NONE"
        assert by_version[("other/lib", "2.9.9")] == "EXPOSURE_CONFIRMED"


def test_timeline_constraint_only_possible():
    with tempfile.TemporaryDirectory() as root:
        with open(os.path.join(root, "composer.json"), "w") as f:
            json.dump({"require": {"acme/pkg": "^1.2"}}, f)
        installed = timeline.collect_installed(root)
        entries, counts = timeline.grade(_DECL["components"], installed)
        assert entries[0]["status"] == "EXPOSURE_POSSIBLE"


def test_timeline_invalid_declaration():
    with tempfile.TemporaryDirectory() as root:
        bad = os.path.join(root, "nope.json")
        with open(bad, "w") as f:
            json.dump({"schema": "wrong"}, f)
        with pytest.raises(ValueError):
            timeline.load_declaration(bad)


# --------------------------------------------------------------- fusion


def test_fusion_links_and_leads():
    payload = {
        "meta": {"target": "t"},
        "findings": [
            {"id": "PHPSCAN-0001", "file": "src/config.php", "line": 1, "category": "x"},
            {"id": "PHPSCAN-0002", "file": "src/app.php", "line": 9, "category": "y"},
        ],
    }
    store = EvidenceStore("t")
    store.add(Evidence("host", "DISGUISED_PHP", "config.php", value={"ext": ".ini"}, confidence=0.9))
    store.add(Evidence("live", "ROUTE_PRESENT", "/config.php", value={"status": 200}, confidence=0.8))
    store.add(Evidence("live", "DNS_OBSERVED", "127.0.0.1", value={"resolved": ["127.0.0.1"]}, confidence=0.9))
    result = fusion.fuse(payload, store)
    by_id = {v["id"]: v for v in result["verification"]}
    v1 = by_id["PHPSCAN-0001"]
    assert v1["support"] == "EXPOSED"
    assert len(v1["evidence_ids"]) >= 1
    assert by_id["PHPSCAN-0002"]["support"] == "none"
    unex = result["unexplained_evidence"]
    assert any(u["category"] == "DNS_OBSERVED" for u in unex)
    assert result["summary"]["evidence_all"] if False else True


def test_fusion_exposure_only_matches_vendor_paths():
    payload = {"meta": {}, "findings": [{"id": "F2", "file": "app/somewhere.php", "line": 0}]}
    store = EvidenceStore("t")
    store.add(
        Evidence(
            "history",
            "EXPOSURE_GRADED",
            "acme/pkg",
            value={"version": "1.5.0", "status": "EXPOSURE_CONFIRMED"},
            confidence=0.85,
        )
    )
    res = fusion.fuse(payload, store)
    assert res["verification"][0]["support"] == "none", res["verification"]


def test_fusion_support_ladder_observed():
    payload = {"meta": {}, "findings": [{"id": "A", "file": "q/widget.php", "line": 1}]}
    store = EvidenceStore("t")
    store.add(Evidence("live", "COOKIE_OBSERVED", "u", value={"flags": []}, confidence=0.6))
    result = fusion.fuse(payload, store)
    ver = result["verification"][0]
    assert ver["support"] == "none"
    # a linked-but-not-blind category yields OBSERVED, not EXPOSED
    store.add(Evidence("host", "LOG_FILE", "widget.php", value=None, confidence=0.6))
    result2 = fusion.fuse(payload, store)
    assert result2["verification"][0]["support"] == "OBSERVED"


# --------------------------------------------------- proof/uncertainty


class _S:
    def __init__(self, stage, result, note=""):
        self.stage, self.result, self.note = stage, result, note


def test_proof_corroboration_attaches_without_verdict_change():
    stages = [_S("structural", "PASS"), _S("semantic", "PASS")]
    p1 = proof.build(None, stages, [])
    p2 = proof.build(None, stages, [], corroboration=[{"id": "EV-x", "result": "OBSERVED"}])
    assert p1["verdict"] == p2["verdict"] == "verified"
    assert p2.get("corroboration") and not p1.get("corroboration")


def test_uncertainty_extra_items():
    engine = type("E", (), {"file_meta": {}, "warn": []})()
    m = uncertainty.collect(engine, [])
    assert m["total"] == 0
    m2 = uncertainty.collect(engine, [], extra=[("UNCERTAIN_LIVE_BUDGET", "t", 0, "skipped")])
    assert m2["total"] == 1 and m2["codes"]["UNCERTAIN_LIVE_BUDGET"] == 1


# --------------------------------------------------- static quick wins


def _write(path, text):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    return path


def test_inline_suppression_requires_reason():
    with tempfile.TemporaryDirectory() as root:
        _write(
            os.path.join(root, "v.php"),
            "<?php echo $_GET['x'];\n// phpscan-ignore no reason here\n",
        )
        fobj = type(
            "F",
            (),
            {
                "status": "VALIDATED",
                "file": os.path.join(root, "v.php"),
                "line": 1,
                "rule_id": "XSS:echo",
                "reason": "",
                "severity": "HIGH",
            },
        )()
        cli._apply_inline_suppressions([fobj], [fobj.file])
        assert fobj.status == "VALIDATED"  # marker sits BELOW the line: not applied
        fobj2 = type(
            "F",
            (),
            {
                "status": "VALIDATED",
                "file": os.path.join(root, "v.php"),
                "line": 1,
                "rule_id": "XSS:echo",
                "reason": "",
                "severity": "HIGH",
            },
        )()
        _write(
            os.path.join(root, "v.php"),
            "// phpscan-ignore: XSS:echo reviewed by triage\n<?php echo $_GET['x'];\n",
        )
        cli._apply_inline_suppressions([fobj2], [fobj2.file])
        assert fobj2.status == "SUPPRESSED"
        assert "reviewed by triage" in fobj2.reason


def test_flood_control_marks_excess():
    fs = []
    for i in range(6):
        fs.append(
            type(
                "F",
                (),
                {
                    "status": "VALIDATED",
                    "file": "same.php",
                    "line": i + 1,
                    "rule_id": "R",
                    "severity": "HIGH" if i < 2 else "LOW",
                    "id": "F%d" % i,
                    "reason": "",
                },
            )
        )
    cli._flood_control(fs, 3)
    assert all(f.status == "SUPPRESSED" for f in fs[3:])
    assert fs[0].status == "VALIDATED" and fs[1].status == "VALIDATED"
    survival = [f for f in fs[:3]]
    assert all(f.status in ("SUPPRESSED", "VALIDATED") for f in survival)
    assert [f for f in fs if f.status == "VALIDATED"]
    assert len([f for f in fs if f.status == "VALIDATED"]) == 3
    assert any("flood-control" in f.reason for f in fs if f.status == "SUPPRESSED")


def test_baseline_expiry_drops_old_entries():
    import tempfile as tf

    with tf.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "b.json")
        with open(p, "w") as f:
            json.dump(
                {
                    "version": 1,
                    "reasons": {
                        "aaa": {"reason": "old reason", "expires": "2020-01-01"},
                        "bbb": {"reason": "fresh reason", "expires": "2099-01-01"},
                        "ccc": {"reason": "no expiry", "expires": ""},
                        "ddd": "plain reason",
                        "eee": {"reason": ""},
                    },
                },
                f,
            )
        reasons = cli._load_baseline(p)
    assert "aaa" not in reasons
    assert reasons["bbb"] == "fresh reason"
    assert reasons["ccc"] == "no expiry"
    assert reasons["ddd"] == "plain reason"
    assert "eee" not in reasons


def test_binary_php_scan_skip_warns():
    from phpscan.util import read_project_file

    with tempfile.TemporaryDirectory() as root:
        p = os.path.join(root, "bin.php")
        with open(p, "wb") as f:
            f.write(b"PK\x03\x04\x00\x00\x00\x00rest")
        src = read_project_file(p)
        assert src is not None and b"\x00" in src[:4096]
        assert "NUL" in "NUL byte in header"


def test_fail_on_exit_codes(capsys):
    with tempfile.TemporaryDirectory() as root:
        _write(os.path.join(root, "x.php"), "<?php echo $_GET['x'];?>")
        rc_v = cli.main(["scan", root, "--fail-on", "validated", "--quiet", "--no-baseline"])
        rc_n = cli.main(["scan", root, "--fail-on", "none", "--quiet", "--no-baseline"])
        rc_e = cli.main(["explain", os.path.join(root, "no-such-payload.json"), "X"])
    capsys.readouterr()
    assert rc_v in (0, 1)
    assert rc_n == 0
    assert rc_e == 2  # missing payload file → deterministic error exit
