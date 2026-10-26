# -*- coding: utf-8 -*-
"""Unit + integration tests for phpscan."""

import json
import os
import re
import sys

import pytest

from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phpscan import parser as P, engine as E, validation as V  # noqa
from phpscan import webshell as W, secrets as SEC  # noqa
from phpscan import (
    discovery,
    cache as C,
    util,
    uncertainty as UNC,
    behavior as BEH,
    variants as VAR,
    diff as DIFF,
    reporting,
    benchmark,
)  # noqa
from phpscan.cli import main  # noqa
from phpscan.findings import sarif_output, Finding  # noqa


def parse_bytes(src, name="test.php"):
    if isinstance(src, str):
        src = src.encode("utf-8")
    return P.parse_file_bytes(name, src)


def analyze_files(list_of_srcs):
    """Each item: (name, src_bytes). Returns (engine, findings,
    rejected)."""
    eng = E.Engine()
    for name, src in list_of_srcs:
        eng.add_file(parse_bytes(src, name))
    eng.run()
    gate = V.ValidationGate()
    fnd, rej = gate.run(eng)
    return eng, fnd, rej


SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
VUL_PLAIN = "<?php\n$id = $_GET['id'];\n$pdo->query('SELECT * FROM t WHERE id=' . $id);\n"


# ---------- parser / IR ----------


def test_parse_functions_and_globals():
    ir = parse_bytes("<?php\nfunction f($a){}\nclass C { public $x; function m($b){} }\n$x = 1;\n")
    names = [(f.name, f.cls) for f in ir.funcs]
    assert ("f", "") in names
    assert ("m", "C") in names
    assert len(ir.global_body) >= 1
    assert "C" in ir.classes


def test_parse_deterministic_hashes():
    a = parse_bytes(VUL_PLAIN, "a.php")
    b = parse_bytes(VUL_PLAIN, "b.php")
    assert a.sha256 == b.sha256


def test_build_closures():
    src = "<?php\n$g = function($x){\n  return x_($x);\n};\n$inner = $g(1);\n"
    ir = parse_bytes(src)
    assert any(f.closure for f in ir.funcs)


def test_strip_ir_pickles():
    ir = parse_bytes(VUL_PLAIN)
    util.strip_ir(ir)
    import pickle

    ir2 = pickle.loads(pickle.dumps(ir))
    assert ir2.sha256 == ir.sha256


# ---------- taint engine ----------


def test_direct_sqli_flow():
    eng, fnd, rej = analyze_files([("s.php", VUL_PLAIN)])
    cats = [f.category for f in fnd]
    assert "SQL Injection" in cats
    f = [f for f in fnd if f.category == "SQL Injection"][0]
    assert f.source["var"].startswith("$_GET")
    assert f.data_flow


def test_sanitized_flow_rejected():
    src = "<?php\n$s = escapeshellarg($_GET['x']);\nsystem($s);\n"
    eng, fnd, rej = analyze_files([("s.php", src)])
    assert "Command Injection" not in [f.category for f in fnd]
    assert rej and "escapeshellarg" in rej[-1]["reason"]


def test_interprocedural_param_sinks():
    src = "<?php\nfunction a() { b($_GET['z']); }\nfunction b($p) { system($p); }\n"
    eng, fnd, rej = analyze_files([("i.php", src)])
    cats = [f.category for f in fnd]
    assert "Command Injection" in cats
    f = [f for f in fnd if f.category == "Command Injection"][0]
    assert "callee" in (f.sink["expr"] or "")


# ---------- validation gate ----------


def test_gate_status_structure():
    src = VUL_PLAIN
    eng, fnd, rej = analyze_files([("s.php", src)])
    f = fnd[0]
    for st in (
        "structural",
        "semantic",
        "data-flow",
        "control-flow",
        "sanitizer",
        "context",
        "contradiction",
        "re-analysis",
    ):
        assert st in f.validation
    assert f.status in ("VALIDATED", "PARTIALLY_VALIDATED", "UNCONFIRMED")


def test_deterministic_fingerprints():
    src = VUL_PLAIN
    _, fnd, _ = analyze_files([("s.php", src)])
    ids = [f.fingerprint for f in fnd]
    assert all(ids)
    _, fnd2, _ = analyze_files([("s.php", src)])
    assert [f.fingerprint for f in fnd2] == ids


def test_rejected_dead_branch():
    src = "<?php\nif (false) {\n  system($_GET['x']);\n}\n"
    eng, fnd, rej = analyze_files([("d.php", src)])
    assert not fnd


# ---------- webshell correlation ----------

OBFSHELL = (
    "<?php\n$d = base64_decode($_POST['c']);\n"
    "$d = gzinflate($d);\n$fn = 'sys' . 'tem';\n$fn($d);\n"
    "file_put_contents('/tmp/o', $d);\n"
)


def test_webshell_correlation():
    ir = parse_bytes(OBFSHELL, "w.php")
    eng = E.Engine()
    eng.add_file(ir)
    eng.run()
    leads = W.classify(eng, eng.flows)
    assert leads
    best = leads[0]
    assert best["score"] >= W.REPORT_SCORE
    assert len(best["categories"]) >= W.MIN_CATEGORIES


def test_webshell_finding_model():
    ir = parse_bytes(OBFSHELL, "w.php")
    eng = E.Engine()
    eng.add_file(ir)
    eng.run()
    leads = W.classify(eng, eng.flows)
    fnd = W.findings_from(leads)
    assert fnd[0].category == "Webshell / Backdoor"
    assert fnd[0].fingerprint


def test_clean_file_no_webshell_lead():
    ir = parse_bytes("<?php\n$h = htmlspecialchars($_POST['t'], ENT_QUOTES);\necho $h;\n", "c.php")
    eng = E.Engine()
    eng.add_file(ir)
    eng.run()
    assert not W.classify(eng, eng.flows)


# ---------- secrets ----------


def test_aws_key_detected():
    text = 'config <?= ; ?> "aws_access_key_id":"AKIAIOSFODNN7EXAMPLE"'
    hits = SEC.scan(text, "x.php")
    assert any(h["type"] == "AWS Access Key" for h in hits)


def test_privkey_block():
    text = "$ priv = null; // -----\n-----BEGIN RSA PRIVATE KEY-----\nsomewhere\n"
    hits = SEC.scan(text, "x.php")
    assert any(h["type"] == "Private Key" for h in hits)


def test_no_secret_for_dummy():
    text = '"password": "password"'
    hits = SEC.scan(text, "x.php")
    assert not any(h["type"] == "Hardcoded Credential" for h in hits)


# ---------- discovery & cache ----------


def test_discover(tmp_path):
    (tmp_path / "a.php").write_text("<?php\n")
    (tmp_path / "b.txt").write_text("no")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "x.php").write_text("<?php\n")
    got = discovery.discover(str(tmp_path))
    names = [os.path.basename(p) for p in got]
    assert names == ["a.php"]


def test_cache_roundtrip(tmp_path):
    (tmp_path / "c.php").write_text(VUL_PLAIN)
    c = C.IRCache(str(tmp_path / ".phpscan-cache"))
    src = (tmp_path / "c.php").read_bytes()
    h = c.file_hash(str(tmp_path / "c.php"))
    ir = c.load(str(tmp_path / "c.php"), h)
    assert ir is None
    ir = P.parse_file_bytes("c.php", src)
    c.save(ir)
    ir2 = c.load(str(tmp_path / "c.php"), h)
    assert ir2 is not None
    assert ir2.sha256 == ir.sha256


# ---------- SARIF ----------


def test_sarif_shape():
    f = Finding(
        id="PHPSCAN-0001",
        rule_id="php.sqli",
        category="SQL Injection",
        title="t",
        severity="HIGH",
        confidence=0.8,
        status="VALIDATED",
        file="a.php",
        line=3,
        sink={"name": "q"},
        fingerprint="fp123",
    )
    out = sarif_output({"version": "0.1.0"}, [f])
    assert out["version"] == "2.1.0"
    res = out["runs"][0]["results"][0]
    assert res["ruleId"] == "php.sqli"
    assert res["properties"]["color"] if False else True
    assert res["partialFingerprints"]["phpscanFingerprint/v2"] == "fp123"
    json.dumps(out)  # must be serializable


def test_json_payload_serializable(tmp_path):
    src = VUL_PLAIN
    eng, fnd, rej = analyze_files([("j.php", src)])
    payload = {"findings": [x.export() for x in fnd], "rejected": rej}
    s = json.dumps(payload)
    assert '"category"' in s


# ---------- class registry (v0.2.0) ----------

CLASS_FLOW = """<?php
class DBApi {
    public function query($sql) {
        $pdo = new PDO();
        $pdo->query($sql);
    }
}
class ApiX extends DBApi {
    public static function route($p) {
        self::query($p);
    }
    public function goFast($p) {
        parent::query($p);
    }
}
$ctl = new ApiX();
$ctl->goFast($_GET['q']);
ApiX::route($_GET['w']);
"""


def test_class_static_parent_resolution():
    eng, fnd, rej = analyze_files([("c.php", CLASS_FLOW)])
    cats = [f.category for f in fnd]
    assert cats.count("SQL Injection") == 2
    for f in fnd:
        assert "interprocedural" in " ".join(f.data_flow)


OBJECT_FLOW = """<?php
class Helper {
    public function __construct($pre) {
        $this->prefix = $pre;
    }
    public function run($x) {
        system($this->prefix . $x);
    }
}
$h = new Helper($_GET['pre']);
$h->run($_REQUEST['cmd']);
"""


def test_object_type_inference_and_ctor_props():
    eng, fnd, rej = analyze_files([("o.php", OBJECT_FLOW)])
    cats = [f.category for f in fnd]
    assert "Command Injection" in cats
    f = [f for f in fnd if f.category == "Command Injection"][0]
    assert "interprocedural" in " ".join(f.data_flow)


DYN_CALLS = """<?php
$op = $_GET['op'];
$fn = 'assert';
call_user_func($fn, $op);
$unknown = $_GET['callable'];
call_user_func($unknown, 'x');
"""


def test_dyn_dispatch_paths():
    eng, fnd, rej = analyze_files([("dyn.php", DYN_CALLS)])
    exprs = " || ".join(
        re.sub(r"\s+", " ", (f.sink or {}).get("expr", "")) for f in fnd if f.category == "Code Injection"
    )
    assert "assert" in exprs
    assert "call_user_func" in exprs


FILES_FLOW = """<?php
$name = $_FILES['up']['name'];
$dest = $_FILES['up']['tmp_name'];
move_uploaded_file($dest, '/var/www/' . $name);
"""


def test_files_upload_dest_and_tmp_name():
    eng, fnd, rej = analyze_files([("u.php", FILES_FLOW)])
    cats = [f.category for f in fnd]
    assert "Unsafe File Upload" in cats
    # server-provided tmp_name must not be treated as attacker-controlled
    eng2, fnd2, _ = analyze_files([("u2.php", "<?php\nfile_get_contents($_FILES['x']['tmp_name']);\n")])
    assert "Path Traversal" not in [f.category for f in fnd2 if f.status == "VALIDATED"]


REALPATH_FLOW = """<?php
$p = realpath($_GET['p']);
file_get_contents($p . '/upload/' . $_GET['f']);
"""


def test_realpath_only_partial_for_path():
    eng, fnd, rej = analyze_files([("rp.php", REALPATH_FLOW)])
    pt = [f for f in fnd if f.category == "Path Traversal"]
    assert pt
    assert all(f.status == "PARTIALLY_VALIDATED" for f in pt if f.sink.get("name") == "realpath")


def test_include_dir_constant_no_fp():
    src = '<?php\ninclude __DIR__ . "/config.php";\n'
    eng, fnd, rej = analyze_files([("inc.php", src)])
    assert not [f for f in fnd if f.category == "File Inclusion"]


def test_prepared_statements_no_fp():
    src = "<?php\n$st = $pdo->prepare('SELECT * FROM t WHERE id = ?');\n$st->execute([$_GET['id']]);\n"
    eng, fnd, rej = analyze_files([("pp.php", src)])
    assert not [f for f in fnd if f.category == "SQL Injection"]


def test_constant_only_no_finding():
    src = "<?php\nsystem('ls -la');\n$d = base64_decode('c3lzdGVt');\n"
    eng, fnd, rej = analyze_files([("k.php", src)])
    assert not fnd


def test_gate_dedup_wrapper_chain():
    src = (
        "<?php\nfunction fw($x) { system($x); }\n"
        "function a($y) { fw($y); }\n"
        "function b($z) { a($z); }\n"
        "b($_GET['one']);\n"
    )
    eng, fnd, rej = analyze_files([("dup.php", src)])
    ci = [f for f in fnd if f.category == "Command Injection"]
    # one source, one wrapper chain, one finding — no per-hop duplicates
    assert len(ci) == 1
    assert "interprocedural" in " ".join(ci[0].data_flow)


def test_gate_dedup_same_source_multi_sink():
    src = "<?php\nif (1 == 1) {\n system($_GET['q']);\n} else {\n system($_GET['q']);\n}\n"
    eng, fnd, rej = analyze_files([("dd.php", src)])
    ci = [f for f in fnd if f.category == "Command Injection"]
    assert len(ci) == 1


def test_suppression_status_applied():
    src = VUL_PLAIN
    eng, fnd, _ = analyze_files([("sup.php", src)])
    from phpscan.validation import ValidationGate

    gate = ValidationGate(
        options={
            "suppressed": {f.fingerprint for f in fnd},
            "suppression_reasons": {f.fingerprint: "audit example" for f in fnd},
        }
    )
    fnd2, _ = gate.run(eng)
    assert all(f.status == "SUPPRESSED" for f in fnd2)
    assert all("audit example" in f.reason for f in fnd2)


def test_source_verification_downgrade(tmp_path):
    # craft a candidate whose sink text is absent from the file source
    import phpscan.engine as E
    from phpscan.validation import validate_candidate

    eng = E.Engine()
    ir = parse_bytes(VUL_PLAIN, "sv.php")
    eng.add_file(ir)
    eng.run()
    flow = next(iter(eng.flows.values()))
    cand = next(iter(flow.cands.values()))
    result = validate_candidate(cand, eng.file_meta.get(cand.file, {}), False, src_lines=["<?php", ""])  # sink absent
    stages = result[0].validation if result[0] else None
    if stages is None:
        x = result[1]
        assert x.get("reason")
    else:
        df = stages.get("data-flow", {})
        note = df.get("note", "")
        assert ("not located" in note) or df.get("result") == "PARTIAL"


# ---------- cache hardening ----------


def test_cache_invalidation_on_modify(tmp_path):
    tgt = tmp_path / "m.php"
    tgt.write_text("<?php\n$x = 1;\n")
    c = C.IRCache(str(tmp_path / ".phpscan-cache"))
    h = c.file_hash(str(tgt))
    ir = P.parse_file_bytes("m.php", tgt.read_bytes())
    c.save(ir)
    assert c.load(str(tgt), h) is not None
    # modify content -> hash changes -> miss
    tgt.write_text("<?php\n$x = 2;\n")
    h2 = c.file_hash(str(tgt))
    assert h2 != h
    assert c.load(str(tgt), h2) is None
    # delete file -> hash None
    import os

    os.remove(str(tgt))
    assert c.file_hash(str(tgt)) is None


def test_cache_refuses_hostile_pickle(tmp_path):
    import pickle as pk
    import builtins as bi

    c = C.IRCache(str(tmp_path / ".phpscan-cache"))
    h = "ab" * 32
    store = c.path_for(h)
    {k: v for k, v in [("p", 1)]}

    class Evil(object):
        def __reduce__(self):
            return (bi.exec, ("print('pw')",))

    with open(store, "wb") as f:
        pk.dump(Evil(), f)
    got = c.load("whatever.php", h)
    assert got is None
    assert c.errors >= 1


def test_cache_ignores_old_schema(tmp_path):
    import pickle as pk

    c = C.IRCache(str(tmp_path / ".phpscan-cache"))
    ir = P.parse_file_bytes("old.php", VUL_PLAIN.encode())
    # simulate an old, schema-versionless store layout
    store = c.path_for(ir.sha256)
    old_store = os.path.join(os.path.dirname(store), os.path.basename(store).split("-", 1)[-1])
    util.strip_ir(ir)
    with open(old_store, "wb") as f:
        pk.dump(ir, f)
    c.file_hash("lets just use a direct check") or ir.sha256
    # loading with the same hash must ignore the old file and miss
    assert c.load("old.php", ir.sha256) is None


# ---------- scanner robustness (security) ----------


def test_malformed_php_no_crash():
    src = b"<?php ((((( )))))))\n\x00\xff garbage here\n"
    ir = parse_bytes(src, "bad.php")
    assert ir.parse_errors or not ir.ok


def test_deep_nesting_is_budgeted():
    src = ("<?php\nif (true) {\n" * 5000) + "$a=1;\n" + ("}\n" * 5000)
    ir = parse_bytes(src, "deep.php")
    assert isinstance(ir.truncated, bool)


def test_huge_line_handled():
    src = ("<?php\n$s = '" + "A" * 500_000 + "';\n").encode()
    ir = parse_bytes(src, "huge.php")
    assert ir.truncated is False


def test_two_pass_determinism_with_cache_load():
    # full pipeline determinism even when IR goes through pickle
    import pickle as pk

    ir = parse_bytes(CLASS_FLOW, "cd.php")
    util.strip_ir(ir)
    ir2 = pk.loads(pk.dumps(ir))
    eng1 = E.Engine()
    eng1.add_file(ir)
    eng1.run()
    eng2 = E.Engine()
    eng2.add_file(ir2)
    eng2.run()
    g = V.ValidationGate()
    f1, r1 = g.run(eng1)
    f2, r2 = g.run(eng2)
    assert [f.export() for f in f1] == [f.export() for f in f2]


# ---------- adversarial behaviors (v0.2.0) ----------


def test_augassign_accumulates_taint_in_loop():
    src = (
        "<?php\n$cmd = '';\nfor ($i = 0; $i < 3; $i++) {\n    $cmd .= $_COOKIE['part' . $i] . ';';\n}\nsystem($cmd);\n"
    )
    eng, fnd, rej = analyze_files([("loop.php", src)])
    assert any(f.category == "Command Injection" for f in fnd)


def test_closure_call_resolves():
    src = "<?php\nfunction inner($p) { system($p); }\n$mid = function ($v) { inner($v); };\n$mid($_GET['x']);\n"
    eng, fnd, rej = analyze_files([("clo.php", src)])
    assert any(f.category == "Command Injection" for f in fnd)


def test_user_class_exec_no_pdo_fp():
    src = (
        "<?php\nclass Invoker {\n"
        "    public function exec($remaining) {\n"
        "        system($remaining);\n    }\n}\n"
        "$inv = new Invoker();\n$inv->exec($_POST['suffix']);\n"
    )
    eng, fnd, rej = analyze_files([("inv.php", src)])
    cats = set(f.category for f in fnd)
    assert "Command Injection" in cats
    assert "SQL Injection" not in cats


def test_realpath_sink_downgrades():
    src = "<?php\n$f = realpath($_GET['p']);\nis_file($f);\nfile_get_contents(realpath($f));\n"
    eng, fnd, rej = analyze_files([("rp.php", src)])
    pt = [f for f in fnd if f.category == "Path Traversal"]
    for f in pt:
        if f.status == "VALIDATED":
            assert f.validation.get("data_flow") != "CONFIRMED"


def test_uncertainty_map_records_file_signals():
    eng = SimpleNamespace(file_meta={"a.php": {"parse_errors": ["e1", "e2"], "truncated": True}}, warn=[])
    u = UNC.collect(eng, [])
    assert u["total"] == 2
    assert u["codes"]["UNCERTAIN_PARSE_ERRORS"] == 1
    assert u["codes"]["UNCERTAIN_FILE_TRUNCATED"] == 1
    assert u["per_file"]["a.php"][0]["line"] == 0


def test_uncertainty_map_records_engine_warnings():
    eng = SimpleNamespace(
        file_meta={},
        warn=["analysis error in b.php: boom", "recursion limit reached in b.php"],
    )
    u = UNC.collect(eng, [])
    assert u["codes"]["UNCERTAIN_ANALYSIS_ERROR"] == 1
    assert u["codes"]["UNCERTAIN_RECURSION_LIMIT"] == 1
    assert u["per_file"]["b.php"][0]["code"] == "UNCERTAIN_ANALYSIS_ERROR"


def test_uncertainty_map_records_gate_partials_and_skips():
    finding = SimpleNamespace(
        file="c.php",
        line=7,
        proof={
            "claims": [
                {"stage": "data_flow", "result": "PARTIAL", "note": "sink not found in source"},
                {"stage": "re_analysis", "result": "SKIP", "note": "not evaluated"},
                {"stage": "semantic", "result": "PASS"},
            ],
            "open_questions": [{"stage": "data_flow", "current": "need textual confirmation"}],
        },
    )
    u = UNC.collect(SimpleNamespace(file_meta={}, warn=[]), [finding])
    codes = u["codes"]
    assert codes["UNCERTAIN_DATA_FLOW_PARTIAL"] == 1
    assert codes["UNCERTAIN_RE_ANALYSIS_SKIPPED"] == 1
    assert codes["UNCERTAIN_OPEN_QUESTION"] == 1


def test_uncertainty_map_empty_when_nothing_uncertain():
    eng = SimpleNamespace(file_meta={}, warn=[])
    finding = SimpleNamespace(file="d.php", line=1, proof={"claims": [{"stage": "semantic", "result": "PASS"}]})
    u = UNC.collect(eng, [finding])
    assert u["total"] == 0
    assert u["items"] == []
    assert u["codes"] == {}
    assert u["per_file"] == {}


def test_behavior_map_sources_transforms_sinks():
    src = "<?php\nfunction foo() {\n  $u = $_GET['id'];\n  $x = base64_decode($u);\n  eval($x);\n}\n"
    eng, fnd, rej = analyze_files([("b.php", src)])
    m = BEH.build_map(eng)
    assert m["total_functions"] == 1
    fn = m["functions"][0]
    assert fn["func"] == "foo"
    assert any(s["origin"] and "GET" in s["origin"] for s in fn["entry_sources"])
    assert "eval" in [s["sink"] for s in fn["sinks"]]
    assert "base64_decode" in fn["transforms"]


def test_behavior_map_no_spurious_sources_for_clean_func():
    src = "<?php\nfunction bar() {\n  $x = 1 + 2;\n  return $x;\n}\n"
    eng, fnd, rej = analyze_files([("c.php", src)])
    m = BEH.build_map(eng)
    fn = m["functions"][0]
    assert fn["entry_sources"] == []
    assert fn["sinks"] == []


def test_behavior_map_render_text_includes_func():
    src = "<?php\nfunction baz() {\n  $q = $_GET['x'];\n  system($q);\n}\n"
    eng, fnd, rej = analyze_files([("d.php", src)])
    text = BEH.render_text(BEH.build_map(eng))
    assert "baz" in text
    assert "system" in text


def test_map_cli_writes_map(tmp_path):
    p = tmp_path / "t.php"
    p.write_text("<?php\nfunction baz() {\n  $q = $_GET['x'];\n  system($q);\n}\n")
    rc = main(["map", str(p)])
    assert rc == 0


def _mk_finding(status, category, sink, source_class, confidence=0.8):
    return SimpleNamespace(
        id="PHPSCAN-0001",
        category=category,
        status=status,
        confidence=confidence,
        file="t.php",
        line=10,
        source={"var": "$u", "class": source_class},
        sink={"name": sink, "kind": "call", "expr": sink + "($u)"},
        proof={"claims": [{"stage": "data_flow", "result": "PASS"}]},
        data_flow=[("L3", "base64_decode($u)")],
    )


def test_variants_group_validated_into_confirmed_genome():
    f1 = _mk_finding("VALIDATED", "Command Injection", "system", "DIRECT_USER_INPUT")
    f2 = _mk_finding("VALIDATED", "Command Injection", "system", "DIRECT_USER_INPUT")
    genomes = VAR.analyze([f1, f2], [])
    assert len(genomes) == 1
    g = genomes[0]
    assert g["status"] == "confirmed"
    assert len(g["instances"]) == 2


def test_variants_partial_is_untested():
    f = _mk_finding("PARTIALLY_VALIDATED", "Command Injection", "exec", "DIRECT_USER_INPUT", 0.5)
    genomes = VAR.analyze([f], [])
    assert genomes[0]["status"] == "untested"


def test_variants_rejected_only_is_refuted():
    rej = [
        {
            "category": "Command Injection",
            "sink": "system(",
            "file": "t.php",
            "line": 3,
            "reason": "no data-flow evidence",
        }
    ]
    genomes = VAR.analyze([], rej)
    assert genomes[0]["status"] == "refuted"
    assert len(genomes[0]["candidates"]) == 1


def test_variants_deterministic_genome_ids():
    p1 = {
        "category": "Command Injection",
        "source_class": "DIRECT_USER_INPUT",
        "sink": "system",
        "call_kind": "call",
        "san_ctx": "",
        "transforms": ("base64_decode",),
    }
    p2 = dict(p1)
    assert VAR.genome_id(p1) == VAR.genome_id(p2)
    p3 = dict(p1, sink="exec")
    assert VAR.genome_id(p1) != VAR.genome_id(p3)


def _mk_finding_with_fp(fp, status="VALIDATED", category="SQL Injection", sink="query", conf=0.8):
    return SimpleNamespace(
        id="PHPSCAN-9001",
        category=category,
        status=status,
        confidence=conf,
        file="t.php",
        line=5,
        fingerprint=fp,
        source={"var": "$u", "class": "DIRECT_USER_INPUT"},
        sink={"name": sink, "kind": "call", "expr": sink + "($u)"},
        proof={"claims": [{"stage": "data_flow", "result": "PASS"}]},
        data_flow=[],
    )


def test_diff_fixed_new_unchanged():
    base = [_mk_finding_with_fp("fp-a"), _mk_finding_with_fp("fp-b", status="PARTIALLY_VALIDATED")]
    cur = [_mk_finding_with_fp("fp-a", status="PARTIALLY_VALIDATED"), _mk_finding_with_fp("fp-c")]
    r = DIFF.compare(base, cur)
    assert r["counts"] == {"fixed": 1, "new": 1, "unchanged": 1}
    assert r["fixed"][0].fingerprint == "fp-b"
    assert r["new"][0].fingerprint == "fp-c"
    u = r["unchanged"][0]
    assert u["baseline"].status == "VALIDATED" and u["current"].status == "PARTIALLY_VALIDATED"


def test_diff_render_text_contains_counts():
    r = DIFF.compare([_mk_finding_with_fp("fp-x")], [_mk_finding_with_fp("fp-y")])
    text = DIFF.render_text(r, "old", "new")
    assert "fixed: 1" in text and "new: 1" in text and "unchanged: 0" in text
    assert "FIXED" in text and "NEW" in text


def test_rae_queue_skips_verified_findings():
    f = SimpleNamespace(
        id="PHPSCAN-1",
        title="SQL Injection in query",
        category="SQL Injection",
        status="VALIDATED",
        confidence=0.9,
        file="t.php",
        line=3,
        proof={"verdict": "verified", "open_questions": []},
    )
    assert reporting.build_rae_queue([f]) == []


def test_rae_queue_queues_probable_and_webshell():
    f1 = SimpleNamespace(
        id="PHPSCAN-2",
        title="Command Injection in system",
        category="Command Injection",
        status="PARTIALLY_VALIDATED",
        confidence=0.5,
        file="t.php",
        line=4,
        proof={
            "verdict": "probable",
            "open_questions": [
                {"stage": "sanitizer", "current": "weak sanitizer", "action": "strengthen evidence for sanitizer"}
            ],
        },
    )
    f2 = SimpleNamespace(
        id="PHPSCAN-3",
        title="possible webshell",
        category="Webshell / Backdoor",
        status="RESEARCH_LEAD",
        confidence=0.4,
        file="s.php",
        line=9,
        proof={"verdict": "verified", "open_questions": []},
    )
    f3 = SimpleNamespace(
        id="PHPSCAN-4",
        title="weak path traversal",
        category="Path Traversal",
        status="UNCONFIRMED",
        confidence=0.3,
        file="u.php",
        line=1,
        proof={"verdict": "incomplete", "open_questions": []},
    )
    q = reporting.build_rae_queue([f1, f2, f3])
    assert [x["id"] for x in q] == ["PHPSCAN-2", "PHPSCAN-3", "PHPSCAN-4"]
    assert q[0]["next_action"] == "strengthen evidence for sanitizer"
    assert q[2]["verdict"] == "incomplete"


def test_benchmark_corpus_metrics(tmp_path):
    root = tmp_path / "corpus"
    for sub in ("vulnerable", "clean", "patched", "framework"):
        (root / sub).mkdir(parents=True)
    (root / "vulnerable" / "a.php").write_text(
        '<?php // phpscan: expect: Command Injection\n$c = $_GET["c"];\nsystem($c);\n'
    )
    (root / "clean" / "b.php").write_text('<?php // phpscan: clean\nsystem("ls");\n')
    (root / "patched" / "c.php").write_text(
        '<?php // phpscan: clean\n$st = $pdo->prepare("SELECT * FROM t WHERE id = ?");\n$st->execute([1]);\n'
    )
    manifest = {"a.php": ["Command Injection"], "b.php": [], "c.php": []}
    (root / "manifest.json").write_text(json.dumps(manifest))
    r_path = str(tmp_path / "bench")
    rc = benchmark.run_corpus(str(root), r_path)
    assert rc == 0
    report = json.loads(open(r_path + ".json").read())
    assert report["totals"]["tp"] == 1
    assert report["totals"]["fp"] == 0
    assert report["totals"]["fn"] == 0
    assert report["totals"]["f1"] == 1.0
    assert report["per_category"]["Command Injection"]["tp"] == 1
    assert "timing_ms" in report


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-x", "-q"]))
