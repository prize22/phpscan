# -*- coding: utf-8 -*-
"""Callable-dispatch taint analysis (array_map / usort / preg_replace_callback / ...).

phpscan resolves the callable argument of PHP's callable-consuming APIs:
constant callables are dispatched into builtin sinks and into analyzed
functions, attacker-controlled callables stay dynamic-dispatch candidates.
These tests cover positive, negative, sanitized, interprocedural, evidence,
determinism, reporting and safety behaviour for that capability.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phpscan import cli, engine as E, parser as P, validation as V  # noqa: E402

ARRAY_MAP_SYSTEM = '<?php\narray_map("system", $_GET["cmd"]);\n'
BENIGN_CALLABLES = r"""<?php
$args = $_GET["args"];
array_map("intval", $args);
array_map("strtoupper", $args);
$rows = ["b", "a"];
usort($rows, "strcmp");
preg_replace_callback('/\\d+/', "strtoupper", $_GET["s"]);
function handler($errno, $errstr) {
    return false;
}
set_error_handler("handler");
"""


def analyze(name, src):
    """Runs the engine + Validation Gate; returns (findings, rejected)."""
    eng = E.Engine()
    eng.add_file(P.parse_file_bytes(name, src.encode("utf-8")))
    eng.run()
    return V.ValidationGate().run(eng)


def cats(findings):
    return [f.category for f in findings]


# ------------------------------------------------------------ positive cases


def test_array_map_constant_callable_detected():
    findings, rejected = analyze("t.php", ARRAY_MAP_SYSTEM)
    hits = [f for f in findings if f.category == "Command Injection"]
    assert hits, "array_map('system', tainted) must reach the gate"
    f = hits[0]
    assert f.status == "VALIDATED"
    assert f.sink["name"] == "system"
    assert "array_map" in f.sink["expr"]
    assert "callable dispatch" in f.sink["expr"]
    assert not rejected


def test_register_shutdown_function_detected():
    findings, _rejected = analyze("t.php", '<?php\nregister_shutdown_function("system", $_GET["cmd"]);\n')
    assert "Command Injection" in cats(findings)


def test_array_filter_and_reduce_positional_forwarding():
    findings, _rejected = analyze("t.php", '<?php\narray_filter($_GET["items"], "exec");\n')
    assert "Command Injection" in cats(findings)

    # array_reduce: elements land in $item (parameter 1), which system()
    # ignores -- only the initial carry (parameter 0) is executed.
    safe = '<?php\n$rows = $_GET["rows"];\narray_reduce($rows, "system", "seed");\n'
    assert "Command Injection" not in cats(analyze("t.php", safe)[0])

    carry = '<?php\n$rows = ["a"];\narray_reduce($rows, "system", $_GET["carry"]);\n'
    assert "Command Injection" in cats(analyze("t.php", carry)[0])


def test_attacker_controlled_callable_is_code_injection():
    src = '<?php\n$rows = $_GET["rows"];\nusort($rows, $_GET["cmp"]);\n'
    findings, _rejected = analyze("t.php", src)
    hits = [f for f in findings if f.category == "Code Injection"]
    assert hits
    assert hits[0].status == "VALIDATED"
    assert "dynamic callable" in hits[0].sink["expr"]


def test_tainted_error_handler_callable_detected():
    findings, _rejected = analyze("t.php", '<?php\nset_error_handler($_GET["handler"]);\n')
    assert "Code Injection" in cats(findings)


def test_optional_forwarded_arguments_are_skipped_when_absent():
    # array_walk's optional third argument is not supplied: the declared
    # forward index must be skipped, while the array itself still reaches
    # parameter 0 of the callable.
    two_args = '<?php\narray_walk($_GET["items"], "system");\n'
    three_args = '<?php\narray_walk($_GET["items"], "system", $_GET["arg"]);\n'
    assert "Command Injection" in cats(analyze("t.php", two_args)[0])
    assert "Command Injection" in cats(analyze("t.php", three_args)[0])
    # a callable-only call site carries no data at all and must not crash
    assert analyze("t.php", '<?php\narray_map("system");\n')[0] == []


# ------------------------------------------------------------ negative cases


def test_benign_callables_produce_no_findings():
    findings, rejected = analyze("t.php", BENIGN_CALLABLES)
    assert findings == []
    assert rejected == []


def test_constant_callable_forwards_no_arguments_when_api_supplies_them():
    # set_error_handler("system", $mask): the mask is the error-type list,
    # never an argument to the handler, so attacker input cannot reach it.
    src = '<?php\nset_error_handler("system", $_GET["mask"]);\n'
    findings, rejected = analyze("t.php", src)
    assert findings == []
    assert rejected == []


# ------------------------------------------------------------ sanitized case


def test_sanitized_forwarded_argument_is_rejected():
    src = '<?php\nregister_shutdown_function("system", escapeshellarg($_GET["cmd"]));\n'
    findings, rejected = analyze("t.php", src)
    assert "Command Injection" not in cats(findings)
    assert rejected, "a candidate should still be produced, then rejected"
    rec = rejected[0]
    assert rec["category"] == "Command Injection"
    assert "escapeshellarg" in rec["reason"]
    assert rec["stages"]["sanitizer"]["result"] == "FAIL"


# ------------------------------------------------------------ interprocedural


def test_constant_callable_resolves_across_function_boundary():
    src = (
        "<?php\n"
        "function run_each($v) {\n"
        "    system($v);\n"
        "}\n"
        "$args = $_GET[\"args\"];\n"
        "array_map(\"run_each\", $args);\n"
    )
    findings, _rejected = analyze("t.php", src)
    hits = [f for f in findings if f.category == "Command Injection"]
    assert hits
    f = hits[0]
    assert f.status == "VALIDATED"
    assert "system" in f.sink["name"]
    assert "callee" in f.sink["expr"]
    assert any("interprocedural" in step for step in f.data_flow)


# ------------------------------------------------------------ evidence


def test_finding_carries_source_sink_and_path_evidence():
    findings, _rejected = analyze("t.php", ARRAY_MAP_SYSTEM)
    f = [x for x in findings if x.category == "Command Injection"][0]
    assert f.source["var"].startswith("$_GET")
    assert f.source["class"] == "DIRECT_USER_INPUT"
    assert len(f.data_flow) >= 2, "dispatch must be recorded in the chain"
    assert any("callable dispatch" in step for step in f.data_flow)
    assert f.validation["data-flow"]["result"] == "PASS"
    assert f.validation["sanitizer"]["result"] == "PASS"
    assert f.validation["control-flow"]["result"] == "PASS"
    assert f.proof


# ------------------------------------------------------------ determinism


def test_findings_are_deterministic():
    src = (
        "<?php\n"
        "array_map(\"system\", $_GET[\"cmd\"]);\n"
        "usort($rows, $_GET[\"cmp\"]);\n"
        "array_filter($_GET[\"items\"], \"exec\");\n"
    )

    def snapshot():
        findings, rejected = analyze("t.php", src)
        return (
            [(f.category, f.status, f.line, f.sink["name"], f.fingerprint, tuple(f.data_flow)) for f in findings],
            [(r["category"], r["line"], r["reason"]) for r in rejected],
        )

    assert snapshot() == snapshot()


# ------------------------------------------------------------ reporting


def test_json_sarif_and_terminal_output_remain_valid(tmp_path, capsys):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "t.php").write_text(ARRAY_MAP_SYSTEM, encoding="utf-8")

    rc = cli.main(["scan", str(src_dir), "--json", "--quiet", "--no-baseline"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["findings"][0]["category"] == "Command Injection"
    assert payload["findings"][0]["sink"]["name"] == "system"

    sarif_path = str(tmp_path / "out.sarif")
    rc = cli.main(["scan", str(src_dir), "--sarif-out", sarif_path, "--quiet", "--no-baseline"])
    assert rc == 0
    with open(sarif_path, encoding="utf-8") as fh:
        sarif = json.load(fh)
    assert sarif["runs"] and sarif["runs"][0]["results"]
    from phpscan.findings import RULE_PREFIX

    assert sarif["runs"][0]["results"][0]["ruleId"] == RULE_PREFIX["Command Injection"]
    capsys.readouterr()

    cli.main(["scan", str(src_dir), "--no-baseline"])
    terminal = capsys.readouterr().out
    assert "Command Injection" in terminal
    assert "callable dispatch" in terminal or "system" in terminal


# ------------------------------------------------------------ safety


def test_scanner_does_not_execute_target_php(tmp_path):
    canary = tmp_path / "executed.txt"
    fixture = tmp_path / "t.php"
    fixture.write_text(
        '<?php\nfile_put_contents("%s", "ran");\narray_map("system", $_GET["cmd"]);\n' % canary.as_posix(),
        encoding="utf-8",
    )
    rc = cli.main(["scan", str(tmp_path), "--quiet", "--no-baseline"])
    assert rc == 0
    assert not canary.exists(), "the scanner must never execute target PHP"


@pytest.mark.parametrize(
    "api,callable_idx,fwd",
    [
        ("array_map", 0, True),
        ("array_filter", 1, True),
        ("usort", 1, True),
        ("preg_replace_callback", 1, True),
        ("register_shutdown_function", 0, True),
        ("set_error_handler", 0, False),
        ("ob_start", 0, False),
    ],
)
def test_registry_matches_declared_layout(api, callable_idx, fwd):
    from phpscan import defs as D

    idx, spec = D.CALLBACK_FUNCS[api]
    assert idx == callable_idx
    assert bool(spec) is fwd
