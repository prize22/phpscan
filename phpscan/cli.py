"""phpscan CLI.

Subcommands:
  scan       run the full pipeline on a target (dir or file)
  research   scan + narrative research report (markdown)
  validate   re-run the Validation Gate on a previous JSON output
  explain    print reasoning for one finding from a JSON output
  rules      list/validate rule overrides
  report     re-render a previous JSON output
  benchmark  run the eval corpus and compute precision/recall/F1
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

from . import __version__
from . import cache as C
from . import defs, discovery, parser as P, util as U
from .findings import Finding, stable_fingerprint
from .validation import ValidationGate
from . import reporting, surface as SURF, webshell as W
from . import rules as RULES
from . import behavior as BEH
from . import variants as VARIANTS
from . import diff as DIFF
from . import uncertainty as UNCERTAINTY


def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="phpscan",
        description="Deterministic local PHP security static analyzer with an evidence-driven Validation Gate.",
    )
    ap.add_argument("--version", action="version", version="phpscan " + __version__)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--debug", action="store_true")
    common.add_argument("--verbose", "-v", action="store_true")
    common.add_argument("--quiet", "-q", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="scan a target", parents=[common])
    p_scan.add_argument("target")
    p_scan.add_argument("--json", action="store_true", help="emit JSON to stdout")
    p_scan.add_argument("--sarif", action="store_true")
    p_scan.add_argument("--out", default=None, help="write JSON payload to a file")
    p_scan.add_argument("--sarif-out", default=None)
    p_scan.add_argument("--incremental", action="store_true", help="use the parse cache (.phpscan-cache)")
    p_scan.add_argument("--include-rejected", action="store_true", help="include rejected stack in output")
    p_scan.add_argument(
        "--baseline",
        default=None,
        help="suppression baseline JSON (by default <target>/.phpscan-baseline.json if present)",
    )
    p_scan.add_argument("--no-baseline", action="store_true", help="ignore the baseline file even if present")
    p_scan.add_argument("--new-only", action="store_true", help="exclude SUPPRESSED findings from output")
    p_scan.add_argument(
        "--no-inline-suppress", action="store_true", help="disable inline '// phpscan-ignore [RULE] reason' suppression"
    )
    p_scan.add_argument(
        "--max-per-file", type=int, default=0, help="flood control: cap findings per (file, rule); 0 disables"
    )
    p_scan.add_argument(
        "--fail-on",
        choices=["none", "validated", "critical"],
        default="none",
        help="scan exit code: validated → non-zero if any finding is validated; critical → same for critical severity",
    )

    p_map = sub.add_parser("map", help="reconstruct data-flow behavior per function", parents=[common])
    p_map.add_argument("target")
    p_map.add_argument("--json", action="store_true", help="emit machine-readable JSON map")
    p_map.add_argument("--out", default=None, help="write text/JSON map to a file")

    p_var = sub.add_parser("variants", help="group findings into security-genome variant clusters", parents=[common])
    p_var.add_argument("target")
    p_var.add_argument("--json", action="store_true", help="emit machine-readable JSON variant table")
    p_var.add_argument("--out", default=None, help="write variant report to a file")

    p_dif = sub.add_parser("diff", help="diff two scans: fixed / new / unchanged findings", parents=[common])
    p_dif.add_argument("baseline")
    p_dif.add_argument("target")
    p_dif.add_argument("--json", action="store_true", help="emit machine-readable JSON diff")
    p_dif.add_argument("--out", default=None, help="write diff report to a file")

    p_res = sub.add_parser("research", help="scan + research report", parents=[common])
    p_res.add_argument("target")
    p_res.add_argument("--out-dir", default=None)
    p_res.add_argument("--incremental", action="store_true")
    p_res.add_argument("--baseline", default=None)
    p_res.add_argument("--no-baseline", action="store_true")
    p_res.add_argument("--new-only", action="store_true")

    p_base = sub.add_parser("baseline", help="create/update the suppression baseline from current scan results")
    p_base.add_argument("target")
    p_base.add_argument("--baseline", default=None, help="baseline file (default <target>/.phpscan-baseline.json)")
    p_base.add_argument("--reason", default="triaged by phpscan baseline")
    p_base.add_argument("--expiry", default=None, help="optional expiry date(s), YYYY-MM-DD or comma-separated")
    p_base.add_argument("--incremental", action="store_true")

    p_val = sub.add_parser("validate", help="validation report")
    p_val.add_argument("target_json")
    p_val.add_argument("--json", action="store_true")

    p_rules = sub.add_parser("rules", help="rule overrides")
    p_rules.add_argument("action", choices=["list", "validate"])
    p_rules.add_argument("rules_file", nargs="?", default=None)

    p_expl = sub.add_parser("explain", help="explain a finding")
    p_expl.add_argument("target_json")
    p_expl.add_argument("finding_id")

    p_rep = sub.add_parser("report", help="re-render previous output")
    p_rep.add_argument("target_json")
    p_rep.add_argument("--format", choices=["terminal", "json", "sarif", "md"], default="terminal")
    p_rep.add_argument("--out", default=None)

    p_bench = sub.add_parser("benchmark", help="run eval corpus")
    p_bench.add_argument("corpus_dir")
    p_bench.add_argument("--out", default=None)

    p_live = sub.add_parser("live", help="passive live observation of a URL (scope-fenced)", parents=[common])
    p_live.add_argument("url")
    p_live.add_argument("--profile", choices=["passive", "safe"], default="passive")
    p_live.add_argument(
        "--allow-host", action="append", default=None, help="host allowed; repeatable; default: host of URL only"
    )
    p_live.add_argument("--timeout", type=float, default=10.0)
    p_live.add_argument("--max-requests", type=int, default=32)
    p_live.add_argument("--no-robots", action="store_true")
    p_live.add_argument("--json", action="store_true")
    p_live.add_argument("--out", default=None)

    p_inv = sub.add_parser("investigate", help="read-only host investigation of a tree", parents=[common])
    p_inv.add_argument("root")
    p_inv.add_argument("--recent-days", type=int, default=30)
    p_inv.add_argument("--max-files", type=int, default=20000)
    p_inv.add_argument("--processes", action="store_true", help="opt-in interpreter enumeration")
    p_inv.add_argument("--json", action="store_true")
    p_inv.add_argument("--out", default=None)

    p_tl = sub.add_parser(
        "timeline", help="component exposure timeline from composer files + declaration", parents=[common]
    )
    p_tl.add_argument("target")
    p_tl.add_argument(
        "--vuln-declaration", default=None, help="operator patch declaration JSON (schema phpscan-patch-timeline/1)"
    )
    p_tl.add_argument("--json", action="store_true")
    p_tl.add_argument("--out", default=None)

    p_cor = sub.add_parser("correlate", help="fuse a scan payload with evidence records", parents=[common])
    p_cor.add_argument("target_json")
    p_cor.add_argument("--evidence", required=True, help="phpscan-evidence.json from live/investigate/timeline")
    p_cor.add_argument("--json", action="store_true")
    p_cor.add_argument("--out", default=None)

    return ap.parse_args(argv)


def load_engine(target, incremental=False, verbose=False):
    files = discovery.discover(target)
    parse_cache = (
        C.IRCache(os.path.join(target if os.path.isdir(target) else os.path.dirname(target) or ".", ".phpscan-cache"))
        if incremental
        else None
    )
    from .engine import Engine

    engine = Engine()
    stats = {"files": len(files), "parsed": 0, "cache_hits": 0, "cache_misses": 0}
    warns = []
    for path in files:
        src = U.read_project_file(path)
        if src is None:
            warns.append("skipped large/unreadable file: " + path)
            continue
        if b"\x00" in src[:4096]:
            warns.append("skipped binary PHP file (NUL byte in header): " + path)
            continue
        ir = None
        if parse_cache is not None:
            ir = parse_cache.load(path, parse_cache.file_hash(path))
        if ir is None:
            if parse_cache is not None:
                stats["cache_misses"] += 1
            if verbose:
                U.eprint("parse %s" % path)
            ir = P.parse_file_bytes(path, src)
            if parse_cache is not None:
                parse_cache.save(ir)
        else:
            stats["cache_hits"] += 1
            ir.source = src
        engine.add_file(ir)
        stats["parsed"] += 1
    stats["functions"] = len(engine.funcs)
    return engine, files, stats, warns


def _apply_user_rules(user_rules):
    if user_rules and os.path.exists(user_rules):
        RULES.apply_rules(defs, user_rules)


def _baseline_path(target, args=None):
    explicit = getattr(args, "baseline", None) if args else None
    if explicit:
        return explicit
    if getattr(args, "no_baseline", False):
        return None
    base = target if os.path.isdir(target) else os.path.dirname(target)
    if base:
        cand = os.path.join(base, ".phpscan-baseline.json")
        if os.path.exists(cand):
            return cand
    return None


def _load_baseline(path):
    import json

    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            reasons = data.get("reasons") or {}
            if isinstance(reasons, dict):
                out = {}
                for k, v in reasons.items():
                    if isinstance(v, str):
                        if v.strip():
                            out[k] = v
                    elif isinstance(v, dict):
                        rr = str(v.get("reason", "")).strip()
                        exp = v.get("expires", "")
                        expired = False
                        try:
                            import datetime

                            if exp:
                                m = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", str(exp))
                                if m:
                                    exp_date = datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                                    expired = exp_date < datetime.date.today()
                                else:
                                    expired = True
                        except ValueError:
                            expired = True
                        if rr and not expired:
                            out[k] = rr
                return out
        except Exception as e:
            U.eprint("baseline unreadable %s: %s" % (path, e))
    return {}


_INLINE_RX = re.compile(r"phpscan-ignore(?:\s*:\s*([\w.\-:]+))?\s+(.+?)\s*$")


def _apply_inline_suppressions(findings, files):
    """Inline suppression: '<...>// phpscan-ignore [RULE] reason' on the
    finding's line or the line directly above.  A suppress marker without
    a reason is invalid and ignored, so '// phpscan-ignore' alone cannot
    hide a finding."""
    wanted = {f.file for f in findings}
    marks = {}
    for path in files:
        if path in wanted:
            src = U.read_project_file(path)
            if src is None:
                continue
            lines = src.decode("utf-8", "replace").splitlines()
            for i, line in enumerate(lines, start=1):
                m = _INLINE_RX.search(line)
                if m:
                    marks[(path, i)] = (m.group(1) or "", m.group(2))
                elif i > 1:
                    marks.setdefault((path, i - 1), None)
    for f in findings:
        if f.status == "SUPPRESSED":
            continue
        rule = (f.rule_id or "").split(":")[0]
        for d in (marks.get((f.file, f.line)), marks.get((f.file, f.line - 1))):
            if not d:
                continue
            scope, reason = d
            if scope and scope.split(":")[0] != rule:
                continue
            if not reason.strip():
                continue
            f.status = "SUPPRESSED"
            f.reason = (f.reason + "; " if f.reason else "") + "inline suppression: " + reason.strip()
            break


_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _flood_control(findings, cap):
    """Per (file, rule) finding cap: past `cap` matches, extra matches are
    marked SUPPRESSED ('flood-control').  0 disables.  Highest severity /
    lowest line numbers survive; the rest are attributed honestly."""
    if not cap or cap < 0:
        return
    groups = {}
    for f in findings:
        groups.setdefault((f.file, f.rule_id), []).append(f)
    for (file, rule), group in groups.items():
        if len(group) <= cap:
            continue
        ordered = sorted(
            group,
            key=lambda f: (-_SEV_RANK.get(str(f.severity).upper(), 0), f.line, f.id),
        )
        for extra in ordered[cap:]:
            extra.status = "SUPPRESSED"
            extra.reason = (
                extra.reason + "; " if extra.reason else ""
            ) + "flood-control: more than %d finding(s) of %s in %s" % (cap, rule, file)


def scan(target, args):
    t0 = time.time()
    engine, files, stats, warns = load_engine(
        target, incremental=getattr(args, "incremental", False), verbose=args.verbose
    )
    engine.run()
    if args.verbose:
        for w in engine.warn:
            U.eprint("engine: " + w)
    reasons = _load_baseline(getattr(args, "baseline", None) or _baseline_path(target, args))
    gate = ValidationGate(
        options={
            "suppressed": set(reasons.keys()),
            "suppression_reasons": reasons,
        }
    )
    findings, rejected = gate.run(engine)
    ws_leads = W.classify(engine, engine.flows)
    ws_findings = W.findings_from(ws_leads)
    for f in ws_findings:
        if not f.fingerprint:
            f.fingerprint = stable_fingerprint(
                f.category, f.file, f.func, (f.sink or {}).get("name", ""), (f.source or {}).get("var", "")
            )
        if f.fingerprint in reasons:
            f.status = "SUPPRESSED"
            r = reasons.get(f.fingerprint, "triaged in baseline")
            f.reason = (f.reason + "; " if f.reason else "") + "suppressed: " + r
    allf = findings + ws_findings
    if not getattr(args, "no_inline_suppress", False):
        _apply_inline_suppressions(allf, files)
    _flood_control(allf, getattr(args, "max_per_file", 0))
    n_sup = sum(1 for f in findings + ws_findings if f.status == "SUPPRESSED")
    stats["suppressed"] = n_sup
    if getattr(args, "new_only", False):
        findings = [f for f in findings if f.status != "SUPPRESSED"]
        ws_findings = [f for f in ws_findings if f.status != "SUPPRESSED"]
    surface = SURF.compute(findings + ws_findings, engine)
    uncertainty = UNCERTAINTY.collect(engine, findings + ws_findings)
    stats["uncertainty_items"] = uncertainty["total"]
    rae = reporting.build_rae_queue(findings + ws_findings)
    stats["rae_queue"] = len(rae)
    meta = reporting.meta_block(__version__, target, len(files), (time.time() - t0) * 1000.0)
    stats["warnings"] = len(engine.warn) + len(warns)
    payload = reporting.export_payload(
        meta,
        findings + ws_findings,
        rejected if getattr(args, "include_rejected", False) else [],
        leads=ws_leads,
        stats=stats,
        surface=surface,
        warnings=engine.warn + warns,
        uncertainty=uncertainty,
        rae=rae,
    )
    return payload, engine, files


def do_scan(args):
    payload, engine, files = scan(target=args.target, args=args)
    if args.out:
        reporting.write_json(args.out, payload)
        if not args.quiet:
            U.eprint("payload written: " + args.out)
    if args.sarif_out:
        version = payload.get("meta", {}).get("version")
        reporting.write_json(
            args.sarif_out,
            reporting.sarif_output({"version": version}, [Finding.from_dict(x) for x in payload["findings"]]),
        )
        if not args.quiet:
            U.eprint("sarif written: " + args.sarif_out)
    if args.json:
        sys.stdout.write(reporting.json_output(payload) + "\n")
    elif args.quiet:
        fnd = payload["findings"]
        print(
            "%s: %d findings (%d validated, %d suppressed)"
            % (
                args.target,
                len(fnd),
                sum(1 for x in fnd if x["status"] == "VALIDATED"),
                sum(1 for x in fnd if x["status"] == "SUPPRESSED"),
            )
        )
    else:
        reporting.terminal_report(payload)
    threshold = getattr(args, "fail_on", "none")
    if threshold == "validated" and any(x["status"] == "VALIDATED" for x in payload["findings"]):
        return 1
    if threshold == "critical" and any(
        x["status"] == "VALIDATED" and str(x.get("severity", "")).upper() == "CRITICAL" for x in payload["findings"]
    ):
        return 1
    return 0


def do_baseline(args):
    args.verbose = getattr(args, "verbose", False)
    args.quiet = getattr(args, "quiet", False)
    payload, engine, files = scan(target=args.target, args=args)
    path = args.baseline or os.path.join(
        args.target if os.path.isdir(args.target) else os.path.dirname(args.target) or ".", ".phpscan-baseline.json"
    )
    existing = _load_baseline(path)
    import datetime

    stamp = datetime.date.today().isoformat()
    reasons = dict(existing)
    added = 0
    expiry = getattr(args, "expiry", None)
    parts = [p.strip() for p in str(expiry).split(",") if p.strip()] if expiry else []
    for i, x in enumerate(payload["findings"]):
        fp = x.get("fingerprint", "")
        if not fp or fp in reasons:
            continue
        r = args.reason or "triaged by phpscan baseline"
        rfull = (
            r
            + " ("
            + stamp
            + ") ["
            + x.get("category", "?")
            + " "
            + x.get("file", "?")
            + ":L"
            + str(x.get("line", 0))
            + "]"
        )
        if parts:
            reasons[fp] = {
                "reason": rfull,
                "expires": parts[i] if i < len(parts) else parts[-1],
            }
        else:
            reasons[fp] = rfull
        added += 1
    out = {"version": 1, "generated": stamp, "tool": "phpscan " + __version__, "reasons": reasons}
    reporting.write_json(path, out)
    if not args.quiet:
        U.eprint("baseline written: %s (%d new, %d total)" % (os.path.abspath(path), added, len(reasons)))
    return 0


def do_research(args):
    payload, engine, files = scan(target=args.target, args=args)
    out_dir = args.out_dir or "."
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "phpscan.json"), "w", encoding="utf-8", newline="\n") as f:
        f.write(reporting.json_output(payload) + "\n")
    with open(os.path.join(out_dir, "research.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(reporting.research_report_md(payload) + "\n")
    sarif = reporting.sarif_output(
        {"version": payload["meta"].get("version")}, [Finding.from_dict(x) for x in payload["findings"]]
    )
    with open(os.path.join(out_dir, "phpscan.sarif"), "w", encoding="utf-8", newline="\n") as f:
        f.write(reporting.json_output(sarif) + "\n")
    if not args.quiet:
        U.eprint("research artifacts in " + os.path.abspath(out_dir))
    return 0


def do_validate(args):
    try:
        findings_all, data = _load(args.target_json)
    except Exception as e:
        U.eprint("cannot load %s: %s" % (args.target_json, e))
        return 2
    report = {"meta": data.get("meta"), "statuses": {}}
    for f in findings_all:
        c = report["statuses"].get(f.status, 0)
        report["statuses"][f.status] = c + 1
    for f in findings_all:
        report[str(f.id)] = dict((f.validation or {}).items())
    if args.json:
        sys.stdout.write(reporting.json_output(report) + "\n")
    else:
        for k, v in report["statuses"].items():
            print("%-22s %s" % (k, v))
        for k, v in report.items():
            if k in ("statuses", "meta"):
                continue
            print(k)
            for st, vv in (v or {}).items():
                if isinstance(vv, dict):
                    print("  %-14s %-8s %s" % (st, vv.get("result", ""), vv.get("note", "")))
    return 0


def do_explain(args):
    findings_all, _ = _load(args.target_json)
    for f in findings_all:
        if f.id == args.finding_id:
            print_explain(f)
            return 0
    U.eprint("finding not found: " + args.finding_id)
    return 2


def _load(path):
    from .findings import load_findings

    return load_findings(path)


def print_explain(f):
    print("%s  %s  %s  (conf %.2f)" % (f.id, f.severity, f.status, f.confidence))
    print("rule: %s   cwe: %s   owasp: %s" % (f.rule_id, f.cwe, f.owasp))
    print("file: %s:%s   function: %s" % (f.file, f.line, f.func))
    print("category: %s" % f.category)
    print("")
    print("Source: %s" % f.source.get("var", ""))
    print("Sink:   %s" % (f.sink or {}).get("expr", ""))
    print("")
    if f.data_flow:
        print("Data flow:")
        for i, step in enumerate(f.data_flow, start=1):
            print("  %d. %s" % (i, step))
        print("")
    print("Validation gate:")
    for k, v in (f.validation or {}).items():
        print("  %-14s %-8s %s" % (k, v.get("result", ""), v.get("note", "")))
    print("")
    print("Recommendation: %s" % f.recommendation)


def do_rules(args):
    if args.action == "list":
        rep = RULES.rule_report()
        print("sink categories:")
        for c in rep["sink_categories"]:
            print("  " + c)
        print(
            "sanitizers (%d): %s"
            % (
                len(rep["sanitizers"]),
                ", ".join(rep["sanitizers"][:40]) + (" ..." if len(rep["sanitizers"]) > 40 else ""),
            )
        )
        print("sources: %s" % ", ".join(rep["sources"]))
        print("transforms: %s" % ", ".join(rep["transforms"]))
        return 0
    if not args.rules_file:
        U.eprint("rules validate requires a rules file")
        return 2
    if not os.path.exists(args.rules_file):
        U.eprint("rules file not found: " + args.rules_file)
        return 2
    try:
        RULES.apply_rules(defs, args.rules_file)
        U.eprint("rules valid: " + args.rules_file)
        return 0
    except Exception as e:
        U.eprint("INVALID rules file: %s" % e)
        return 2


def do_map(args):
    engine, files, stats, warns = load_engine(
        target=args.target, incremental=getattr(args, "incremental", False), verbose=args.verbose
    )
    engine.run()
    m = BEH.build_map(engine)
    text = BEH.render_text(m) if not args.json else reporting.json_output(m)
    if args.out:
        reporting.write_json(args.out, m if args.json else {"map": text})
        U.eprint("map written: " + args.out)
    else:
        sys.stdout.write(text)
    return 0


def do_variants(args):
    payload, engine, files = scan(target=args.target, args=args)
    findings_all = [Finding.from_dict(x) for x in payload["findings"]]
    rejected = payload.get("rejected") or []
    genomes = VARIANTS.analyze(findings_all, rejected)
    text = (
        VARIANTS.render_text(genomes)
        if not args.json
        else reporting.json_output({"genomes": genomes, "total": len(genomes)})
    )
    if args.out:
        reporting.write_json(args.out, {"genomes": genomes, "total": len(genomes)} if args.json else {"variants": text})
        U.eprint("variants written: " + args.out)
    else:
        sys.stdout.write(text)
    return 0


def _scan_args(target):
    from types import SimpleNamespace

    return SimpleNamespace(
        target=target,
        incremental=False,
        verbose=False,
        include_rejected=True,
        quiet=True,
        baseline=None,
        no_baseline=True,
        new_only=False,
    )


def do_diff(args):
    baseline_findings = None
    blabel = args.baseline
    if args.baseline.lower().endswith(".json") and os.path.exists(args.baseline):
        findings_all, _data = _load(args.baseline)
        baseline_findings = findings_all
    else:
        payload_b, _, _ = scan(target=args.baseline, args=_scan_args(args.baseline))
        baseline_findings = [Finding.from_dict(x) for x in payload_b["findings"]]
    payload_c, _, _ = scan(target=args.target, args=_scan_args(args.target))
    current_findings = [Finding.from_dict(x) for x in payload_c["findings"]]

    result = DIFF.compare(baseline_findings, current_findings)
    serial = {
        "baseline": blabel,
        "current": args.target,
        "fixed": [DIFF._finding_summary(f) for f in result["fixed"]],
        "new": [DIFF._finding_summary(f) for f in result["new"]],
        "unchanged": [
            {"baseline": DIFF._finding_summary(u["baseline"]), "current": DIFF._finding_summary(u["current"])}
            for u in result["unchanged"]
        ],
        "counts": result["counts"],
    }
    text = DIFF.render_text(result, blabel, args.target) if not args.json else reporting.json_output(serial)
    if args.out:
        reporting.write_json(args.out, serial if args.json else {"diff": text})
        U.eprint("diff written: " + args.out)
    else:
        sys.stdout.write(text)
    return 0


def do_report(args):
    findings_all, data = _load(args.target_json)
    if args.format == "json":
        sys.stdout.write(reporting.json_output(data) + "\n")
        return 0
    if args.format == "sarif":
        out = reporting.sarif_output({"version": data.get("meta", {}).get("version")}, findings_all)
        text = reporting.json_output(out)
        if args.out:
            reporting.write_json(args.out, out)
            U.eprint("sarif written: " + args.out)
        else:
            sys.stdout.write(text + "\n")
        return 0
    if args.format == "md":
        md = reporting.research_report_md(data)
        if args.out:
            with open(args.out, "w", encoding="utf-8", newline="\n") as f:
                f.write(md)
            U.eprint("markdown written: " + args.out)
        else:
            sys.stdout.write(md)
        return 0
    reporting.terminal_report(data)
    return 0


def do_benchmark(args):
    from .benchmark import run_corpus

    return run_corpus(args.corpus_dir, args.out)


def _scope_from_args(args, url):
    from .live import Scope, URLOutOfScope
    import urllib.parse

    hosts = args.allow_host or []
    base_host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if not base_host:
        raise URLOutOfScope("cannot determine host of: %s" % url)
    allowed = {base_host} | {h.lower() for h in hosts}
    return Scope(
        allow_hosts=allowed,
        timeout=getattr(args, "timeout", 10.0),
        max_requests=getattr(args, "max_requests", 32),
    )


def do_live(args):
    from . import live, probing

    try:
        scope = _scope_from_args(args, args.url)
    except ValueError as e:
        U.eprint("scope error: %s" % e)
        return 2
    if args.profile == "safe":
        store, summary = probing.run_safe(args.url, scope)
    else:
        store, summary = live.run_passive(args.url, scope, probe_robots=not args.no_robots)
    rep = {
        "schema": "phpscan-live-report/1",
        "profile": args.profile,
        "summary": summary,
        "evidence": store.to_dict(),
    }
    text = reporting.json_output(rep) if args.json else _live_text(summary)
    if args.out:
        reporting.write_json(args.out, rep)
        if not args.quiet:
            U.eprint("live report written: " + args.out)
    else:
        sys.stdout.write(text + "\n")
    return 0


def _live_text(summary):
    lines = []
    for k in ("base_url", "requests", "bytes_downloaded", "records", "probes"):
        if k in summary:
            lines.append("%-16s %s" % (k, summary[k]))
    cats = summary.get("records_by_category") or {}
    for c in sorted(cats):
        lines.append("  %-28s %4d" % (c, cats[c]))
    notes = summary.get("notes") or []
    for n in notes[:16]:
        lines.append("  note: " + n)
    return "\n".join(lines)


def do_investigate(args):
    from . import host

    opts = {
        "recent_days": args.recent_days,
        "max_files": args.max_files,
        "processes": args.processes,
    }
    store, summary = host.run_investigate(args.root, opts)
    rep = {
        "schema": "phpscan-host-report/1",
        "summary": summary,
        "evidence": store.to_dict(),
    }
    text = reporting.json_output(rep) if args.json else _host_text(summary, store)
    if args.out:
        reporting.write_json(args.out, rep)
        if not args.quiet:
            U.eprint("host report written: " + args.out)
    else:
        sys.stdout.write(text + "\n")
    return 0


def _host_text(summary, store):
    lines = ["root: %s" % summary["root"], "files_seen: %s" % summary["files_seen"], "records: %s" % summary["records"]]
    cats = {}
    for r in store.records:
        cats[r.category] = cats.get(r.category, 0) + 1
    for c in sorted(cats):
        lines.append("  %-28s %4d" % (c, cats[c]))
    for n in (summary.get("notes") or [])[:16]:
        lines.append("  note: " + n)
    return "\n".join(lines)


def do_timeline(args):
    from . import timeline
    from .evidence import EvidenceStore

    store = EvidenceStore(args.target)
    try:
        store, summary, entries = timeline.run_timeline(args.target, args.vuln_declaration, store=store)
    except ValueError as e:
        U.eprint("invalid declaration: %s" % e)
        return 2
    rep = {
        "schema": "phpscan-timeline-report/1",
        "summary": summary,
        "evidence": store.to_dict(),
        "entries": entries,
    }
    text = reporting.json_output(rep) if args.json else _timeline_text(summary, entries)
    if args.out:
        reporting.write_json(args.out, rep)
        if not args.quiet:
            U.eprint("timeline report written: " + args.out)
    else:
        sys.stdout.write(text + "\n")
    return 0


def _timeline_text(summary, entries):
    lines = [
        "installed components: %s" % summary.get("installed_components"),
        "declaration: %s" % summary.get("declaration"),
        "entries: %s" % summary.get("total"),
    ]
    for k, v in sorted((summary.get("counts") or {}).items()):
        lines.append("  %-22s %4d" % (k, v))
    for e in entries[:48]:
        lines.append("  %-30s %-18s %s" % (e["name"], e["status"], e["reason"]))
    return "\n".join(lines)


def do_correlate(args):
    from .evidence import EvidenceStore
    from . import fusion

    try:
        store = EvidenceStore.load(args.evidence)
    except (OSError, ValueError) as e:
        U.eprint("cannot load evidence: %s" % e)
        return 2
    try:
        with open(args.target_json, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, ValueError) as e:
        U.eprint("cannot load scan payload: %s" % e)
        return 2
    result = fusion.fuse(payload, store)
    if args.json:
        sys.stdout.write(reporting.json_output(result) + "\n")
    else:
        s = result["summary"]
        print(
            "findings: %s   linked: %s   unlinked: %s" % (s["findings"], s["evidence_linked"], s["evidence_unlinked"])
        )
        for v in result["verification"]:
            if v["support"] != "none":
                print("  %-16s %-9s  %s" % (v["id"], v["support"], "; ".join(v["reasons"][:2])))
        for u in result["unexplained_evidence"][:24]:
            print("  unexplained: %s %s %s" % (u["origin"], u["category"], u["target"]))
    if args.out:
        reporting.write_json(args.out, result)
        if not args.quiet:
            U.eprint("fusion written: " + args.out)
    return 0


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(errors="replace")
    args = parse_args(argv if argv is not None else sys.argv[1:])
    handlers = {
        "scan": do_scan,
        "research": do_research,
        "validate": do_validate,
        "explain": do_explain,
        "rules": do_rules,
        "report": do_report,
        "benchmark": do_benchmark,
        "map": do_map,
        "variants": do_variants,
        "diff": do_diff,
        "baseline": do_baseline,
        "live": do_live,
        "investigate": do_investigate,
        "timeline": do_timeline,
        "correlate": do_correlate,
    }
    fn = handlers.get(args.cmd)
    if fn is None:
        U.eprint("unknown command: %s" % args.cmd)
        return 2
    try:
        return fn(args)
    except KeyboardInterrupt:
        U.eprint("interrupted")
        return 130
    except Exception as e:  # noqa: BLE001
        U.eprint("phpscan error: %s: %s" % (e.__class__.__name__, e))
        if getattr(args, "debug", False):
            import traceback

            traceback.print_exc(file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
