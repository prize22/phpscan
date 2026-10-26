"""Output rendering: terminal summary, JSON, SARIF, research report."""

from __future__ import annotations


from .findings import write_json, sarif_output, json_output  # noqa


def meta_block(version, target, files, elapsed_ms):
    return {
        "version": version,
        "target": target,
        "files": files,
        "elapsed_ms": int(elapsed_ms),
    }


def export_payload(
    meta,
    findings,
    rejected,
    leads=None,
    stats=None,
    surface=None,
    warnings=None,
    obf=None,
    uncertainty=None,
    rae=None,
    evidence=None,
    timeline=None,
    fusion=None,
):
    stats = stats or {}
    payload = {
        "meta": meta,
        "stats": stats,
        "findings": [f.export() for f in findings],
        "rejected": [_strip_rejected(r) for r in rejected],
        "leads": leads or [],
        "surface": surface,
        "warnings": warnings or [],
        "obfuscation": obf,
        "uncertainty": uncertainty,
        "rae": rae or [],
    }
    if evidence is not None:
        payload["evidence"] = evidence
    if timeline is not None:
        payload["timeline"] = timeline
    if fusion is not None:
        payload["fusion"] = fusion
    return payload


def _strip_rejected(r):
    if isinstance(r, dict):
        return r
    return {"reason": str(r)}


def build_rae_queue(findings):
    """RAE research queue: findings whose proof is not fully verified,
    plus webshell findings (manual-review posture), each with the open
    questions that the proof layer recorded.  Nothing is invented here --
    questions come straight from gate stage results."""
    queue = []
    for f in list(findings or []):
        proof = getattr(f, "proof", None) or {}
        verdict = proof.get("verdict")
        if verdict == "verified" and f.category != "Webshell / Backdoor":
            continue
        questions = proof.get("open_questions") or []
        queue.append(
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "file": f.file,
                "line": f.line,
                "verdict": verdict or "unevaluated",
                "status": f.status,
                "confidence": round(f.confidence, 2),
                "questions": questions,
                "next_action": questions[0]["action"] if questions else "review manually",
            }
        )
    return queue


def terminal_report(payload):
    from .findings import Finding

    findings = [Finding.from_dict(d) for d in payload["findings"]]
    bars = "=" * 78
    lines = []
    lines.append(bars)
    lines.append("phpscan  " + payload["meta"].get("version", "?") + "  —  deterministic PHP security scan")
    m = payload["meta"]
    st = payload.get("stats") or {}
    lines.append(
        "target: %s   files: %s   time: %s ms" % (m.get("target", "?"), m.get("files", "?"), m.get("elapsed_ms", "?"))
    )
    if st:
        lines.append(
            "files parsed: %s (cache hits %s)   funcs: %s"
            % (st.get("parsed", st.get("files", "?")), st.get("cache_hits", "0"), st.get("functions", "?"))
        )
    print("\n".join(lines))

    s = payload.get("stats") or {}
    if s:
        print("")
    by_status = {}
    for f in findings:
        by_status.setdefault(f.status, 0)
        by_status[f.status] += 1
    print("Findings by status: " + ", ".join("%s=%s" % (k, v) for k, v in sorted(by_status.items())))
    by_sev = {}
    for f in findings:
        by_sev.setdefault(f.severity, 0)
        by_sev[f.severity] += 1
    print(
        "Findings by severity: " + ", ".join("%s=%s" % (k, v) for k, v in sorted(by_sev.items(), key=lambda kv: -kv[1]))
    )

    if findings:
        print("\n" + "-" * 78)
        for f in findings[:40]:
            print("")
            print("%s  %s  %s" % (f.id, f.severity, f.status))
            print("  %s:%s" % (f.file, f.line))
            print("  rule:      %s   (conf %.2f)" % (f.rule_id, f.confidence))
            print("  title:     %s" % f.title)
            print("  function:  %s" % f.func)
            print("  source:    %s" % f.source.get("var", ""))
            print("  sink:      %s" % (f.sink or {}).get("expr", ""))
            if f.reason:
                print("  note:      %s" % f.reason)
            if f.data_flow:
                print("  data flow:")
                for step in f.data_flow[:8]:
                    print("    %s" % step)
            print("  gate:      " + ", ".join("%s=%s" % (k, v["result"]) for k, v in (f.validation or {}).items()))
    rej = payload.get("rejected") or []
    if rej:
        print("\nRejected candidate stack (validation-gate failures): %d" % len(rej))
        for r in rej[:8]:
            print(
                "  REJECT %s %s:%s — %s"
                % (r.get("category", "?"), r.get("file", "?"), r.get("line", "?"), r.get("reason", ""))
            )
    leads = payload.get("leads") or []
    if leads:
        print("\nResearch leads: %d" % len(leads))
        for ln in leads[:10]:
            if isinstance(ln, dict):
                print(
                    "  LEAD %s:%s — %s"
                    % (ln.get("title", ln.get("file", "?")), ln.get("line", "?"), ln.get("note", ""))
                )
            else:
                print("  LEAD %s" % str(ln))
    rae = payload.get("rae") or []
    if rae:
        print("")
        print("RAE research queue: %d" % len(rae))
        for q in rae[:10]:
            print(
                "  QUEUE %s %s:%s — %s  (verdict=%s, status=%s)"
                % (q["id"], q["file"], q["line"], q["title"], q["verdict"], q["status"])
            )
            if q.get("next_action"):
                print("      next: " + q["next_action"])
    u = payload.get("uncertainty") or {}
    codes = u.get("codes") or {}
    if codes:
        print("")
        print(
            "uncertainty: %d items   " % u.get("total", 0)
            + ", ".join("%s=%d" % (k, v) for k, v in sorted(codes.items()))
        )
    print("")


def research_report_md(payload):
    """Full research narrative (exec report) as markdown."""
    from .findings import Finding

    findings = [Finding.from_dict(d) for d in payload["findings"]]
    m = payload["meta"]
    out = []
    out.append("# phpscan Research Report")
    out.append("")
    out.append("- Version: %s" % m.get("version", "?"))
    out.append("- Target: `%s`" % m.get("target", "?"))
    out.append("- Files: %s   Time: %sms" % (m.get("files", "?"), m.get("elapsed_ms", "?")))
    out.append("")
    surface = payload.get("surface") or {}
    if surface:
        out.append("## Attack Surface")
        out.append("")
        if surface.get("entry_files"):
            out.append("**Entry files** (heuristic detection):")
            for path in surface["entry_files"][:10]:
                out.append("- `%s`" % path)
        if surface.get("source_contexts"):
            out.append("")
            out.append("**Top user-input sources:**")
            out.append("")
            out.append("| source | findings |")
            out.append("|---|---|")
            for k, v in list(surface["source_contexts"].items())[:10]:
                out.append("| `%s` | %s |" % (k, v))
        out.append("")
    out.append("## Findings")
    out.append("")
    if not findings:
        out.append(
            "No accepted findings after the full Validation "
            "Gate. Rejected candidates are listed below for "
            "auditability."
        )
    else:
        out.append("| ID | Severity | Status | Category | Location | Confidence |")
        out.append("|---|---|---|---|---|---|")
        for f in findings:
            out.append(
                "| %s | %s | %s | %s | `%s:%s` | %.2f |"
                % (f.id, f.severity, f.status, f.category, f.file, f.line, f.confidence)
            )
    out.append("")
    out.append("## Validation Gate details")
    for f in findings[:30]:
        out.append("")
        out.append("### %s — %s (%s)" % (f.id, f.category, f.status))
        out.append("")
        out.append("- **File**: `%s:%s`" % (f.file, f.line))
        out.append("- **Sink**: `%s`" % ((f.sink or {}).get("expr", "")))
        out.append("- **Source**: `%s`" % f.source.get("var", ""))
        if f.data_flow:
            out.append("- **Data flow**:")
            for step in f.data_flow:
                out.append("    1. %s" % step)
        out.append("- **Gate**:")
        out.append("")
        out.append("| stage | result | note |")
        out.append("|---|---|---|")
        for k, v in (f.validation or {}).items():
            out.append("| %s | %s | %s |" % (k, v.get("result", ""), v.get("note", "")))
        out.append("")
    rej = payload.get("rejected") or []
    if rej:
        out.append("## Rejected candidates (kept for audit)")
        out.append("")
        out.append("| category | location | reason |")
        out.append("|---|---|---|")
        for r in rej:
            out.append(
                "| %s | `%s:%s` | %s |"
                % (r.get("category", "?"), r.get("file", "?"), r.get("line", "?"), r.get("reason", ""))
            )
        out.append("")
    return "\n".join(out) + "\n"


def write_outputs(payload, out_json=None, out_sarif=None, out_md=None):
    if out_json:
        write_json(out_json, payload)
    if out_sarif:
        version = payload.get("meta", {}).get("version")
        write_json(out_sarif, sarif_output({"version": version}, [Finding_or_path(f) for f in payload["findings"]]))
    if out_md:
        with open(out_md, "w", encoding="utf-8", newline="\n") as f:
            f.write(research_report_md(payload))


def Finding_or_path(d):
    from .findings import Finding

    return Finding.from_dict(d)
