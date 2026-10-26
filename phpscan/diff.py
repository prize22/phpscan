"""Differential analysis: fixed / new / unchanged between two scans.

Compares findings by stable fingerprint (path-stable: category, file,
function, sink, source -- line numbers excluded so forward edits don't
invalidate the comparison).  Classifies each finding as:

* FIXED      present in the baseline scan, absent in the current scan
* NEW        absent in the baseline scan, present in the current scan
* UNCHANGED  present in both (with status/confidence drift noted)

Nothing here changes detection: it only regroups two completed scans so
researchers can see what a patch fixed, what regressed, and what stayed
the same.
"""

from __future__ import annotations


def _by_fp(findings):
    out = {}
    for f in findings or []:
        fp = getattr(f, "fingerprint", "") or ""
        out.setdefault(fp, []).append(f)
    return out


def compare(baseline_findings, current_findings):
    base = _by_fp(baseline_findings)
    cur = _by_fp(current_findings)

    fixed, new, unchanged = [], [], []
    for fp, blist in base.items():
        clist = cur.get(fp)
        if clist is None:
            fixed.extend(blist)
        else:
            for bf in blist:
                for cf in clist:
                    unchanged.append({"baseline": bf, "current": cf})
    for fp, clist in cur.items():
        if fp not in base:
            new.extend(clist)

    return {
        "fixed": fixed,
        "new": new,
        "unchanged": unchanged,
        "counts": {"fixed": len(fixed), "new": len(new), "unchanged": len(unchanged)},
    }


def _finding_summary(f):
    return {
        "id": getattr(f, "id", None),
        "category": getattr(f, "category", ""),
        "file": getattr(f, "file", ""),
        "line": int(getattr(f, "line", 0) or 0),
        "status": getattr(f, "status", ""),
        "confidence": round(getattr(f, "confidence", 0.0) or 0.0, 2),
        "severity": getattr(f, "severity", ""),
    }


def render_text(compare_result, baseline_label="baseline", current_label="current"):
    c = compare_result
    lines = []
    lines.append("phpscan diff — %s → %s" % (baseline_label, current_label))
    lines.append("=" * 78)
    lines.append(
        "fixed: %d   new: %d   unchanged: %d" % (c["counts"]["fixed"], c["counts"]["new"], c["counts"]["unchanged"])
    )
    for kind, label in (("fixed", "FIXED"), ("new", "NEW")):
        for f in c[kind]:
            s = _finding_summary(f)
            lines.append(
                "  %-8s %-9s %-22s %s:%s  (conf %.2f, %s)"
                % (label, s["category"], s["severity"], s["file"], s["line"], s["confidence"], s["status"])
            )
    for u in c["unchanged"]:
        b, cc = u["baseline"], u["current"]
        sb, sc = _finding_summary(b), _finding_summary(cc)
        drift = ""
        if sb["status"] != sc["status"]:
            drift = " status %s→%s" % (sb["status"], sc["status"])
        if sb["confidence"] != sc["confidence"]:
            drift += " conf %.2f→%.2f" % (sb["confidence"], sc["confidence"])
        lines.append(
            "  %-8s %-9s %-22s %s:%s%s" % ("UNCHANGED", sb["category"], sb["severity"], sb["file"], sb["line"], drift)
        )
    return "\n".join(lines) + "\n"
