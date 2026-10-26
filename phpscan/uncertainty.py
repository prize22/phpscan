"""Uncertainty map: every place phpscan admits it does not know.

The engine and gate are honest about their limits: parse errors,
truncated files, failed analysis, weak taint propagation, partial
sanitizer evidence, skipped re-analysis stages.  This module collects
those signals into a single deterministic uncertainty map attached to
each scan payload:

    {
      "items": [{"code": ..., "file": ..., "line": ..., "detail": ...}, ...],
      "codes":   {"UNCERTAIN_PARSE_ERRORS": 3, ...},
      "total":   N,
      "per_file": {"path": [items...], ...},
    }

Codes are stable strings; nothing here is invented -- each item traces
to an engine warning, file-meta record, or gate stage result.
"""

from __future__ import annotations

import re

_CODE_WARN_RE = re.compile(r"error in (.+?):")


def _warn_file(msg):
    m = _CODE_WARN_RE.search(msg or "")
    if m:
        return m.group(1)
    return ""


def collect(engine, findings, rejected=None, extra=None):
    """extra: optional iterable of (code, file, line, detail) produced by
    non-static layers (live/host/history).  Appended as first-class
    UNCERTAIN_* items so downstream rendering/tests see one uniform map."""
    items = []
    codes = {}
    per_file = {}

    def add(code, file="", line=0, detail=""):
        item = {"code": code, "file": file or "", "line": int(line or 0), "detail": detail}
        items.append(item)
        codes[code] = codes.get(code, 0) + 1
        if file:
            per_file.setdefault(file, []).append(item)

    if extra:
        for code, file, line, detail in extra:
            add(code, file, line, detail)

    # --- file-level signals ----------------------------------------------
    for path, meta in sorted((engine.file_meta or {}).items()):
        pe = (meta or {}).get("parse_errors") or []
        if pe:
            add("UNCERTAIN_PARSE_ERRORS", path, detail="%d parse error(s) during parsing" % len(pe))
        if meta.get("truncated"):
            add("UNCERTAIN_FILE_TRUNCATED", path, detail="file truncated during parsing")

    # --- engine warnings --------------------------------------------------
    for w in list(engine.warn or []):
        if "recursion limit" in w.lower():
            add("UNCERTAIN_RECURSION_LIMIT", _warn_file(w), detail=w)
        else:
            add("UNCERTAIN_ANALYSIS_ERROR", _warn_file(w), detail=w)

    # --- per-finding gate evidence ----------------------------------------
    for f in list(findings or []):
        pf = getattr(f, "proof", None) or {}
        claims = pf.get("claims") or []
        for c in claims:
            result = c.get("result")
            if result == "PARTIAL":
                add("UNCERTAIN_%s_PARTIAL" % c["stage"].upper(), f.file, f.line, c.get("note", "") or "")
            elif result == "SKIP":
                add("UNCERTAIN_%s_SKIPPED" % c["stage"].upper(), f.file, f.line, c.get("note", "") or "")
        open_q = pf.get("open_questions") or []
        for q in open_q:
            add("UNCERTAIN_OPEN_QUESTION", f.file, f.line, q.get("current", "") or "")

    total = len(items)
    return {
        "items": items,
        "codes": dict(sorted(codes.items())),
        "total": total,
        "per_file": per_file,
    }
