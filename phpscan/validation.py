"""The phpscan Validation Gate.

Runs 8 independent validation stages between taint detection and
reporting. Every candidate must survive the gate; failures are recorded
(not discarded) so debug output can show why something was rejected.

Stages:
  1. structural       — parse integrity, candidate completeness
  2. semantic         — sink/category semantics are coherent
  3. data-flow        — evidence chain present and source-anchored
  4. control-flow     — guard-stack reachability
  5. sanitizer        — sanitizer-context strength match
  6. context          — category-specific context checks
  7. contradiction    — contradictory evidence in the chain
  8. re-analysis      — strict-mode agreement (independent pass)

Statuses: VALIDATED, PARTIALLY_VALIDATED, UNCONFIRMED, REJECTED.
Scores/confidence drive severity; every stage result is kept.
"""

from __future__ import annotations

import re

from . import cfg
from . import proof as proofmod
from .findings import Finding, RULE_PREFIX, stable_fingerprint

# The sanitizer context that actually mitigates each category.
# A "strong" sanitizer whose ctx is in this set rejects the candidate;
# "medium"/"weak" sanitizer of that ctx degrades to PARTIAL.
CAT_SAN_CONTEXTS = {
    "SQL Injection": {"sql", "numeric"},
    "Command Injection": {"shell", "numeric"},
    "Cross-Site Scripting": {"html", "url"},
    "File Inclusion": {"path", "numeric"},
    "Path Traversal": {"path", "numeric", "alpha"},
    "Arbitrary File Write": {"path", "numeric"},
    "Unsafe File Upload": {"path", "alpha"},
    "Insecure Deserialization": {"numeric", "generic"},
    "Server-Side Request Forgery": {"url", "ip"},
    "Open Redirect": {"url", "numeric", "alpha"},
    "Header Injection": {"numeric"},
    "Code Injection": {"generic", "numeric"},
}

BASE_SEVERITY = {
    "SQL Injection": "HIGH",
    "Command Injection": "CRITICAL",
    "Code Injection": "CRITICAL",
    "Cross-Site Scripting": "MEDIUM",
    "File Inclusion": "CRITICAL",
    "Path Traversal": "HIGH",
    "Arbitrary File Write": "HIGH",
    "Unsafe File Upload": "HIGH",
    "Server-Side Request Forgery": "HIGH",
    "Insecure Deserialization": "HIGH",
    "Open Redirect": "LOW",
    "Header Injection": "MEDIUM",
    "Information Disclosure": "LOW",
    "Webshell / Backdoor": "CRITICAL",
    "Hardcoded Secret": "HIGH",
    "Dangerous Function": "LOW",
}

RECOMMENDATIONS = {
    "SQL Injection": "Use prepared statements with bound parameters; never interpolate request data into SQL strings.",
    "Command Injection": "Avoid passing request data to shell commands; "
    "if unavoidable, validate against a strict "
    "allow-list and use escapeshellarg + escapeshellcmd "
    "on every argument.",
    "Code Injection": "Remove eval()/assert(); there is no safe way to evaluate attacker-controlled code.",
    "Cross-Site Scripting": "Encode output with a context-appropriate "
    "encoder (htmlspecialchars with ENT_QUOTES for "
    "HTML body); avoid echoing request data.",
    "File Inclusion": "Do not pass request data to include/require; use a static allow-list mapping.",
    "Path Traversal": "Canonicalize the path (realpath) and verify it stays under the intended base directory.",
    "Arbitrary File Write": "Do not derive destination paths from request data; validate against an allow-list.",
    "Unsafe File Upload": "Validate uploaded files server-side: extension "
    "and content allow-lists, randomized storage "
    "names outside the webroot.",
    "Server-Side Request Forgery": "Do not fetch URLs built from request "
    "data; validate against an allow-list "
    "of hosts/ports.",
    "Insecure Deserialization": "Do not unserialize untrusted input; use JSON or allowed_classes=[] on PHP >= 7.0.",
    "Open Redirect": "Validate redirect targets against a fixed allow-list; reject absolute URLs from request data.",
    "Header Injection": "Reject CR/LF characters in header values.",
    "Information Disclosure": "Do not call phpinfo() in production code.",
    "Webshell / Backdoor": "This file correlates with known webshell patterns; review manually.",
    "Hardcoded Secret": "Move the secret to environment configuration.",
    "Dangerous Function": "Review whether this function is required; remove dangerous built-ins from production code.",
}


def _short(s, limit=110):
    s = s or ""
    return s if len(s) <= limit else s[:limit] + "…"


def _norm_php(t):
    if not isinstance(t, str):
        return ""
    t = t.split("   (callee", 1)[0]
    for ch in ("'", '"', "`", ";"):
        t = t.replace(ch, "")
    return re.sub(r"\s+", "", t)


def sink_located_in_source(sink_expr, line, src_lines):
    """Independent textual check: the sink call recorded by the taint
    engine must be locatable in the file's own source text. This is a
    second, model-free confirmation that the reported location is real
    (catches stale line numbers and engine drift)."""
    se = _norm_php(sink_expr)
    if len(se) < 6:
        return True  # too short to verify reliably
    line = int(line or 0)
    if line and 1 <= line <= len(src_lines):
        for i in range(max(1, line - 3), min(len(src_lines), line + 3) + 1):
            if se in _norm_php(src_lines[i - 1]):
                return True
    return se in _norm_php("\n".join(src_lines))


class GateResult:
    __slots__ = ("stage", "result", "note")

    def __init__(self, stage, result, note=""):
        self.stage = stage
        self.result = result
        self.note = note

    def export(self):
        return {"result": self.result, "note": self.note}


def validate_candidate(cand, file_meta, strict_agree, src_lines=None):
    """Runs all 8 stages. Returns (finding_or_None, rejected_record)."""
    stages = []
    notes = []
    facts = {}
    cat = getattr(cand, "cat", "")

    def add(stage, result, note=""):
        stages.append(GateResult(stage, result, note))
        return result

    # -- stage 1: structural ------------------------------------------------
    perr = (file_meta or {}).get("parse_errors") or []
    facts["file_parse_errors"] = len(perr)
    facts["file_truncated"] = bool((file_meta or {}).get("truncated"))
    if (file_meta or {}).get("truncated"):
        add("structural", "FAIL", "file truncated (size or node limits); analysis partial")
        return None, _rejected(cand, stages, "file truncated")
    if perr:
        add("structural", "PARTIAL", "file has PHP parse errors: %d" % len(perr))
        notes.append("file contains parse errors")
    else:
        add("structural", "PASS")
    cexp = getattr(cand, "sink_expr", "")
    if not cexp and cand.cat not in ("Webshell / Backdoor",):
        add("structural", "FAIL", "candidate missing sink expression")
        return None, _rejected(cand, stages, "no sink expression")

    # -- stage 2: semantic ---------------------------------------------------
    kind = getattr(cand, "call_kind", "")
    facts["call_kind"] = kind or None
    facts["sink_name"] = getattr(cand, "sink_name", "") or None
    facts["sink_arg_index"] = getattr(cand, "arg_idx", None)
    if cand.cat == "Webshell / Backdoor":
        add("semantic", "PASS", "signal correlation category")
    elif not kind:
        add("semantic", "FAIL", "candidate has no call kind")
        return None, _rejected(cand, stages, "no call kind")
    else:
        add("semantic", "PASS", "kind=" + kind)

    # -- stage 3: data-flow ---------------------------------------------------
    val = getattr(cand, "val", None)
    chain = tuple(getattr(val, "chain", ()) or ())
    origin = getattr(val, "origin", "")
    uncertain = getattr(val, "uncertain", "")
    facts["chain_steps"] = len(chain)
    facts["source_origin"] = origin or None
    facts["value_level"] = getattr(val, "level", None) if val else None
    if cand.cat == "Webshell / Backdoor":
        add("data-flow", "PASS", "correlation evidence" if getattr(cand, "evidence", None) else "PASS")
    elif chain:
        adds = "source anchored: " + origin if origin else "chain present"
        add("data-flow", "PASS", adds)
        if len(chain) >= 2:
            notes.append(" flows through %d intermediate step(s)" % (len(chain) - 1))
        if src_lines is not None and cand.cat not in ("Webshell / Backdoor", "Hardcoded Secret", "Dangerous Function"):
            located = sink_located_in_source(getattr(cand, "sink_expr", ""), getattr(cand, "line", 0), src_lines)
            facts["sink_text_located_in_source"] = located
            if located:
                add("data-flow", "PASS", "sink text independently located in file source")
            else:
                add(
                    "data-flow",
                    "PARTIAL",
                    "sink text not located in file source; location evidence is weaker than the model claim",
                )
                notes.append("sink not found in file source")
    elif uncertain:
        add("data-flow", "PARTIAL", "taint is uncertain: " + uncertain)
        notes.append("taint propagation is uncertain")
    else:
        add("data-flow", "FAIL", "no data-flow evidence")
        return None, _rejected(cand, stages, "no data-flow evidence")

    # -- stage 4: control-flow reachability -----------------------------------
    guards = getattr(cand, "guards", ()) or ()
    conditional, dead = cfg.classify_guards(guards)
    facts["guard_conditions"] = len(conditional)
    if dead:
        add("control-flow", "FAIL", "; ".join(dead))
        return None, _rejected(cand, stages, "dead branch (constant condition)")
    if conditional:
        add("control-flow", "PASS", "inside %d conditional branch(es); reachable" % len(conditional))
    else:
        add("control-flow", "PASS", "unconditional")

    # -- stage 5: sanitizer-context match -------------------------------------
    san = getattr(val, "sanitizer", "") if val else ""
    san_ctx = getattr(val, "sanitizer_ctx", "") if val else ""
    san_str = getattr(val, "sanitizer_strength", "") if val else ""
    facts["path_sanitizer"] = san or None
    facts["sanitizer_context"] = san_ctx or None
    facts["sanitizer_strength"] = san_str or None
    allowed = CAT_SAN_CONTEXTS.get(cat)
    if san and allowed and san_ctx in allowed and san_str == "strong":
        add(
            "sanitizer",
            "FAIL",
            "value fully sanitized with %s (context=%s, strength=strong) before this sink" % (san, san_ctx),
        )
        return None, _rejected(cand, stages, "sanitizer %s (strong, %s) neutralizes this sink" % (san, san_ctx))
    elif san and allowed and san_ctx in allowed and san_str in ("medium", "weak"):
        add(
            "sanitizer",
            "PARTIAL",
            "sanitizer %s is context=%s strength=%s; bypasses are possible" % (san, san_ctx, san_str),
        )
        notes.append("weak sanitizer %s" % san)
    elif san:
        add("sanitizer", "PASS", "sanitizer %s does not apply to this sink context (%s)" % (san, san_ctx or "unknown"))
    else:
        add("sanitizer", "PASS", "no sanitizer in path")

    # -- stage 6: category-specific context ------------------------------------
    ctx_fail = None
    sink_name = getattr(cand, "sink_name", "")
    if cat == "File Inclusion" and getattr(val, "const", ""):
        ctx_fail = "include operand is a constant"
    elif cat == "Cross-Site Scripting" and san == "escapeshellarg":
        ctx_fail = None
    if ctx_fail:
        add("context", "FAIL", ctx_fail)
        return None, _rejected(cand, stages, ctx_fail)
    add("context", "PASS")

    # -- stage 7: contradiction -------------------------------------------------
    contra = []
    for step in chain:
        text = step[1] if isinstance(step, tuple) else str(step)
        if "[sanitizer " in text and san_str == "strong" and allowed and san_ctx in allowed:
            contra.append("chain records strong sanitizer " + san)
    if getattr(val, "level", 0) == 0 and not getattr(cand, "no_taint", False):
        contra.append("value level is 0 (not tainted)")
    if contra:
        add("contradiction", "FAIL", "; ".join(set(contra)))
        return None, _rejected(cand, stages, contra[0])
    add("contradiction", "PASS")

    # -- stage 8: strict re-analysis agreement ----------------------------------
    facts["strict_reanalysis_agreement"] = (
        "agree" if strict_agree is True else ("disagree" if strict_agree is False else "not_recorded")
    )
    if strict_agree is True:
        add("re-analysis", "PASS", "independent strict pass agrees")
    elif strict_agree is False:
        add("re-analysis", "PARTIAL", "strict re-analysis disagreed; downgraded")
        notes.append("strict re-analysis disagreed")
    else:
        add("re-analysis", "SKIP", "no strict result recorded")

    # ---- scoring / status / severity ---------------------------------------
    level = getattr(val, "level", 0) if val else 0
    conf = 0.0
    if getattr(cand, "no_taint", False):
        conf = 0.55
    elif level >= 2:
        conf = 0.72
    elif level == 1:
        conf = 0.40
    if len(notes) >= 1:
        conf -= 0.05 * len(notes)
    if strict_agree is True:
        conf += 0.06
    inter = _is_interproc(cand)
    if inter:
        conf += 0.04
    conf = max(0.05, min(0.95, conf))

    if any(s.result == "PARTIAL" for s in stages):
        status = "PARTIALLY_VALIDATED"
    elif conf >= 0.60:
        status = "VALIDATED"
    elif level <= 1 or getattr(val, "uncertain", ""):
        status = "UNCONFIRMED"
    else:
        status = "PARTIALLY_VALIDATED"

    sev = BASE_SEVERITY.get(cat, "MEDIUM")
    if level == 1 and sev == "CRITICAL":
        sev = "HIGH"
    if status == "UNCONFIRMED" and sev in ("CRITICAL", "HIGH"):
        sev = "MEDIUM"
    if cand.cat in ("Information Disclosure", "Dangerous Function"):
        sev = "LOW"

    caller_file, caller_func = _attribution(cand)
    src_name = origin or uncertain or "{expression}"
    src_level = "DIRECT_USER_INPUT" if level >= 2 else "INDIRECT"
    proofrec = proofmod.build(cand, stages, notes, facts=facts)
    finding = Finding(
        id=None,
        rule_id=RULE_PREFIX.get(cat, "php.misc"),
        category=cat,
        title="%s in %s" % (cat, sink_name or "code"),
        severity=sev,
        confidence=conf,
        status=status,
        file=caller_file,
        line=int(getattr(cand, "line", 0) or 0),
        func=caller_func,
        source={"var": src_name, "class": src_level, "level": level},
        sink={"name": sink_name, "kind": getattr(cand, "call_kind", ""), "expr": _short(cexp)},
        data_flow=[_short("L%s: %s" % (ln, t)) for (ln, t) in chain],
        evidence=[
            "function: " + caller_func,
            "sink call: " + _short(cexp),
        ],
        validation={s.stage: s.export() for s in stages},
        proof=proofrec,
        recommendation=RECOMMENDATIONS.get(cat, "Review manually."),
        reason="; ".join(notes) if notes else "",
    )
    return finding, None


def _attribution(cand):
    func = getattr(cand, "func", "")
    caller_file = getattr(cand, "file", "")
    if isinstance(func, str):
        return caller_file, func
    return caller_file, str(func)


def _is_interproc(cand):
    ie = getattr(cand, "sink_expr", "") or ""
    return "callee" in ie or "interprocedural" in ie


def _rejected(cand, stages, reason):
    func = getattr(cand, "func", "")
    rec = {
        "category": getattr(cand, "cat", "?"),
        "file": getattr(cand, "file", "?"),
        "line": getattr(cand, "line", 0),
        "sink": _short(getattr(cand, "sink_expr", "")),
        "reason": reason,
        "stages": {s.stage: s.export() for s in stages},
        "fingerprint": stable_fingerprint(
            getattr(cand, "cat", ""), getattr(cand, "file", ""), func, getattr(cand, "sink_name", ""), ""
        ),
        "proof": proofmod.rejected_proof(cand, stages, reason),
    }
    try:
        rec["chain"] = [_short("L%s: %s" % (ln, t)) for (ln, t) in (getattr(cand.val, "chain", ()) or ())]
    except Exception:
        rec["chain"] = []
    return rec


class ValidationGate:
    """Applies the gate to all candidates produced by the engine.

    options keys:
      suppressed      set of stable fingerprints to mark SUPPRESSED
      suppression_reasons  {fingerprint: reason} shown to the user
    """

    def __init__(self, options=None):
        self.options = options or {}

    @staticmethod
    def _src_lines(engine):
        out = {}
        for ir in engine.files:
            src = getattr(ir, "source", None)
            if isinstance(src, (bytes, bytearray)) and src:
                out[ir.path] = src.decode("utf-8", "replace").splitlines()
        return out

    def run(self, engine):
        findings = []
        rejected = []
        by_fp = {}
        dup_count = 0
        sup = self.options.get("suppressed") or set()
        sup_reasons = self.options.get("suppression_reasons") or {}
        srcmap = self._src_lines(engine)
        for fkey, flow in engine.flows.items():
            file_meta = engine.file_meta.get(getattr(flow.func, "file", ""), {})
            for key, cand in flow.cands.items():
                strict_agree = engine.strict_keys.get(self._ckey(cand), False)
                finding, reject = validate_candidate(
                    cand, file_meta, strict_agree, src_lines=srcmap.get(getattr(cand, "file", ""))
                )
                if finding:
                    fp = stable_fingerprint(
                        finding.category,
                        finding.file,
                        finding.func,
                        finding.sink.get("name", ""),
                        finding.source.get("var", ""),
                    )
                    finding.fingerprint = fp
                    if fp in by_fp:
                        dup_count += 1
                        prev = by_fp[fp]
                        if finding.confidence > prev.confidence:
                            by_fp[fp] = finding
                    else:
                        by_fp[fp] = finding
                elif reject:
                    reject["func"] = getattr(cand, "func", "")
                    rejected.append(reject)
        for fp, f in by_fp.items():
            if fp in sup:
                f.status = "SUPPRESSED"
                reason = sup_reasons.get(fp, "triaged in suppression baseline")
                f.reason = (f.reason + "; " if f.reason else "") + "suppressed: " + reason
            findings.append(f)
        findings.sort(key=lambda f: (-f.confidence, f.file, f.line, f.category))
        for i, f in enumerate(findings):
            f.id = "PHPSCAN-%04d" % (i + 1)
        return findings, rejected

    @staticmethod
    def _ckey(cand):
        from . import engine as E

        return E.cand_fkey(cand)
