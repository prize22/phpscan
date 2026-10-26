"""Webshell / backdoor detection by signal correlation.

A modern PHP webshell rarely relies on one vulnerable construct.  It
combines: attacker-controlled entry points, string assembly at runtime,
obfuscated or dynamically-resolved calls, and command/file execution.
phpscan correlates these *signals* per function and requires multiple
independent signal categories before reporting — with a weighted score
and a manual-review posture (RESEARCH_LEAD).
"""

from __future__ import annotations

import re

# weighted categories; at least MIN_CATEGORIES must score for a report
MIN_CATEGORIES = 2
REPORT_SCORE = 6

WEIGHTS = {
    "source": 3,
    "obfuscation": 3,
    "dynamic-exec": 4,
    "shell": 2,
    "file-write": 1,
    "dynamic-call": 3,
    "interpolation": 1,
    "server-uri": 2,
    "upload": 2,
}

SIGNAL_RULES = [
    (
        "source",
        [
            re.compile(r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[", re.I),
            re.compile(r"\$_FILES", re.I),
            re.compile(r"php://input", re.I),
            re.compile(r"\$_ENV", re.I),
        ],
    ),
    (
        "obfuscation",
        [
            re.compile(
                r"\b(base64_decode|str_rot13|gzinflate|gzuncompress|"
                r"gzdecode|convert_uudecode|hex2bin|strrev|"
                r"convert_uuencode|zlib_decode)\s*\(",
                re.I,
            ),
            re.compile(r"\bpreg_replace\s*\(.*/[a-zA-Z]*e[a-zA-Z]*['\"]", re.I),
            re.compile(r"\b(chr|pack|sprintf)\s*\(\s*(~|\d+)", re.I),
            re.compile(r"\bxor\b|\^\s*['\"]", re.I),
        ],
    ),
    (
        "dynamic-exec",
        [
            re.compile(r"\b(eval|assert|create_function|preg_replace)\s*\(", re.I),
        ],
    ),
    (
        "shell",
        [
            re.compile(
                r"\b(system|exec|passthru|shell_exec|popen|proc_open|"
                r"pcntl_exec)\s*\(",
                re.I,
            ),
            re.compile(r"`[^`]+`"),
        ],
    ),
    (
        "file-write",
        [
            re.compile(r"\b(file_put_contents|fwrite|fputs)\s*\(", re.I),
            re.compile(r"\b(fopen|file_get_contents)\s*\([^)]*php://", re.I),
        ],
    ),
    (
        "dynamic-call",
        [
            re.compile(r"\$[a-zA-Z_]\w*\s*\(", re.M),
            re.compile(r"\bcall_user_func(_array)?\s*\(", re.I),
            re.compile(
                r"\b(array_map|array_walk|usort|uasort|uksort|"
                r"array_filter|array_reduce|register_shutdown_function|"
                r"set_error_handler|spl_autoload_register)\s*\(",
                re.I,
            ),
            re.compile(r"\$(\{)?\s*['\"]?\s*\\?\\?[a-zA-Z_]", re.I),
        ],
    ),
    (
        "server-uri",
        [
            re.compile(
                r"\$_SERVER\s*\[\s*['\"]?(REQUEST_URI|QUERY_STRING|"
                r"HTTP_USER_AGENT|HTTP_X_FORWARDED_FOR|HTTP_REFERER)",
                re.I,
            ),
        ],
    ),
    (
        "upload",
        [
            re.compile(r"\bmove_uploaded_file\s*\(", re.I),
            re.compile(r"\$_FILES\s*\[.*?\]\s*\[\s*['\"]?tmp_name", re.I),
        ],
    ),
]

# benign names that are extremely common and must not count as
# dynamic-call signals by themselves
BENIGN_VARCALL = re.compile(r"^\$(this|GLOBALS|self)$")


def _signals_in(text):
    """Returns list of (category, sample) present in the text."""
    out = []
    for cat, rules in SIGNAL_RULES:
        for rx in rules:
            m = rx.search(text)
            if m:
                sample = (m.group(0) or "")[:60]
                out.append((cat, sample))
                break
    return out


def analyze_function(flow, name, file_path, start_line):
    """Correlates engine signals + raw text signals for one function."""
    state = {"score": 0}
    cats = {}
    details = []

    def add(cat, detail, weight):
        if cat not in cats:
            cats[cat] = True
            state["score"] += weight
            details.append((cat, detail))
        elif detail:
            details.append((cat, detail))

    # engine-level signals (trace-verified) — weight higher
    for cat, sample in engine_signal_summary(flow):
        add(cat, sample, WEIGHTS.get(cat, 1) + 1)

    # raw-text signals from signal details + call text
    text = "\n".join(str(sig.get("detail", "")) for sig in flow.signals)
    text += "\n" + "\n".join(t or "" for (_, t) in flow.calls_text)
    for cat, sample in _signals_in(text):
        add(cat, sample, WEIGHTS.get(cat, 1))

    return {
        "file": file_path,
        "func": name,
        "line": start_line,
        "score": state["score"],
        "categories": sorted(k for k in cats),
        "details": details,
    }


EXECCAT = {
    "Command Injection",
    "Code Injection",
    "Insecure Deserialization",
    "Arbitrary File Write",
    "SQL Injection",
    "File Inclusion",
    "Path Traversal",
}


def engine_signal_summary(flow):
    """Dedupes flow.signals into (category, sample) model."""
    out = {}
    for sig in flow.signals:
        s = sig.get("sig", "")
        d = sig.get("detail", "")
        if s == "source":
            out.setdefault("source", "source: " + d)
        elif s == "source-FILES":
            out.setdefault("source", "source: " + d)
        elif s == "interpolation":
            out.setdefault("interpolation", "interpolation: " + d)
        elif s == "varfunc":
            out.setdefault("dynamic-call", "variable function: " + d)
        elif s == "dynamic-exec":
            out.setdefault("dynamic-exec", "dynamic exec: " + d)
        elif s == "call-backtick":
            out.setdefault("shell", "backtick: " + d)
        elif s == "sink":
            cat = d.split(":")[0] if d else ""
            if cat in EXECCAT:
                out.setdefault("dynamic-exec", "sink: " + d)
        elif s == "trace-call":
            out.setdefault("dynamic-call", "trace: " + d)
        elif s == "trace-args":
            out.setdefault("dynamic-call", "trace-args: " + d)
        elif s == "file-write":
            out.setdefault("file-write", "file write: " + d)
    return sorted(out.items())


def classify(engine, flows):
    """Runs correlation across all functions.

    Returns list of webshell candidate dicts, sorted by score."""
    results = []
    for fkey, flow in flows.items():
        func = getattr(flow, "func", None)
        fname = flow.display() + "()"
        start = getattr(func, "line", 0)
        res = analyze_function(flow, fname, getattr(func, "file", ""), start)
        res["score"] = int(res["score"])
        # top-level code collects file-wide signals; require a much
        # harder threshold so normal files do not become leads
        if fname.startswith("{global}"):
            need = (REPORT_SCORE + 6, MIN_CATEGORIES + 2)
        else:
            need = (REPORT_SCORE, MIN_CATEGORIES)
        if res["score"] >= need[0] and len(res["categories"]) >= need[1]:
            res["status"] = "RESEARCH_LEAD"
        elif res["score"] >= need[0] - 2 and not fname.startswith("{global}"):
            res["status"] = "UNCONFIRMED"
        else:
            continue
        results.append(res)
    results.sort(key=lambda r: (-r["score"], r["file"], r["line"]))
    return results


def findings_from(results):
    """Converts high-score correlation results into Finding dicts."""
    from .findings import Finding

    fnd = []
    for i, res in enumerate(results):
        cats = res["categories"]
        ev = [
            "signals: %s" % ", ".join(cats),
            "score: %d (threshold %d, min categories %d)" % (res["score"], REPORT_SCORE, MIN_CATEGORIES),
        ]
        for c, d in res["details"][:8]:
            ev.append("%s: %s" % (c, d))
        f = Finding(
            id="PHPSCAN-M%03d" % (i + 1),
            rule_id="php.webshell",
            category="Webshell / Backdoor",
            title="Webshell pattern correlation in %s" % (res["func"],),
            severity="CRITICAL" if res["score"] >= 10 else "HIGH",
            confidence=min(0.9, 0.08 * res["score"] + 0.3),
            status=res["status"],
            file=res["file"],
            line=res["line"],
            func=res["func"],
            source={},
            sink={"name": "signal-correlation", "kind": "webshell", "expr": ""},
            data_flow=[],
            evidence=ev,
            validation={
                "correlation": {
                    "result": "PASS",
                    "note": "%d independent signal categories weighted %d" % (len(cats), res["score"]),
                }
            },
            recommendation="Webshell / Backdoor: review this function "
            "manually; correlate uses of dynamic calls with "
            "attacker-controlled input.",
            reason="",
        )
        from .findings import category_fingerprint

        f.fingerprint = category_fingerprint(
            "Webshell / Backdoor", res["file"], res["line"], "signal-correlation", ",".join(cats)
        )
        fnd.append(f)
    return fnd
