"""Behavior reconstruction: per-function data-flow maps.

From the fixed-point engine results (engine.flows), this module
reconstructs, for every analyzed function:

* entry sources — attacker-controlled inputs read by the function
* transforms — encoding/decoding/string transforms applied along the way
* sinks — dangerous calls reached with tainted arguments
* returns — which parameters flow out of the function return value
* calls — every call site textually recorded by the engine
* closures — variables bound to anonymous functions

The output is purely derived from engine state: nothing is guessed and
nothing is validated here.  It answers "what does this code do with
user input?" so researchers can trace source → transform → sink by hand.

Text mode is a compact per-function trace; --json emits the full map
suitable for diffing between two scans.
"""

from __future__ import annotations

from . import engine as E


def _var_base(key):
    base = key.split(".")[-1] if key else ""
    if base.startswith("$"):
        base = base[1:]
    return base


def _source_level_name(level):
    try:
        from . import defs as D

        return D.LEVEL_NAMES.get(level, "UNKNOWN")
    except Exception:
        return "UNKNOWN"


def build_map(engine):
    funcs = []
    for key in sorted(engine.flows.keys()):
        flow = engine.flows.get(key)
        if flow is None:
            continue
        func = flow.func
        entry_sources = []
        transforms = set()
        uncertain_seen = False
        for k, v in (flow.state or {}).items():
            origin = getattr(v, "origin", None) or ""
            level = getattr(v, "level", 0) or 0
            if origin or getattr(v, "uncertain", ""):
                entry_sources.append(
                    {
                        "var": _var_base(k),
                        "origin": origin or (getattr(v, "uncertain", "") or "{expression}"),
                        "level": level,
                        "level_class": _source_level_name(level),
                        "line": int(getattr(v, "source_line", 0) or 0),
                        "file": getattr(v, "source_file", "") or func.file,
                    }
                )
                if getattr(v, "uncertain", ""):
                    uncertain_seen = True
            for t in getattr(v, "transforms", ()) or ():
                transforms.add(t)

        sinks = []
        for ck, cand in (flow.cands or {}).items():
            val = getattr(cand, "val", None)
            tr = []
            if val is not None:
                for t in getattr(val, "transforms", ()) or ():
                    transforms.add(t)
                    tr.append(t)
                if getattr(val, "uncertain", ""):
                    uncertain_seen = True
            sinks.append(
                {
                    "line": int(getattr(cand, "line", 0) or 0),
                    "category": getattr(cand, "cat", ""),
                    "sink": getattr(cand, "sink_name", ""),
                    "call_kind": getattr(cand, "call_kind", ""),
                    "receiver": getattr(cand, "receiver", "") or None,
                    "arg_idx": int(getattr(cand, "arg_idx", 0) or 0),
                    "expr": getattr(cand, "sink_expr", "") or "",
                    "transforms": tr,
                    "sanitizer": getattr(val, "sanitizer", "") if val else "",
                    "sanitizer_ctx": getattr(val, "sanitizer_ctx", "") if val else "",
                }
            )

        calls = []
        for line, text in flow.calls_text or []:
            calls.append({"line": int(line or 0), "text": text})

        funcs.append(
            {
                "key": E.func_key(func),
                "file": func.file,
                "func": func.name or "{closure}",
                "cls": func.cls or None,
                "line": int(func.line or 0),
                "entry_sources": entry_sources,
                "transforms": sorted(transforms),
                "returns": sorted(int(p) for p in (flow.ret_params or ())),
                "sinks": sinks,
                "calls": calls,
                "closure_vars": {k: E.func_key(cf) for k, cf in (flow.closure_vars or {}).items()},
                "uncertain": uncertain_seen,
            }
        )
    return {"functions": funcs, "total_functions": len(funcs)}


def render_text(m):
    lines = []
    lines.append("phpscan behavior map — %d function(s)" % m["total_functions"])
    lines.append("=" * 78)
    for fn in m["functions"]:
        lines.append("")
        head = fn["file"]
        if fn["cls"]:
            head += "::" + fn["cls"]
        head += "::" + fn["func"] + "()"
        lines.append("# " + head + " (L%s)" % fn["line"])
        if fn["entry_sources"]:
            lines.append("  entry sources:")
            for s in fn["entry_sources"]:
                lines.append("    $%s <- %s (%s)" % (s["var"], s["origin"], s["level_class"]))
        if fn["transforms"]:
            lines.append("  transforms: " + ", ".join(fn["transforms"]))
        if fn["returns"]:
            lines.append("  returns tainted via param(s): " + ", ".join(str(p) for p in fn["returns"]))
        if fn["closure_vars"]:
            lines.append("  closure-bound vars: " + ", ".join(sorted(fn["closure_vars"].keys())))
        if fn["sinks"]:
            lines.append("  sinks:")
            for s in fn["sinks"]:
                loc = "%s:%s" % (fn["file"], s["line"])
                lines.append(
                    "    L%s %s(%s) arg#%s — %s [%s]"
                    % (s["line"], s["sink"], s["call_kind"], s["arg_idx"], s["category"], loc)
                )
                if s["expr"]:
                    lines.append("      expr: " + s["expr"][:120])
                if s["transforms"]:
                    lines.append("      transforms: " + ", ".join(s["transforms"]))
                if s["sanitizer"]:
                    lines.append("      sanitizer: %s (ctx=%s)" % (s["sanitizer"], s["sanitizer_ctx"]))
        if not fn["entry_sources"] and not fn["sinks"] and not fn["calls"]:
            lines.append("  (no security-relevant behavior detected)")
        if fn["uncertain"]:
            lines.append("  note: some taint propagation in this function is uncertain")
    return "\n".join(lines) + "\n"
