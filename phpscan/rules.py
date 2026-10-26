"""YAML rule-wheel loading.

User rule files may EXTEND the built-in registries:
  sinks:      extra functions/methods per category
  sanitizers: extra sanitizer definitions
  sources:    context/level overrides
Validation: categories must be known; arg indexes must be ints >= -1.
"""

from __future__ import annotations


import yaml

from . import defs


def _as_dict(data, key):
    v = data.get(key) or {}
    if not isinstance(v, dict):
        raise ValueError("rules: '%s' must be a mapping" % key)
    return v


def apply_rules(engine_defs, rules_path):
    """Mutates copies of the built-in defs with user content."""
    with open(rules_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    if not isinstance(raw, dict):
        raise ValueError("rules file must be a mapping")
    sinks = _as_dict(raw, "sinks")
    for cat, spec in sinks.items():
        if cat not in defs.SINKS:
            raise ValueError("rules: unknown sink category %r" % cat)
        funcs = spec.get("funcs") or {}
        for name, idx in funcs.items():
            if not isinstance(idx, int) or idx < -1:
                raise ValueError("rules: bad arg index for sink %r in %r" % (name, cat))
            defs.SINKS[cat]["funcs"][name.lower()] = idx
        margs = spec.get("methods") or {}
        for name, idx in margs.items():
            if not isinstance(idx, int) or idx < -1:
                raise ValueError("rules: bad arg index for method %r in %r" % (name, cat))
            defs.SINKS[cat]["method_args"][name.lower()] = idx
    sans = _as_dict(raw, "sanitizers")
    for name, spec in sans.items():
        if not isinstance(spec, dict) or "ctx" not in spec:
            raise ValueError("rules: sanitizer %r needs 'ctx'" % name)
        defs.SANITIZERS[name.lower()] = {
            "ctx": str(spec.get("ctx", "generic")),
            "strength": str(spec.get("strength", "medium")),
        }
    srcs = _as_dict(raw, "sources")
    for name, spec in srcs.items():
        lvl = int(spec.get("level", 2)) if isinstance(spec, dict) else int(spec)
        defs.TAINTED_CONTEXTS[name] = lvl
    return raw


def rule_report():
    out = {
        "sink_categories": sorted(defs.SINKS),
        "sanitizers": sorted(defs.SANITIZERS),
        "sources": sorted(defs.TAINTED_CONTEXTS),
        "transforms": sorted(defs.TRANSFORMS),
    }
    return out
