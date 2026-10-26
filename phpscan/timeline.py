"""Patch timeline & exposure reasoning (v0.4) -- origin=history evidence.

Answers: "is what the network exposes consistent with a patched or
unpatched component version?"  Inputs are deliberately operator-
supplied: a patch declaration describing affected ranges per
component.  phpscan ships NO vulnerability database and never claims
compromise from a version string alone -- it grades exposure
(EXPOSURE_CONFIRMED / _POSSIBLE / _NONE / INSUFFICIENT_DATA) and lets
the fusion layer pair that with live observations.

Sources (read-only):
  composer.lock / composer.json under the target tree
  operator declaration: schema phpscan-patch-timeline/1
"""

from __future__ import annotations

import json
import os
import re

from .evidence import Evidence, EvidenceStore

DECL_SCHEMA = "phpscan-patch-timeline/1"

# composer constraint operators we honor (subset, honest: unknown -> UNCERTAIN)
_OPS = (">=", "<=", ">", "<", "=", "^", "~")


def load_declaration(path):
    """Loads and validates the operator patch declaration file."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or data.get("schema") != DECL_SCHEMA:
        raise ValueError("patch declaration must be JSON with schema %s" % DECL_SCHEMA)
    if not isinstance(data.get("components"), list):
        raise ValueError("declaration needs a 'components' list")
    return data


def collect_installed(target):
    """Reads composer.lock/-json under target; returns {name: [versions_or_constraints]}."""
    from . import discovery

    skip = set(discovery.SKIP_DIRS)
    out = {}
    root = target if os.path.isdir(target) else os.path.dirname(target) or "."
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip and not os.path.islink(os.path.join(dirpath, d))]
        for fn in ("composer.lock", "composer.json"):
            if fn in filenames:
                comps = _read_composer_file(os.path.join(dirpath, fn), fn)
                for name, ver in comps:
                    out.setdefault(name.lower(), set()).add(str(ver))
    return _norm(out)


def _read_composer_file(path, fn):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    comps = []
    if fn == "composer.lock":
        for block in ("packages", "packages-dev"):
            for p in data.get(block) or []:
                comps.append((str(p.get("name", "")), str(p.get("version", "") or "")))
    else:
        for block in ("require", "require-dev"):
            for name, constraint in (data.get(block) or {}).items():
                comps.append((str(name), str(constraint or "")))
    return comps


def _norm(nv):
    out = {}
    for name, vers in nv.items():
        if not name or name == "php" or name.startswith("ext-"):
            continue
        out[name] = sorted(v for v in vers if v)
    return out


def _pver(s):
    """Parse 'v1.2.3' style into comparable tuple; None if impossible."""
    m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(s).strip())
    if not m:
        return None
    a = int(m.group(1))
    b = int(m.group(2) or 0)
    c = int(m.group(3) or 0)
    return (a, b, c)


def _match_one(constraint, v):
    c = str(constraint).strip()
    if c in ("*", ""):
        return True
    for op in _OPS:
        if c.startswith(op):
            rest = c[len(op) :].strip()
            rv = _pver(rest)
            if rv is None:
                return None
            if op == "^":
                return rv <= v if v[0] == rv[0] else False
            if op == "~":
                return v >= rv if v[0] == rv[0] else False
            if op == "=":
                return v == rv
            return {"<": v < rv, ">": v > rv, "<=": v <= rv, ">=": v >= rv}[op]
    lv = _pver(c)
    if lv is None:
        return None
    return v == lv


def compare(version, constraints):
    """True if version matches the affected constraint list; None if unknown."""
    v = _pver(version)
    if v is None:
        return None
    if not constraints:
        return False
    results = []
    for c in constraints:
        r = _match_one(c, v)
        results.append(r)
    if any(r is True for r in results):
        return True
    if all(r is False for r in results):
        return False
    return None


def _is_exact_version(text):
    return bool(re.match(r"^v?\d+(\.\d+)*$", str(text).strip()))


def grade(decl_components, installed):
    """Grade installed components against declaration. Returns (entries, counts)."""
    entries = []
    counts = {}
    by_name = {str(c.get("name", "")).lower(): c for c in decl_components}
    for name, versions in sorted(installed.items()):
        for ver in versions or [""]:
            decl = by_name.get(name)
            if not decl:
                counts["undeclared"] = counts.get("undeclared", 0) + 1
                entries.append(
                    {
                        "name": name,
                        "version": ver,
                        "status": "EXPOSURE_NONE",
                        "reason": "component not covered by operator declaration",
                        "declaration_ref": None,
                        "confidence": 0.4,
                        "uncertainty": ["no declaration for this component"],
                    }
                )
                continue
            if _is_exact_version(ver):
                matched = compare(ver, decl.get("affected", []))
                if matched is None:
                    status = "INSUFFICIENT_DATA"
                    reason = "version not parseable against declaration constraints"
                elif matched:
                    status = "EXPOSURE_CONFIRMED"
                    reason = "installed version is inside declared affected range"
                else:
                    status = "EXPOSURE_NONE"
                    reason = "installed version is outside declared affected range"
            else:
                # constraint-only (composer.json without lock): keep it conservative
                status = "EXPOSURE_POSSIBLE"
                reason = "constraint '%s' present without resolved lock version" % ver
            counts[status] = counts.get(status, 0) + 1
            entries.append(
                {
                    "name": name,
                    "version": ver,
                    "status": status,
                    "reason": reason,
                    "declaration_ref": {
                        k: decl.get(k) for k in ("name", "affected", "patched", "summary") if decl.get(k) is not None
                    },
                    "confidence": 0.85 if status != "INSUFFICIENT_DATA" else 0.3,
                    "uncertainty": list(decl.get("uncertainty", ())),
                }
            )
    return entries, counts


def run_timeline(target, declaration_path=None, now=None, store=None):
    """Returns (store, summary, entries). Evidence origin=history."""
    store = store if store is not None else EvidenceStore(target, "0.4.0")
    installed = collect_installed(target)
    entries = []
    summary = {
        "installed_components": len(installed),
        "declaration": declaration_path,
        "total": 0,
        "notes": [],
    }

    def ev(category, name, value, conf, uncertainty=(), tags=()):
        store.add(
            Evidence(
                "history",
                category,
                name,
                value=value,
                confidence=conf,
                ts=now,
                tags=list(tags),
                uncertainty=list(uncertainty),
            )
        )

    for name, vers in sorted(installed.items()):
        ev("COMPONENT_OBSERVED", name, {"versions": vers}, 0.8)
    if declaration_path is None:
        summary["notes"].append("no patch declaration supplied")
    else:
        decl = load_declaration(declaration_path)
        entries, counts = grade(decl.get("components", []), installed)
        for e in entries:
            ev(
                "EXPOSURE_GRADED",
                e["name"],
                {"version": e["version"], "status": e["status"], "reason": e["reason"]},
                e["confidence"],
                e["uncertainty"],
                tags=("timeline",),
            )
        summary["counts"] = dict(sorted(counts.items()))
        summary["total"] = len(entries)
    return store, summary, entries
