"""Variant Hunter + Security Genome.

A *genome* is an abstract fingerprint of a vulnerability pattern:
category + source class + sink + call kind + sanitizer context +
transforms observed on the chain.  Findings that share a genome are the
same bug shape at different sites; the hunter groups them, then classifies
each site as confirmed (validated finding), untested (weak/partial
evidence) or refuted (rejected by the gate).

Output is purely derived from gate results: nothing here changes what is
reported, it only regroups it so researchers can see how many sites share
one pattern and which of them survived the proof.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from . import defs as D

_TRANSFORM_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _transforms_in_chain(chain):
    found = []
    for step in chain or ():
        text = step[1] if isinstance(step, tuple) else str(step)
        for m in _TRANSFORM_RE.finditer(text):
            name = m.group(1).lower()
            if name in D.TRANSFORMS:
                found.append(name)
    return tuple(sorted(set(found)))


def _pattern_from_finding(f):
    return {
        "category": f.category or "",
        "source_class": ((f.source or {}).get("class") or "-"),
        "sink": ((f.sink or {}).get("name") or "-"),
        "call_kind": ((f.sink or {}).get("kind") or "-"),
        "san_ctx": "",
        "transforms": _transforms_in_chain(getattr(f, "data_flow", []) or []),
    }


def _pattern_from_reject(r):
    return {
        "category": r.get("category", ""),
        "source_class": "-",
        "sink": r.get("sink", "").rsplit("(", 1)[0] if r.get("sink") else "-",
        "call_kind": "-",
        "san_ctx": "",
        "transforms": tuple(),
    }


def genome_id(pattern):
    base = "|".join(
        [
            pattern["category"],
            pattern["source_class"],
            pattern["sink"],
            pattern["call_kind"],
            pattern["san_ctx"],
            ",".join(pattern["transforms"]),
        ]
    )
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]


def analyze(findings, rejected):
    """Groups findings + rejected candidates into genome records."""
    genomes: dict[str, dict[str, Any]] = {}

    def record(gid, pattern, kind, ref):
        g = genomes.get(gid)
        if g is None:
            g = {"id": gid, "pattern": dict(pattern), "instances": [], "candidates": []}
            genomes[gid] = g
        if kind == "instance":
            g["instances"].append(ref)
        else:
            g["candidates"].append(ref)

    for f in list(findings or []):
        pattern = _pattern_from_finding(f)
        record(
            genome_id(pattern),
            pattern,
            "instance",
            {"id": f.id, "file": f.file, "line": f.line, "status": f.status, "confidence": round(f.confidence, 2)},
        )
    for r in list(rejected or []):
        pattern = _pattern_from_reject(r)
        record(
            genome_id(pattern),
            pattern,
            "candidate",
            {"file": r.get("file", ""), "line": r.get("line", 0), "reason": r.get("reason", "")},
        )

    for g in genomes.values():
        inst_statuses = [i["status"] for i in g["instances"]]
        if any(s == "VALIDATED" for s in inst_statuses):
            g["status"] = "confirmed"
        elif inst_statuses:
            g["status"] = "untested"
        else:
            g["status"] = "refuted"

    return sorted(genomes.values(), key=lambda g: (g["status"], g["id"]))


def render_text(genomes):
    lines = []
    lines.append("phpscan variant hunter — %d security genome(s)" % len(genomes))
    lines.append("=" * 78)
    for g in genomes:
        p = g["pattern"]
        sig = "%s @ %s%s" % (
            p["category"],
            p["sink"],
            (" via " + ", ".join(p["transforms"])) if p["transforms"] else "",
        )
        lines.append("")
        lines.append("genome %s  [%s]" % (g["id"], g["status"].upper()))
        lines.append("  pattern: %s  (source_class=%s, call_kind=%s)" % (sig, p["source_class"], p["call_kind"]))
        lines.append(
            "  validated instances: %d   rejected candidates: %d"
            % (sum(1 for i in g["instances"] if i["status"] == "VALIDATED"), len(g["candidates"]))
        )
        for i in g["instances"][:6]:
            lines.append("    * %s:%s  (%s, conf %.2f)" % (i["file"], i["line"], i["status"], i["confidence"]))
        if len(g["instances"]) > 6:
            lines.append("    ... and %d more instance(s)" % (len(g["instances"]) - 6))
        for c in g["candidates"][:4]:
            lines.append("    - %s:%s  rejected: %s" % (c["file"], c["line"], c["reason"][:80]))
        if len(g["candidates"]) > 4:
            lines.append("    ... and %d more rejected candidate(s)" % (len(g["candidates"]) - 4))
    return "\n".join(lines) + "\n"
