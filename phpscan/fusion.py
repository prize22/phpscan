"""Evidence fusion (v0.4): static findings x live/host/history records.

The static engine decides WHAT code looks vulnerable.  This module asks
WHICH of those findings are corroborated -- or contradicted -- by what
could actually be observed (HTTP surface, dropped artifacts, installed
component versions).  It attaches a *verification axis* to findings but
never changes gate verdicts: merging happens as additional proof
claims, and `fusion` reports its own support ladder:

    OBSERVED   evidence exists about the related object
    EXPOSED    the dangerous object itself was seen in the wild
               (a route answering, an artifact present)
    SUSPECTED  only weak/indirect signals
    none       no evidence linked

All matching is reflective: every match records the evidence ids and
the reason, so a reviewer can undo any link.
"""

from __future__ import annotations

import os
from typing import Any

SUPPORT_ORDER = {"none": 0, "SUSPECTED": 1, "OBSERVED": 2, "EXPOSED": 3}


def fuse(scan_payload, evidence_store=None, timeline_entries=None):
    """Returns dict {fusion summary, verification per finding, unexplained_evidence}.

    scan_payload: dict from export_payload (or evidence-loadable payload).
    evidence_store: EvidenceStore (optional).
    timeline_entries: entries from timeline.run_timeline (optional).
    """
    findings = scan_payload.get("findings") or []
    store = evidence_store
    timeline_entries = timeline_entries or []

    # fingerprint evidence for quick reflection
    live_routes = []  # (path, record)
    host_paths: dict[str, list[Any]] = {}
    exposure = []
    for r in getattr(store, "records", []) or []:
        cat = r.category
        tgt = (r.target or "").replace("\\", "/")
        if cat == "ROUTE_PRESENT" or cat == "ROUTE_GUARDED":
            live_routes.append((tgt, r))
        elif cat == "EXPOSURE_GRADED":
            exposure.append(r)
        elif r.origin == "host":
            path = _basenameish(tgt)
            if path:
                host_paths.setdefault(path, []).append(r)

    verifications = []
    used_ids = set()
    for f in findings:
        ffile = _norm_path(f.get("file", ""))
        leaf = _basenameish(ffile)
        ver = {"id": f.get("id"), "support": "none", "evidence_ids": [], "reasons": []}
        matched = []
        # live route matched by file leaf (e.g., exposed .env, exposed config)
        for path, rec in live_routes:
            path_l = path.lower()
            if not leaf:
                continue
            if path_l.endswith(leaf.lower()) and leaf.lower() not in ("index.php",):
                matched.append((rec, "route '%s' answered for this file's name" % path))
        # host artifacts matched by path leaf or target dir
        for name, recs in host_paths.items():
            if not leaf:
                continue
            if _rel_dirs_share(ffile, name):
                for rec in recs:
                    matched.append((rec, "host artifact at related path '%s'" % name))
        # exposure grades matched only for vendor-shelved paths
        vendor_prefix = None
        if "/vendor/" in "/" + ffile:
            idx = ffile.find("/vendor/")
            vendor_prefix = ffile[idx + 8 :]
        vendor_name = _vendor_name(vendor_prefix) if vendor_prefix else None
        if vendor_name:
            for rec in exposure:
                if vendor_name.startswith((rec.target or "").lower()):
                    matched.append((rec, "component exposure grade '%s'" % (rec.value or {}).get("status")))

        if matched:
            ids = sorted({r.id for r, _ in matched})
            used_ids.update(ids)
            ex = False
            for rec, why in matched:
                ver["evidence_ids"] = ids
                ver["reasons"].append(why)
                if rec.category in ("ROUTE_PRESENT", "CREDENTIAL_ARTIFACT", "DISGUISED_PHP", "EXPOSURE_GRADED"):
                    ex = True
            ver["support"] = "EXPOSED" if ex else "OBSERVED"
        verifications.append(ver)

    # unexplained evidence -> new research leads
    unexplained = []
    if store is not None:
        for r in store.records:
            if r.id in used_ids:
                continue
            unexplained.append(
                {
                    "id": r.id,
                    "origin": r.origin,
                    "category": r.category,
                    "target": r.target,
                    "confidence": r.confidence,
                    "uncertainty": list(r.uncertainty),
                }
            )

    counts: dict[str, int] = {}
    for v in verifications:
        counts[v["support"]] = counts.get(v["support"], 0) + 1
    summary = {
        "findings": len(findings),
        "verification_counts": dict(sorted(counts.items())),
        "evidence_total": len(getattr(store, "records", []) or []),
        "evidence_linked": len(used_ids),
        "evidence_unlinked": len(unexplained),
        "timeline_entries": len(timeline_entries),
    }
    return {
        "summary": summary,
        "verification": verifications,
        "unexplained_evidence": unexplained,
    }


def _norm_path(p):
    return str(p).replace("\\", "/").lstrip("./")


def _basenameish(p):
    return os.path.basename(str(p)) if p else ""


def _rel_dirs_share(a, b):
    """True when the tree-ish relative positions overlap (path/leaf)."""
    return a.endswith(b) or b.endswith(a) or _basenameish(a).lower() == _basenameish(b).lower()


def _vendor_name(tail):
    tail = tail.replace("\\", "/")
    parts = [p for p in tail.split("/") if p]
    if len(parts) >= 2:
        return (parts[0] + "/" + parts[1]).lower()
    if parts:
        return parts[-1].lower()
    return ""
