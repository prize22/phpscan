"""Evidence model, store and redaction (v0.4).

Every observation phpscan makes outside static analysis — an HTTP header,
a discovered route, a suspicious host file — becomes an :class:`Evidence`
record.  Records are *observations*, never conclusions: the fusion layer
(see fusion.py) correlates them and the existing Proof Engine is the only
component allowed to issue verdicts.

Design contracts:

* Deterministic: two identical collections of records serialize to
  byte-identical JSON (sorted keys, stable ids).
* Attributable: every record carries its origin (static/live/host/history),
  the tool version and a timestamp.
* Uncertainty-preserving: a record may state what is NOT known; it never
  upgrades itself to "vulnerable"/"compromised".
* Secret-safe: values are passed through :func:`redact` before they can
  reach any report; the original never leaves the local run.
"""

from __future__ import annotations

import hashlib
import json
import os

SCHEMA_VERSION = "phpscan-evidence/1"

# record origins — closed set, propagated to reporting
ORIGIN_STATIC = "static"
ORIGIN_LIVE = "live"
ORIGIN_HOST = "host"
ORIGIN_HISTORY = "history"

# confidence is a bounded float 0..1; categories are free strings but the
# well-known ones are documented in docs/evidence-fusion.md.


def _now_iso(ts=None):
    import datetime

    if ts is None:
        return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    if isinstance(ts, str):
        return ts
    if hasattr(ts, "isoformat"):
        return ts.isoformat(timespec="seconds").replace("+00:00", "Z")
    ts = datetime.datetime.fromtimestamp(float(ts), datetime.timezone.utc)
    return ts.isoformat(timespec="seconds").replace("+00:00", "Z")


def redact(value, label=""):
    """Redact a possibly-sensitive value into safe evidence.

    Returns ``{"redacted": True, "kind": label or "value",
    "sha256": <first 16 of hash>, "hint": safe prefix}``.
    The hint keeps at most the first 3 characters plus an ellipsis check,
    enough for a human to recognize the artifact shape without exposing it.
    """
    if value is None:
        return {"redacted": False, "value": None}
    if not isinstance(value, str):
        value = str(value)
    h = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]
    hint = value[:3] + "..." if len(value) > 6 else "***"
    return {"redacted": True, "kind": label or "sensitive", "sha256": h, "hint": hint}


class Evidence:
    """One observation.  Never a conclusion."""

    __slots__ = (
        "id",
        "ts",
        "origin",
        "category",
        "target",
        "value",
        "normalized",
        "confidence",
        "request_ref",
        "response_ref",
        "evidence",
        "uncertainty",
        "tags",
        "source_ref",
    )

    def __init__(
        self,
        origin,
        category,
        target,
        value=None,
        normalized=None,
        confidence=0.5,
        ts=None,
        request_ref=None,
        response_ref=None,
        evidence=None,
        uncertainty=None,
        tags=None,
        source_ref=None,
        eid=None,
    ):
        self.origin = origin
        self.category = category
        self.target = target
        self.value = value if value is None else redact(value) if _looks_sensitive(category, value) else _clip(value)
        self.normalized = normalized
        self.confidence = round(min(max(float(confidence), 0.0), 1.0), 2)
        self.ts = _now_iso(ts)
        self.request_ref = request_ref
        self.response_ref = response_ref
        self.evidence = dict(evidence or {})
        self.uncertainty = list(uncertainty or ())
        self.tags = sorted(set(tags or ()))
        self.source_ref = source_ref
        if eid is None:
            eid = _eid(self.origin, self.category, self.target, self.value, self.normalized)
        self.id = eid

    def to_dict(self):
        return {
            "id": self.id,
            "ts": self.ts,
            "origin": self.origin,
            "category": self.category,
            "target": self.target,
            "value": self.value,
            "normalized": self.normalized,
            "confidence": self.confidence,
            "request_ref": self.request_ref,
            "response_ref": self.response_ref,
            "evidence": self.evidence,
            "uncertainty": self.uncertainty,
            "tags": self.tags,
            "source_ref": self.source_ref,
        }

    @classmethod
    def from_dict(cls, d):
        e = cls(
            d.get("origin", ORIGIN_LIVE),
            d.get("category", ""),
            d.get("target", ""),
            None,
            d.get("normalized"),
            d.get("confidence", 0.5),
            d.get("ts"),
            d.get("request_ref"),
            d.get("response_ref"),
            d.get("evidence"),
            d.get("uncertainty"),
            d.get("tags"),
            d.get("source_ref"),
            eid=d.get("id"),
        )
        e.value = d.get("value")
        return e


def _clip(value):
    if isinstance(value, dict):
        return {k: _clip(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_clip(v) for v in value]
    if isinstance(value, str) and len(value) > 512:
        return value[:509] + "..."
    return value


_SENSITIVE_CATEGORIES = {
    "CREDENTIAL_ARTIFACT",
    "KEY_MATERIAL",
    "SESSION_MATERIAL",
    "CONFIG_SECRET",
    "ENVIRONMENT_SECRET",
}


def _looks_sensitive(category, value):
    return category in _SENSITIVE_CATEGORIES and isinstance(value, str)


def _eid(origin, category, target, value, normalized):
    raw = "\x1f".join(
        [
            origin,
            category,
            target,
            json.dumps(value, sort_keys=True, default=str),
            "" if normalized is None else str(normalized),
        ]
    )
    return "EV-" + hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


class EvidenceStore:
    """Ordered, deterministic collection of evidence records."""

    def __init__(self, target="", tool_version="0.4.0"):
        self.target = target
        self.tool_version = tool_version
        self.records = []

    def add(self, record):
        if isinstance(record, dict):
            record = Evidence.from_dict(record)
        self.records.append(record)
        return record

    def __len__(self):
        return len(self.records)

    def by_origin(self, origin):
        return [r for r in self.records if r.origin == origin]

    def by_category(self, category):
        return [r for r in self.records if r.category == category]

    def to_dict(self):
        recs = sorted(self.records, key=lambda r: r.id)
        seen = set()
        deduped = []
        for r in recs:
            if r.id in seen:
                continue
            seen.add(r.id)
            deduped.append(r)
        self.records = deduped
        from . import __version__

        return {
            "schema": SCHEMA_VERSION,
            "tool": "phpscan",
            "tool_version": __version__,
            "target": self.target,
            "total": len(deduped),
            "origin_counts": {o: sum(1 for r in deduped if r.origin == o) for o in sorted({r.origin for r in deduped})},
            "category_counts": {
                c: sum(1 for r in deduped if r.category == c) for c in sorted({r.category for r in deduped})
            },
            "records": [r.to_dict() for r in deduped],
        }

    def write(self, path):
        data = self.to_dict()
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
        return data

    @classmethod
    def load(cls, path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or data.get("schema") != SCHEMA_VERSION:
            raise ValueError(
                "not a phpscan evidence file (schema mismatch): %r"
                % (
                    data.get(
                        "schema",
                    )
                )
            )
        store = cls(data.get("target", ""), data.get("tool_version", ""))
        store.records = [Evidence.from_dict(r) for r in data.get("records", [])]
        return store


def evidence_path(target_dir):
    return os.path.join(target_dir, "phpscan-evidence.json")
