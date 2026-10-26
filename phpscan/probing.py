"""Safe probing layer (v0.4, explicit opt-in).

The passive observer (live.py) never mutates a request.  Probing uses a
hard-coded, benign vocabulary of differences -- a duplicate query key,
a HEAD vs GET -- and compares responses like a scientist: measure,
perturb by one bit, measure again.  Nothing here sends payloads, attack
strings, or any content a WAF would classify.  Collecting PROBE-level
readings happens only when the operator explicitly chooses the ``safe``
profile.

Outputs are Evidence records (origin=live, tag ``probe``).
"""

from __future__ import annotations

import urllib.parse

from .live import LiveObserver, Scope
from .evidence import EvidenceStore

# read-only route touches (paths of interest in real deployments)
INTERESTING_PATHS = (
    "/.env",
    "/.git/HEAD",
    "/composer.json",
    "/composer.lock",
    "/phpinfo.php",
    "/info.php",
    "/admin",
    "/wp-login.php",
    "/config.php",
)

SECRET_PATHS = {"/.env", "/composer.lock"}


def _rec(category, target, value, conf, now=None, tags=("probe",), uncertainty=(), evid=None):
    return {
        "origin": "live",
        "category": category,
        "target": target,
        "value": value,
        "confidence": conf,
        "ts": now,
        "tags": list(tags),
        "uncertainty": list(uncertainty),
        "evidence": evid or {},
    }


def run_safe(base_url, scope=None, now=None, store=None):
    """Safe-profile probing; returns (store, summary).

    state key values: touch budget/lack are observations, conclusions are
    deferred to the fusion layer.
    """
    store = store if store is not None else EvidenceStore(base_url, "0.4.0")
    scope = scope or Scope()
    summary = {"base_url": base_url, "requests": 0, "probes": 0, "notes": []}

    def ev(category, target, value, conf, uncertainty=(), evid=None):
        from .evidence import Evidence

        store.add(
            Evidence(
                "live",
                category,
                target,
                value=value,
                confidence=conf,
                ts=now,
                tags=["probe"],
                uncertainty=list(uncertainty),
                evidence=evid or {},
            )
        )

    has_query = bool(urllib.parse.urlsplit(base_url).query)

    # -- 1. read-only route touches ----------------------------------------
    for path in INTERESTING_PATHS:
        url = urllib.parse.urljoin(base_url, path)
        if not scope.allows(url):
            ev("SCOPE_REFUSAL", base_url, {"path": path, "reason": "out of scope"}, 1.0)
            continue
        page = LiveObserver(scope).get(url)
        if page is None:
            summary["probes"] += 1
            continue
        summary["probes"] += 1
        status = page["status"]
        if status == 200:
            ev("ROUTE_PRESENT", path, {"status": 200, "bytes": page["bytes"]}, 0.8)
            if path in SECRET_PATHS:
                from .live import _secrets_in

                for hit in _secrets_in(page["text"]):
                    ev(
                        "CREDENTIAL_ARTIFACT",
                        path,
                        {"type": hit["type"], "line": hit["line"], "via": "route-touch"},
                        0.9,
                        {"content confirmed over live route"},
                    )
        elif status in (401, 403):
            ev("ROUTE_GUARDED", path, {"status": status}, 0.85)
        elif status == 404:
            ev("ROUTE_ABSENT", path, {"status": 404}, 0.4)
        else:
            ev("RESPONSE_ANOMALY", path, {"status": status}, 0.5)

    # -- 2. base content-type observation ----------------------------------
    get_obs = LiveObserver(scope)
    getp = get_obs.get(base_url)
    if getp is not None:
        ev(
            "METHOD_INFO",
            base_url,
            {"get_status": getp["status"], "ct": getp["headers"].get("content-type")},
            0.6,
        )
    summary["bytes_downloaded"] = get_obs._bytes_downloaded

    # -- 3. differential query param (benign, lexical only) ----------------
    sep = "&" if has_query else "?"
    probe_b = _append_diff_param(base_url, sep)
    if probe_b is None:
        ev("PROBE_SKIPPED", base_url, {"reason": "no usable query position"}, 0.5)
    else:
        page_a = LiveObserver(scope).get(base_url)
        page_b = LiveObserver(scope).get(probe_b)
        if page_a is not None and page_b is not None:
            delta = page_b["bytes"] - page_a["bytes"]
            changed = page_a["status"] != page_b["status"] or abs(delta) > 64
            ev(
                "PARAM_BEHAVIOR_DIFF",
                base_url,
                {"status": [page_a["status"], page_b["status"]], "len_delta": delta, "changed": bool(changed)},
                0.7,
            )
        elif page_a is None or page_b is None:
            ev("PROBE_UNCERTAIN", base_url, None, 0.2, {"probe request failed"})

    summary["requests"] = scope.spent
    return store, summary


def _append_diff_param(base_url, sep):
    """Benign differential: appends ``x=phpscan`` (lexical, no payload)."""
    if "://" not in base_url:
        return None
    return base_url + sep + "x=phpscan"
