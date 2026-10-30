"""Live passive observation engine (v0.4).

Listens at a base URL within an explicit scope and records what the
application *itself* exposes to any casual visitor: headers, redirects,
robots.txt, fingerprints, error pages.  No parameter mutation, no
endpoint brute-force, no payloads, no writes -- mutation belongs to a
separate module (probing.py) and is opt-in by profile.

Safety contracts:

* ``scope`` allow-lists exact hosts and schemes; every URL -- including
  each redirect hop -- is validated before any request is made.  A hop
  out of scope is recorded and the chain stops.
* Requests are bounded by a hard budget (count and total bytes); nothing
  is cached and nothing is retried automatically.
* Anything a human would consider a credential is redacted by
  evidence.redact before it can reach a report.
* Failures become UNCERTAIN records; the engine never turns a network
  error into a security conclusion.
"""

from __future__ import annotations

import http.client
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from .evidence import Evidence, EvidenceStore
from .log import get_logger, redact_url

logger = get_logger("live")

MAX_BODY = 512 * 1024
MAX_HOPS = 5
MIN_INTERVAL = 0.0

SECURITY_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

FINGERPRINTS = (
    ("wp-json", "WordPress REST"),
    ("wp-content", "WordPress"),
    ("XSRF-TOKEN", "Laravel"),
    ("X-Generator", None),
    ("generator", None),
    ("csrf", None),
    ("xsrf-token", "Laravel"),
    ("joomla", "Joomla"),
    ("drupal", "Drupal"),
    ("/static/", "static asset"),
)


class URLOutOfScope(ValueError):
    """Raised (and recorded) when a URL escapes the observation scope."""


class Scope:
    """Explicit allow-list: schemes, hosts, and request budget."""

    def __init__(
        self,
        allow_hosts=(),
        schemes=("http", "https"),
        max_requests=32,
        max_total_bytes=1024 * 1024,
        timeout=10.0,
        min_interval=MIN_INTERVAL,
    ):
        self.allow_hosts = frozenset(h.lower().strip(" .") for h in allow_hosts if h and h.strip())
        self.schemes = frozenset(s.lower() for s in schemes)
        self.max_requests = int(max_requests)
        self.max_total_bytes = int(max_total_bytes)
        self.timeout = float(timeout)
        self.min_interval = float(min_interval)
        self.spent = 0
        self._last_t = 0.0

    def allows(self, url):
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError:
            return False
        if parsed.scheme.lower() not in self.schemes:
            return False
        host = (parsed.hostname or "").lower()
        if not host or host not in self.allow_hosts:
            return False
        return True

    def consume(self):
        """Returns True if budget remains and one request may proceed."""
        if self.spent >= self.max_requests:
            return False
        now = time.monotonic()
        wait = self.min_interval - (now - self._last_t)
        if wait > 0:
            time.sleep(wait)
        self._last_t = time.monotonic()
        self.spent += 1
        return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: A002
        return None


_OpenerCache: dict[str, object] = {}
OpenerClass = None


def _opener():
    global OpenerClass
    if OpenerClass is None:
        OpenerClass = urllib.request.build_opener(_NoRedirect)
    return OpenerClass


DEFAULT_UA = "phpscan-passive/0.4 (operator-authorized observation; equality: read-only GET)"


def fetch(url, scope, method="GET"):
    """One in-scope request; returns a response dict or an error dict."""
    if not scope.allows(url):
        raise URLOutOfScope("url outside scope (host allow-list): %s" % urllib.parse.urlsplit(url).hostname)
    if not scope.consume():
        logger.debug("request budget exhausted; skipping %s", redact_url(url))
        return {"status": 0, "error": "budget exhausted", "url": url}
    try:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", DEFAULT_UA)
        req.add_header("Accept-Encoding", "identity")
        with _opener().open(req, timeout=scope.timeout) as resp:
            body = resp.read(scope.max_total_bytes + 1)
            truncated = len(body) > scope.max_total_bytes
            if truncated:
                body = body[: scope.max_total_bytes]
                scope.max_total_bytes = 0
            else:
                scope.max_total_bytes -= len(body)
            return {
                "status": resp.status,
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "body": body,
                "truncated": truncated,
                "url": resp.geturl(),
            }
    except urllib.error.HTTPError as exc:
        # with redirects disabled, 3xx (and any non-2xx we want to see)
        # arrives here; surface it as a real response.
        body = b""
        try:
            body = exc.read(MAX_BODY)
        except Exception as body_exc:  # noqa: BLE001
            logger.debug("could not read HTTP error body: %s", body_exc.__class__.__name__)
        return {
            "status": exc.code,
            "headers": {k.lower(): v for k, v in (exc.headers or {}).items()},
            "body": body,
            "truncated": False,
            "url": url,
        }
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        name = exc.__class__.__name__
        msg = getattr(exc, "reason", exc)
        logger.info("request failed: %s (%s: %s)", redact_url(url), name, msg)
        return {"status": 0, "error": "%s: %s" % (name, msg), "url": url}


class LiveObserver:
    """Passive GET observer; failures become notes, never conclusions."""

    def __init__(self, scope=None):
        self.scope = scope or Scope()
        self.notes = []
        self._bytes_downloaded = 0

    def get(self, url):
        t0 = time.monotonic()
        resp = fetch(url, self.scope)
        if resp.get("error"):
            self.notes.append("request error: %s (%s)" % (resp["url"], resp["error"]))
            return None
        dt = int((time.monotonic() - t0) * 1000)
        body = resp.get("body") or b""
        self._bytes_downloaded += len(body)
        return {
            "status": resp.get("status", 0),
            "headers": resp.get("headers", {}),
            "text": body.decode("utf-8", "replace")[:MAX_BODY],
            "bytes": len(body),
            "ms": dt,
            "url": resp.get("url", url),
            "truncated": resp.get("truncated", False),
        }


def run_passive(
    base_url,
    scope=None,
    probe_robots=True,
    now=None,
    store=None,
):
    """Observes base URL within scope; returns (store, summary).

    Summary keys: requests, bytes_downloaded, records, notes, records_by_category.
    """
    store = store if store is not None else EvidenceStore(base_url, "0.4.0")
    scope = scope or Scope()
    parsed = urllib.parse.urlsplit(base_url)

    def rec(category, target, value, conf=0.7, uncertainty=(), tags=(), evid=None, source_ref=None):
        e = Evidence(
            "live",
            category,
            target,
            value=value,
            confidence=conf,
            ts=now,
            uncertainty=list(uncertainty),
            tags=list(tags),
            evidence=evid or {},
            source_ref=source_ref,
        )
        store.add(e)
        return e

    summary = {"base_url": base_url, "requests": 0, "bytes_downloaded": 0, "records": 0, "notes": []}

    # -- DNS ----------------------------------------------------------------
    host = parsed.hostname or ""
    if host:
        t0 = time.monotonic()
        ips = observer_resolve(scope, host)
        dt = int((time.monotonic() - t0) * 1000)
        if ips:
            rec("DNS_OBSERVED", host, {"resolved": ips[:8], "ms": dt}, 0.9)
        else:
            rec(
                "DNS_UNCERTAIN",
                host,
                None,
                0.2,
                uncertainty=["resolver returned no addresses"],
            )
            summary["notes"].append("dns failure for %s" % host)

    # -- HTTP base ----------------------------------------------------------
    page = None
    if scope.allows(base_url):
        obs = LiveObserver(scope)
        page = obs.get(base_url)
        summary["bytes_downloaded"] += obs._bytes_downloaded
        summary["notes"].extend(obs.notes)
    else:
        rec(
            "SCOPE_REFUSAL",
            host,
            {"url": base_url},
            1.0,
            uncertainty=["base url outside scope"],
        )
        return store, _finish(summary, store, scope)

    if page is None:
        rec(
            "HTTP_UNCERTAIN",
            base_url,
            None,
            0.2,
            uncertainty=["request failed (network/schema/runtime error)"],
        )
        return store, _finish(summary, store, scope)

    status = page["status"]
    page_e = rec(
        "HTTP_RESPONSE_OBSERVED",
        base_url,
        {"status": status, "ct": page["headers"].get("content-type"), "ms": page["ms"]},
        0.9,
    )

    headers = page["headers"]
    server = headers.get("server")
    xpb = headers.get("x-powered-by")
    if server:
        rec("SERVER_HEADER_OBSERVED", base_url, server[:200], 0.9)
    if xpb:
        rec("PHP_VERSION_OBSERVED", base_url, xpb[:200], 0.85)
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    if missing:
        rec("SECURITY_HEADERS_MISSING", base_url, {"missing": missing}, 0.8)
    for name in ("x-generator", "generator"):
        if headers.get(name):
            rec("FRAMEWORK_FINGERPRINT", base_url, headers[name][:200], 0.8)

    setc = headers.get("set-cookie")
    if setc:
        flags = []
        low = setc.lower()
        for fl in ("httponly", "secure", "samesite"):
            if fl in low:
                flags.append(fl)
        rec(
            "COOKIE_OBSERVED",
            base_url,
            {"flags": flags, "missing": [f for f in ("secure", "httponly", "samesite") if f not in low]},
            0.6,
        )

    # body fingerprints
    text = page["text"]
    low = text.lower()
    for marker, label in FINGERPRINTS:
        if label and marker in low:
            rec("FRAMEWORK_FINGERPRINT", base_url, label, 0.5)
            break
    for secret in _secrets_in(text):
        rec("CREDENTIAL_ARTIFACT", base_url, {"type": secret["type"], "line": secret["line"]}, 0.8, source_ref=secret)

    if status >= 500:
        rec("ERROR_PAGE_OBSERVED", base_url, {"status": status}, 0.7)
    if status == 404 and "stack trace" in low:
        rec("ERROR_PAGE_OBSERVED", base_url, {"status": status, "detail": "stack trace"}, 0.8)

    # -- redirects ------------------------------------------------------------
    if status in (301, 302, 303, 307, 308) and "location" in headers:
        page_e.evidence["redirect"] = _follow_redirects(base_url, headers["location"], scope, rec, summary)

    # -- robots ------------------------------------------------------------
    if probe_robots and scope.allow_hosts:
        robots_url = urllib.parse.urljoin(base_url, "/robots.txt")
        if scope.allows(robots_url):
            obs = LiveObserver(scope)
            rpage = obs.get(robots_url)
            summary["bytes_downloaded"] += obs._bytes_downloaded
            if rpage is not None and rpage["status"] == 200 and "disallow" in rpage["text"].lower():
                rules = []
                for line in rpage["text"].splitlines():
                    m = re.match(r"\s*Disallow:\s*(\S+)", line, re.I)
                    if m:
                        rules.append(m.group(1))
                if rules:
                    rec("ROBOTS_DISALLOW", robots_url, {"paths": rules[:64]}, 0.8)
            page_e.evidence["robots"] = rpage["status"] if rpage is not None else "error"

    return store, _finish(summary, store, scope)


def observer_resolve(scope, host):
    """DNS resolve honoring scope timeouts; returns sorted IP list or None."""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(scope.timeout)
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        logger.info("dns resolution failed for %s (%s)", host, exc.__class__.__name__)
        return None
    finally:
        socket.setdefaulttimeout(old)
    return sorted({i[4][0] for i in infos if i[0] in (socket.AF_INET, socket.AF_INET6)})


def _follow_redirects(base_url, location, scope, rec, summary, hops=0):
    chain = []
    url = urllib.parse.urljoin(base_url, location)
    for _ in range(MAX_HOPS):
        if not scope.allows(url):
            chain.append({"url": url, "blocked": "out of scope"})
            rec(
                "SCOPE_REFUSAL",
                base_url,
                {"redirect_url": url, "reason": "out of scope"},
                1.0,
                uncertainty=["redirect chain left scope; stopped"],
            )
            break
        obs = LiveObserver(scope)
        resp = obs.get(url)
        chain.append({"url": url, "status": resp["status"] if resp else None})
        summary["bytes_downloaded"] += obs._bytes_downloaded
        if resp is None:
            break
        if resp["status"] not in (301, 302, 303, 307, 308):
            break
        nxt = resp["headers"].get("location")
        if not nxt:
            break
        url = urllib.parse.urljoin(url, nxt)
    return {"hops": chain}


def _finish(summary, store, scope=None):
    summary["requests"] = scope.spent if scope else 0
    summary["records"] = len(store)
    cats: dict[str, int] = {}
    for r in store.records:
        cats[r.category] = cats.get(r.category, 0) + 1
    summary["records_by_category"] = dict(sorted(cats.items()))
    return summary


_ENV_ASSIGN = re.compile(r"(?i)\b([a-z0-9_]*(?:key|token|secret|password)[a-z0-9_]*)\s*=\s*['\"]?([^\s'\"]{8,120})")


def _secrets_in(text):
    from .secrets import scan

    hits = []
    try:
        for r in scan(text, "http-body"):
            hits.append({"line": r["line"], "type": r["type"]})
    except Exception as exc:  # noqa: BLE001 - never fail a scan over the secret regexes
        logger.debug("body secret scan skipped: %s", exc.__class__.__name__)
    # unquoted environment-style assignments (secrets.scan matches quoted only)
    for i, line in enumerate(text.splitlines(), 1):
        m = _ENV_ASSIGN.search(line)
        if m:
            hits.append({"line": i, "type": "Environment Assignment: " + m.group(1).upper()})
    return hits
