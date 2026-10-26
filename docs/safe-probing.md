# Safe probing (phpscan 0.4.0)

`phpscan live --profile safe` adds the smallest vocabulary of *benign*
differences that still yields real field evidence. Each probe is
documented here; anything not listed will never be sent.

## The safe probe set

1. **Route touches** -- read-only GET to a fixed list:
   `/.env`, `/.git/HEAD`, `/composer.json`, `/composer.lock`,
   `/phpinfo.php`, `/info.php`, `/admin`, `/wp-login.php`, `/config.php`.
   Records:
   - `ROUTE_PRESENT` (200) / `ROUTE_GUARDED` (401/403) / `ROUTE_ABSENT`
     (404) / `RESPONSE_ANOMALY` (other),
   - plus `CREDENTIAL_ARTIFACT` when the response body contains quoted
     secret-shaped values or plain `KEY=...` environment assignments
     (redacted).

2. **Lexical request differential** -- GET base URL vs GET
   `base?...&x=phpscan` (a fixed literal token, no payload). Response
   deltas become `PARAM_BEHAVIOR_DIFF`; failure to observe is
   `PROBE_UNCERTAIN`. The toy parameter is never interpreted by the
   app as an exploit because it is not one.

3. **Content/type observation** -- base page response metadata only
   (`METHOD_INFO` records GET status + content type; no HEAD/POST
   methods are issued in this release).

## Boundaries (unchanged from passive)

- Same host allow-list, budget, response cap, no retries, no caching.
- Every probe carries the `probe` tag; fusion treats probe evidence as
  originating live data.
- The passive profile alone does none of the above; `safe` is explicit.

## Explicit non-goals

- No payloads, no shell escape attempts, no XSS polyglots, no uploads,
  no permission-change requests, no credential stuffing, no scanning of
  clients under test fronts. Differential probes exist to compare
  *behavior*, not to trigger bugs.
