# Live analysis (phpscan 0.4.0)

`phpscan live` observes a live HTTP surface passively and records what the
application *itself* exposes to any visitor. It is NOT a scanner in the
traditional sense: no payloads, no endpoint brute-force, no parameter fuzzing.

## What it observes (passive profile, default)

- DNS resolution of the target host (`DNS_OBSERVED` / `DNS_UNCERTAIN`)
- Root page response: status, content type, timing (`HTTP_RESPONSE_OBSERVED`)
- `Server` header (`SERVER_HEADER_OBSERVED`), `X-Powered-By`
  (`PHP_VERSION_OBSERVED` -- never a version claim on its own, only the
  string as presented by the server)
- Presence/absence of standard security headers
  (`SECURITY_HEADERS_MISSING` lists only what is absent)
- Cookies: flags present vs missing (`COOKIE_OBSERVED`)
- Real redirect chains, hop by hop (`HTTP_RESPONSE_OBSERVED` +
  redirect evidence; out-of-scope hops stop the chain avec a
  `SCOPE_REFUSAL` record)
- `robots.txt` rules (`ROBOTS_DISALLOW`) unless `--no-robots`
- Framework/body markers (`FRAMEWORK_FINGERPRINT`) - advisory signal only
- Plain-text credentials in the page body (`CREDENTIAL_ARTIFACT`) -
  redacted by design, see evidence model

## Safety model

1. **Scope is a hard allow-list.** Only hosts passed via `--allow-host`
   or the URL's own host may be contacted; each redirect hop is checked.
2. **Budget.** `--max-requests` bounds the number of requests; response
   size is capped; nothing is retried or cached.
3. **No mutation.** The passive profile only GETs; there is no POST, no
   set-anything, no destructive request.
4. **Errors are uncertainty, not facts.** Network failures produce
   `*_UNCERTAIN` records, never "vulnerable" or "compromised".
5. **Records are evidence, not verdicts.** The layers are graded by the
   fusion layer (docs/evidence-fusion.md) and feed the Proof Engine
   corroboration, which never overrides gate results.

## Usage

```
python -m phpscan.cli live http://target.local/ --json
python -m phpscan.cli live http://target.local/ --profile safe --allow-host api.target.local
python -m phpscan.cli live http://target.local/ --out live-report.json
```

## Profiles

- `passive` (default): root page, redirects, robots.txt.
- `safe` (explicit opt-in): additionally performs read-only route touches
  from a fixed benign list (see docs/safe-probing.md) and one
  lexical-only request differential. Still no payloads.
