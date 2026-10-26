# Evidence fusion (phpscan 0.4.0)

The 0.4 layering: three passive *evidence producers* (LIVE, HOST,
HISTORY) all write into one evidence store; the static engine keeps
deciding WHAT code looks vulnerable; the fusion layer decides which
findings are corroborated or contradicted by what was *observed* in the
world. The Proof Engine verdict vocabulary is unchanged.

## Evidence record model (`phpscan-evidence.json`)

```json
{"schema": "phpscan-evidence/1", "tool": "phpscan", "tool_version": "0.4.0",
 "target": "...", "total": N,
 "records": [{"id": "EV-...", "ts": "...", "origin": "live|host|history",
              "category": "...", "target": "...", "value": {...},
              "confidence": 0.0-1.0, "uncertainty": [...],
              "evidence": {...}, "tags": [...]}]}
```

Contracts:
- Deterministic: identical collections serialize identically; ids are
  content hashes so they are stable across runs.
- Secret-safe: `_SENSITIVE_CATEGORIES` values get `redacted=True`
  (sha256-16fingerprint + 3-char hint), so no plaintext secret can leak
  into reports.
- Records are observations only; `category` is a stable string from
  `docs/live-analysis.md`, `docs/host-investigation.md`, and the
  `EXPOSURE_*` timeline states below.

## Corroboration into the Proof Engine

`proof.build(..., corroboration=[...])` attaches a separate
corroboration section (evidence ids + support), without touching gate
claims/verdict: what static analysis proved about code and what was
observed about the world remain explicit, independent axes.

## Support ladder (fusion output)

| support | meaning |
|---|---|
| `EXPOSED` | the named dangerous object itself was seen live (an exposed route, an artifact dropped at that path, a graded affected version) |
| `OBSERVED` | related evidence exists (cookies, headers, logs, related paths) |
| `none` | nothing linked |

Plus full `unexplained_evidence` list so nothing observed can silently go unused.

## Patch timeline (`phpscan timeline`)

Inputs: `composer.lock`/`composer.json` under the target, plus an
operator-supplied exposure **declaration** file, schema
`phpscan-patch-timeline/1`:

```json
{"schema": "phpscan-patch-timeline/1",
 "components": [{"name": "vendor/pkg",
                 "affected": ["<7.9.3"],
                 "patched": ["7.9.3"],
                 "summary": "operator note"}]}
```

States: `EXPOSURE_CONFIRMED` (installed version inside a declared
affected range), `EXPOSURE_POSSIBLE` (constraint-only install, no lock
version resolved), `EXPOSURE_NONE` (installed outside ranges / not
declared), `INSUFFICIENT_DATA` (unparseable). phpscan ships NO
vulnerability database; the declaration is the operator's assertion.

## Fusion + correlate workflow

```
python -m phpscan.cli live http://host/ --out live-report.json
python -m phpscan.cli investigate path/to/app --out host-report.json
python -m phpscan.cli timeline path/to/app --vuln-declaration decl.json
python -m phpscan.cli correlate phpscan.json --evidence live-report.json
```

Correlate output: per-finding support + reasons + unexplained leads.
