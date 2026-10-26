# The phpscan Validation Gate

## Positions

Detection heuristics intentionally over-approximate. The Validation Gate is
what makes phpscan's output auditable: **every accepted finding carries the
result and note of all 8 stages**, and every rejection is retained with the
stage that rejected it and the reason. A candidate is a taint candidate
produced by the engine; the gate turns it into a finding, a rejection, or a
downgraded status.

## Stages

| # | stage | checks | fail action |
|---|-------|--------|-------------|
| 1 | structural | file parsed without error/truncation; candidate has sink expression | reject; UNCONFIRMED note possible on partial parse |
| 2 | semantic | category/type pair is coherent; call kind recorded | reject |
| 3 | data-flow | evidence chain exists and is source-anchored (or declared uncertain → PARTIAL); since 0.2.0 sink-expression presence is also verified against the file's source text — a chain that points at no sink in that textual context is guessed-at, so a missing sink text is a guaranteed PARTIAL "not located in source" | reject |
| 4 | control-flow | guard stack reachability (constant-false guards → unreachable) | reject |
| 5 | sanitizer | sanitizer context vs. sink context with strength | strong mismatch → reject; medium/weak → PARTIAL note |
| 6 | context | category-specific context checks | reject on fail |
| 7 | contradiction | chain vs. non-taint level vs. chain text consistency | reject |
| 8 | re-analysis | independent strict-mode pass (unknown calls and reads treated as attacker-controlled) | disagreement → PARTIAL |

## Status semantics

- **VALIDATED** — all stages pass with a scored confidence ≥0.60 and no
  degrading notes.
- **PARTIALLY_VALIDATED** — gate passes but with honest caveat notes (weak
  sanitizer, uncertain propagation steps, strict disagreement).
- **UNCONFIRMED** — real propagations too weak to call; research-relevant.
- **RESEARCH_LEAD** — Webshell correlation signal stack (multiple independent
  evidence categories) — manual review prompt, treated as a lead not a
  vulnerability claim.
- **REJECTED** (retained, not deleted) — any gate failure; forever visible in
  `rejected[]` with the stage and reason. This exists because silently
  discarding candidates is how tools hide bugs and hiding false negatives.
- **SUPPRESSED** (since 0.2.0) — the finding's stable fingerprint matches an
  entry in the accepted baseline (`<target>/.phpscan-baseline.json`);
  reported with the recorded reason, excluded from `--new-only` and from
  failure counts.

## Stable fingerprints (0.2.0)

fingerprints = hash of `(category, file, func, sink, source-class)`
deliberately line-free: the same semantic finding keeps its fingerprint
across line moves, so baselines don't churn on reformat. Two candidates
that differ only in the source variable within one function are distinct
findings.

## Sanitizer contexts (stage 5)

| category | mitigating contexts |
|---|---|
| SQL Injection | `sql`, `numeric` |
| Command Injection | `shell`, `numeric` |
| XSS | `html`, `url` |
| File Inclusion | `path`, `numeric` |
| Path Traversal | `path`, `numeric`, `alpha` |
| Arbitrary File Write | `path`, `numeric` |
| Unsafe File Upload | `path`, `alpha` |
| Insecure Deserialization | `numeric`, `generic` |
| SSRF | `url`, `ip` |
| Open Redirect | `url`, `numeric`, `alpha` |
| Header Injection | `numeric` |
| Code Injection | `generic`, `numeric` |

Contexts are strict: `escapeshellarg` (strong+`shell`) rejects a Command
Injection sink but is not treated as an XSS sanitizer for echo contexts.

## Why not a neural gate?

Because the gate must be auditable. Each stage is a deterministic function
over the candidate evidence; a reviewer can read exactly why a finding is
VALIDATED or REJECTED from `finding.validation`. This is by design: we
optimize for verifiability (see `docs/claims.md`).
