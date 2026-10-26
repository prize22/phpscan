# phpscan vs. other PHP security tools — differentiations (honest)

## What actually makes phpscan different

1. **Evidence-driven Validation Gate with retained rejections.**
   Most analyzers (including popular ones) suppress or emit heuristics.
   phpscan retains every rejected candidate with the exact stage and
   reason. This audits into false-positive/full-false-negative views,
   putting the reviewer in charge. Rare among static tools.

2. **Stage-scoped sanitizer modeling with context AND strength.**
   `escapeshellarg` does not cover SQL sinks; `htmlspecialchars` does not
   cover shell sinks. When the context matches and the sanitizer is
   `strong` → finding is rejected. `medium`/`weak` sanitizers → marked
   honestly as PARTIALLY_VALIDATED (not silent suppression).

3. **Honest status tiers.**
   `VALIDATED / PARTIALLY_VALIDATED / UNCONFIRMED / RESEARCH_LEAD` plus
   retained REJECTED records. This lets researchers sort findings by
   real verification. Most tools have just a confidence number with no
   provenance sections.

4. **Interprocedural model via probe analysis.**
   Each callable is probed (each parameter treated as tainted) to produce
   caller-independent callee summaries replayed by callers with their own
   argument taints. Full source lines preserved across the call boundary.
   Practical, transparent, no heavy points-to analysis required for the
   benchmark categories.

5. **Webshell correlation as a distinct detector class.**
   Unlike simple signature matching, phpscan webshells are scored via
   ≥2 weighted independent signal categories (source + obfuscation +
   dynamic execution + write). Status is a lead — never presented as a
   vulnerability finding without manual review.

6. **No network at all.** Local-first; deterministic; no CRS/CDN.

## What phpscan does NOT claim better than others

- Full IR/points-to analysis depth of commercial tools (e.g. solid global
  flow summaries across framework MVC edge cases, model layer taint hops).
- Type-juggling precision in PHP 8 typed contexts (e.g. typed properties
  narrowing) — phpscan's IR is flow-based, not type-inferencing.
- Language coverage for frameworks: Autoload/`spl_autoload_register` ->
  framework DI container receivers still resolve to member-analysis sink
  paths only.
- SBOM graders (you would use `cloc`/`composer` tooling, not phpscan).

These are intentional scope decisions for a**local-first research-grade
positioning**, not hidden bugs. See `limitations.md`.
