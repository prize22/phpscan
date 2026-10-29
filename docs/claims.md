# Claims — what phpscan actually proves

Honest claims, each tied to how they are tested. This file is the promise
surface: if a claim breaks, it is a bug in phpscan.

## Verified by tests present in this repo (`pytest` + benchmark)

1. **Parsing is deterministic.** Same source → same `FileIR` content hash;
   finding IDs and fingerprints are stable across runs (unit tests).
2. **No regex finding shortcuts.** Sinks/sources/sanitizers are keyed in
   registry structures and matched on the parsed IR, not by scanning source
   text for findings (architecture invariant; parsing tests).
3. **The target code is never executed.** phpscan parses with tree-sitter,
   never calls the PHP host. No network calls. The only "decode" of constant
   expressions happens in Python for static strings (`base64_decode('...')`
   as pure const math), never against running code (by construction; no test
   can prove a negative — audits welcome).
4. **Taint with interprocedural replay.** Source → sink flows through
   function parameters are found (dedicated test).
5. **Sanitizer honored when context matches.** `escapeshellarg` before a
   Command sink is rejected by the gate (test).
6. **Dead constant branches are rejected** (control-flow stage, tested).
7. **Webshell correlation requires ≥2 independent signal categories** and
   is reported as a RESEARCH_LEAD, not silently a vulnerability (tested).
8. **Secrets scanner is reduce-noise-first**: `password` fields with
   dummy/obvious values do not trigger (tested).
9. **Benchmark reproducibility.** `phpscan benchmark eval` measures against
   the corpus shipped in `eval/` (vulnerable, clean, webshell). Full status
   of the current run is printed by the command; the README does not hardcode
   numbers.
10. **Class/inheritance dispatch resolves.** `self::`, `parent::` and
    object calls on inferred instance types resolve inherited methods
    (tested, incl. mixed static/instance entry points).
11. **Constructor property wiring.** `$obj = new C($_GET[p]); $obj->m()`
    finds the sink when the ctor wires the arg into a property (tested).
12. **Suppression is deterministic.** The same finding keeps the same
    stable fingerprint across runs (dedup tests); baseline-accepted
    fingerprints resurface as SUPPRESSED, never as a different ID
    (tested, line-free fingerprints).
13. **Cache hardening.** Old-schema caches are ignored (tested) and
    pickled data of foreign classes is refused (tested).
14. **Callable dispatch is analyzed, not skipped.** A constant callable
    handed to `array_map`/`array_filter`/`usort`/
    `register_shutdown_function`/… reaches builtin sinks and callee
    summaries through that API's own argument→parameter map; an
    attacker-controlled callable becomes a Code Injection candidate;
    benign callables and APIs that forward no caller argument stay silent
    (positive, negative, sanitized, interprocedural and determinism tests,
    plus `eval/` corpus entries).

## What phpscan ALSO honestly claims (limits)

- Interprocedural analysis is **bounded fixed-point** (up to 8 passes
  with a convergence check) — summaries commit one hop per pass;
  wrapper chains converge, but dynamically-bound callables outside
  resolvable forms are approximated via named-function and class
  registries; methods called through unknown objects (i.e. `$pdo2`
  above `$this`) fall to the member-sink path with no class-sensitive
  flow beyond that.
- Global `$_SERVER[REQUEST_URI]` style uses are *sources only when assigned
  to a well-known level*; phpscan may downgrade to INDIRECT on some paths.
- The webshell detector is **correlation-based** and may generate lead noise
  on hot files with legit dynamic calls; it is intentionally not VALIDATED
  because the evidence is not a vulnerability claim.
- Secrets scanner has no bloom filter; it is anchored to lines, so output
  can contain noise on big keys packed tightly.
- Deep reflection and `$$var` metaprogramming structurally lower flows to
  INDIRECT rather than TAINTED unless proven by dynamic-call trace evidence.

See `limitations.md` for the full maintain-list view.

## On benchmark numbers

The default eval corpus is **synthetic and small** (40 files under
`eval/`: vulnerable, clean patterns, webshell, the 0.2.0 adversarial
set, plus the 0.3.0 `patched/` fixed variants and `framework/`
multi-file fixtures). It
exists to verify the harness and give a fast regression loop.
Precision/recall numbers printed there are **not** to be read as
performance on real codebases — the point of the tool is
defense-in-depth via the Validation Gate with per-stage notes; the
corpus will grow.
