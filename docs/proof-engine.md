# Proof Engine & research tooling (phpscan 0.3.0)

phpscan's core identity is the distinction between **found something** (the
engine emitted a candidate), **proved something** (the Validation Gate
passed), and **don't know yet** (uncertainty remains).  The 0.3.0 tooling
makes that distinction explicit and machine-readable.

## Proof Engine (`phpscan/proof.py`)

Every finding accepted by the Validation Gate now carries a `proof`
record.  It restates each of the 8 gate stages as a falsifiable question:

| stage | question |
|-------|----------|
| structural | Is the reported location real, parseable code in this file? |
| semantic | Is this call a security-relevant sink in this argument position? |
| data-flow | Does a concrete data path lead from attacker-controlled input to this argument? |
| control-flow | Is the sink reachable on at least one execution path? |
| sanitizer | Could sanitization on the path neutralize the value in this context? |
| context | Does the value reach the dangerous argument of this call? |
| contradiction | Do any recorded facts contradict the vulnerability? |
| re-analysis | Does an independent stricter re-analysis agree? |

Each question is answered from facts the analysis actually established
(source origin, taint level, guard conditions, sanitizer context/strength,
chain length, sink-text-in-source, strict-agreement).  Where a stage
failed the claim is marked refuted.  The proof layer recomputes nothing —
it only restates gate results in falsifiable form, so it cannot disagree
with the gate it explains.

Verdict: `verified` (all stages PASS), `probable` (some PARTIAL), `incomplete`
(stage SKIPped), `disproven` (a stage FAILed — rejected candidates only).

The `proof` record also lists `open_questions` — the PARTIAL/SKIP stages
— which feed the RAE research queue.

## Uncertainty map (`phpscan/uncertainty.py`)

Parse errors, truncated files, engine warnings (analysis errors, recursion
limits), partial and skipped gate stages, and open proof questions are
collected into structured uncertainty codes:

- `UNCERTAIN_PARSE_ERRORS`, `UNCERTAIN_FILE_TRUNCATED`
- `UNCERTAIN_ANALYSIS_ERROR`, `UNCERTAIN_RECURSION_LIMIT`
- `UNCERTAIN_<STAGE>_PARTIAL`, `UNCERTAIN_<STAGE>_SKIPPED`
- `UNCERTAIN_OPEN_QUESTION`

Emitted in the scan payload as `uncertainty` (items, per-code counts,
per-file grouping) and summarized in the terminal report.  Nothing here is
invented — each item traces to an engine warning, file-meta record, or gate
stage result.

## Behavior reconstruction — `phpscan map` (`phpscan/behavior.py`)

Reconstructs, for every analyzed function, strictly from engine flows:

- entry sources (superglobals, file contents, etc. read by the function)
- transforms applied along the way (base64_decode, urlencode, …)
- sinks reached with tainted arguments (category, sink, call kind,
  expression, transforms, sanitizer state)
- parameters returned tainted, closure-bound variables, call sites

Output modes: human-readable text trace (default) or `--json`.  Read-only
and deterministic — nothing is guessed, nothing is validated here.

## Variant Hunter / Security Genome — `phpscan variants` (`phpscan/variants.py`)

A *genome* fingerprints a vulnerability pattern: category, source class,
sink, call kind, sanitizer context, transforms on the chain.  Findings
sharing one genome are the same bug shape at different sites.  Each site
is classified:

- `confirmed` — at least one validated instance
- `untested` — instances exist but none validated
- `refuted` — only rejected candidates

Rejected candidates are kept as `candidates` with their rejection reason,
so researchers can see how many sites share a pattern and which survived
the proof.

## Differential analysis — `phpscan diff` (`phpscan/diff.py`)

Compares two scans by line-free stable fingerprint (category, file,
function, sink, source — line numbers excluded so forward edits don't
invalidate the comparison).  Classifies findings as `fixed` (in baseline,
gone now), `new` (absent before, present now), `unchanged` (in both, with
status/confidence drift noted).  Inputs: two directory targets, or a
previous JSON output as the baseline.

## RAE research queue (`rae` in the payload)

Findings whose proof is not `verified`, plus all webshell/backdoor leads
(manual-review posture), are queued with their open questions and a next
action (`strengthen evidence for <stage>` or `review manually`).  Nothing
is invented: questions come straight from gate stage results.

## Determinism & honesty rules

- No feature changes what is reported: proof, uncertainty, genomes, diffs,
  and the queue are pure regroupings/restatements of gate output.
- Results are never manufactured: the benchmark gate (P/R/F1 on the eval
  corpus) must still hold after any change.
- Every capability has tests; nothing ships without at least one test.
