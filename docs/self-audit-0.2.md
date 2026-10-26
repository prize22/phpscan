# phpscan v0.2.0 — Self-Audit Report

Scope: adversarial audit of the phpscan engine itself during the 0.2.0
hardening phase. This report documents what was attacked, what was
found, what was fixed, and what is still open. Everything is verified
against the actual tree (`tests/`, `eval/`, probes under
`%TEMP%\opencode`), not from memory.

## 1. Engine attack summary

### Fixed in this phase (with verification)

1. **Augmented assignments dropped (`parser._assign_operands`).**
   `$cmd .= $_COOKIE['p'.$i]` was silently parsed as nothing at all:
   the operand splitter looked only for a bare `=` child, and
   augmented-assignment nodes carry `.=`/`+=`/… as a single child, so
   every augassign statement vanished from the IR. Fixed by matching any
   compound assignment operator. Verified: new test
   `test_augassign_accumulates_taint_in_loop`; taint accumulation inside
   `for` bodies now produces Command Injection candidates.
2. **`relative_scope` unwrapping (`parser._call`).** tree-sitter-php
   wraps `self`/`parent` receivers in a `relative_scope` node, which
   previously broke all `self::`/`parent::` method resolution.
   Verified by `test_class_static_parent_resolution` and the benchmark
   class-chain fixture.
3. **Class-name case normalization.** `_static_scope_class` returned
   raw-case names (`ApiX`) while `classmap` keys are lowercase, so
   `ApiX::route(...)` and `$ctl->exec(...)` failed to resolve. Fixed
   with `.lower()` at registration/lookup edges.
4. **Inheritance resolution.** A method used through a subclass
   (`self::query` where `query` is defined in the parent) did not
   resolve at all — the paren-covering generic method-args match made
   it *appear* to work before. `_resolve_class_method` now walks the
   parent chain. Verified via `test_class_static_parent_resolution`
   (two distinct sources, two findings).
5. **Dedup key lost sources.** Flow-level candidate keys did not
   include the taint origin, so two entry points flowing into one callee
   sink deduped to one finding before fingerprints. Candidate keys now
   include a bounded origin segment. Verified: two sources → two
   findings.
6. **Fixed-point completion.** Interprocedural summaries commit one hop
   per pass; `MAX_PASSES` was 3 (too few for wrapper chains) with no
   convergence check. `run()` now iterates up to 8 passes and stops on a
   summary-signature fixed point. Verified:
   `test_gate_dedup_wrapper_chain` (3-deep chain b→a→fw→system).
7. **ctor-prop and member-call double counting.** A resolved user
   method no longer *also* receives the generic name-based sink match
   (`PDO::exec` matching `$_invoker->exec()`). Verified:
   `test_user_class_exec_no_pdo_fp`, no SQL Injection FP.
8. **Closure-stored callables.** `$f = function($v){ inner($v); };
   $f($_GET['x'])` resolved through the invocation
   (closure index built by file+line). Verified:
   `test_closure_call_resolves`.
9. **carryover fixes kept from mid-phase:** `_rejected` 4-arg misuse,
   `fwrite/fputs` sink removal, k-arg dest sinks
   (`move_uploaded_file`/`copy`/`rename`/`link`/`symlink`), `$_FILES`
   key semantics (`tmp_name`/`error` benign), `__DIR__`-style constants
   handled as const strings, `ERR_UPLOAD_OK` etc.

### Adversarial corpus additions

- `eval/vulnerable/adv_wrapper.php` (stream-filter wrapper receiver),
  `adv_nested_transforms.php`, `adv_alias.php`, `adv_loop_accum.php`,
  `adv_class_chain.php` (self/parent/object dispatch), `adv_upload.php`,
  `adv_ctor_prop.php`, `adv_closure.php` — all found, benchmark
  `tp=19 fp=0 fn=0 F1=1.000`.
- `eval/clean/` additions for semantics that must not fire:
  `realpath_clean.php` (downgrade expected), `tmp_name_clean.php`,
  `prep_execute_clean.php`, `dir_include_clean.php`,
  `const_webshell_decode.php` — no validated findings.

## 2. Cache & pickling hardening

- Cache filenames now carry `SCHEMA_VERSION=3`; an old-schema cache file
  is ignored (verified: `test_old_schema_cache_ignored`).
- Pickling loads through `_SafeUnpickler` which refuses
  non-phpscan classes (verified: `test_hostile_pickle_refused`).
- Cache-hit incremental results keep source text attached so the gate's
  stage-3 source verification works (verified:
  `test_cache_invalidation_on_modify`, dedup tests, two-pass determinism
  through strip→pickle→repickle: `test_two_pass_determinism_with_cache_load`).

## 3. Baseline / suppression workflow

Verified end-to-end via CLI on a scratch project: baseline written from
current findings; rescan suppresses those (SUPPRESSED status, counter
exposed); `--new-only` returns nothing; adding a new vulnerable file
raises exactly the new finding. Baseline is line-free via stable
fingerprints, so non-hand-edits don't churn it.

## 4. Performance (measured, honest numbers)

- Eval corpus scan (19 PHP files): ~540 ms wall total, including
  Python interpreter startup.
- Synthesized big file (300 functions + 300 calls, ~1300 lines):
  parse 54 ms, engine 53 ms, gate 10 ms, 300 findings, no blowup.
The per-file incremental cache avoids re-parsing unchanged files.

## 5. What is still open (honest)

- **Corpora:** deterministic benchmark is a single parser/corpus
  setup (typical vuln-dev data, hand-written fixtures). No real-world
  corpus yet — e.g. DVWA, Snowden shell, linshao/cybersecurity webshell
  shards (Wikidata/VCDB mapping pending). Numbers here are
  internal-benchmark numbers; they are not transferable claims to real
  repos.
- **Recall limits:** dynamic features outside this phase's scope
  (variable reuse across many assignments, complex trait use, dynamic
  property names outside `$_FILES`, `$$var`, string-distilled callables
  other than the resolvable forms) still produce conservative results.
- **Method-args heuristics:** name-based member sink matching can still
  over-fire on unknown receivers (objects whose type we cannot infer);
  typed user-class receivers now suppress this, but inspection data
  (poorly typed `$this->db` etc.) keeps name-matching.
- **Include model:** includes resolve within one invocation in one
  pass; cross-file include state threading remains a future item.
- **Property tests:** one determinism property test; broader
  property-based generator (per-expression) not implemented.

## 6. Verification matrix

- `pytest` — 43 tests, all passing at time of writing.
- `ruff check phpscan tests` + `ruff format` — clean.
- `phpscan benchmark eval` — tp=19 fp=0 fn=0 F1=1.000.
- Probes c1–c4 (class/dedup, ctor-prop, dyn-dispatch, upload flows)
  under `%TEMP%\opencode\`.
