# Changelog

## 0.4.0 — evidence fusion & live security research engine

- Evidence model (`phpscan/evidence.py`): deterministic, id-stable
  observation records (`phpscan-evidence/1`) with origin
  (static/live/host/history), category, confidence, explicit
  uncertainty, and automatic redaction of sensitive values (sha256
  fingerprint + hint; plaintext never reaches a report).
- Live passive observation (`phpscan live`, `phpscan/live.py`):
  scope-fenced (host allow-list, scheme allow-list, hard request byte
  budgets, per-hop redirect checks), read-only GET observation of
  headers, `X-Powered-By`, security headers, cookies, robots.txt,
  redirect chains (out-of-scope hop → `SCOPE_REFUSAL`), framework
  fingerprints, error pages, and redacted credential artifacts.
- Safe probing (`phpscan live --profile safe`, `phpscan/probing.py,
  explicit opt-in): fixed benign route touches, lexical request
  differential, response anomaly classification. No payloads by design.
- Host investigation (`phpscan investigate`, `phpscan/host.py`,
  read-only): dropped/sneaky/hidden/double-extended PHP, disguised PHP
  in non-PHP files (binary-safe sniffing), backup artifacts, config/log
  positions with secret scanning, recency proxy, persistence-candidate
  existence checks, opt-in process enumeration (wmic / /proc).
- Patch timeline (`phpscan timeline`, `phpscan/timeline.py`): composer
  component collection operator-submitted patch declarations (schema
  `phpscan-patch-timeline/1`) into EXPOSURE_CONFIRMED / _POSSIBLE /
  _NONE / INSUFFICIENT_DATA grades. No bundled vulnerability database.
- Fusion (`phpscan correlate`, `phpscan/fusion.py`): links evidence to
  findings with explicit reasons and a support ladder
  (EXPOSED / OBSERVED / none), queues unexplained evidence as research
  leads. Attaches fusion output as Proof Engine `corroboration`
  (`phpscan/proof.py` extension) — gate verdicts are unchanged.
- Static-side hardening: inline suppression
  (`// phpscan-ignore [RULE] reason`, reason mandatory), baseline
  suppressions with optional `expires` dates, per-(file,rule) flood
  control (`--max-per-file`), binary PHP skip (NUL-byte header check),
  `--fail-on validated|critical` exit codes, catch-all CLI exit 2 +
  `--debug` traceback.
- Export payload gains optional `evidence` / `timeline` / `fusion`
  sections; uncertainty map accepts extra non-static items via
  `uncertainty.collect(..., extra=...)`.
- Four new CLI subcommands (live / investigate / timeline / correlate);
  all eleven previous subcommands unchanged. Eval benchmark unchanged:
  tp=20 fp=0 fn=0, F1=1.000.
- Tests: 83 pytest tests (60 previous + 23 new), ruff clean.
- Docs: `docs/live-analysis.md`, `docs/safe-probing.md`,
  `docs/host-investigation.md`, `docs/evidence-fusion.md`.

## 0.3.0 — evidence-driven security research instrument

- Proof Engine: every accepted finding now carries a `proof` record with an
  explicit evidence checklist (phpscan/proof.py). Each Validation Gate stage
  is restated as a falsifiable question ("Is the sink location real code in
  this file?", "Does a concrete data path lead from attacker-controlled input
  to this argument?", …), answered from facts the analysis actually
  established, with refutation flagged where a stage failed. Verdicts:
  verified / probable / incomplete / disproven.
- Uncertainty map: parse errors, truncated files, engine warnings, partial
  and skipped gate stages are collected into structured uncertainty codes
  (UNCERTAIN_PARSE_ERRORS, UNCERTAIN_FILE_TRUNCATED, UNCERTAIN_ANALYSIS_ERROR,
  UNCERTAIN_*_PARTIAL/SKIPPED, UNCERTAIN_OPEN_QUESTION) attached to the scan
  payload as `uncertainty` and summarized in the terminal report
  (phpscan/uncertainty.py).
- Behavior reconstruction (`phpscan map`): per-function source → transform
  → sink map built strictly from engine flows, text or JSON output
  (phpscan/behavior.py).
- Variant Hunter / Security Genome (`phpscan variants`): findings grouped
  by genome fingerprint (category, source class, sink, call kind,
  transforms) into confirmed / untested / refuted variant clusters
  (phpscan/variants.py).
- Differential analysis (`phpscan diff`): fixed / new / unchanged findings
  between two scans, compared by line-free stable fingerprints
  (phpscan/diff.py).
- RAE research queue: findings whose proof is not verified (plus all
  webshell leads) are queued with their open questions and next actions,
  emitted as `rae` in the payload and in the terminal report.
- Eval corpus expanded: `eval/patched/` (fixed variants of cmdi, sqli,
  path, xss) and `eval/framework/` (multi-file interprocedural controller);
  benchmark now scans those dirs and emits `timing_ms`. Corpus result
  tp=20 fp=0 fn=0 (P=R=F1=1.000).
- Tests: 60 pytest tests, ruff clean.

## 0.2.0 — hardening phase

- Class registry: `self::`/`static::`/`parent::` + inheritance-aware
  method resolution (parent-walking `_resolve_class_method`), object type
  inference from `new Class()`, constructor property wiring (taint seeds
  from ctor args into instance properties).
- Dynamic dispatch: `call_user_func[_array]`/`ob_start`/etc. resolve
  constant and derived callables (incl. `[$class, $method]` string forms
  and `'class::method'` strings); unresolved tainted dispatch emits a Code
  Injection candidate.
- Closure-stored callables: `$f = function (...) {...}; $f($_GET[...])`
  resolves to the closure body and replays its parameter summary.
- Superglobal semantics split for `$_FILES`: `tmp_name`/`error` are
  benign, `name`/`type`/`size` stay attacker-controlled.
- Sink-vs-sanitizer: known sanitizer sinks (`preg_replace` etc.) carry
  the sanitizer through instead of raw taint.
- Parser/IR: augmented assignments (`.=`, `+=`, …) previously dropped are
  now parsed; `relative_scope` (`self`/`parent`) unwrapping during method
  calls; parse budget + `RecursionError` guards; `ERROR` nodes recorded.
- Engine: fixed-point interprocedural convergence (up to 8 passes with a
  summary-signature check; replaces the fixed 3 passes); k-arg dest
  sinks added (`move_uploaded_file`, `copy`, `rename`, `link`,
  `symlink`); strict provenance tie-in; dead code removed.
- Validation Gate: stable (line-free) fingerprints; suppression +
  baseline workflow (`scan --baseline/--new-only`, `baseline` subcommand
  writing `.phpscan-baseline.json`); stage-3 source-text verification of
  sink expression presence (`--no-baseline` unaffected); rejected
  records carry stable fingerprints; `SUPPRESSED` status.
- Cache: schema-versioned cache filename; hardened pickling that rejects
  non-phpscan classes; cache hits re-attach source text for incremental
  gate verification.
- Adversarial eval corpus (+8 vulnerable / +5 clean fixtures) — wrapper
  receivers, nested transforms, superglobals through aliases, loop
  accumulation, class chains, closures, uploads, ctor wiring.
- Tests: 43 pytest tests incl. determinism (strip → pickle → repickle
  identity), hostile-pickle refusal, old-schema cache ignore, case
  normalization, and all adversarial fixtures above.

## 0.1.0 — first internal release

- tree-sitter-php based deterministic parser + IR (functions, methods,
  closures, global code, includes).
- Taint engine with 3-pass fixed point, probe-based interprocedural
  summaries (sink hits + param-return flows), sanitizer contexts and
  strengths, decode-transform chains, backticks/varfunc/`php://input`,
  echo/header/curl special-cases, Information Disclosure candidates.
- 8-stage deterministic Validation Gate with retained REJECTED records.
- Findings model: PHPSCAN ids, fingerprints, CWE/OWASP maps, JSON + SARIF
  2.1.0 renderers; research/finding explain views.
- Webshell/backdoor correlation (weighted, >=2 signal categories) +
  secrets scanner (entropy + context) + attack-surface summary.
- CLI: scan/research/validate/explain/rules/report/benchmark.
- YAML rule extension format, validated at load time (`rules validate`).
- Incremental parse cache (sha256-keyed, pickled FileIR with AST nodes
  stripped).
- Eval corpus (vulnerable/clean/webshell) + benchmark metrics command.
- Test suite (parser, taint, gate, webshell, secrets, cache, SARIF,
  determinism; 20 cases green at release).
