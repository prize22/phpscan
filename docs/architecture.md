# phpscan architecture

## Pipeline

```
files → discovery → parse (tree-sitter-php) → IR → taint engine
      → Validation Gate (8 stages) → findings model → renderers
```

Secondary analyzers feed the same output model:

- **webshell.py**: signal correlation (weighted categories ≥2)
- **secrets.py**: regex/entropy secret detection
- **surface.py**: attack-surface summary from findings + engine view
- **benchmark.py**: eval-corpus precision/recall/F1

## Parsing

- tree-sitter-php full grammar, wrapped by `parser.py`.
- Never regex scans findings; the parser is deterministic: `sha256(src)`
  keys caches; same source → same FileIR/IDs (tested).
- File size, nesting depth, node budgets enforced in `util.py` so giant or
  hostile sources cannot blow the lab (limits do not emit findings).

## IR (`ir.py`)

- `FileIR` = funcs + `global_body` (top-level code as pseudo-func
  `{global}`) + classes + includes + parse_errors.
- `FuncIR` = callable unit (function/method/closure). Closures attach to the
  enclosing function with `anon_id`.
- Statements linearize control flow into blocks with guards; expressions
  carry typed alternatives (var/const/strlit/bin/cast/cond/arr/call/other).
- A single `VarRef` representation: `$base[part][part2]…` where property
  segments are marked, keeping dynamic-key propagation explicit.

## Taint engine (`engine.py`)

- Callable-argument dispatch (constant callables into builtin sinks /
  analyzed functions, dynamic callables) is implemented in
  `callable_dispatch.py`; the engine orchestrates resolution and flow.
- One `FuncFlow` per callable; `Engine.run` applies fixed-point
  interprocedural iteration (up to 8 passes with a summary-signature
  convergence check; halts earlier when summaries stop changing).
- Interprocedural model: probe analysis — every function is analyzed once
  per pass with each parameter seeded as attacker input; the observed
  sink hits and param-return flows become the callee summary; callers
  replay these summaries against their real arguments. Full line-level
  chains are preserved across call boundaries (`callee file:L<line>`).
- Class registry: every declared class is registered; call resolution
  walks `classmap` + `class_parents` (so `self::`, `static::`, `parent::`
  and object calls resolve inherited members). Objects are typed when
  created (`$v = new X(...)`); constructor property wiring seeds taint
  from ctor args into instances through `_seed_new_props`.
- Dynamic dispatch: `call_user_func[_array]`, `ob_start`, `usort`, etc.
  resolve constant callables or `[$class, $method]` / `'C::m'` string
  forms; unresolvable tainted dispatch stays a Code Injection candidate.
  Callable-consuming APIs (`array_map`, `array_filter`, `array_reduce`,
  `array_walk[_recursive]`, `usort`/`uasort`/`uksort`,
  `preg_replace_callback`, `mb_ereg_replace_callback`,
  `register_shutdown_function`, `set_error_handler`,
  `set_exception_handler`, `spl_autoload_register`) forward arguments
  through a per-API map — e.g. `array_reduce` elements reach `$item`,
  not `$carry` — so a constant callable is checked against the parameter
  that actually receives attacker data, and the call site keeps its
  chain step (`[callable dispatch to …]`) as evidence.
- Closure-stored callables resolve: `$f = function($v){ mail($v); };
  $f($_GET[x]);` reuses the closure's parameter summary at invocation.
- Superglobal nuances: `$_FILES['x']['tmp_name'|'error']` is
  server-controlled (not attacker data); `name|type|size` remains
  attacker-controlled.
- Sanitizers modeled with context (`shell`, `html`, `sql`, `numeric`,
  `path`, `url`, …) and strength (`strong`, `medium`, `weak`); when a
  call site matches a known sanitizer's sink key, the sanitizer is
  recorded through the value rather than raw taint.
- Decode chains (`base64_decode`, `gzinflate`, …) preserved as transforms,
  including pure static decoding of constant expressions (never executed).
- Backtick shell expressions, variable functions, openssl_random calls and
  `php://input` source rewards handled as first-class candidates/signals.
- Signals engine (used by webshell correlation and research reporting):
  source, interpolation, dynamic-exec, varfunc, file writes, etc.

## Validation Gate (`validation.py`)

8 deterministic stages, see `docs/validation-gate.md`. All gate decisions
are recorded in the finding's `validation` map. Rejected candidates are
**kept** and exported (`--include-rejected` / research payload `rejected[]`),
including which exact stage rejected and why.

## Findings model (`findings.py`)

- `PHPSCAN-####` + `PHPSCAN-M###` (webshell) IDs; JSON + SARIF 2.1.0.
- Fingerprint (sha1 truncated) = `category|file|line|sink|source` —
  deterministic and stable.
- Rules derive from `rule_id` per category + CWE + OWASP maps.

## Outputs

- terminal (`reporting.terminal_report`) — evidence blocks with gate stage
  results per finding, rejected-stack summary, leads.
- JSON payload — findings, rejected, leads, surface, stats, warnings.
- SARIF 2.1.0 — `runs[0].results`, `ruleId`, logical locations,
  partialFingerprints mapping directly to deterministic findings.
- Markdown research report (via `research.md`) — direct usage of episodes
  for internal review or tracing.

## Caching / incremental

- Pickled `FileIR` under `target/.phpscan-cache` keyed by
  `sha256(src)` and the cache schema version (v3 in 0.2.0); node
  references stripped via `util.strip_ir` before pickling.
- `--incremental` enables it; content hash validates freshness.
- Pickle loading is hardened: only phpscan's own classes load
  (`_SafeUnpickler`), anything else is refused. Source text is
  re-attached on cache hits so gate source verification still works.
- Suppression: `baseline` writes `.phpscan-baseline.json` (stable
  fingerprints + reasons); scan applies it, `--new-only` filters.

Static analysis performs no network activity. The optional `live` command
contacts only operator-scoped HTTP(S) targets; see `docs/live-analysis.md`.
