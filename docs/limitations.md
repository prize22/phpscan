# phpscan limitations — maintained list

Every entry here is a *known* limit. Items are grouped by confidence and
verification status. Items with `[verified]` have tests demonstrating them.

## Analysis depth limits

-[verified] Interprocedural propagation is fixed-point up to 8 passes
 (with a summary-signature convergence check); callee summaries cover
 sinks reached through directly-called functions/methods, closures, and
 closure-stored callables — not `$$var`-style indirections beyond
 resolvable forms.

-[verified] Class dispatch: `self::`/`static::`/`parent::`/object calls
 resolve through analyzed classes with inheritance. Receivers whose
 type is unknowable (dynamic assignment, polling props) fall back to
 name-based member sink matching, which can over- or under-fire.

-[verified] `new PDO()` receivers get no class body, so prepared
 statements (`prepare(...)`) with bound args (`execute([...])`) are not
 SQL Injection sources; the tainted `execute` arguments alone are not
 injected. Untyped DB wrapper members still match by method name and
 may produce false SQL Injection on custom wrappers.

-[verified] Closure-stored callables resolve concretely
 (`$f = function($v){...}; $f($_GET[x]);`), and constant callables handed
 to callable-consuming APIs dispatch into the callee's parameter summary
 (`array_map('helper', $tainted)` where `helper` reaches a sink). Still
 open: an *inline* closure used directly as that argument
 (`array_map(function($v){ system($v); }, $tainted)`) gets no parameter
 seeding, so the inner sink is not attributed to the call site; array-form
 callables (`[$obj, 'method']`) and multi-callable APIs (`array_udiff*`,
 `array_uintersect*`) are not modeled.

-[not fully solved] PHP reflection, `$$` variable variables, and
 `call_user_func` with attacker arrays lower confidence (INDIRECT)
 rather than being precise. Resolvable constant-string dispatches
 (`call_user_func('mysqli_real_escape_string', ...)`) are handled.

- Autoloader-based construction of objects (framework plugin routing) is
  out of flow: we do not follow `__construct` parameter walkthrough chains
  across files (yet).

## Sanitizer modeling

- `filter_var` is context-aware only when the validator appears as a
  function call; complex expressions (e.g. `filter_var($_GET[x] !== false)`
  composites) produce `INDIRECT`, not a silently `strong` sanitizer.
- `addslashes` is modeled as weak by DESIGN — bypasses exist (documented
  in maturity guides); never silently rejected.

## Webshell detection

- Correlation-based (2+ categories) — leads, not vulnerability claims.
- Sophisticated single-category webshells (e.g. data swapped through
  custom decode functions only once, heavily nested) can score below
  thresholds and be missed.

## Secrets

- Line-anchored regex + entropy; no global detectors: a long embedded
  Base64 blob not tied to any keyword wouldn't trigger.
- Only high-signal sources are listed (hardcoded keys, tokens, JWTs,
  private keys).

## Live / host / timeline / evidence-fusion layers (0.4)

- **Redaction is category-based, not content-based.** Evidence values are
  auto-redacted only when the record's category is one of the documented
  sensitive set (CREDENTIAL_ARTIFACT, KEY_MATERIAL, SESSION_MATERIAL,
  CONFIG_SECRET, ENVIRONMENT_SECRET). A secret-shaped string that
  happens to sit in another category (e.g. inside a generic HTTP body
  observation field) is only length-clipped, not redacted. Reviewers
  should treat any live-collected body text as potentially sensitive.
- live/probing observe only what a browser-like GET would see; no
  authenticated-source replay, no cookies sent, no session reuse.
- `CONCURRENCY`: single-threaded by design; no parallel request/worker
  pools exist, so unbounded concurrency is not possible (neither is
  speed on huge scopes).
- correlate matches evidence to findings by file basename/suffix,
  vendor path prefix, and route names; generic names (index.php,
  common config.php usages) can under- or over-link. Every link keeps
  its evidence ids so it can be manually undone.
- Exposure grading is driven entirely by the operator's patch
  declaration; without a declaration nothing is graded, and with a
  wrong declaration grades are wrong. phpscan has no bundled CVE/
  vulnerability database and cannot know real vendor patch dates.
- Evidence records are append-only observations: if a target changes
  between collection and correlation, older records stay valid in the
  store and may describe a state that no longer exists. Records carry
  their collection timestamp; nothing silently expires them.
- `investigate` does not follow remote logs or analyze arbitrary
  persistence mechanisms; the persistence checks are existence probes
  on known paths only.

## Performance

- No parallelism (single thread); tree-sitter is fast; 8MB file cap with
  AST-node budget guards pathological sources.

## Output interface

- No HTML UI; CLI/json/sarif/markdown only.

---
Found an entry you can falsify? Replace it with a failing test in
`tests/` and open the PR — that is the preferred way to shrink this list.
