# phpscan

A deterministic, local-first, CLI-first **PHP Security Research Engine**: static
analysis grounded in real data-flow (taint) evidence, a multi-stage
**Validation Gate** between detection and reporting, attack-surface mapping,
webshell/backdoor correlation, and honest, auditable output.

- **Local-first**: runs entirely on your machine; targets are never uploaded.
- **Never executes target PHP.** phpscan never evals, includes, or lints your
  application code. It parses it with tree-sitter (Python host, not regex
  scanning for findings) and analyzes the abstract representation.
- **Deterministic**: the same input produces the same output byte-for-byte
  (fingerprinted findings, stable IDs).
- **Honest**: every accepted finding carries its full evidence chain and all
  8 validation stage results. Rejected candidates are retained for debug/audit.

## Install

```bash
python -m pip install -e .
```

Requirements: Python 3.9+; deps: `tree-sitter`, `tree-sitter-php`, `PyYAML`.

## Docker

Build a self-contained runtime image (no local Python install required):

```bash
docker build -t phpscan:local .
```

Version smoke test:

```bash
docker run --rm phpscan:local --version
```

### Scanning a host directory

The container's working directory is `/work`. Mount the tree you want to
review there and pass the **in-container** path — that path is what phpscan
sees, and it is the only filesystem it can reach:

```bash
docker run --rm -v "$PWD:/work" phpscan:local scan /work/src
```

Write reports through the same mount so they land back on the host
(`--out`, `--sarif-out`, `--out-dir` are resolved inside the container):

```bash
docker run --rm -v "$PWD:/work" phpscan:local scan /work/src --json --out /work/out.json
docker run --rm -v "$PWD:/work" phpscan:local scan /work/src --sarif-out /work/out.sarif
docker run --rm -v "$PWD:/work" phpscan:local research /work/src --out-dir /work/phpscan-report
```

`./out.json`, `./out.sarif` and `./phpscan-report/` then appear in the
current host directory. Mount the source read-only if you do not want the
scanned tree modified by anything else on the host:

```bash
docker run --rm -v "$PWD/src:/work/src:ro" phpscan:local scan /work/src
```

### Users and permissions

The image runs as a non-root user (`phpscan`, fixed UID/GID `10001`) rather
than as root. Reading typical host source trees works unmodified; files the
container writes into the mount are owned by `10001`, which may not match
your host user. Run with your own UID/GID to make outputs yours:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" phpscan:local scan /work/src --json --out /work/out.json
```

### Notes

- **The image ships no PHP interpreter**, and phpscan never executes target
  PHP — in a container or anywhere else. It parses source with tree-sitter
  and analyzes the abstract representation.
- The image installs runtime dependencies only; development extras
  (`pytest`, `pytest-cov`, `ruff`, `pip-audit`) are not present.
- Container-scoped commands such as `investigate` observe the container
  itself (its processes and filesystem), not the host — mount what you need
  to inspect. `live` still needs outbound network access to the target URL.

## Quick start

```bash
phpscan scan path/to/src                 # terminal report
phpscan scan path/to/src --json --out out.json
phpscan scan path/to/src --sarif-out out.sarif
phpscan research path/to/src --out-dir report-dir   # scan + markdown/SARIF
phpscan explain out.json PHPSCAN-0001    # one finding, full reasoning
phpscan map path/to/src                  # source → transform → sink per function
phpscan variants path/to/src             # security-genome variant clusters
phpscan diff out.json path/to/src         # fixed / new / unchanged between two scans
phpscan benchmark eval                   # run the corpus, print P/R/F1
phpscan rules list                       # show registries
```

Recommended workflow:

```bash
phpscan research . --out-dir phpscan-report
```

produces:

- `phpscan.json` — machine-readable payload (findings, rejected stack, leads,
  surface map, warnings)
- `research.md` — narrative research report
- `phpscan.sarif` — SARIF 2.1.0 for CI/IDE integration

## What it detects (categories)

SQL Injection, Cross-Site Scripting, Command Injection, Code Injection
(eval/assert), File Inclusion, Path Traversal, Arbitrary File Write, Unsafe
File Upload, SSRF, Insecure Deserialization, Open Redirect, Header Injection,
Information Disclosure (phpinfo), Webshell/Backdoor correlation, Hardcoded
Secrets, Dangerous Function (research leads).

## CLI

| command    | purpose                                        |
|------------|------------------------------------------------|
| scan       | full pipeline, JSON/SARIF/terminal output      |
| research   | scan + research artifacts (json/sarif/md)      |
| validate   | re-render validation stage table               |
| explain    | explain one finding (source → sink → gate)     |
| rules      | list/validate YAML rule overrides              |
| report     | re-render a previous JSON payload              |
| baseline   | write a suppression baseline (`.phpscan-baseline.json`) |
| benchmark  | run the eval corpus and print P/R/F1           |
| map        | reconstruct source → transform → sink per function |
| variants   | group findings into security-genome clusters |
| diff       | fixed / new / unchanged between two scans |
| live       | passive live observation of a URL (scope-fenced; `--profile safe` adds benign probing) |
| investigate| read-only host investigation of a tree (dropped/disguised PHP, backups, configs, logs, `--processes` opt-in) |
| timeline   | component exposure grading from composer files + an operator patch declaration |
| correlate  | fuse a scan payload with an evidence store (live/host/history) |

### Diagnostic logging

Internal diagnostics (probe/connection failures, unreadable files,
recoverable internal errors) go to **stderr** through a standard-library
logger and never into report output. The default level is `WARNING`, so
everyday runs stay quiet; raise it to see what the engine is doing:

```bash
phpscan --log-level DEBUG scan path/to/src
```

Levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. The option is
accepted before or after the subcommand. Findings, terminal reports, JSON
and SARIF output are unaffected by logging.

## Baseline / triage workflow (NEW in 0.2.0)

Findings are fingerprinted line-free (category + file + function + sink +
source), so suppressions survive code movement but not semantic edits:

```bash
phpscan baseline path/to/src                # adjudicates today's findings
phpscan scan path/to/src                    # rescan: those become SUPPRESSED
phpscan scan path/to/src --new-only         # show only new candidates
```

The baseline is `<target>/.phpscan-baseline.json` and is human-editable —
each entry carries a `reason` string you should fill in.

## v0.3.0 — evidence-driven research instrument

phpscan now separates "found something" from "proved something":

- **Proof Engine** — every finding ships a machine-readable proof record
  (`proof` in the JSON payload, shown by `explain`): each Validation Gate
  stage restated as a falsifiable question with the answer the analysis
  actually established. Verdicts: verified / probable / incomplete /
  disproven.
- **Uncertainty map** — parse errors, truncated files, engine warnings and
  partial/skipped gate stages become structured uncertainty codes in the
  payload (`uncertainty`), summarized in the terminal report.
- **`map`** — per-function source → transform → sink reconstruction,
  text or JSON.
- **`variants`** — Security Genome clustering: findings grouped by genome
  fingerprint into confirmed / untested / refuted variant clusters.
- **`diff`** — fixed / new / unchanged findings between two scans, compared
  by line-free stable fingerprints.
- **RAE research queue** — not-yet-verified findings (and all webshell
  leads) queued with open questions and next actions (`rae` in the payload).

See `docs/proof-engine.md`.

## v0.4.0 — evidence fusion & live research engine

Authorization note: `live`, `investigate`, `timeline`, and `correlate`
run under **operator responsibility and local scope enforcement only**.
Do not point phpscan at systems you are not permitted to test. Every
request targets stay within the declared host allow-list, request and
byte budgets; out-of-scope hops are recorded and stopped.

Static analysis is now separable from field evidence. Three new passive
evidence producers (LIVE / HOST / HISTORY) write into one deterministic
evidence store (`phpscan-evidence.json`), and the `correlate` command
fuses it with a scan payload:

- **`live`** — scope-fenced, budgeted, read-only HTTP observation:
  headers, redirect chains, robots.txt, fingerprints, error pages.
  `--profile safe` adds fixed benign route touches and one lexical
  request differential — still no payloads. Every out-of-scope hop is
  recorded and stopped.
- **`investigate`** — read-only host audit: dropped/sneaky PHP,
  disguised PHP in non-PHP files, double extensions, backups, config/log
  secret scans (redacted), recent-modification proxy, opt-in process
  enumeration.
- **`timeline`** — exposure grading (confirmed/possible/none/insufficient
  data) for installed component versions against an operator-supplied
  patch declaration. No built-in vulnerability database.
- **`correlate`** — evidence↔findings fusion: per-finding support ladder
  (EXPOSED / OBSERVED / none), unexplained-evidence leads, and Proof
  Engine corroboration that never changes gate verdicts.
- **Static-side hardening (0.4)** — inline suppression
  (`// phpscan-ignore [RULE] reason` with a mandatory reason, also in
  baselines with optional `expires` dates), per-(file,rule) flood control
  (`--max-per-file`), binary PHP skip, and `--fail-on validated|critical`
  exit codes.

Privacy: reports carry redacted secret material only (sha256 fingerprint
+ 3-char hint); plaintext never leaves the local run.

See `docs/live-analysis.md`, `docs/safe-probing.md`,
`docs/host-investigation.md`, `docs/evidence-fusion.md`.

## The Validation Gate

Detection is deliberately noisy; a deterministic 8-stage gate is applied
**between detection and reporting**:

1. structural — parse integrity, candidate completeness
2. semantic — sink/category coherence
3. data-flow — evidence chain present and source-anchored
4. control-flow — guard-stack reachability (dead constant branches rejected)
5. sanitizer — sanitizer-context strength match (strong mismatch rejects)
6. context — category-specific context checks
7. contradiction — contradictory evidence inside the chain
8. re-analysis — independent strict-mode pass; disagreement downgrades

Statuses: `VALIDATED`, `PARTIALLY_VALIDATED`, `UNCONFIRMED`,
`RESEARCH_LEAD`, and retained `REJECTED` records for debug/audit. See
`docs/validation-gate.md`.

## Benchmark

```
phpscan benchmark eval
```

runs the shipped eval corpus (`eval/vulnerable`, `eval/clean`,
`eval/webshell`, plus `eval/patched` fixed variants and `eval/framework`
multi-file fixtures) and prints overall precision/recall/F1 plus a
per-category tp/fp/fn table; the JSON side-report written next to
`--out` additionally carries `timing_ms` and per-category detail. The
corpus is small and synthetic — it verifies the harness and
regression behavior, not real-world coverage. See `docs/claims.md` for
exactly what is and is not claimed.

## Docs

- [docs/architecture.md](docs/architecture.md)
- [docs/proof-engine.md](docs/proof-engine.md) — Proof Engine, uncertainty map,
  map/variants/diff/RAE design
- [docs/validation-gate.md](docs/validation-gate.md)
- [docs/rules.md](docs/rules.md)
- [docs/claims.md](docs/claims.md) — what is actually proven backed by tests
- [docs/differentiation.md](docs/differentiation.md)
- [docs/limitations.md](docs/limitations.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md) — reporting a vulnerability, authorized-research policy

## License

MIT.
