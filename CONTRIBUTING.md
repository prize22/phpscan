# Contributing to phpscan

Core principles:

1. **Local-first.** Static analysis makes no network calls; optional `live`
   observation contacts only operator-authorized targets. No telemetry, no
   auto-updates, no credential upload.
2. **Determinism.** Every output (IDs, fingerprints, ordering, JSON) is
   deterministic. If a test shows nondeterminism, the code is wrong.
3. **Never execute target PHP.** The parser runs in the Python interpreter
   over the taint IR — no subprocess PHP lint, no `php -l`.
4. **Honesty in classification.** No finding ever borrows evidence from a
   model/magic. The Validation Gate notes are the observable source of
   record; if your change needs to bend a stage, adjust that stage's
   documented semantics (docs/validation-gate.md) in the same PR.
5. **Corpus increases always.** New detector behavior requires:
   (a) unit tests in `tests/`, (b) at least one vulnerable + one clean
   corpus fixture under `eval/`.

## Local development

PHPSCAN is configured through CLI flags and local files. It does not read
environment variables directly or require a `.env` file. It requires
Python 3.11 or newer; regenerate the lockfile on Python 3.11 so the resolved
set matches CI.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: source .venv/Scripts/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest tests -q
python -m pytest tests -q -m network
python -m ruff check .
python -m mypy phpscan
phpscan benchmark eval
python -m pip_audit -r requirements-lock.txt --strict
```

CI runs the same dependency audit against `requirements-lock.txt` and a
`locked` job installs that file with `--require-hashes`, runs `pip check`,
the unit and network suites, the benchmark, and verifies `phpscan --version`.

Install the locked environment directly with:

```bash
python -m pip install --require-hashes -r requirements-lock.txt
python -m pip install --no-deps -e .
python -m pip check
```

After changing dependencies, regenerate the lock with the pinned `pip-tools`
(from the `dev` extra):

```bash
pip-compile --extra=dev --allow-unsafe --generate-hashes --newline=lf \
    --output-file requirements-lock.txt pyproject.toml
```

The command preserves existing pins; pass `--upgrade` only when you intend to
re-resolve the whole set. The `# via` annotations are host-specific, so
regenerate on Linux with Python 3.11 for a byte-identical file. Commit
`pyproject.toml` and `requirements-lock.txt` together.

## Code conventions

- Python 3.11+ compatible syntax; dataclasses for IR.
- Modules may not import from CLI.
- Registry edits live in `defs.py`, never inline constants scattered
  through engine code.
