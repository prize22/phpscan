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
environment variables directly or require a `.env` file.

```bash
python -m pip install -e .[dev]
python -m pytest tests -q
python -m mypy phpscan
phpscan benchmark eval
python -m pip_audit -r requirements-lock.txt --strict
```

CI runs the same dependency audit against `requirements-lock.txt`. After
changing dependencies, regenerate the lock with:

```bash
pip-compile --extra=dev --output-file=requirements-lock.txt pyproject.toml
```

## Code conventions

- Python 3.9+ compatible syntax (no `match`, keep `__slots__` light);
  dataclasses for IR.
- Modules may not import from CLI.
- Registry edits live in `defs.py`, never inline constants scattered
  through engine code.
