# Contributing to phpscan

Core principles:

1. **Local-only.** No network calls, no telemetrics, no auto-updates.
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

## Env

```bash
python -m pip install -e .[dev]
python -m pytest tests -q
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
