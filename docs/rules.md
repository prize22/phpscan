# Rule overrides (YAML)

phpscan's built-in registries ship in `phpscan/defs.py`. Use rule files to
**extend** them (you can currently only add entries, never weaken built-in
categories):

```yaml
sinks:
  SQL Injection:
    funcs:
      my_legacy_query: 0        # function, tainted arg index 0 (-1 = any)
    methods:
      run_raw: 0                # method, tainted arg index 0
  Arbitrary File Write:
    funcs:
      my_store_file: 0

sanitizers:
  my_escape_thing:
    ctx: sql                    # context key (see validation-gate.md)
    strength: medium            # strong | medium | weak

sources:
  $_MY_INPUT: 2                 # level 2 = direct user input
```

Constraints (validated by `phpscan rules validate <file>`, tested):

- sink categories must exist in the built-in defs;
- arg indexes are `int >= -1`;
- sanitizers require `ctx`; strength defaults to `medium`;
- source values are int taint levels.

## Listing built-in state

```
phpscan rules list
```

prints sink categories, sanitizers, sources, and transforms.

## Rules are additive by design

A rule file cannot remove a built-in sink or demote a built-in sanitizer.
This keeps a baseline: rule files are for project-specific APIs (e.g. a
legacy DB class), not for suppressing findings.
