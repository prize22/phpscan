"""Control-flow reachability utilities.

Not a full compiler CFG: the flow engine already captures branch/loop
semantics over the linearized IR. This module makes reachability facts
explicit for the Validation Gate: constant-false guard chains, nested
dead blocks, and loop-depth notes.
"""

from __future__ import annotations


def classify_guards(guards):
    """Returns (always_reachable, dead_reasons). A candidate's guard stack
    is [(block_kind, guard_text, guard_eval_result), ...]."""
    dead = []
    conditional = []
    for kind, guard, ge in guards:
        if ge == "false":
            if kind in ("if", "elseif"):
                dead.append("inside code guarded by constant-false condition: " + (guard or "if").strip())
            elif kind in ("while", "for", "do", "foreach"):
                dead.append("inside loop with constant-false condition: " + (guard or kind))
        elif ge == "dynamic":
            conditional.append((kind, guard or ""))
    return conditional, dead


def guard_primitives_feasible(cond_text):
    """Conservative: any nontrivial condition is treated as feasible."""
    return True


def reachability_report(conditional, dead):
    if dead:
        return "UNREACHABLE", dead
    if conditional:
        return "CONDITIONAL", conditional
    return "REACHABLE", []
