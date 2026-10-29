"""Callable-argument dispatch for taint analysis.

Resolves the callable argument accepted by PHP's callable-consuming APIs
(array_map, usort, preg_replace_callback, ...) into a builtin taint sink or
into an analyzed function, and models attacker-controlled callables as
dynamic dispatch candidates. No target PHP is ever executed.
"""

from __future__ import annotations

from typing import Optional

from . import defs as D
from . import ir as I
from . import util as U


_MAX_CHAIN = 24


def _short(s, limit=72):
    return "?" if s is None else U.truncate_for_display(str(s), limit)


def _chain_join(chain, steps):
    out = tuple(chain) + tuple(steps)
    if len(out) > _MAX_CHAIN:
        out = out[-_MAX_CHAIN:]
    return out


def expand_forwarding(cb_idx, spec, nargs) -> list:
    """Expand a defs forwarding map into concrete (outer, param) pairs."""
    pairs = []
    for outer, param in spec:
        if outer == D.REST:
            pairs.extend((j, param) for j in range(cb_idx + 1, nargs))
        else:
            pairs.append((outer, param))
    return pairs


def resolve_dispatch_callable(engine, scope_func, called) -> Optional[I.FuncIR]:
    """Resolve a callable name (or ``Class::method``) to an analyzed function."""
    if not called:
        return None
    cl = called.lower()
    if "::" in cl:
        cls2, meth2 = cl.split("::", 1)
        cls3 = engine._static_scope_class(scope_func, cls2)
        if cls3:
            return engine.classmap.get((cls3, meth2))
        return None
    return engine.named_funcs.get(cl)


def replay_callee_sinks(flow, target, summary, argvals, fwd_map, line) -> None:
    """Replay a callee's parameter-sink summary against caller values.

    ``fwd_map`` pairs a caller argument index with the callee parameter
    it lands in; ``None`` means direct positional (identity) mapping,
    which is how ordinary call sites forward their arguments.
    """
    if summary is None:
        return
    pairs = ((i, i) for i in range(len(argvals))) if fwd_map is None else fwd_map
    for outer_idx, param_idx in pairs:
        if outer_idx >= len(argvals):
            continue
        v = argvals[outer_idx]
        if not v.has_taint():
            continue
        for hit in summary["sinks"].get(param_idx, ()):
            vc = v.clone()
            vc.chain = _chain_join(
                v.chain,
                (
                    (
                        line,
                        "flows through "
                        + _short(target.qualified)
                        + " into sink "
                        + hit.sink_name
                        + "  [interprocedural]",
                    ),
                ),
            )
            flow.mk_candidate(
                hit.cat,
                "call" if hit.call_kind == "function" else "func-summary",
                hit.sink_name,
                "",
                outer_idx,
                hit.line,
                sink_expr=_short(hit.sink_expr) + "   (callee " + target.file + ":L" + str(hit.line) + ")",
                val=vc,
                file_override=target.file,
            )


def sink_check(flow, called, args, fwd, line, callsite_short) -> None:
    """A constant callable naming a builtin sink function.

    Mirrors builtin dispatch, but the value that reaches the sink is
    selected by the API's forwarding map instead of assuming the
    call_user_func "argument 1" layout.
    """
    cl = (called or "").strip().lower()
    if not cl:
        return
    for cat, spec in D.SINKS.items():
        idx = spec["funcs"].get(cl)
        if idx is None:
            continue
        for outer_idx, param_idx in fwd:
            if idx != -1 and idx != param_idx:
                continue
            if outer_idx >= len(args):
                continue
            v = args[outer_idx][2]
            if not v.has_taint():
                continue
            note = _short(callsite_short) + "  [callable dispatch to " + cl + "]"
            vc = v.clone()
            vc.chain = _chain_join(v.chain, ((line, note),))
            flow.mk_candidate(cat, "call", cl, "", outer_idx, line, sink_expr=note, val=vc)
            return
        return


def builtin_sink_check(flow, called, args, line, callsite) -> None:
    cl = (called or "").strip().lower()
    if not cl:
        return
    for cat, spec in D.SINKS.items():
        idx = spec["funcs"].get(cl)
        if idx is None:
            continue
        i = 1 + (0 if idx <= 0 else idx)
        if i >= len(args):
            return
        v = args[i][2]
        if v.has_taint():
            flow.mk_candidate(
                cat,
                "call",
                cl,
                "",
                1,
                line,
                sink_expr=_short(callsite) + "  [dispatches to builtin " + cl + "]",
                val=v,
            )
        return


def dispatch(flow, lname, args, argvals, line, callsite_short) -> None:
    """Callable-consuming API: resolve its callable argument.

    Constant callables are dispatched into builtin sinks and into
    analyzed functions (interprocedural summary replay); a callable
    taken from attacker input stays an unresolved dynamic call, exactly
    like the call_user_func family. The call itself keeps flowing
    through the engine, so transforms/sanitizers still apply.
    """
    cb_idx, fwd_spec = D.CALLBACK_FUNCS[lname]
    if cb_idx >= len(argvals):
        return
    cb_val = argvals[cb_idx]
    cb_text = (cb_val.const or "").strip()
    fwd = expand_forwarding(cb_idx, fwd_spec, len(argvals))
    if not cb_text:
        if cb_val.has_taint():
            flow.mk_candidate(
                "Code Injection",
                "call",
                lname,
                "",
                cb_idx,
                line,
                sink_expr=_short(callsite_short) + "  [dynamic callable, unresolved target]",
                val=cb_val,
            )
            flow.push_signal("dyn_dispatch", _short(callsite_short), line)
        return
    target = resolve_dispatch_callable(flow.engine, flow.func, cb_text)
    if target is not None:
        replay_callee_sinks(flow, target, flow.engine.summary_for(target), argvals, fwd, line)
        return
    sink_check(flow, cb_text, args, fwd, line, callsite_short)
