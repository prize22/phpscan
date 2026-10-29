"""Taint analysis engine.

Per-function abstract interpretation over the IR: propagates taint from
registered sources through assignments/transforms/sanitizers to registered
sinks, emitting Candidate Findings with evidence chains. Interprocedural
behavior uses param-probe summaries: each function is analyzed once with
params clean (to collect real findings), then once with every param seeded
as attacker-controlled to learn which params can reach which sinks or the
return value. Callers then replay those summaries with their own argument
taints. No target PHP is ever executed.
"""

from __future__ import annotations

import re

from . import callable_dispatch as CD
from . import defs as D
from . import ir as I
from . import render as R

GUARD_DYNAMIC = "dynamic"
GUARD_FALSE = "false"
GUARD_TRUE = "true"

_MAX_CHAIN = 24
_MAX_TRANSFORMS = 12
_SEP = "\x01"

_COND_BRANCHES = ("if", "elseif", "else")
_LOOP_KINDS = ("for", "while", "do", "foreach")


def key_of(parts):
    return "$" + _SEP.join(str(p) for p in parts)


def guard_eval(guard):
    g = (guard or "").strip().strip("()").strip()
    if not g:
        return GUARD_DYNAMIC
    if g in ("0", "false", "FALSE", "''", '""', "null", "NULL"):
        return GUARD_FALSE
    if g in ("1", "true", "TRUE"):
        return GUARD_TRUE
    return GUARD_DYNAMIC


def val_origin(v):
    if v is None:
        return "?"
    if v.origin:
        return v.origin
    if v.uncertain:
        return v.uncertain
    if getattr(v, "const", ""):
        return v.const[:40]
    return "{expression}"


def _short(s, limit=72):
    if s is None:
        return "?"
    s = re.sub(r"\s+", " ", str(s))
    if len(s) <= limit:
        return s
    return s[: limit - 3] + "..."


def _chain_join(chain, steps):
    out = tuple(chain) + tuple(steps)
    if len(out) > _MAX_CHAIN:
        out = out[-_MAX_CHAIN:]
    return out


def _tj(transforms, t):
    out = tuple(transforms)
    if t and t not in out:
        out = out + (t,)
    if len(out) > _MAX_TRANSFORMS:
        out = out[-_MAX_TRANSFORMS:]
    return out


def _merge_val(a, b):
    if b is None:
        return a.clone() if a is not None else FlowVal()
    if a is None:
        return b.clone()
    v = a.clone()
    if b.level > v.level:
        v.level = b.level
        v.origin = b.origin
        v.origin_kind = b.origin_kind
        v.source_file = b.source_file
        v.source_line = b.source_line
        v.chain = b.chain
        v.transforms = b.transforms
        v.sanitizer = b.sanitizer
        v.sanitizer_ctx = b.sanitizer_ctx
        v.sanitizer_strength = b.sanitizer_strength
        v.src_param = b.src_param
        if not v.uncertain:
            v.uncertain = b.uncertain
    elif b.level == v.level:
        if not v.origin and b.origin:
            v.origin = b.origin
            v.origin_kind = b.origin_kind
            v.source_file = b.source_file
            v.source_line = b.source_line
            v.chain = b.chain
            v.transforms = b.transforms
            if v.src_param < 0 and b.src_param >= 0:
                v.src_param = b.src_param
        if not v.uncertain:
            v.uncertain = b.uncertain
    if b.level < v.level and v.src_param < 0 and b.src_param >= 0:
        pass
    if v.src_param < 0 and b.src_param >= 0 and b.has_taint():
        v.src_param = b.src_param
    return v


def _concat_vals(a, b, line, op="."):
    bclean = b is None or b.is_clean_const()
    aclean = a is None or a.is_clean_const()
    if aclean and bclean:
        v = FlowVal()
        v.const = ("" if a is None else a.const) + ("" if b is None else b.const)
        return v
    if a is None or not a.has_taint():
        v = b.clone() if b is not None else FlowVal()
    elif b is None or not b.has_taint():
        v = a.clone()
    else:
        v = a.clone() if a.level >= b.level else b.clone()
    if (a is not None and a.const) or (b is not None and b.const):
        v.const = ("" if a is None else a.const or "") + ("" if b is None else b.const or "")
    if v.level > D.LVL_NONE:
        lt = a.transforms if a is not None else ()
        rx = b.transforms if b is not None else ()
        merged = lt
        for x in rx:
            merged = _tj(merged, x)
        if op == ".":
            merged = _tj(merged, "concat")
        v.transforms = merged
        v.chain = _chain_join(v.chain, ((line, _concat_step(a, b, op)),))
    return v


def _concat_step(a, b, op):
    "<int>" if a is None or (not a.has_taint() and a.is_clean_const() and not a.const) else ""
    getattr(a, "fx", None)
    display_a = "" if a is None else ("" if (a.is_clean_const() and not a.const) else _short(a.origin or "?", 24))
    display_b = "" if b is None else ("" if (b.is_clean_const() and not b.const) else _short(b.origin or "?", 24))
    return ".." + op + "  concat of " + display_a + " + " + display_b


def _compute_bin(lv, rv, op, line):
    """Arithmetic/other binary ops: taint flows through most numeric ops."""
    lclean = lv is None or lv.is_clean_const()
    rclean = rv is None or rv.is_clean_const()
    if lclean and rclean:
        return FlowVal()
    base = lv.clone() if lv is not None and lv.has_taint() else rv.clone() if rv is not None else FlowVal()
    base.chain = _chain_join(
        base.chain,
        (
            (
                line,
                "  "
                + _short(op or "?")
                + "-op of "
                + _short(lv.origin or "const")
                + " and "
                + _short(rv.origin or "const"),
            ),
        ),
    )
    return base


def _foreach_extract(guard):
    g = guard or ""
    m = re.search(r"foreach\s*\(", g)
    if not m:
        return None
    m = re.search(r"as\s+(.+)", g)
    if not m:
        return None
    clause = m.group(1).split(")")[0]
    if "=>" in clause:
        keytext, valtext = clause.split("=>", 1)
        if not valtext:
            return None
    else:
        valtext = clause
        keytext = ""
    vm = re.search(r"\$[A-Za-z_]\w*", valtext)
    if not vm:
        return None
    marr = re.search(r"foreach\s*\(\s*\$[A-Za-z_]\w*", g)
    if not marr:
        return None
    arrtext = g[marr.start() + len("foreach") + 2 :]
    j = arrtext.find(" as")
    if j >= 0:
        arrtext = arrtext[:j].strip()
    else:
        return None
    valparts = _text_to_parts(valtext)
    keyparts = _text_to_parts(keytext) if keytext else ()
    parts = _text_to_parts(arrtext)
    return (parts, valparts, keyparts)


def _text_to_parts(text):
    text = (text or "").strip().rstrip(")").lstrip("(").strip("$")
    m = re.match(r"^(\w+)", text)
    if not m:
        return ()
    segs = [m.group(1)]
    rest = text[m.end() :]
    while rest:
        if rest[0] == "[":
            j = rest.find("]")
            if j < 0:
                break
            key = rest[1:j].strip().strip("'\"")
            if key:
                segs.append(key)
            rest = rest[j + 1 :]
            continue
        if rest.startswith("->"):
            m2 = re.match(r"^->(\w+)", rest)
            if m2:
                segs.append("=" + m2.group(1))
                rest = rest[m2.end() :]
                continue
        break
    return tuple(segs)


def decode_const_transform(fname, vals):
    f = (fname or "").lower()
    for v in vals:
        if v is None:
            return None
    if f == "base64_decode" and vals:
        import base64

        try:
            return base64.b64decode(vals[0]).decode("utf-8", "replace")
        except Exception:
            return None
    if f == "base64_encode" and vals:
        import base64

        return base64.b64encode((vals[0] or "").encode("utf-8")).decode("ascii", "replace")
    if f == "str_rot13" and vals:
        import codecs

        try:
            return codecs.encode(vals[0], "rot13")
        except Exception:
            return None
    if f == "hex2bin" and vals:
        try:
            return bytes.fromhex((vals[0] or "").replace(" ", "")).decode("utf-8", "replace")
        except Exception:
            return None
    if f == "bin2hex" and vals:
        return (vals[0] or "").encode("utf-8", "replace").hex()
    if f == "strrev" and vals:
        return (vals[0] or "")[::-1]
    if f == "str_replace" and len(vals) >= 3:
        try:
            return vals[2].replace(vals[0], vals[1])
        except Exception:
            return None
    if f in ("strtolower", "strtoupper") and vals:
        return vals[0].lower() if f == "strtolower" else vals[0].upper()
    return None


def _param_tag(idx):
    return "param#" + str(idx)


class FlowVal:
    __slots__ = (
        "level",
        "origin",
        "origin_kind",
        "source_file",
        "source_line",
        "chain",
        "transforms",
        "sanitizer",
        "sanitizer_ctx",
        "sanitizer_strength",
        "const",
        "uncertain",
        "src_param",
    )

    def __init__(
        self,
        level=D.LVL_NONE,
        origin="",
        origin_kind="",
        source_file="",
        source_line=0,
        chain=(),
        transforms=(),
        sanitizer="",
        sanitizer_ctx="",
        sanitizer_strength="",
        const="",
        uncertain="",
        src_param=-1,
    ):
        self.level = level
        self.origin = origin
        self.origin_kind = origin_kind
        self.source_file = source_file
        self.source_line = source_line
        self.chain = tuple(chain)
        self.transforms = tuple(transforms)
        self.sanitizer = sanitizer
        self.sanitizer_ctx = sanitizer_ctx
        self.sanitizer_strength = sanitizer_strength
        self.const = const
        self.uncertain = uncertain
        self.src_param = src_param

    def clone(self):
        return FlowVal(
            self.level,
            self.origin,
            self.origin_kind,
            self.source_file,
            self.source_line,
            self.chain,
            self.transforms,
            self.sanitizer,
            self.sanitizer_ctx,
            self.sanitizer_strength,
            self.const,
            self.uncertain,
            self.src_param,
        )

    @staticmethod
    def source(level, origin, file="", line=0, src_param=-1):
        v = FlowVal(
            level=level,
            origin=origin,
            origin_kind=D.LEVEL_NAMES.get(level, "UNKNOWN"),
            source_file=file,
            source_line=line,
            src_param=src_param,
        )
        v.chain = ((line, origin + "  [source: " + D.LEVEL_NAMES.get(level, "?") + "]"),)
        return v

    def has_taint(self):
        return self.level > D.LVL_NONE or self.uncertain != ""

    def is_clean_const(self):
        return self.level == D.LVL_NONE and self.uncertain == "" and not self.transforms


class Candidate:
    __slots__ = (
        "cat",
        "call_kind",
        "sink_name",
        "receiver",
        "arg_idx",
        "file",
        "line",
        "func",
        "val",
        "sink_expr",
        "guards",
        "arg_named",
        "no_taint",
        "const_guard",
    )

    def __init__(
        self,
        cat,
        call_kind,
        sink_name,
        receiver,
        arg_idx,
        file,
        line,
        func,
        val,
        sink_expr,
        guards,
        arg_named=None,
        no_taint=False,
        const_guard=False,
    ):
        self.cat = cat
        self.call_kind = call_kind
        self.sink_name = sink_name
        self.receiver = receiver
        self.arg_idx = arg_idx
        self.file = file
        self.line = line
        self.func = func
        self.val = val
        self.sink_expr = sink_expr
        self.guards = tuple(guards)
        self.arg_named = arg_named
        self.no_taint = no_taint
        self.const_guard = const_guard


class ParamSinkHit:
    __slots__ = ("param_idx", "cat", "sink_name", "line", "sink_expr", "call_kind", "receiver", "no_taint")

    def __init__(self, param_idx, cat, sink_name, line, sink_expr, call_kind, receiver, no_taint=False):
        self.param_idx = param_idx
        self.cat = cat
        self.sink_name = sink_name
        self.line = line
        self.sink_expr = sink_expr
        self.call_kind = call_kind
        self.receiver = receiver
        self.no_taint = no_taint


class FuncFlow:
    MAX_DEPTH = 12

    def __init__(self, engine, func, probe=False, strict=False):
        self.engine = engine
        self.func = func
        self.probe = probe
        self.strict = strict
        self.state = {}
        self.types = {}  # var base -> class name (lowercase)
        self.prop_params = {}  # probe-mode: prop name -> param idx
        self.closure_vars = {}  # var base -> closure FuncIR
        self.wildcard = None
        self.wildcard_origin = ""
        self.wildcard_param = -1
        self.guard_stack = []
        self.cands = {}
        self.param_sinks = {}
        self.ret_params = set()
        self.signals = []
        self.ret = None
        self.calls_text = []
        self.depth = 0
        self.dynjumps = 0

    def push_signal(self, sig, detail, line):
        self.signals.append({"sig": sig, "detail": detail, "line": line})

    def display(self):
        if self.func.cls:
            return self.func.cls + "::" + self.func.name
        return self.func.name

    def run(self):
        state = {}
        for i, p in enumerate(self.func.params):
            if self.probe:
                state[key_of((p.name,))] = FlowVal.source(
                    D.LVL_TAINTED, _param_tag(i), self.func.file, self.func.line, src_param=i
                )
        self.state = state
        self.walk(self.func.body)
        return self

    def walk(self, stmts):
        i = 0
        n = len(stmts)
        while i < n:
            s = stmts[i]
            if s.kind == "block" and s.block_kind in _COND_BRANCHES:
                blocks = [s]
                j = i + 1
                while j < n and stmts[j].kind == "block" and stmts[j].block_kind in ("elseif", "else"):
                    blocks.append(stmts[j])
                    j += 1
                self.cond_chain(blocks)
                i = j
                continue
            if s.kind == "block":
                self.block_stmt(s)
            else:
                self.stmt(s)
            i += 1

    def cond_chain(self, blocks):
        main = self.state
        outs = []
        skip_elseif = False
        for b in blocks:
            ge = guard_eval(b.guard)
            if b.block_kind == "else" and skip_elseif:
                skip_elseif = False
            if ge == GUARD_FALSE and not skip_elseif:
                skip_elseif = True
                continue
            if ge == GUARD_FALSE and skip_elseif:
                skip_elseif = True
                continue
            branch = dict(main)
            self.state = branch
            self.guard_stack.append((b.block_kind, b.guard, ge))
            if b.block_kind in _LOOP_KINDS:
                for _p in range(2):
                    self.walk(b.stmts)
                    if _p == 0:
                        self.state = _merge_states([dict(main), self.state])
            else:
                self.walk(b.stmts)
            self.guard_stack.pop()
            outs.append(self.state)
            if ge == GUARD_TRUE:
                # branch always taken; skip remaining (dead) branches
                skip_elseif = "stop"
                outs = [branch]
                break
            self.state = main
        merged = dict(main)
        for o in outs:
            merged = _merge_states([merged, o])
        self.state = merged

    def block_stmt(self, s):
        ge = guard_eval(s.guard)
        self.guard_stack.append((s.block_kind, s.guard, ge))
        if s.block_kind == "foreach":
            prepared = _foreach_extract(s.guard)
            base_v = None
            if prepared is not None:
                arrparts, valparts, keyparts = prepared
                base_v = self.eval_var(I.VarRef(parts=arrparts[:1]), line=s.line)
            for _p in range(2):
                if prepared is not None and base_v is not None:
                    if valparts:
                        self.state[key_of(valparts)] = base_v.clone()
                    if keyparts:
                        self.state[key_of(keyparts)] = base_v.clone()
                self.walk(s.stmts)
                if _p == 0:
                    self.state = _merge_states([self.state, self.state])
        elif s.block_kind in _LOOP_KINDS and ge != GUARD_FALSE:
            for _p in range(2):
                self.walk(s.stmts)
        else:
            self.walk(s.stmts)
        self.guard_stack.pop()

    def stmt(self, s):
        k = s.kind
        if k in ("assign", "augassign"):
            self._assign_stmt(s)
        elif k == "call":
            if s.call is not None:
                self.eval_call(s.call, s.line)
        elif k == "include":
            self._include_stmt(s)
        elif k == "echo":
            self._echo_stmt(s)
        elif k == "return":
            val = self.eval(s.ret, s.line)
            if val is not None and val.has_taint():
                self.ret = _merge_val(self.ret, val)
                if val.src_param >= 0:
                    self.ret_params.add(val.src_param)
        elif k == "unset":
            for t in s.targets:
                if t is not None:
                    self.state.pop(key_of(t.parts), None)
        elif k == "expr":
            self.eval(s.value, s.line)
        elif k == "closure":
            self.closure_stmt(s)

    def closure_stmt(self, s):
        cf = s.ret
        if cf is None:
            return
        use_state = {}
        for uv in cf.use_vars:
            exact = key_of((uv,))
            found = None
            if exact in self.state:
                found = self.state[exact]
            else:
                base = exact
                for key, vv in self.state.items():
                    if key.startswith(base + _SEP):
                        found = vv
                        break
            if found is not None and found.src_param >= 0:
                use_state[key_of((uv.lower(),))] = found.clone()
        self.depth += 1
        try:
            self.engine.run_closure(self, cf, use_state, self.depth)
        finally:
            self.depth -= 1

    def _assign_stmt(self, s):
        if s.target is None:
            return
        val = self.eval(s.value, s.line)
        if val is None:
            val = FlowVal()
        if s.kind == "augassign":
            op = s.op.rstrip("=")
            old = self.state_val(s.target.ref, prefer=True)
            if old is None:
                old = FlowVal()
            if op == ".":
                val = _concat_vals(old, val, s.line)
            else:
                val = _compute_bin(old, val, op, s.line)
        self._apply_assign(s.target, val, s.line, s.value)
        if isinstance(s.value, I.ExprArr) and val.has_taint():
            self._apply_array_literal(s.target, s.value, s.line)
        if val.has_taint():
            self.push_signal("assign", R.var_display(s.target.ref) + " <= " + _short(R.expr_repr(s.value)), s.line)

    def _apply_assign(self, tgt, val, line, expr):
        parts = tgt.ref.parts
        key = key_of(parts)
        # a deeper write keyed under this path is now stale
        pref = key + _SEP
        stale = [k for k in self.state if k.startswith(pref)]
        for k in stale:
            del self.state[k]
        self.state[key] = val
        base = parts[0]
        if len(parts) == 1:
            self.types.pop(base.lower(), None)
        nc = getattr(expr, "new_class", "")
        if nc:
            self.types[base.lower()] = nc.lower()
            self._seed_new_props(tgt, expr, line)
        cl = getattr(expr, "closure_line", 0)
        if cl:
            cf = self.engine.closure_index.get((self.func.file, cl))
            if cf is not None and len(parts) == 1 and parts[0] not in ("this",):
                self.closure_vars[parts[0].lower()] = cf
        if self.probe and parts[0] == "this" and len(parts) == 2 and parts[1].startswith("=") and val.src_param >= 0:
            self.prop_params[parts[1][1:].lower()] = val.src_param

    def _seed_new_props(self, tgt, expr, line):
        nc = (getattr(expr, "new_class", "") or "").lower()
        ctor = self.engine.classmap.get((nc, "__construct"))
        if ctor is None:
            return
        summ = self.engine.summary_for(ctor)
        if summ is None:
            return
        args = getattr(expr, "new_args", None) or []
        for prop, pi in (summ.get("props") or {}).items():
            if pi >= len(args):
                continue
            pv = self.eval(args[pi], line)
            if pv is None or not pv.has_taint():
                continue
            pk = key_of(tgt.ref.parts[:1] + ("=" + prop,))
            cv = pv.clone()
            cv.chain = _chain_join(
                cv.chain,
                (
                    (
                        line,
                        _short(nc) + "::__construct() wires arg " + str(pi) + " into ->" + prop + "  [interprocedural]",
                    ),
                ),
            )
            self.state[pk] = cv

    def _apply_array_literal(self, tgt, arr, line):
        for kx, vx in arr.items:
            kv = self.const_of(kx) if kx is not None else None
            if kv:
                cv = self.eval(vx, line)
                if cv is None:
                    cv = FlowVal()
                if cv.has_taint():
                    self.state[key_of(tgt.ref.parts + (kv,))] = cv

    def _echo_stmt(self, s):
        for a in s.args:
            if a is None:
                continue
            val = self.eval(a, s.line)
            if val is None or not val.has_taint():
                continue
            self.mk_candidate(
                "Cross-Site Scripting", "echo", "echo", "", 0, s.line, sink_expr="echo " + R.expr_repr(a), val=val
            )

    def _include_stmt(self, s):
        if s.value is None:
            return
        val = self.eval(s.value, s.line)
        if val is None:
            val = FlowVal()
        if self.is_const_expr(s.value):
            return
        ge_last = self.guard_stack[-1][2] if self.guard_stack else GUARD_DYNAMIC
        self.mk_candidate(
            "File Inclusion",
            "include",
            s.mode,
            "",
            0,
            s.line,
            sink_expr=R.expr_repr(s.value),
            val=val,
            const_guard=(ge_last == GUARD_FALSE),
        )

    def eval(self, e, line):
        if e is None:
            return None
        if isinstance(e, I.ExprConst):
            return FlowVal(const=str(e.value))
        if isinstance(e, I.ExprStrLit):
            return self.eval_strlit(e, line)
        if isinstance(e, I.ExprVar):
            return self.eval_var(e.ref, line)
        if isinstance(e, I.ExprBin):
            return self.eval_bin(e, line)
        if isinstance(e, I.ExprSeqAssign):
            tgt = e.target
            val = self.eval(e.value, line)
            if val is None:
                val = FlowVal()
            self._apply_assign(tgt, val, line, e.value)
            if isinstance(e.value, I.ExprArr) and val.has_taint():
                self._apply_array_literal(tgt, e.value, line)
            return val
        if isinstance(e, I.ExprCast):
            inner = self.eval(e.operand, line)
            if inner is None:
                return None
            ct = e.cast_type.lower()
            if ct in D.CAST_SANE:
                out = inner.clone()
                out.level = D.LVL_NONE
                out.uncertain = ""
                out.src_param = -1
                out.sanitizer = "cast:" + ct
                out.sanitizer_ctx = "numeric"
                out.sanitizer_strength = "strong"
                out.origin = inner.origin
                out.origin_kind = inner.origin_kind
                out.source_file = inner.source_file
                out.source_line = inner.source_line
                out.chain = _chain_join(
                    inner.chain, ((line, _short(R.expr_repr(e)) + "  [cast " + ct + ": sanitized]"),)
                )
                return out
            out = inner.clone()
            out.chain = _chain_join(inner.chain, ((line, _short(R.expr_repr(e)) + "  [transform]"),))
            return out
        if isinstance(e, I.ExprCond):
            tv = self.eval(e.then, line)
            ov = self.eval(e.other, line)
            return _merge_val(tv, ov)
        if isinstance(e, I.ExprArr):
            v = FlowVal()
            for kx, vx in e.items:
                val = self.eval(vx, line)
                if val is not None:
                    v = _merge_val(v, val)
            return v
        if isinstance(e, I.ExprCall):
            return self.eval_call(e, line)
        if isinstance(e, I.ExprOther):
            v = FlowVal()
            for ref in e.vars:
                rv = self.eval_var(ref, line)
                v = _merge_val(v, rv)
            return v
        return FlowVal()

    def eval_bin(self, e, line):
        op = e.op
        if op in ("==", "!=", "===", "!==", "<", ">", "<=", ">=", "<=>", "instanceof"):
            self.eval(e.left, line)
            self.eval(e.right, line)
            return FlowVal()
        if op in ("&&", "||", "and", "or", "xor", "??"):
            lv = self.eval(e.left, line)
            rv = self.eval(e.right, line)
            return _merge_val(lv, rv)
        ln = self.eval(e.left, line)
        r = self.eval(e.right, line)
        if op in (".", ",", " ", "", "|?"):
            return _concat_vals(ln, r, line)
        return _compute_bin(ln, r, op, line)

    def eval_var(self, ref, line):
        v = self.state_val(ref)
        if v is not None:
            return v
        lvl = self._superglobal_level(ref)
        if lvl > D.LVL_NONE:
            origin = R.var_display(ref)
            self.push_signal("source", origin, ref.src_line)
            return FlowVal.source(lvl, origin, self.func.file, ref.src_line)
        return FlowVal()

    def _superglobal_level(self, ref):
        base = ref.parts[0]
        lvl = D.TAINTED_CONTEXTS.get(base)
        if lvl is None:
            return D.LVL_NONE
        if base == "_SERVER":
            if len(ref.parts) > 1:
                k = ref.parts[1]
                if k.startswith("="):
                    return D.LVL_NONE
                k = k.lower()
                if k in D.SERVER_SENSITIVE_KEYS:
                    return D.LVL_TAINTED
                if k in D.SERVER_SAFE_KEYS:
                    return D.LVL_NONE
                return D.LVL_INDIRECT
            return D.LVL_INDIRECT
        if base == "argv":
            return D.LVL_INDIRECT
        if base == "_FILES":
            return self._files_level(ref.parts)
        return lvl

    def _files_level(self, parts):
        if len(parts) < 2:
            return D.LVL_INDIRECT
        last = parts[-1]
        if last.startswith("="):
            return D.LVL_TAINTED
        if last in D.FILES_OK_KEYS:
            return D.LVL_NONE
        if last in D.FILES_INPUT_KEYS:
            return D.LVL_TAINTED
        return D.LVL_TAINTED

    def state_val(self, ref, prefer=False):
        parts = ref.parts
        v = self._lookup_path(parts)
        if v is not None:
            return v
        lvl = self._superglobal_level(ref)
        if lvl > D.LVL_NONE:
            self.push_signal("source", R.var_display(ref), ref.src_line)
            return FlowVal.source(lvl, R.var_display(ref), self.func.file, ref.src_line)
        if self.wildcard is not None:
            return FlowVal(
                self.wildcard,
                self.wildcard_origin,
                "",
                "",
                0,
                ((0, self.wildcard_origin),),
                src_param=self.wildcard_param,
            )
        return None

    def _lookup_path(self, parts):
        parts = tuple(parts)
        v = self.state.get(key_of(parts))
        if v is not None:
            return v
        pp = parts
        while len(pp) > 1:
            pp = pp[:-1]
            v = self.state.get(key_of(pp))
            if v is not None:
                return v
        basekey = key_of(parts[:1])
        merged = FlowVal()
        for k, val in self.state.items():
            if k == basekey or k.startswith(basekey + _SEP):
                merged = _merge_val(merged, val)
        if merged.has_taint():
            return merged
        return None

    def eval_strlit(self, e, line):
        v = FlowVal()
        if all(p[0] == "str" for p in e.parts):
            v.const = "".join(p[1] for p in e.parts)
            return v
        for kind, data in e.parts:
            if kind == "str":
                continue
            if kind == "var":
                pv = self.eval_var(I.VarRef(parts=tuple(data)), line=line)
                v = _concat_vals(v, pv, line)
            elif kind == "expr":
                iv = self.eval_interpolated_expr(data, line)
                v = _concat_vals(v, iv, line)
        if any(p[0] != "str" for p in e.parts):
            v.transforms = _tj(v.transforms, "string-interpolation")
        if v.has_taint():
            self.push_signal("interpolation", '"' + R._parts_text(e.parts) + '"', line)
        return v

    def eval_interpolated_expr(self, raw, line):
        m = re.match(r"^\$([A-Za-z_]\w*)((?:\[[^\]]*\]|->\w+)*)", raw or "")
        if m:
            parts = [m.group(1)]
            rest = m.group(2)
            pos = 0
            while pos < len(rest) and rest[pos] in ("[", "-"):
                if rest[pos] == "[":
                    j = rest.find("]", pos)
                    if j < 0:
                        break
                    key = rest[pos + 1 : j].strip().strip("'\"")
                    if not key:
                        break
                    parts.append(key)
                    pos = j + 1
                elif rest[pos : pos + 2] == "->":
                    m2 = re.match(r"[A-Za-z_]\w*", rest[pos + 2 :])
                    if not m2:
                        break
                    parts.append("=" + m2.group(0))
                    pos += 2 + len(m2.group(0))
                else:
                    break
            ref = I.VarRef(parts=tuple(parts))
            return self.eval_var(ref, line)
        return FlowVal(uncertain="complex interpolation {" + (raw or "") + "}")

    def eval_call(self, call, line):
        if call is None or call.target is None:
            return FlowVal()
        args = []
        for named, aexpr in call.args:
            v = self.eval(aexpr, line)
            if v is None:
                v = FlowVal()
            args.append((named, aexpr, v))
        kind = call.target.kind
        name = call.target.name
        lname = name.lower()
        callsite = R.expr_repr(call)
        callsite_short = _short(callsite)

        if kind == "backtick":
            v = args[0][2] if args else FlowVal()
            self.push_signal("shell", callsite_short, line)
            self.mk_candidate("Command Injection", "backtick", "`", "", 0, line, sink_expr=callsite, val=v)
            return FlowVal()
        if kind == "varfunc":
            argdesc = ",".join(_short(x[2].origin) for x in args if x)
            self.push_signal("varfunc", name + "(" + argdesc + ")", line)
            chainv = args[0][2].clone() if args else FlowVal()
            chainv.uncertain = "dynamic call $" + name.strip("$")
            varname = name.strip("$").lower()
            if not self.closure_vars.get(varname):
                if args and args[0][2].has_taint():
                    self.push_signal(
                        "dyn_call_tainted", name + "(" + ",".join(_short(val_origin(x[2])) for x in args) + ")", line
                    )
                return chainv
            # closure-stored function: resolved below via resolve_call
        if kind == "function" and lname in D.WILDCARD_TAINT_FUNCS:
            v0 = args[0][2] if args else FlowVal()
            if v0.has_taint() and v0.level >= D.LVL_INDIRECT:
                self.wildcard = v0.level
                self.wildcard_origin = "extract(" + _short(v0.origin or "superarray") + ")"
                self.wildcard_param = v0.src_param
                self.push_signal("extract", callsite_short, line)
            return FlowVal()
        if kind == "function" and lname in D.SOURCE_PRODUCERS:
            const0 = self.const_of(call.args[0][1]) if call.args else ""
            sup = D.SOURCE_PRODUCERS[lname]
            if "php://input" in (const0 or "") or sup == "stdin":
                origin = callsite_short
                self.push_signal("source", "php://input" if sup == "php://input" else "stdin", line)
                return FlowVal.source(D.LVL_TAINTED, origin, self.func.file, line)
        if kind == "function" and lname == "assert":
            if args and args[0][2].has_taint():
                self.mk_candidate("Code Injection", "call", "assert", "", 0, line, sink_expr=callsite, val=args[0][2])
            self.push_signal("dynamic_exec", callsite_short, line)
            return FlowVal()
        if kind == "function" and lname == "header":
            v0 = args[0][2] if args else FlowVal()
            prefix = self.header_arg_prefix(call.args[0][1]) if call.args else ""
            lp = (prefix or "").strip().lower()
            if lp.startswith("location") or lp.startswith("refresh"):
                cat = "Open Redirect"
            elif v0.has_taint():
                cat = "Header Injection"
            else:
                cat = ""
            if cat:
                self.mk_candidate(cat, "call", "header", "", 0, line, sink_expr=callsite, val=v0)
            return FlowVal()
        if kind == "function" and lname == "curl_setopt" and len(args) >= 3:
            const1 = (self.const_of(call.args[1][1]) or "").upper()
            if "url" in const1.replace("curlopt_", "").lower():
                v2 = args[2][2]
                self.mk_candidate(
                    "Server-Side Request Forgery",
                    "call",
                    "curl_setopt",
                    _short(args[0][2].origin) or "$curl",
                    2,
                    line,
                    sink_expr=callsite,
                    val=v2,
                )
            return FlowVal()
        target = self.engine.resolve_call(self.func, call, self.types, self)
        skip_generic_sink = target is not None
        if not skip_generic_sink:
            recv_cls = self._receiver_class(call, kind)
            if (
                recv_cls
                and recv_cls in self.engine.class_names
                and not self._class_has_method(recv_cls, (call.target.name or "").lower())
            ):
                # the analyzed class owning this receiver provably has no
                # such method, so generic name-based sink matches (e.g.
                # PDO::exec) cannot apply to it
                skip_generic_sink = True
        None if skip_generic_sink else self._match_sink(kind, call, args, callsite, line)
        ret = self._call_return(call, args, line, target, callsite_short)
        self.calls_text.append((line, callsite_short))
        self.push_signal("call", callsite_short, line)
        return ret

    def _receiver_class(self, call, kind):
        recv = (call.target.receiver or "").strip()
        if kind == "member":
            if recv == "$this" and self.func.cls:
                return self.func.cls.lower()
            if recv.startswith("$") and "->" not in recv:
                t = (self.types or {}).get(recv[1:].lower())
                if t:
                    return t.lower()
        elif kind == "static":
            sc = self.engine._static_scope_class(self.func, recv)
            if sc:
                return sc.lower()
        return None

    def _class_has_method(self, cls, lname):
        seen = set()
        while cls and cls not in seen:
            seen.add(cls)
            if (cls, lname) in self.engine.classmap:
                return True
            cls = self.engine.class_parents.get(cls)
        return False

    def _sink_val(self, name, call, v, line, callsite):
        lname = name.lower()
        if lname not in D.SANITIZERS:
            return v
        ctx, strength = self.sanitizer_of(lname, call)
        out = v.clone()
        out.level = max(v.level, D.LVL_INDIRECT)
        out.sanitizer = lname
        out.sanitizer_ctx = ctx
        out.sanitizer_strength = strength
        out.chain = _chain_join(v.chain, ((line, _short(callsite) + "  [sanitizer " + lname + " (" + strength + ")]"),))
        return out

    def _match_sink(self, kind, call, args, callsite, line):
        name = call.target.name
        lname = name.lower()
        hit = None
        if kind == "function":
            for cat, spec in D.SINKS.items():
                idx = spec["funcs"].get(lname)
                if idx is None:
                    continue
                cand_idxs = range(len(args)) if idx == -1 else (idx,)
                for i in cand_idxs:
                    if i >= len(args):
                        continue
                    named, aexpr, v = args[i]
                    if not v.has_taint():
                        continue
                    cat2 = self._maybe_recat(cat, args)
                    v_final = self._sink_val(name, call, v, line, callsite)
                    self.mk_candidate(cat2, "call", name, "", i, line, sink_expr=callsite, val=v_final)
                    hit = (cat2, name, i, v_final)
                    break
        elif kind in ("member", "static"):
            for cat, spec in D.SINKS.items():
                idx = spec["method_args"].get(lname)
                if idx is None:
                    continue
                recv = call.target.receiver or ""
                if kind == "static" and not recv:
                    continue
                cand_idxs = range(len(args)) if idx == -1 else (idx,)
                for i in cand_idxs:
                    if i >= len(args):
                        continue
                    named, aexpr, v = args[i]
                    if not v.has_taint():
                        continue
                    cat2 = self._maybe_recat(cat, args)
                    v_final = self._sink_val(name, call, v, line, callsite)
                    self.mk_candidate(cat2, kind, name, recv, i, line, sink_expr=callsite, val=v_final, arg_named=named)
                    hit = (cat2, name, i, v_final)
                    break
        return hit

    def _maybe_recat(self, cat, args):
        if cat == "Arbitrary File Write" and len(args) >= 2:
            v1 = args[1][2]
            if v1.has_taint() and "_FILES" in (v1.origin or ""):
                return "Unsafe File Upload"
        return cat

    def _call_return(self, call, args, line, target, callsite_short):
        name = call.target.name
        lname = name.lower()
        argvals = [x[2] for x in args]
        if lname in D.DYN_DISPATCH_FUNCS and target is None and args:
            called = (argvals[0].const or "").strip() if argvals else ""
            tgt2 = CD.resolve_dispatch_callable(self.engine, self.func, called)
            if tgt2 is not None:
                target = tgt2
                args = args[1:]
                argvals = argvals[1:]
                callsite_short = _short(callsite_short) + " [dispatch -> " + tgt2.qualified + "]"
            else:
                CD.builtin_sink_check(self, called, args, line, callsite_short)
        if target is None and lname in D.CALLBACK_FUNCS and args:
            CD.dispatch(self, lname, args, argvals, line, callsite_short)
        if target is not None:
            summary = self.engine.summary_for(target)
            # replay callee sink summaries with caller taints
            CD.replay_callee_sinks(self, target, summary, argvals, None, line)
            ret = FlowVal()
            if summary is not None and summary["ret_params"]:
                for i in summary["ret_params"]:
                    if i < len(argvals) and argvals[i].has_taint():
                        out = argvals[i].clone()
                        out.chain = _chain_join(
                            out.chain,
                            ((line, "return value from " + _short(call.target.name) + "()  [interprocedural]"),),
                        )
                        ret = _merge_val(ret, out)
            return ret
        if lname in D.DYN_DISPATCH_FUNCS and argvals and argvals[0].has_taint():
            self.mk_candidate(
                "Code Injection",
                "call",
                lname,
                "",
                0,
                line,
                sink_expr=_short(callsite_short) + "  [dynamic callable, unresolved target]",
                val=argvals[0],
            )
            self.push_signal("dyn_dispatch", _short(callsite_short), line)
        if lname in D.SANITIZERS and args:
            ctx, strength = self.sanitizer_of(lname, call)
            v0 = args[0][2]
            out = v0.clone() if v0 is not None else FlowVal()
            out.chain = _chain_join(
                v0.chain if v0 else (),
                ((line, _short(callsite_short) + "  [sanitizer " + lname + " (" + strength + ")]"),),
            )
            if v0 is not None and v0.level > D.LVL_NONE:
                out.level = max(v0.level, D.LVL_INDIRECT)
                out.sanitizer = lname
                out.sanitizer_ctx = ctx
                out.sanitizer_strength = strength
                out.origin = v0.origin
                out.origin_kind = v0.origin_kind
                out.source_file = v0.source_file
                out.source_line = v0.source_line
                out.uncertain = ""
                out.src_param = v0.src_param
            return out
        if lname in D.TRANSFORMS and args:
            v0 = args[0][2]
            out = None
            if v0 is not None:
                out = v0.clone()
                out.transforms = _tj(v0.transforms, lname)
                out.chain = _chain_join(v0.chain, ((line, _short(callsite_short) + "  [transform " + lname + "]"),))
            allv = self.all_args_const(call)
            if allv is not None:
                if out is None:
                    out = FlowVal()
                dec = decode_const_transform(lname, allv)
                if dec is not None:
                    out.const = dec
                return out
            return out if out is not None else FlowVal()
        if any(lname.startswith(p) for p in D.PASSTHROUGH_PREFIXES):
            merged = FlowVal()
            for named, aexpr, v in args:
                if v.has_taint():
                    out = v.clone()
                    out.chain = _chain_join(v.chain, ((line, _short(callsite_short) + "  [custom]"),))
                    merged = _merge_val(merged, out)
            return merged
        if lname in ("phpinfo", "show_source", "highlight_file"):
            self.mk_candidate(
                "Information Disclosure",
                "call",
                name,
                "",
                0,
                line,
                sink_expr=callsite_short,
                val=FlowVal(),
                no_taint=True,
            )
            return FlowVal()
        ret = FlowVal()
        if args and any(v.has_taint() for v in argvals):
            ret.uncertain = "opaque result of " + _short(callsite_short) + " with tainted arguments"
        if self.strict:
            for named, aexpr, v in args:
                if v and v.has_taint():
                    out = v.clone()
                    out.uncertain = ""
                    out.origin = v.origin or ("unknown " + _short(callsite_short))
                    out.chain = _chain_join(v.chain, ((line, _short(callsite_short) + "  [opaque result, strict]"),))
                    ret = _merge_val(ret, out)
        return ret

    def const_of(self, e):
        if e is None:
            return None
        if isinstance(e, I.ExprConst) and e.kind in ("string", "num"):
            return str(e.value)
        if isinstance(e, I.ExprConst) and e.kind == "const" and str(e.value) in D.KNOWN_STRING_CONSTS:
            return str(e.value)
        if isinstance(e, I.ExprStrLit):
            if all(p[0] == "str" for p in e.parts):
                return "".join(p[1] for p in e.parts)
            return None
        if isinstance(e, I.ExprBin) and e.op in (".", ",", " ", ""):
            return _join_const(self.const_of(e.left), self.const_of(e.right))
        if isinstance(e, I.ExprCast):
            return self.const_of(e.operand)
        if isinstance(e, I.ExprCall) and e.target.kind == "function" and e.target.name in D.TRANSFORMS and e.args:
            vals = [self.const_of(entry[1]) for entry in e.args]
            if any(v is None for v in vals):
                return None
            return decode_const_transform(e.target.name.lower(), vals)
        return None

    def all_args_const(self, call):
        vals = [self.const_of(a[1]) for a in call.args]
        if any(v is None for v in vals):
            return None
        return vals

    def header_arg_prefix(self, e):
        v = self.const_of(e)
        if v:
            return v
        if isinstance(e, I.ExprBin):
            ln = self.const_of(e.left)
            if ln:
                return ln
            r = self.const_of(e.right)
            if r:
                return r
        if isinstance(e, I.ExprStrLit):
            inner = ""
            for kind, data in e.parts:
                inner += data[1] if kind == "str" else " "
            return inner
        return ""

    def sanitizer_of(self, lname, call):
        spec = D.SANITIZERS.get(lname, {"ctx": "generic", "strength": "strong"})
        ctx = spec["ctx"]
        strength = spec["strength"]
        if ctx == "generic" and len(call.args) >= 2:
            vf = (self.const_of(call.args[1][1]) or "").lower()
            specvf = D.FILTER_VAR_VALIDATORS.get(vf)
            if specvf:
                ctx = specvf["ctx"]
                strength = specvf["strength"]
        return ctx, strength

    def mk_candidate(
        self,
        cat,
        call_kind,
        sink_name,
        receiver,
        arg_idx,
        line,
        sink_expr,
        val,
        arg_named=None,
        no_taint=False,
        const_guard=False,
        file_override=None,
    ):
        if val is None:
            val = FlowVal()
        src_param = getattr(val, "src_param", -1)
        if not no_taint and not val.has_taint():
            return
        if src_param >= 0:
            hit = ParamSinkHit(
                param_idx=src_param,
                cat=cat,
                sink_name=sink_name,
                line=line,
                sink_expr=sink_expr,
                call_kind=call_kind,
                receiver=receiver,
                no_taint=no_taint,
            )
            self.param_sinks.setdefault(src_param, []).append(hit)
            return
        fkey = (
            cat,
            sink_name,
            arg_idx,
            line,
            (sink_expr or "")[:48],
            file_override or self.func.file,
            (getattr(val, "origin", "") or "")[:24],
        )
        if fkey in self.cands:
            return
        self.cands[fkey] = Candidate(
            cat=cat,
            call_kind=call_kind,
            sink_name=sink_name,
            receiver=receiver,
            arg_idx=arg_idx,
            file=file_override or self.func.file,
            line=line,
            func=self.display() + "()",
            val=val,
            sink_expr=sink_expr,
            guards=tuple(self.guard_stack),
            arg_named=arg_named,
            no_taint=no_taint,
            const_guard=const_guard,
        )
        self.signals.append({"sig": "sink", "detail": cat + ":" + sink_name, "line": line})

    def is_const_expr(self, e):
        return self.const_of(e) is not None


def _merge_states(states):
    merged = {}
    for s in states:
        for k, v in s.items():
            merged[k] = _merge_val(merged.get(k), v)
    return merged


def _join_const(ln, r):
    if ln is None or r is None:
        return None
    try:
        return ln + r
    except TypeError:
        return None


def func_key(func):
    return (func.file, func.cls, func.name, func.anon_id, func.line)


def cand_fkey(cand):
    return (
        getattr(cand, "cat", ""),
        getattr(cand, "sink_name", ""),
        getattr(cand, "arg_idx", 0),
        getattr(cand, "line", 0),
        (getattr(cand, "sink_expr", "") or "")[:48],
        getattr(cand, "file", ""),
        (getattr(getattr(cand, "val", None), "origin", "") or "")[:24],
    )


class Engine:
    MAX_PASSES = 8
    MAX_CLOSURE_DEPTH = 6

    def __init__(self, options=None):
        self.options = options or {}
        self.files = []
        self.named_funcs = {}
        self.classmap = {}
        self.class_parents = {}
        self.funcs = {}
        self.summaries = {}
        self.flows = {}
        self.pass_no = 1
        self.warn = []
        self._closure_stack = set()
        self.strict_keys = {}
        self.file_meta = {}
        self.class_names = set()
        self.closure_index = {}  # (file, line) -> closure FuncIR

    def add_file(self, file_ir):
        self.files.append(file_ir)
        self.file_meta[file_ir.path] = {
            "parse_errors": list(file_ir.parse_errors),
            "truncated": bool(getattr(file_ir, "truncated", False)),
            "bytes": int(getattr(file_ir, "size", 0)),
        }
        for cname, parent in (file_ir.class_parents or {}).items():
            self.class_parents[cname.lower()] = parent.lower()
        for cname in file_ir.class_names or []:
            self.class_names.add(cname.lower())
        if file_ir.global_body:
            g = I.FuncIR(name="{global}", body=list(file_ir.global_body), file=file_ir.path, line=1)
            self.funcs[func_key(g)] = g
        for f in file_ir.funcs:
            k = func_key(f)
            if k in self.funcs:
                continue
            self.funcs[k] = f
            if f.closure:
                self.closure_index[(f.file, f.line)] = f
                continue
            if not f.name or f.name == "{closure}":
                continue
            self.named_funcs[f.name.lower()] = f
            if f.cls:
                self.classmap[(f.cls.lower(), f.name.lower())] = f

    def summary_for(self, func):
        return self.summaries.get(func_key(func))

    def _static_scope_class(self, scope_func, scope):
        s = (scope or "").strip()
        if s in ("self", "static", "$this"):
            return (scope_func.cls or "").lower() or None
        if s == "parent":
            return self.class_parents.get((scope_func.cls or "").lower()) or None
        return s.lower() or None if s else None

    def _dyn_callable_target(self, scope_func, call, flow=None):
        if not call.args:
            return None
        if flow is not None:
            txt = flow.const_of(call.args[0][1])
        else:
            e0 = call.args[0][1]
            txt = e0.value if isinstance(e0, I.ExprConst) else None
        if txt is None:
            return None
        txt = txt.strip()
        if "::" in txt:
            cls, meth = txt.split("::", 1)
            cls2 = self._static_scope_class(scope_func, cls)
            if cls2:
                return self.classmap.get((cls2.lower(), meth.lower()))
            return None
        return self.named_funcs.get(txt.lower())

    def resolve_call(self, scope_func, call, objtypes=None, flow=None):
        name = call.target.name
        lname = name.lower()
        kind = call.target.kind
        if kind == "function":
            if lname in D.DYN_DISPATCH_FUNCS:
                return self._dyn_callable_target(scope_func, call, flow)
            return self.named_funcs.get(lname)
        if kind == "static":
            cls = self._static_scope_class(scope_func, call.target.receiver or "")
            if cls:
                return self._resolve_class_method(cls, lname)
            return None
        if kind == "member":
            recv = (call.target.receiver or "").strip()
            if recv == "$this" and scope_func.cls:
                return self._resolve_class_method(scope_func.cls, lname)
            if recv.startswith("$") and "->" not in recv:
                cls = (objtypes or {}).get(recv[1:].lower())
                if cls:
                    return self._resolve_class_method(cls, lname)
            return None
        if kind == "varfunc":
            cv = getattr(flow, "closure_vars", {}) if flow is not None else {}
            return cv.get(lname.lstrip("$"))
        return None

    def _resolve_class_method(self, cls, lname):
        cur = (cls or "").strip().lower()
        seen = set()
        while cur and cur not in seen:
            seen.add(cur)
            f = self.classmap.get((cur, lname))
            if f is not None:
                return f
            cur = self.class_parents.get(cur, "")
        return None

    def run_closure(self, env_flow, cf, use_state, depth=0):
        if cf is None or depth > self.MAX_CLOSURE_DEPTH:
            return
        key = func_key(cf)
        if key in self._closure_stack:
            return
        self._closure_stack.add(key)
        try:
            sub = FuncFlow(self, cf)
            sub.depth = depth
            sub.state = dict(use_state)
            sub.guard_stack = list(env_flow.guard_stack)
            sub.wildcard = env_flow.wildcard
            sub.wildcard_origin = env_flow.wildcard_origin
            sub.walk(cf.body)
            for k, c in sub.cands.items():
                env_flow.cands.setdefault(k, c)
            for k, hits in sub.param_sinks.items():
                merged = env_flow.param_sinks.get(k)
                merged = (merged or []) + list(hits)
                env_flow.param_sinks[k] = merged
            for r in sub.ret_params:
                env_flow.ret_params.add(r)
            env_flow.signals.extend(sub.signals)
            env_flow.calls_text.extend(sub.calls_text)
            return sub
        finally:
            self._closure_stack.discard(key)

    def run(self):
        keys = list(self.funcs.keys())
        summaries = {}
        flows = {}
        probe_flows = {}
        prev_sig = None
        for _pass in range(self.MAX_PASSES):
            self.pass_no = _pass + 1
            for key in keys:
                func = self.funcs[key]
                flow = self._analyze(func, probe=False)
                probe = self._analyze(func, probe=True) if func.params else flow
                summaries[key] = self._build_summary(probe)
                flows[key] = flow
                if func.params:
                    probe_flows[key] = probe
            # summaries from this pass are reachable to the next
            self.summaries = dict(summaries)
            # stop early once the interprocedural summaries reach a fixed
            # point (deep call chains converge one hop per pass)
            sig = self._summary_sig()
            if sig == prev_sig:
                break
            prev_sig = sig
        self.summaries = summaries
        self.flows = flows
        self.probe_flows = probe_flows
        self._strict_recheck(keys)
        return self

    def _summary_sig(self):
        rows = []
        for k, s in self.summaries.items():
            rows.append(
                (
                    k,
                    tuple(sorted((i, len(h)) for i, h in s["sinks"].items())),
                    len(s["ret_params"]),
                    tuple(sorted((p, v) for p, v in (s.get("props") or {}).items())),
                )
            )
        return tuple(sorted(rows, key=repr))

    def _strict_recheck(self, keys):
        """Stage-8 support: an independent conservative pass.

        Treats unknown call results, property reads and array reads as
        potentially attacker-controlled.  Candidates that survive this
        stricter model gain confidence; the rest degrade."""
        for key in keys:
            func = self.funcs[key]
            flow = self.flows.get(key)
            if flow is None or not flow.cands:
                continue
            try:
                sflow = FuncFlow(self, func, strict=True)
                sflow.run()
            except Exception:
                continue
            for ck in sflow.cands:
                self.strict_keys[ck] = True

    def _analyze(self, func, probe=False):
        flow = FuncFlow(self, func, probe=probe)
        try:
            flow.run()
        except RecursionError:
            self.warn.append("recursion limit reached in " + func.file)
        except Exception as e:
            self.warn.append("analysis error in " + func.file + ": " + str(e)[:120])
        return flow

    def _build_summary(self, probe):
        sinks = {}
        for idx, hits in probe.param_sinks.items() if probe else []:
            sinks[idx] = list(hits)
        return {
            "sinks": dict(sinks),
            "ret_params": tuple(sorted(probe.ret_params if probe else ())),
            "props": dict(getattr(probe, "prop_params", {}) if probe else {}),
        }
