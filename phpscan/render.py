"""Readable rendering of IR expressions for reports and explanations."""

from __future__ import annotations

from . import ir as I


def var_display(ref):
    out = "$" + str(ref.parts[0])
    for p in ref.parts[1:]:
        if p.startswith("="):
            out += "->" + p[1:]
        else:
            out += "[" + p + "]"
    return out


def ref_display(ref):
    if ref is not None:
        return var_display(ref)
    return ""


def expr_repr(e, limit=160):
    if e is None:
        return "?"
    if isinstance(e, I.ExprConst):
        return str(e.value)
    if isinstance(e, I.ExprVar):
        return var_display(e.ref)
    if isinstance(e, I.ExprSeqAssign):
        tgt = ref_display(e.target.ref) if e.target else "?"
        return tgt + " = " + expr_repr(e.value)
    if isinstance(e, I.ExprStrLit):
        txt = _parts_text(e.parts)
        return '"' + txt + '"'
    if isinstance(e, I.ExprBin):
        if e.op in (".", "", "|?"):
            return expr_repr(e.left) + " . " + expr_repr(e.right)
        if e.op in (" ", ","):
            return expr_repr(e.left) + ", " + expr_repr(e.right)
        return expr_repr(e.left) + " " + e.op + " " + expr_repr(e.right)
    if isinstance(e, I.ExprCall):
        name = e.target.name
        r = e.target.receiver or ""
        if e.target.kind == "member":
            expr_repr(_recv(e)) if False else (r if not r.startswith("$_") else varref_from_text(r))
            return _recv_aligned(e, name)
        if e.target.kind == "static":
            return f"{r}::{name}({args_repr(e)})"
        if e.target.kind == "varfunc":
            return f"{name}({args_repr(e)})"
        if e.target.kind == "backtick":
            txt = args_repr(e)
            return "`" + txt + "`"
        return f"{name}({args_repr(e)})"
    if isinstance(e, I.ExprCast):
        return "(" + e.cast_type + ")" + expr_repr(e.operand)
    if isinstance(e, I.ExprCond):
        return expr_repr(e.cond) + " ? " + expr_repr(e.then) + " : " + expr_repr(e.other)
    if isinstance(e, I.ExprArr):
        return (
            "[" + ", ".join((expr_repr(k) + " => " if k is not None else "") + expr_repr(v) for (k, v) in e.items) + "]"
        )
    if isinstance(e, I.ExprOther):
        return e.raw or "{opaque}"
    return "?"


def _recv_aligned(e, name):
    r = e.target.receiver or ""
    if r.startswith("$") and "[" in r:
        vr = varref_from_text(r)
        if vr is not None:
            return var_display(vr) + "->" + name + "(" + args_repr(e) + ")"
    return r + "->" + name + "(" + args_repr(e) + ")"


def _recv(e):
    return None


def _parts_text(parts):
    out = []
    for p in parts:
        if p[0] == "str":
            out.append(p[1])
        elif p[0] == "var":
            name = p[1][0]
            segs = p[1][1:] if len(p) > 1 else ()
            out.append("$" + name + "".join(("->" + s[1:] if s.startswith("=") else "[" + s + "]") for s in segs))
        else:
            out.append("{" + p[1] + "}")
    return "".join(out)


def args_repr(e):
    out = []
    for key, a in e.args:
        if key:
            out.append(key + ": " + expr_repr(a))
        else:
            out.append(expr_repr(a))
    return ", ".join(out)


def varref_from_text(text):
    text = text.strip()
    if not text.startswith("$"):
        return None
    m = text[1:]
    j = 0
    while j < len(m) and (m[j].isalnum() or m[j] == "_"):
        j += 1
    base = m[:j]
    rest = m[j:]
    parts = []
    while rest[:1] == "[":
        k = rest.find("]")
        if k < 0:
            break
        key = rest[1:k].strip().strip("'\"")
        if not key:
            break
        parts.append(key)
        rest = rest[k + 1 :]
    while rest[:2] == "->":
        m2 = rest[2:]
        j2 = 0
        while j2 < len(m2) and (m2[j2].isalnum() or m2[j2] == "_"):
            j2 += 1
        if j2 == 0:
            break
        parts.append("=" + m2[:j2])
        rest = m2[j2:]
    return I.VarRef(parts=(base,) + tuple(parts))
