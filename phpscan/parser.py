"""tree-sitter-php -> IR builder.

Converts the native parse tree of a PHP file into the engine's normalized IR.
This module never evaluates or executes target PHP; it only reads node bytes
to extract names, string literals and guards.
"""

from __future__ import annotations

from typing import Optional

from . import ast_collect as A
from . import ir as I
from . import util as U
from .ast_collect import ParseCancelled
from .ast_collect import _ANON_FN_NODES, _CLASS_NODES

_CALL_KIND = {
    "function_call_expression": "function",
    "member_call_expression": "member",
    "scoped_call_expression": "static",
}

_INCLUDE_KIND = {
    "include_expression": "include",
    "include_once_expression": "include_once",
    "require_expression": "require",
    "require_once_expression": "require_once",
}

_PUNCT = {"(", ")", ",", ";", ":"}

_SKIP = {
    "php_tag",
    "php_end_tag",
    "comment",
    "text",
    "text_interpolation",
    "use_declaration",
    "namespace_use_declaration",
    "namespace_use_clause",
    "namespace_declaration",
    "use_as_clause",
    "CONST",
    "static_modifier",
    "attribute",
    "attribute_list",
    "modifier",
    "visibility_modifier",
    "final_modifier",
    "abstract_modifier",
    "declaration_modifier",
    "**",
}

_PROP_EQ = "="


def node_text(node, src):
    if src is None:
        return b""
    return src[node.start_byte : node.end_byte]


def _norm_key(k):
    k = k.strip().strip("'\"")
    return k


class Builder:
    """Builds one FileIR from a parsed tree."""

    def __init__(self, path, src, tree):
        self.path = path
        self.src = src
        self.tree = tree
        self.budget = 0
        self.depth = 0

    def tick(self):
        self.budget += 1
        if self.budget > U.MAX_AST_NODES:
            raise ParseCancelled("AST node budget exceeded")
        if self.depth > U.MAX_PARSE_DEPTH:
            raise ParseCancelled("AST nesting limit exceeded")

    def make_file(self, display=None, size=0, sha=""):
        file_ir = I.FileIR(path=self.path, display=display or self.path, sha256=sha, size=size)
        root = self.tree.root_node
        progs, root_error = A.program_nodes(root)
        if root_error:
            file_ir.parse_errors.append((1, "document-level parse error"))
            return file_ir

        excluded, classes = A.collect_declarations(self, progs, file_ir)

        for prog in progs:
            try:
                stmts = []
                for c in prog.children:
                    if c.id in excluded or c.type in _SKIP:
                        continue
                    stmts.extend(self._statement(c))
                    self._attach_closures(c, stmts, file_ir)
                file_ir.global_body.extend(stmts)
            except ParseCancelled:
                file_ir.truncated = True
            except RecursionError:
                file_ir.truncated = True
                import sys as _sys

                _sys.setrecursionlimit(max(_sys.getrecursionlimit(), 3000))

        # record top-level syntax errors (tree-sitter ERROR nodes) so
        # structural validation can flag partial parses
        for prog in progs:
            for c in prog.children:
                if c.is_error:
                    file_ir.parse_errors.append((c.start_point[0] + 1, "syntax error"))
                    break

        for fn in list(file_ir.funcs):
            self._extract_closures(fn, file_ir)
        file_ir.classes = list(classes.keys())
        for prog in progs:
            for c in prog.children:
                if c.type in _INCLUDE_KIND:
                    operand = self._include_operand(c)
                    if operand is not None:
                        file_ir.includes.append((_INCLUDE_KIND[c.type], operand))
        return file_ir

    def _extract_closures(self, fn, file_ir):
        return A.extract_closures(self, fn, file_ir)

    def _attach_closures(self, node, stmts, file_ir):
        return A.attach_closures(self, node, stmts, file_ir)

    def _include_operand(self, node):
        exprs = []
        for c in node.children:
            if c.type in _PUNCT or c.type in ("include", "require", "include_once", "require_once", "_once"):
                continue
            if c.type in _INCLUDE_KIND:
                continue
            try:
                e = self._expr(c)
            except ParseCancelled:
                continue
            if e is not None:
                exprs.append(e)
        if not exprs:
            return None
        if len(exprs) == 1:
            return exprs[0]
        cur = exprs[0]
        for e in exprs[1:]:
            cur = I.ExprBin(".", cur, e)
        return cur

    def _function(self, node, cls=""):
        self.tick()
        params = []
        name = ""
        body = []
        static = False
        use_vars = []
        closure = node.type in _ANON_FN_NODES
        for c in node.children:
            if c.type == "name":
                name = self._text(c)
            elif c.type in ("formal_parameters", "parameters"):
                params = self._params(c)
            elif c.type == "compound_statement":
                body = self._block_content(c)
            elif c.type == "use_clause" and closure:
                for cc in c.children:
                    if cc.type == "variable_name":
                        use_vars.append(self._text(cc).lstrip("$"))
            elif c.type == "static_modifier":
                static = True
            elif closure and c.type == "arrow_function_body":
                e = self._expr(c)
                body = [I.Stmt(kind="return", line=node.start_point[0] + 1, ret=e)]
        return I.FuncIR(
            name=name or "{closure}",
            params=params,
            body=body,
            cls=cls,
            static=static,
            line=node.start_point[0] + 1,
            file=self.path,
            closure=closure,
            use_vars=use_vars,
        )

    def _params(self, node):
        params = []
        for c in node.children:
            if c.type in (
                "simple_parameter",
                "variadic_parameter",
                "property_promotion_parameter",
                "classified_parameter",
            ):
                by_ref = False
                pname = ""
                for cc in c.children:
                    if cc.type == "reference_modifier":
                        by_ref = True
                    elif cc.type == "variable_name":
                        pname = self._text(cc).lstrip("$")
                if pname:
                    params.append(I.Param(name=pname, by_ref=by_ref))
        return params

    def _statement(self, node):
        self.depth += 1
        if self.depth > U.MAX_PARSE_DEPTH:
            raise ParseCancelled("statement nesting limit exceeded")
        try:
            self.tick()
            t = node.type
            line = node.start_point[0] + 1
            if t in _SKIP or t in (
                "break_statement",
                "continue_statement",
                "throw_statement",
                "goto_statement",
                "label_statement",
                "declare_statement",
                "global_declaration",
                "string_value",
                "empty_statement",
                "endif",
                "endwhile",
                "endfor",
                "endforeach",
                "endswitch",
            ):
                return []
            if t in _CLASS_NODES or t == "function_definition":
                return []
            if t in ("declaration_list", "case_statement_list"):
                return []
            if t == "expression_statement":
                return self._expression_statement(node)
            if t == "echo_statement":
                args = []
                for c in node.children:
                    if c.type in ("echo", ";", ","):
                        continue
                    if c.type == "sequence_expression":
                        for cc in c.children:
                            if cc.type == ",":
                                continue
                            e = self._expr(cc)
                            if e is not None:
                                args.append(e)
                        continue
                    e = self._expr(c)
                    if e is not None:
                        args.append(e)
                return [I.Stmt(kind="echo", node=node, line=line, args=args)]
            if t in _INCLUDE_KIND:
                operand = self._include_operand(node)
                return [I.Stmt(kind="include", node=node, line=line, mode=_INCLUDE_KIND[node.type], value=operand)]
            if t == "return_statement":
                val = None
                for c in node.children:
                    if c.type not in ("return", ";"):
                        val = self._expr(c)
                        break
                return [I.Stmt(kind="return", node=node, line=line, ret=val)]
            if t == "unset_statement":
                targets = []
                for c in node.children:
                    if c.type in ("(", ")", ",", ";", "unset"):
                        continue
                    if c.type in ("variable_name", "subscript_expression"):
                        r = self._varref(c)
                        if r:
                            targets.append(r)
                return [I.Stmt(kind="unset", node=node, line=line, targets=targets)]
            if t in (
                "if_statement",
                "while_statement",
                "for_statement",
                "do_statement",
                "foreach_statement",
                "switch_statement",
                "try_statement",
                "case_statement",
                "default_statement",
                "alternative_case",
                "elseif_clause",
                "else_clause",
                "catch_clause",
                "finally_clause",
                "switch_block",
            ):
                return self._block_statement(node)
            if t in ("global_declaration", "static_declaration"):
                return []
            stmts = []
            for c in node.children:
                stmts.extend(self._statement(c))
            return stmts
        finally:
            self.depth -= 1

    def _expression_statement(self, node):
        line = node.start_point[0] + 1
        out = []
        for c in node.children:
            t = c.type
            if t == ";":
                continue
            if t == "assignment_expression":
                tgt, val = self._assign_operands(c)
                if tgt is None:
                    continue
                out.append(I.Stmt(kind="assign", node=c, line=line, target=tgt, value=val))
                continue
            if t == "augmented_assignment_expression":
                tgt, val = self._assign_operands(c)
                op = ""
                for cc in c.children:
                    txt = self._text(cc).strip()
                    if txt == "=":
                        continue
                    if (
                        txt in (".=", "+=", "-=", "*=", "/=", "|=", "&=", "^=", "%=", "**=", "<<=", ">>=", "??")
                        and not cc.children
                    ):
                        op = txt
                if tgt is not None and op:
                    out.append(I.Stmt(kind="augassign", node=c, line=line, target=tgt, value=val, op=op))
                continue
            if t in _INCLUDE_KIND:
                operand = self._include_operand(c)
                out.append(I.Stmt(kind="include", node=c, line=line, mode=_INCLUDE_KIND[t], value=operand))
                continue
            if t in _CALL_KIND:
                call = self._call(c)
                if call:
                    out.append(I.Stmt(kind="call", node=c, line=line, call=call))
                continue
            if t in ("echo_statement",):
                out.extend(self._statement(c))
                continue
            if t in (
                "exit_statement",
                "throw_statement",
                "yield_expression",
                "update_expression",
                "increment_expression",
                "clone_expression",
                "instanceof_expression",
                "delete_statement",
                "print_intrinsic",
                "exit_intrinsic",
            ):
                continue
            if t == "eprint_noop":
                continue
            e = self._expr(c)
            if e is not None:
                out.append(I.Stmt(kind="expr", node=c, line=line, value=e))
        return out

    _ASSIGN_OPS = ("=", ".=", "+=", "-=", "*=", "/=", "|=", "&=", "^=", "%=", "**=", "<<=", ">>=", "??=")

    def _assign_operands(self, node):
        kids = list(node.children)
        eq_idx = None
        for i, c in enumerate(kids):
            txt = self._text(c)
            if txt in self._ASSIGN_OPS and not c.children:
                eq_idx = i
                break
        if eq_idx is None or eq_idx == 0 or eq_idx + 1 >= len(kids):
            tgt2, val2 = self._assign_shorthand_operands(kids)
            return tgt2, val2
        tgt = self._lvalue_of(kids[eq_idx - 1])
        rhs = self._expr_of_nodes(kids[eq_idx + 1 :])
        return tgt, rhs

    def _assign_shorthand_operands(self, kids):
        # list / array-destructuring assignment: [$a, $b] = ...
        return None, None

    def _expr_of_nodes(self, nodes):
        exprs = [self._expr(n) for n in nodes]
        exprs = [e for e in exprs if e is not None]
        if not exprs:
            return None
        if len(exprs) == 1:
            return exprs[0]
        cur = exprs[0]
        for e in exprs[1:]:
            cur = I.ExprBin(" ", cur, e)
        return cur

    def _lvalue_of(self, node):
        ref = self._varref(node)
        if ref is None:
            return None
        return I.LV(ref=ref, src_byte=node.start_byte)

    def _block_statement(self, node):
        t = node.type
        line = node.start_point[0] + 1

        def raw(c):
            return self._text(c)

        if t == "if_statement":
            cond = ""
            stmts = []
            alt_stmts = []
            for c in node.children:
                if c.type == "parenthesized_expression":
                    cond = raw(c)
                elif c.type == "compound_statement":
                    blk = I.Stmt(kind="block", block_kind="if", guard=cond, node=node, line=line)
                    blk.stmts = self._block_content(c)
                    stmts.append(blk)
                elif c.type in ("else_clause", "elseif_clause"):
                    stmts.extend(self._block_statement(c))
                elif c.type in ("if", ";"):
                    continue
                else:
                    alt_stmts.extend(self._statement(c))
            if alt_stmts and not any(s.kind == "block" and s.block_kind == "if" for s in stmts):
                blk = I.Stmt(kind="block", block_kind="if", guard=cond, node=node, line=line)
                blk.stmts = alt_stmts
                stmts.insert(0, blk)
            return stmts
        if t in ("elseif_clause", "else_clause"):
            kind = "elseif" if t == "elseif_clause" else "else"
            guard = ""
            compound = None
            trailing = []
            alt_stmts = []
            for c in node.children:
                if c.type == "parenthesized_expression":
                    guard = raw(c)
                elif c.type == "compound_statement":
                    compound = c
                elif c.type in ("else_clause", "elseif_clause"):
                    trailing.extend(self._block_statement(c))
                elif c.type in ("else", "elseif", "if", ";"):
                    continue
                else:
                    alt_stmts.extend(self._statement(c))
            out = []
            if compound is not None:
                blk = I.Stmt(kind="block", block_kind=kind, guard=guard, node=node, line=line)
                blk.stmts = self._block_content(compound)
                out.append(blk)
            elif alt_stmts:
                blk = I.Stmt(kind="block", block_kind=kind, guard=guard, node=node, line=line)
                blk.stmts = alt_stmts
                out.append(blk)
            out.extend(trailing)
            return out
        if t in ("for_statement", "while_statement", "foreach_statement"):
            guard = ""
            compound = None
            alt_stmts = []
            skip_kw = {"for", "while", "foreach", "as", "pair"}
            for c in node.children:
                if c.type == "compound_statement":
                    compound = c
                elif c.type == "parenthesized_expression":
                    guard = raw(c)
                elif c.type in skip_kw or c.type in ("(", ")"):
                    continue
                elif compound is None and c.type not in (";", ":"):
                    alt_stmts.extend(self._statement(c))
            blk = I.Stmt(kind="block", block_kind=t.split("_")[0], guard=guard, node=node, line=line)
            if compound is not None:
                blk.stmts = self._block_content(compound)
            else:
                blk.stmts = alt_stmts
            return [blk]
        if t == "do_statement":
            compound = None
            inner_alt = []
            condat = ""
            for c in node.children:
                if c.type == "compound_statement":
                    compound = c
                elif c.type == "parenthesized_expression":
                    condat = raw(c)
                elif c.type == "do" or c.type == "while" or c.type == ";":
                    continue
                elif compound is None:
                    inner_alt.extend(self._statement(c))
                    break
            blk = I.Stmt(kind="block", block_kind="do", guard=condat, node=node, line=line)
            if compound is not None:
                blk.stmts = self._block_content(compound)
            else:
                blk.stmts = inner_alt
            return [blk]
        if t == "switch_statement":
            guard = ""
            out = []
            swblk = None
            alt_stmts = []
            for c in node.children:
                if c.type == "parenthesized_expression":
                    guard = raw(c)
                elif c.type == "switch_block":
                    swblk = c
                elif c.type in ("switch", ";"):
                    continue
                elif c.type in ("case_statement", "default_statement", "alternative_case"):
                    out.extend(self._block_statement(c))
                else:
                    alt_stmts.extend(self._statement(c))
            blk = I.Stmt(kind="block", block_kind="switch", guard=guard, node=node, line=line)
            if swblk is not None:
                blk.stmts = self._block_content(swblk)
            out.insert(0, blk)
            return out
        if t in ("case_statement", "default_statement", "alternative_case"):
            blk = I.Stmt(kind="block", block_kind="case", node=node, line=line)
            blk.stmts = self._block_content(node)
            return [blk]
        if t == "switch_block":
            blk = I.Stmt(kind="block", block_kind="switchbody", node=node, line=line)
            blk.stmts = self._block_content(node)
            return [blk]
        if t == "try_statement":
            stmt = I.Stmt(kind="block", block_kind="try", node=node, line=line)
            for c in node.children:
                if c.type == "compound_statement":
                    stmt.stmts = self._block_content(c)
                    break
            out = [stmt]
            for c in node.children:
                if c.type in ("catch_clause", "finally_clause"):
                    out.extend(self._block_statement(c))
            return out
        if t in ("catch_clause", "finally_clause"):
            blk = I.Stmt(kind="block", block_kind="catch", node=node, line=line)
            blk.stmts = self._block_content(node)
            return [blk]
        stmts = []
        for c in node.children:
            stmts.extend(self._statement(c))
        return stmts

    def _block_content(self, node):
        stmts = []
        self.depth += 1
        try:
            for c in node.children:
                if c.type in _SKIP or c.type in ("case", "default"):
                    continue
                stmts.extend(self._statement(c))
                self._attach_closures(c, stmts, None)
        finally:
            self.depth -= 1
        return stmts

    def _call(self, node):
        t = node.type
        line = node.start_point[0] + 1
        if t == "function_call_expression":
            head = None
            args_node = None
            children = list(node.children)
            for c in children:
                if c.type == "arguments":
                    args_node = c
                elif head is None:
                    head = c
            name_txt = self._text(head) if head is not None else ""
            args = self._args(args_node)
            if head is None:
                tgt = I.CallTarget(kind="dynamic", name=name_txt)
            elif head.type in ("variable_name", "dynamic_variable_name"):
                tgt = I.CallTarget(kind="varfunc", name=name_txt)
            elif head.type == "name":
                tgt = I.CallTarget(kind="function", name=name_txt)
            else:
                tgt = I.CallTarget(kind="dynamic", name=name_txt)
            return I.ExprCall(target=tgt, args=args, src_byte=node.start_byte, src_line=line)
        if t == "member_call_expression":
            children = list(node.children)
            args_node = next((c for c in children if c.type == "arguments"), None)
            recv_node = None
            mname = ""
            after_arrow = False
            for c in children:
                if c.type in ("->", "?->"):
                    after_arrow = True
                    continue
                if c.type == "arguments":
                    continue
                if recv_node is None:
                    recv_node = c
                    continue
                if after_arrow and not mname:
                    mname = self._text(c)
                    break
            recv_txt = self._text(recv_node) if recv_node is not None else ""
            args = self._args(args_node)
            tgt = I.CallTarget(kind="member", name=mname, receiver=recv_txt)
            return I.ExprCall(target=tgt, args=args, src_byte=node.start_byte, src_line=line)
        if t == "scoped_call_expression":
            args_node = None
            names = []
            for c in node.children:
                if c.type == "arguments":
                    args_node = c
                elif c.type == "::":
                    continue
                elif c.type == "relative_scope":
                    inner = [cc for cc in c.children if cc.type not in ("(", ")", "::")]
                    if inner:
                        names.append(self._text(inner[-1]))
                elif c.type in ("name", "variable_name", "dynamic_variable_name"):
                    names.append(self._text(c))
            scope = names[0] if names else ""
            mname = names[1] if len(names) > 1 else ""
            args = self._args(args_node)
            tgt = I.CallTarget(kind="static", name=mname, receiver=scope)
            return I.ExprCall(target=tgt, args=args, src_byte=node.start_byte, src_line=line)
        return None

    def _args(self, args_node):
        args: list[tuple[Optional[str], object]] = []
        if args_node is None:
            return args
        for c in args_node.children:
            if c.type in _PUNCT or c.type == "comment":
                continue
            if c.type == "argument":
                kids = list(c.children)
                if len(kids) >= 2 and any(k.type == ":" for k in kids):
                    named = self._text(kids[0])
                    e = self._expr(kids[-1])
                    if e is not None:
                        args.append((named, e))
                        continue
                sub = [k for k in kids if k.type not in _PUNCT]
                e = self._expr_of_nodes(sub)
                if e is not None:
                    args.append((None, e))
                continue
            if c.type == "spread":
                for k in c.children:
                    e = self._expr(k)
                    if e is not None:
                        args.append((None, e))
                continue
            e = self._expr(c)
            if e is not None:
                args.append((None, e))
        return args

    def _expr(self, node):
        self.depth += 1
        try:
            self.tick()
            t = node.type
            if t == "parenthesized_expression":
                for c in node.children:
                    if c.type in ("(", ")"):
                        continue
                    if c.type in (",",):
                        continue
                    return self._expr(c)
                return None
            if t == "variable_name":
                ref = self._varref(node)
                if ref is None:
                    return I.ExprOther(raw=self._text(node), vars=[])
                return I.ExprVar(ref=ref)
            if t == "dynamic_variable_name":
                raw = self._text(node)
                inner: list[I.VarRef] = []
                for c in node.children:
                    if c.type == "$":
                        continue
                    e = self._expr(c)
                    if isinstance(e, I.ExprVar):
                        inner.append(e.ref)
                    else:
                        inner = []
                        break
                return I.ExprOther(raw=raw, vars=inner if inner else [])
            if t == "subscript_expression":
                ref = self._varref(node)
                if ref is not None:
                    return I.ExprVar(ref=ref)
                return I.ExprOther(raw=self._text(node), vars=self._vars_in(node))
            if t in ("member_access_expression", "nullsafe_member_access_expression"):
                kids = list(node.children)
                obj = kids[0] if kids else None
                mnode = None
                for c in kids:
                    if c.type in ("->", "?->"):
                        continue
                    if c is not obj:
                        mnode = c
                        break
                pname = self._text(mnode) if mnode is not None else ""
                if obj is not None and obj.type in ("variable_name", "subscript_expression"):
                    ref = self._varref(obj)
                    if ref and pname:
                        parts = ref.parts + (_PROP_EQ + pname,)
                        return I.ExprVar(
                            ref=I.VarRef(
                                parts=parts,
                                is_property=True,
                                src_byte=node.start_byte,
                                src_line=node.start_point[0] + 1,
                            )
                        )
                return I.ExprOther(raw=self._text(node), vars=self._vars_in(node))
            if t == "name":
                txt = self._text(node)
                return I.ExprConst(kind="const", value=txt, raw=txt)
            if t in ("integer", "float", "octal", "hexadecimal", "binary"):
                return I.ExprConst(kind="num", value=self._text(node), raw=self._text(node))
            if t in ("true", "false", "null"):
                return I.ExprConst(kind="bool", value=t, raw=t)
            if t in ("string", "encapsed_string"):
                return self._string_expr(node)
            if t == "binary_expression":
                op = ""
                operands = []
                for c in node.children:
                    txt = self._text(c).strip()
                    if txt in BINARY_OPS and not c.children:
                        op = txt
                        continue
                    operands.append(c)
                if len(operands) == 2:
                    ln = self._expr(operands[0])
                    r = self._expr(operands[1])
                    if ln is not None and r is not None:
                        return I.ExprBin(op if op else "|?", ln, r)
                return I.ExprOther(raw=self._text(node), vars=self._vars_in(node))
            if t == "assignment_expression":
                tgt, val = self._assign_operands(node)
                if tgt is None:
                    return I.ExprOther(raw=self._text(node), vars=self._vars_in(node))
                return I.ExprSeqAssign(target=tgt, value=val)
            if t == "augmented_assignment_expression":
                tgt, val = self._assign_operands(node)
                if tgt is None:
                    return I.ExprOther(raw=self._text(node), vars=self._vars_in(node))
                op = ""
                for cc in node.children:
                    txt = self._text(cc).strip()
                    if (
                        txt in (".=", "+=", "-=", "*=", "/=", "|=", "&=", "^=", "%=", "**=", "<<=", ">>=", "??")
                        and not cc.children
                    ):
                        op = txt
                return _aug_expr(op, tgt, val)
            if t in _CALL_KIND:
                call = self._call(node)
                if call is not None:
                    return call
                return I.ExprOther(raw=self._text(node), vars=[])
            if t == "array_creation_expression":
                items = []
                for c in node.children:
                    if c.type == "array_element_initializer":
                        key = None
                        val = None
                        kids = [k for k in c.children if k.type not in ("=>", ",")]
                        if len(kids) == 2 and any(k.type == "=>" for k in c.children):
                            key = self._expr(kids[0])
                            val = self._expr(kids[1])
                        elif kids:
                            val = self._expr(kids[-1])
                        if val is not None:
                            items.append((key, val))
                    elif c.type not in ("array", "(", ")", "[", "]", ","):
                        e = self._expr(c)
                        if e is not None:
                            items.append((None, e))
                return I.ExprArr(items=items)
            if t == "shell_command_expression":
                bparts = []
                for c in node.children:
                    if c.type == "string_content":
                        bparts.append(("str", src_slice(self.src, c).decode("utf-8", "replace")))
                    elif c.type in ("variable_name", "subscript_expression"):
                        ref = self._varref(c)
                        if ref is not None:
                            bparts.append(("var", ref.parts))
                    elif c.type in ("interpolation", "template_expression"):
                        rawx = self._text(c)
                        inner_ref = None
                        for cc in c.children:
                            if cc.type not in ("{", "}", "$"):
                                inner_ref = self._varref(cc)
                                if inner_ref is not None:
                                    break
                        if inner_ref is not None:
                            bparts.append(("var", inner_ref.parts))
                        else:
                            bparts.append(("expr", rawx.strip("{} ")))
                if not bparts:
                    bparts = [("str", self._text(node).strip("`"))]
                return I.ExprCall(
                    target=I.CallTarget(kind="backtick", name="`", receiver=None),
                    args=[(None, I.ExprStrLit(raw="", parts=tuple(bparts)))],
                    src_byte=node.start_byte,
                    src_line=node.start_point[0] + 1,
                )
            if t == "cast_expression":
                ctype = ""
                operand = None
                for c in node.children:
                    if c.type == "cast_type":
                        ctype = self._text(c).strip()
                    elif c.type not in ("(", ")"):
                        operand = self._expr(c)
                return I.ExprCast(cast_type=ctype, operand=operand or I.ExprConst("other", ""))
            if t == "conditional_expression":
                cs = []
                for c in node.children:
                    if c.type in ("?", ":", "??="):
                        continue
                    e = self._expr(c)
                    if e is not None:
                        cs.append(e)
                if len(cs) >= 3:
                    return I.ExprCond(cs[0], cs[1], cs[2])
                if len(cs) == 2:
                    return I.ExprCond(None, cs[0], cs[1])
                return I.ExprOther(raw=self._text(node), vars=self._vars_in(node))
            if t in _ANON_FN_NODES:
                return I.ExprOther(raw=self._text(node), vars=self._vars_in(node), closure_line=node.start_point[0] + 1)
            if t == "object_creation_expression":
                cname = ""
                seen_new = False
                args_node = None
                for c in node.children:
                    if c.type == "new":
                        seen_new = True
                        continue
                    if c.type == "arguments":
                        args_node = c
                        continue
                    if seen_new and not cname and c.type == "name":
                        cname = self._text(c)
                return I.ExprOther(
                    raw=self._text(node), vars=self._vars_in(node), new_class=cname, new_args=self._args(args_node)
                )
            if t in (
                "clone_expression",
                "yield_expression",
                "update_expression",
                "increment_expression",
                "instanceof_expression",
                "throw_expression",
                "delete_statement",
                "list_expression",
                "array_destructuring",
                "print_intrinsic",
                "exit_statement",
                "match_expression",
                "compound_string",
            ):
                return I.ExprOther(raw=self._text(node), vars=self._vars_in(node))
            if node.is_error or node.is_missing:
                return I.ExprOther(raw=self._text(node), vars=self._vars_in(node))
            stmts = []
            for c in node.children:
                if c.type in _PUNCT:
                    continue
                e = self._expr(c)
                if e is not None:
                    stmts.append(e)
            if not stmts:
                return I.ExprOther(raw=self._text(node), vars=self._vars_in(node))
            if len(stmts) == 1:
                return stmts[0]
            cur = stmts[0]
            for e in stmts[1:]:
                cur = I.ExprBin(" ", cur, e)
            return cur
        finally:
            self.depth -= 1

    def _string_expr(self, node):
        raw = self._text(node)
        inner = raw[1:-1] if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"') else raw
        parts = self._string_parts_structure(node, inner)
        return I.ExprStrLit(raw=inner, parts=parts)

    def _string_parts_structure(self, node, inner):
        parts = []
        has_structure = False
        for c in node.children:
            t = c.type
            if t == "string_content":
                txt = src_slice(self.src, c).decode("utf-8", "replace")
                if node.type == "string":
                    txt = _php_unescape(txt)
                parts.append(("str", txt))
            elif t in ("variable_name", "subscript_expression"):
                ref = self._varref(c)
                if ref is not None:
                    parts.append(("var", ref.parts))
                    has_structure = True
                else:
                    parts.append(("expr", self._text(c)))
                    has_structure = True
            elif t in ("interpolation", "template_expression"):
                rawx = self._text(c)
                ref = None
                for cc in c.children:
                    if cc.type not in ("{", "}", "$"):
                        ref = self._varref(cc)
                        if ref is not None:
                            break
                if ref is not None:
                    parts.append(("var", ref.parts))
                else:
                    parts.append(("expr", rawx.strip("{} ")))
                has_structure = True
        if not has_structure:
            return (("str", inner),)
        return tuple(parts)

    def _vars_in(self, node):
        vars = []
        for c in node.children:
            if c.type == "variable_name":
                r = self._varref(c)
                if r:
                    vars.append(r)
            else:
                vars.extend(self._vars_in(c))
        return vars

    def _varref(self, node):
        t = node.type
        if t == "variable_name":
            base = self._text(node).lstrip("$")
            if not base:
                return None
            return I.VarRef(parts=(base,), src_byte=node.start_byte, src_line=node.start_point[0] + 1)
        if t == "dynamic_variable_name":
            inner = None
            for c in node.children:
                if c.type in ("variable_name", "dynamic_variable_name"):
                    r = self._varref(c)
                    if r:
                        inner = r
            if inner:
                nm = (
                    "$" + inner.base
                    if t == "dynamic_variable_name" and not inner.parts[0].startswith("$")
                    else inner.base
                )
                return I.VarRef(parts=(nm,), src_byte=node.start_byte, src_line=node.start_point[0] + 1)
            return None
        if t == "subscript_expression":
            kids = list(node.children)
            if not kids:
                return None
            first = kids[0]
            if first.type not in (
                "variable_name",
                "subscript_expression",
                "member_access_expression",
                "nullsafe_member_access_expression",
            ):
                return None
            r = self._varref(first)
            if r is None:
                return None
            key = ""
            for c in kids[1:]:
                if c.type in ("[", "]", "{", "}"):
                    continue
                key = self._key_text(c)
                break
            if key == "" and len(kids) > 1:
                parts = r.parts
            else:
                parts = r.parts + ((key,) if key else ())
            return I.VarRef(parts=parts, src_byte=node.start_byte, src_line=node.start_point[0] + 1)
        if t in ("member_access_expression", "nullsafe_member_access_expression"):
            kids = list(node.children)
            obj = kids[0] if kids else None
            mnode = None
            for c in kids:
                if c.type in ("->", "?->"):
                    continue
                if c is not obj:
                    mnode = c
                    break
            pname = self._text(mnode) if mnode is not None else ""
            if obj is None or pname == "":
                return None
            if obj.type in ("variable_name", "subscript_expression", "dynamic_variable_name"):
                r = self._varref(obj)
                if r:
                    return I.VarRef(
                        parts=r.parts + (_PROP_EQ + pname,),
                        is_property=True,
                        src_byte=node.start_byte,
                        src_line=node.start_point[0] + 1,
                    )
            return None
        return None

    def _key_text(self, node):
        if node is None:
            return ""
        if node.type in ("string", "encapsed_string"):
            v = string_literal_value(node, self.src)
            return v if v is not None else ""
        if node.type in ("integer", "float"):
            return _q(self._text(node))
        return ""

    def _text(self, node):
        return node_text(node, self.src).decode("utf-8", "replace")


def _aug_expr(op, tgt, val):
    return I.ExprSeqAssign(target=tgt, value=val)


def src_slice(src, node):
    if src is None or node is None:
        return b""
    return src[node.start_byte : node.end_byte]


def _q(b):
    return b.decode("utf-8", "replace") if isinstance(b, bytes) else b


BINARY_OPS = {
    ".",
    "+",
    "-",
    "*",
    "/",
    "%",
    "**",
    "==",
    "===",
    "!=",
    "!==",
    ">",
    "<",
    ">=",
    "<=",
    "<=>",
    "&&",
    "||",
    "and",
    "or",
    "xor",
    "??",
    "|",
    "&",
    "^",
    "<<",
    ">>",
    "instanceof",
    ",",
}


def string_literal_value(node, src):
    """Static value of a string/number token node; None if not static."""
    if node is None or src is None:
        return None
    t = node_text(node, src).decode("utf-8", "replace")
    if node.type == "integer":
        return t
    if node.type in ("true", "false", "null"):
        return t
    if node.type in ("string", "encapsed_string"):
        contents = [script for script in node.children if script.type == "string_content"]
        dynamic = any(
            c.type in ("variable_name", "subscript_expression", "interpolation", "template_expression")
            for c in node.children
        )
        if not contents:
            return None
        body = "".join(src[c.start_byte : c.end_byte].decode("utf-8", "replace") for c in contents)
        if dynamic:
            return body
        return _php_unescape(body)
    return None


def _php_unescape(body):
    if "\\" not in body:
        return body
    try:
        body.encode("ascii")
    except UnicodeEncodeError:
        return body
    out = []
    i = 0
    n = len(body)
    esc = {
        "n": "\n",
        "t": "\t",
        "r": "\r",
        '"': '"',
        "'": "'",
        "\\": "\\",
        "v": "\v",
        "f": "\f",
        "e": "\x1b",
        "0": "\x00",
    }
    while i < n:
        c = body[i]
        if c == "\\" and i + 1 < n:
            nxt = body[i + 1]
            if nxt in esc:
                out.append(esc[nxt])
                i += 2
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _scan_interp(inner):
    parts: list[tuple[str, object]] = []
    buf = []
    i = 0
    n = len(inner)
    while i < n:
        c = inner[i]
        if c == "\\":
            if i + 1 < n and inner[i + 1] in ("{", "$"):
                buf.append(inner[i + 1])
                i += 2
                continue
            buf.append(inner[i + 1] if i + 1 < n and inner[i + 1] == c else inner[min(i + 1, n - 1)])
            i += 2
            continue
        if c == "$" and i + 1 < n and (inner[i + 1].isalpha() or inner[i + 1] == "_"):
            j = i + 1
            m = _simple_var_end(inner, j)
            name = inner[j:m]
            k = m
            segs = []
            while k < n:
                if inner[k] == "[":
                    depth = 0
                    ln = k
                    while ln < n:
                        if inner[ln] == "[":
                            depth += 1
                        elif inner[ln] == "]":
                            depth -= 1
                            if depth == 0:
                                break
                        ln += 1
                    if depth != 0:
                        break
                    key = inner[k + 1 : ln].strip().strip("'\"")
                    if not key or not all(ch.isalnum() or ch == "_" for ch in key):
                        break
                    segs.append(key)
                    k = ln + 1
                    continue
                if inner[k] == "-" and k + 1 < n and inner[k + 1] == ">":
                    m2 = _simple_var_end(inner, k + 2)
                    if m2 > k + 2:
                        segs.append(_PROP_EQ + inner[k + 2 : m2])
                        k = m2
                        continue
                break
            if buf:
                parts.append(("str", "".join(buf)))
                buf = []
            parts.append(("var", (name,) + tuple(segs)))
            i = k
            continue
        if c == "{" and i + 1 < n and inner[i + 1] == "$":
            depth = 0
            k = i
            while k < n:
                if inner[k] == "{":
                    depth += 1
                elif inner[k] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            if depth == 0:
                expr = inner[i : k + 1].strip("{} ").strip()
                if buf:
                    parts.append(("str", "".join(buf)))
                    buf = []
                parts.append(("expr", expr))
                i = k + 1
                continue
            buf.append(c)
            i += 1
            continue
        buf.append(c)
        i += 1
    if buf:
        parts.append(("str", "".join(buf)))
    return tuple(parts)


def _simple_var_end(s, i):
    j = i
    n = len(s)
    while j < n and (s[j].isalnum() or s[j] == "_"):
        j += 1
    return j


def parse_source_bytes(src):
    import tree_sitter_php
    from tree_sitter import Language, Parser

    lang = Language(tree_sitter_php.language_php())
    p = Parser(lang)
    return p.parse(src)


def parse_file_bytes(display, src):
    """Parses a file's bytes and fills sha256/size into the FileIR."""
    tree = parse_source_bytes(src)
    return Builder(display, src, tree).make_file(display=display, size=len(src), sha=U.sha256_bytes(src))
