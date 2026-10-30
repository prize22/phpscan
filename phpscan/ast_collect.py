"""AST collection helpers for the PHP IR builder.

Walks the tree-sitter parse tree to collect class, method, function and
closure declarations. The collector operates on a Builder-like object that
supplies the expression/statement/text parsing primitives; it does not
import ``parser`` so the dependency direction stays ``parser -> ast_collect``.
"""

from __future__ import annotations

from . import ir as I

_CLASS_NODES = ("class_declaration", "trait_declaration", "interface_declaration", "enum_declaration")

_METHODS_NODE = ("method_declaration",)

_ANON_FN_NODES = (
    "anonymous_function",
    "arrow_function",
    "anonymous_function_creation_expression",
    "arrow_function_creation_expression",
)


class ParseCancelled(Exception):
    pass


def program_nodes(root):
    """Return (program nodes, document-level error) for a tree-sitter root."""
    nodes = []
    if root.type == "document":
        for c in root.children:
            if c.type == "php":
                for cc in c.children:
                    if cc.type == "program":
                        nodes.append(cc)
    elif root.type == "program":
        nodes.append(root)
    elif root.is_error:
        return nodes, True
    return nodes, False


def collect_declarations(builder, program_nodes, file_ir):
    """Collect classes, methods and top-level functions into ``file_ir``."""
    excluded = set()
    classes = {}

    def collect(node, cur_class):
        if node.type in _CLASS_NODES:
            excluded.add(node.id)
            cname = ""
            parent = ""
            for c in node.children:
                if c.type == "name":
                    cname = builder._text(c)
                    break
            for c in node.children:
                if c.type == "base_clause":
                    for cc in c.children:
                        if cc.type == "name":
                            parent = builder._text(cc)
                            break
            if cname:
                classes[cname] = True
                file_ir.class_names.append(cname)
                if parent:
                    file_ir.class_parents[cname] = parent
            to_scan = []
            for c in node.children:
                if c.type in ("declaration_list", "enum_declaration_list", "declaration_list,"):
                    to_scan.append(c)
            for dl in to_scan:
                for cc in dl.children:
                    if cc.type in _METHODS_NODE:
                        try:
                            fn = builder._function(cc, cls=cname)
                            if fn.name and fn.name != "{closure}":
                                file_ir.funcs.append(fn)
                        except ParseCancelled:
                            file_ir.truncated = True
            for c in node.children:
                if c.type in _CLASS_NODES:
                    builder.depth += 1
                    try:
                        collect(c, cur_class)
                    finally:
                        builder.depth -= 1
            return
        if node.type == "function_definition":
            excluded.add(node.id)
            try:
                fn = builder._function(node, cls="")
                if fn.name:
                    file_ir.funcs.append(fn)
            except ParseCancelled:
                file_ir.truncated = True
            return
        for c in node.children:
            collect(c, cur_class)

    for prog in program_nodes:
        try:
            collect(prog, "")
        except ParseCancelled:
            file_ir.truncated = True
        except RecursionError:
            file_ir.truncated = True
            import sys as _sys

            _sys.setrecursionlimit(max(_sys.getrecursionlimit(), 3000))

    return excluded, classes


def extract_closures(builder, fn, file_ir):
    found = []

    def rec(n):
        if n.type in _ANON_FN_NODES:
            found.append(n)
            for c in n.children:
                if c.type in _ANON_FN_NODES:
                    rec(c)
            return
        for c in n.children:
            rec(c)

    for st in fn.body:
        if st.node is not None:
            rec(st.node)
    closure_sts = []
    for anon in found:
        existing = [f for f in file_ir.funcs if f.closure and f.anon_id == anon.id]
        if existing:
            cf = existing[0]
        else:
            try:
                cf = builder._function(anon, cls="{closure}")
            except ParseCancelled:
                continue
            cf.closure = True
            cf.file = builder.path
            cf.anon_id = anon.id
            file_ir.funcs.append(cf)
        closure_sts.append(I.Stmt(kind="closure", line=cf.line, ret=cf))
    fn.body.extend(closure_sts)


def attach_closures(builder, node, stmts, file_ir):
    found = []

    def rec(n):
        if n.type in _ANON_FN_NODES:
            found.append(n)
            for c in n.children:
                if c.type in _ANON_FN_NODES:
                    rec(c)
            return
        for c in n.children:
            rec(c)

    rec(node)
    for anon in found:
        existing = [f for f in file_ir.funcs if f.closure and f.anon_id == anon.id]
        if not existing:
            try:
                cf = builder._function(anon, cls="{closure}")
            except ParseCancelled:
                continue
            cf.closure = True
            cf.file = builder.path
            cf.anon_id = anon.id
            file_ir.funcs.append(cf)
        else:
            cf = existing[0]
        st = I.Stmt(kind="closure", line=cf.line, ret=cf)
        stmts.append(st)
