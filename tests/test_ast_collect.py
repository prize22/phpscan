# -*- coding: utf-8 -*-
"""Module-boundary tests for ast_collect (AST declaration collection)."""

from phpscan import ast_collect as A
from phpscan import ir as I
from phpscan import parser as P


def _builder(src, name="t.php"):
    tree = P.parse_source_bytes(src)
    return P.Builder(name, src, tree), tree


def _find(node, node_type):
    if node.type == node_type:
        return node
    for c in node.children:
        found = _find(c, node_type)
        if found is not None:
            return found
    return None


def test_collect_declarations_classes_methods_and_functions():
    src = (
        b"<?php\n"
        b"function top($a) {}\n"
        b"class Base {}\n"
        b"class C extends Base { public function m($b) {} }\n"
    )
    builder, tree = _builder(src)
    file_ir = I.FileIR(path="t.php")
    progs, root_error = A.program_nodes(tree.root_node)
    assert root_error is False

    excluded, classes = A.collect_declarations(builder, progs, file_ir)

    assert classes == {"Base": True, "C": True}
    assert file_ir.class_names == ["Base", "C"]
    assert file_ir.class_parents == {"C": "Base"}
    funcs = {(f.name, f.cls) for f in file_ir.funcs}
    assert ("top", "") in funcs
    assert ("m", "C") in funcs
    assert excluded


def test_program_nodes_reports_document_level_error():
    class _ErrorRoot:
        type = "ERROR"
        is_error = True
        children = ()

    nodes, root_error = A.program_nodes(_ErrorRoot())
    assert nodes == []
    assert root_error is True


def test_attach_closures_registers_and_reuses_closure():
    src = b"<?php\n$g = function ($x) { return $x; };\n"
    builder, tree = _builder(src)
    file_ir = I.FileIR(path="t.php")
    anon = _find(tree.root_node, "anonymous_function")
    assert anon is not None

    stmts = []
    A.attach_closures(builder, anon, stmts, file_ir)
    assert len(stmts) == 1
    assert stmts[0].kind == "closure"
    assert len(file_ir.funcs) == 1
    assert file_ir.funcs[0].closure is True
    assert file_ir.funcs[0].anon_id == anon.id

    A.attach_closures(builder, anon, stmts, file_ir)
    assert len(file_ir.funcs) == 1
    assert [s.ret for s in stmts] == [file_ir.funcs[0], file_ir.funcs[0]]


def test_extract_closures_appends_closure_statements():
    src = b"<?php\n$g = function ($x) { return $x; };\n"
    builder, tree = _builder(src)
    file_ir = I.FileIR(path="t.php")
    anon = _find(tree.root_node, "anonymous_function")
    fn = I.FuncIR(name="outer", body=[I.Stmt(kind="expr", node=anon)])

    A.extract_closures(builder, fn, file_ir)

    assert len(file_ir.funcs) == 1
    assert file_ir.funcs[0].closure is True
    assert fn.body[-1].kind == "closure"
    assert fn.body[-1].ret is file_ir.funcs[0]
