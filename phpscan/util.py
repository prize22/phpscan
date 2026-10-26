import contextlib
import hashlib
import os
import re
import sys

MAX_FILE_SIZE = 8 * 1024 * 1024
MAX_PARSE_DEPTH = 4096
MAX_FILE_LINES = 250_000
MAX_TOKENS_PER_FILE = 10_000_000
MAX_AST_NODES = 600_000

MAX_FILE_SIZE_SOFT = 256 * 1024
MAX_FILE_SIZE_SOFT_LINES = 12_000


class AnalysisLimitsExceeded(Exception):
    pass


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def read_project_file(path, max_size=MAX_FILE_SIZE):
    """Read a regular file safely. Symlinks already resolved by discovery."""
    try:
        with open(path, "rb") as f:
            data = f.read(max_size + 1)
    except OSError:
        return None
    if len(data) > max_size:
        return None
    return data


def truncate_for_display(s, limit=72):
    s = re.sub(r"\s+", " ", s)
    if len(s) <= limit:
        return s
    return s[: limit - 3] + "..."


def eprint(*args):
    print(*args, file=sys.stderr)


@contextlib.contextmanager
def swallow_os_errors():
    try:
        yield
    except OSError:
        pass


def is_windows():
    return os.name == "nt"


def relpath_display(target_dir, path):
    try:
        return os.path.relpath(path, target_dir)
    except ValueError:
        return path


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0


def strip_ir(ir):
    """Removes AST-node references from a FileIR tree so it is picklable
    and lighter. Nodes are only needed at parse/closure extraction
    time; the flow engine never touches st.node."""
    for fn in ir.funcs:
        for st in fn.body:
            _strip_stmt(st)
    for st in ir.global_body:
        _strip_stmt(st)
    ir.includes = [(mode, None) for (mode, _e) in ir.includes]
    ir.source = b""


def _strip_expr(e):
    from . import ir as I

    if e is None:
        return
    if isinstance(e, (I.ExprVar,)):
        return
    if isinstance(e, (I.ExprConst, I.ExprStrLit, I.ExprOther)):
        return
    if isinstance(e, I.ExprBin):
        _strip_expr(e.left)
        _strip_expr(e.right)
        return
    if isinstance(e, I.ExprCast):
        _strip_expr(e.operand)
        return
    if isinstance(e, I.ExprSeqAssign):
        _strip_expr(e.value)
        return
    if isinstance(e, I.ExprArr):
        for k, v in e.items:
            _strip_expr(k)
            _strip_expr(v)
        return
    if isinstance(e, I.ExprCond):
        _strip_expr(e.cond)
        _strip_expr(e.then)
        _strip_expr(e.other)
        return
    if isinstance(e, I.ExprCall):
        for named, a in e.args:
            _strip_expr(a)
        return


def _strip_stmt(st):
    st.node = None
    _strip_expr(st.value)
    _strip_expr(st.ret)
    for a in st.args:
        _strip_expr(a)
    for t in st.targets:
        expr = t if not hasattr(t, "ref") else None
        if expr is not None and hasattr(expr, "node"):
            _strip_expr(expr)
    for mode, e in getattr(st, "includes", []) or []:
        _strip_expr(e)
    for s2 in st.stmts:
        _strip_stmt(s2)
