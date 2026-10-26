from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(slots=True)
class VarRef:
    """A concrete variable reference: $base[path...] or $base->prop..."""

    parts: tuple[str, ...]
    is_property: bool = False
    src_byte: int = 0
    src_line: int = 0

    @property
    def base(self):
        return self.parts[0]

    def key(self):
        return "$" + "/".join(self.parts)

    def display(self):
        return "$" + self.parts[0] + "".join(("->" + p if self.is_property else "[" + p + "]") for p in self.parts[1:])

    def is_superglobal(self):
        return self.base.startswith("_")


@dataclass(slots=True)
class ExprVar:
    ref: VarRef


@dataclass(slots=True)
class ExprConst:
    kind: str  # 'string' | 'num' | 'const' | 'bool' | 'other'
    value: Any
    raw: str = ""


@dataclass(slots=True)
class ExprStrLit:
    """String literal with optional interpolation parts."""

    raw: str
    parts: tuple = ()  # ('str', text) | ('var', VarRef) | ('expr', raw)


@dataclass(slots=True)
class ExprBin:
    op: str
    left: Any
    right: Any


@dataclass(slots=True)
class ExprCast:
    cast_type: str
    operand: Any


@dataclass(slots=True)
class ExprSeqAssign:
    """Assignment used as an expression: `while ($row = f())`."""

    target: Any  # LV]
    value: Any


@dataclass(slots=True)
class ExprArr:
    items: list  # list of (key|None, Expr)


@dataclass(slots=True)
class ExprCond:
    cond: Any
    then: Any
    other: Any


@dataclass(slots=True)
class CallTarget:
    """Resolved textual description of a call site."""

    kind: str  # 'function' | 'member' | 'static' | 'varfunc' | 'backtick' | 'dynamic'
    name: str
    receiver: Optional[str] = None


@dataclass(slots=True)
class ExprCall:
    target: CallTarget
    args: list  # list of (key|None, Expr)
    src_byte: int = 0
    src_line: int = 0
    in_interp: bool = False


@dataclass(slots=True)
class ExprOther:
    raw: str
    vars: list = field(default_factory=list)  # VarRefs seen inside
    new_class: str = ""  # set when expression is `new ClassName(...)`
    new_args: list = field(default_factory=list)
    closure_line: int = 0  # set when expression is `function (...) {...}`


@dataclass(slots=True)
class LV:
    """Assignment target."""

    ref: VarRef
    src_byte: int = 0


@dataclass
class Stmt:
    kind: str  # assign|augassign|call|include|echo|return|unset|block|global_stmt...
    node: Any = None  # tree-sitter node
    line: int = 0
    # assign / augassign
    target: Optional[LV] = None
    value: Any = None
    op: str = ""
    # call
    call: Optional[ExprCall] = None
    # include
    mode: str = "include"  # include/include_once/require/require_once
    # echo
    args: list = field(default_factory=list)
    # block
    block_kind: str = ""
    guard: str = ""
    stmts: list = field(default_factory=list)
    # return
    ret: Any = None
    # unset
    targets: list = field(default_factory=list)
    # closure handled inline


@dataclass(slots=True)
class Param:
    name: str
    by_ref: bool = False


@dataclass(slots=True)
class FuncIR:
    name: str
    params: list = field(default_factory=list)  # list[Param]
    body: list = field(default_factory=list)  # list[Stmt]
    cls: str = ""  # class name or ""
    static: bool = False
    line: int = 0
    file: str = ""
    closure: bool = False
    use_vars: list = field(default_factory=list)  # closure use($x)
    returns_ref: bool = False
    fid: str = ""
    anon_id: int = 0

    @property
    def qualified(self):
        return self.file + "#" + (self.cls + "::" if self.cls else "") + self.name

    def qual_key(self):
        return (self.file, self.cls, self.name)


@dataclass
class FileIR:
    path: str
    display: str = ""
    sha256: str = ""
    size: int = 0
    lines: int = 0
    funcs: list = field(default_factory=list)  # list[FuncIR]
    global_body: list = field(default_factory=list)  # list[Stmt] top-level statements
    classes: list = field(default_factory=list)  # list[str]
    class_parents: dict = field(default_factory=dict)  # cls -> extends name
    class_names: list = field(default_factory=list)  # every declared class
    includes: list = field(default_factory=list)  # list[(mode, Expr)]
    parse_errors: list = field(default_factory=list)  # list[(line, text)]
    truncated: bool = False
    parse_ms: float = 0.0
    source: bytes = b""

    @property
    def ok(self):
        return not self.parse_errors and not self.truncated
