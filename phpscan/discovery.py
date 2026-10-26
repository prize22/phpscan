"""Target discovery: deterministic, symlink-safe PHP file walk."""

from __future__ import annotations

import os

PHP_EXTS = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps", ".inc"}
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor_bin", ".phpscan-cache"}


def discover(root, max_files=20000):
    """Returns sorted list of PHP file paths under root."""
    roots = [root]
    if os.path.isfile(root):
        ext = os.path.splitext(root)[1].lower()
        return [root] if ext in PHP_EXTS else []
    out = []
    while roots:
        cur = roots.pop(0)
        try:
            entries = list(os.scandir(cur))
        except (PermissionError, FileNotFoundError):
            continue
        for e in entries:
            if e.is_symlink():
                continue
            if e.is_dir():
                if e.name.lower() in SKIP_DIRS:
                    continue
                roots.append(e.path)
            elif e.is_file():
                ext = os.path.splitext(e.name)[1].lower()
                if ext in PHP_EXTS:
                    out.append(e.path)
    return sorted(out)[:max_files]


def file_meta(path):
    st = os.stat(path)
    return {"size": st.st_size, "mtime": int(st.st_mtime)}
