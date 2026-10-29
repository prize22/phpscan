"""Read-only host investigation (v0.4).

Investigates the on-disk neighborhood of a PHP surface: dropped/sneaky
PHP artifacts, disguised PHP in non-PHP files, double extensions,
backup leftovers, recently modified code, config/log positions with
credential scans, and (opt-in) running interpreters.  Everything is
recorded as an Evidence observation (origin=host); nothing deletes,
renames, or writes anything.  Conclusion-making stays with the fusion
layer and Proof Engine.

Boundaries (all defaults): file count cap, size cap for content reads,
mtime window for "recent" classification, and process enumeration runs
only under explicit opt-in.
"""

from __future__ import annotations

import hashlib
import os
import re

from . import discovery
from .evidence import Evidence, EvidenceStore
from .log import get_logger

logger = get_logger("host")

READ_CAP = 128 * 1024
SKIP_DIRS = set(discovery.SKIP_DIRS) | {".idea", ".vscode", "__pycache__"}

BACKUP_EXT = {".bak", ".old", ".save", ".orig", ".swp", ".copy", ".tmp", ".swo"}
PHP_EXTS = set(discovery.PHP_EXTS)
UPLOAD_DIR_HINTS = (
    "upload",
    "uploads",
    "media",
    "files",
    "images",
    "img",
    "tmp",
    "temp",
    "data",
    "cache",
    "assets",
    "attachments",
)
CONFIG_NAMES = {
    "config.php",
    "wp-config.php",
    "settings.php",
    ".env",
    ".env.local",
    "database.php",
    "db.php",
    "configuration.php",
    "config.inc.php",
}
LOG_HINTS = ".log"
PERSISTENCE_PATHS = (
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/systemd/system",
    "/etc/init.d",
    "/etc/rc.local",
    "wp-content/mu-plugins",
)


def run_investigate(root, opts=None, now=None, store=None):
    """Walks ``root`` read-only; returns (store, summary)."""
    opts = opts or {}
    store = store if store is not None else EvidenceStore(root, "0.4.0")
    max_files = int(opts.get("max_files", 20000))
    recent_days = int(opts.get("recent_days", 30))
    do_processes = bool(opts.get("processes", False))
    summary = {"root": root, "files_seen": 0, "records": 0, "notes": []}

    import time

    now_epoch = time.time() if now is None else float(now)

    def ev(category, path, value, conf, uncertainty=(), tags=(), evid=None, mtime=None, size=None):
        ref = {"path": path}
        if mtime is not None:
            ref["mtime"] = int(mtime)
        if size is not None:
            ref["size"] = size
        store.add(
            Evidence(
                "host",
                category,
                path,
                value=value,
                confidence=conf,
                ts=now,
                source_ref=ref,
                uncertainty=list(uncertainty),
                tags=list(tags),
                evidence=evid or {},
            )
        )

    recent_cutoff = now_epoch - recent_days * 86400
    files = walk_all(root, max_files)
    summary["files_seen"] = len(files)

    for path in files:
        try:
            st = os.stat(path)
        except OSError as exc:
            logger.debug("cannot stat %s (%s); skipped", path, exc.__class__.__name__)
            continue
        mtime, size = st.st_mtime, st.st_size
        name = os.path.basename(path)
        lowname = name.lower()
        ext = os.path.splitext(name)[1].lower()
        rel = _rel(root, path)

        if ext in BACKUP_EXT or lowname.endswith(("~", ".bak", ".old")):
            ev("BACKUP_ARTIFACT", rel, {"ext": ext}, 0.7, mtime=mtime, size=size)
        if lowname.startswith(".") and ext in PHP_EXTS:
            ev("HIDDEN_PHP", rel, {"name": name}, 0.8, mtime=mtime, size=size)
        if (
            ".php." in lowname
            or lowname.endswith(".phtml.jpg")
            or re.search(r"\.php\d?\.(jpg|png|gif|txt|pdf|zip|jpeg|bmp|webp)$", lowname)
        ):
            ev("DOUBLE_EXTENSION", rel, {"name": name}, 0.85, mtime=mtime, size=size)
        if name.lower() in CONFIG_NAMES and size > 0:
            ev("CONFIG_FILE", rel, {"size": size}, 0.8, mtime=mtime, size=size)
            _secret_scan_file(ev, path, rel, mtime, size)
        if LOG_HINTS in lowname and ext == ".log" or lowname in ("error_log", "debug.log"):
            ev("LOG_FILE", rel, {"size": size}, 0.6, mtime=mtime, size=size)
            _secret_scan_file(ev, path, rel, mtime, size, cap=64 * 1024)

        parent = _rel(root, os.path.dirname(path))
        match_dirs = [p for p in parent.lower().replace("\\", "/").split("/") if p]
        in_uploadish = any(h in match_dirs or p.startswith(h) for p in match_dirs for h in UPLOAD_DIR_HINTS)
        if ext in PHP_EXTS and size > 0 and (in_uploadish or ext != ".php"):
            ev("PHP_LOCATION_NOTED", rel, {"dir": parent, "ext": ext}, 0.6, mtime=mtime, size=size)
        if ext in PHP_EXTS and size == 0:
            ev("EMPTY_PHP", rel, None, 0.3, mtime=mtime, size=size)

        if mtime >= recent_cutoff:
            ev("RECENT_FILE", rel, {"days_old": round((now_epoch - mtime) / 86400, 2)}, 0.5, mtime=mtime, size=size)

        if ext not in PHP_EXTS and _sniff_php(path):
            ev("DISGUISED_PHP", rel, {"ext": ext or "(none)"}, 0.9, mtime=mtime, size=size)

    for base in _persistence_candidates(root):
        try:
            ok = os.path.exists(base)
        except OSError as exc:
            logger.debug("cannot check persistence path %s (%s)", base, exc.__class__.__name__)
            ok = False
        if ok:
            ev(
                "PERSISTENCE_CANDIDATE",
                _rel(root, base),
                {"detail": "known persistence location exists under/off root"},
                0.4,
                uncertainty=["existence only; content not analyzed"],
            )

    if do_processes:
        _scan_processes(ev, summary)

    summary["records"] = len(store)
    return store, summary


def walk_all(root, max_files=20000):
    """Symlink-safe, deterministic walk of every file (not only PHP)."""
    if os.path.isfile(root):
        return [root]
    out, roots = [], [root]
    while roots and len(out) < max_files:
        cur = roots.pop(0)
        try:
            entries = list(os.scandir(cur))
        except PermissionError:
            logger.warning("directory not readable (permission denied): %s", cur)
            continue
        except FileNotFoundError as exc:
            logger.debug("skipping unreadable directory %s (%s)", cur, exc.__class__.__name__)
            continue
        for e in entries:
            if e.is_symlink():
                continue
            if e.is_dir():
                if e.name.lower() in SKIP_DIRS:
                    continue
                roots.append(e.path)
            elif e.is_file():
                out.append(e.path)
    return sorted(out)[:max_files]


def _rel(root, path):
    """Path relative to root, forward slashes (stable across OSes)."""
    try:
        r = os.path.relpath(path, root)
    except ValueError:
        return path.replace("\\", "/")
    if r.startswith(".."):
        return os.path.abspath(path).replace("\\", "/")
    return r.replace("\\", "/")


def _secret_scan_file(ev, path, rel, mtime, size, cap=READ_CAP):
    from .secrets import scan

    try:
        with open(path, "rb") as f:
            data = f.read(cap)
        if data[:8].upper().startswith(b"\x89PNG\x0d\x0a\x1a\x0a") or b"\x00" in data[:64]:
            return
        hits = scan(data.decode("utf-8", "replace"), rel)
    except OSError as exc:
        logger.debug("secret scan skipped for %s (%s)", rel, exc.__class__.__name__)
        return
    for h in hits[:32]:
        ev(
            "CREDENTIAL_ARTIFACT",
            rel,
            {"type": h["type"], "line": h["line"]},
            0.85,
            mtime=mtime,
            size=size,
        )


def _sniff_php(path):
    """True when a non-PHP file still contains PHP code markers."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        logger.debug("cannot sniff %s (%s)", path, exc.__class__.__name__)
        return False
    try:
        with open(path, "rb") as f:
            head = f.read(min(size, 16384))
            if size > 16384:
                f.seek(max(0, size - 16384))
                tail = f.read(16384)
            else:
                tail = b""
    except OSError as exc:
        logger.debug("cannot read %s for php sniffing (%s)", path, exc.__class__.__name__)
        return False
    for blob in (head, tail):
        low = blob.lower()
        for marker in (b"<?php", b"<?=", b'<script language="php">'):
            if marker in low:
                return True
    return False


def _persistence_candidates(root):
    root = os.path.abspath(root)
    yield os.path.join(root, "wp-content", "mu-plugins")
    if os.name != "nt":
        for p in PERSISTENCE_PATHS:
            if p.startswith("/"):
                yield p


def _scan_processes(ev, summary):
    """Opt-in, best-effort interpreter enumeration (read-only)."""
    import subprocess

    try:
        if os.name == "nt":
            out = subprocess.run(
                ["wmic", "process", "get", "ProcessId,CommandLine", "/format:csv"],
                capture_output=True,
                timeout=20,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            data = out.stdout if out.returncode == 0 else ""
            if not data.strip():
                raise OSError("wmic unavailable")
            for line in data.splitlines()[1:]:
                line = line.strip()
                if not line or "," not in line:
                    continue
                node, cmdline, pid = line.rsplit(",", 2)
                _classify_process(ev, cmdline, pid, summary)
        else:  # POSIX: /proc walk
            for pid in sorted(os.listdir("/proc")):
                if not pid.isdigit():
                    continue
                try:
                    with open("/proc/%s/cmdline" % pid, "rb") as f:
                        raw = f.read(4096)
                except OSError:
                    continue
                cmdline = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
                if cmdline:
                    _classify_process(ev, cmdline, pid, summary)
    except Exception as exc:  # noqa: BLE001
        logger.warning("opt-in process enumeration failed (%s)", exc.__class__.__name__)
        summary["notes"].append("process enumeration failed (%s)" % exc.__class__.__name__)
        ev(
            "PROCESSES_UNCERTAIN",
            "localhost",
            None,
            0.2,
            ("process enumeration unavailable or denied",),
        )


def _classify_process(ev, cmdline, pid, summary):
    if not cmdline:
        return
    interp = cmdline.split()[0].lower() if cmdline.split() else ""
    base = os.path.basename(interp)
    if not (base.startswith("php") or base.startswith("python") or base.startswith("node") or base.startswith("perl")):
        return
    h = hashlib.sha256(cmdline.encode("utf-8", "replace")).hexdigest()[:16]
    ev(
        "PROCESS_OBSERVED",
        "localhost",
        {"pid": re.sub(r"\D", "", pid) or pid, "interpreter": base},
        0.6,
        evid={"cmdline_sha256": h},
    )
