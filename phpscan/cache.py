"""Incremental parse cache.

Cache layout: dir/.phpscan-cache/v<VER>-<sha256prefix>.phpscan (pickled
FileIR).  Stores the lighter FileIR form (tree nodes stripped) validated
against the source file's content hash, so unchanged files skip
re-parsing.  The schema version key keeps older pickles from being
loaded after IR changes; unpickling is restricted to phpscan modules so
a tampered cache directory cannot turn into code execution.
"""

from __future__ import annotations

import hashlib
import os
import pickle

from . import util

SCHEMA_VERSION = 3


class _SafeUnpickler(pickle.Unpickler):
    """Refuse classes outside the phpscan package.

    A cache directory is writable state; a hostile pickle planted there
    must not execute arbitrary code. See SECURITY.md.
    """

    def find_class(self, module, name):
        if module == "phpscan.ir" and name.startswith("_") is False:
            try:
                from . import ir

                if hasattr(ir, name):
                    return getattr(ir, name)
            except Exception:
                pass
        raise pickle.UnpicklingError("unpickling %s.%s refused (cache safety)" % (module, name))


class IRCache:
    def __init__(self, cache_dir):
        self.dir = cache_dir
        self.hits = 0
        self.misses = 0
        self.errors = 0
        try:
            os.makedirs(cache_dir, exist_ok=True)
        except OSError:
            self.dir = None

    @staticmethod
    def file_hash(path):
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 16), b""):
                    h.update(chunk)
        except OSError:
            return None
        return h.hexdigest()

    def path_for(self, file_hash):
        if not self.dir or not file_hash:
            return None
        return os.path.join(self.dir, "v%d-%s.phpscan" % (SCHEMA_VERSION, file_hash[:32]))

    def load(self, path, file_hash):
        store = self.path_for(file_hash)
        if not store or not os.path.exists(store):
            self.misses += 1
            return None
        try:
            with open(store, "rb") as f:
                ir = _SafeUnpickler(f).load()
        except Exception:
            self.errors += 1
            self.misses += 1
            return None
        if ir.sha256 != file_hash:
            self.misses += 1
            return None
        self.hits += 1
        return ir

    def save(self, ir):
        store = self.path_for(ir.sha256)
        if not store:
            return
        try:
            util.strip_ir(ir)
            with open(store, "wb") as f:
                pickle.dump(ir, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            self.errors += 1
