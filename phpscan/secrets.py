"""Hardcoded-secret detection (entropy + context, regex-only)."""

from __future__ import annotations

import math
import re

AWS = re.compile(r"A[KS]IA[0-9A-Z]{16}")
GOOGLE = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
GITHUB = re.compile(r"gh[pousr]_[0-9A-Za-z]{36,255}")
SLACK = re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")
JWT = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}")
PK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
HEROKU = re.compile(
    r"[0-9a-f]{8}@[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
    r"-[0-9a-f]{4}-[0-9a-f]{12}"
)
STRIPE = re.compile(r"[sk|rk|pk]_(live|test)_[0-9a-zA-Z]{10,}")

WORD_ASSIGN = re.compile(
    r"""(?ix)\b(pass(word)?|pwd|secret|api[_-]?key|token|auth|access|"
       private|signing|client)"?\s*[:=]\s*['"]([^'"\s]{8,120})['"]"""
)

FB_BLACKLIST = (
    "password",
    "example",
    "changeme",
    "change_me",
    "placeholder",
    "secret123",
    "12345678",
    "点点滴滴",
    "todo",
    "fixme",
    "dummy",
    "test1234",
    "default",
    "true",
    "false",
    "null",
)


def shannon(s):
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    bits = 0.0
    for c in freq.values():
        p = c / len(s)
        bits -= p * math.log2(p)
    return bits / 4.0


def scan(text, path):
    """Returns list of {line, type, key, entropy} results."""
    out = []
    for ln, line in enumerate(text.splitlines(), start=1):
        for rx, t in (
            (AWS, "AWS Access Key"),
            (GOOGLE, "Google API Key"),
            (GITHUB, "GitHub Token"),
            (SLACK, "Slack Token"),
            (JWT, "JWT"),
            (PK, "Private Key"),
            (HEROKU, "Heroku API Key"),
            (STRIPE, "Stripe Key"),
        ):
            m = rx.search(line)
            if m:
                val = m.group(0)
                out.append(
                    {"file": path, "line": ln, "type": t, "value": val[:8] + "…", "entropy": round(shannon(val), 2)}
                )
        m = WORD_ASSIGN.search(line)
        if m:
            val = m.group(3)
            low = val.lower()
            if low not in FB_BLACKLIST and not low.startswith("$"):
                ent = shannon(val)
                if ent >= 0.45:
                    out.append(
                        {
                            "file": path,
                            "line": ln,
                            "type": "Hardcoded Credential",
                            "value": val[:8] + "…",
                            "entropy": round(ent, 2),
                        }
                    )
    return out
