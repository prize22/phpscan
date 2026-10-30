"""Structured diagnostic logging for PHPSCAN internals.

This module carries *internal* diagnostics only: probe and connection
failures, unreadable files, recoverable internal errors, debug traces.
It is never the channel for findings, reports or machine-readable
output -- those stay on the existing stdout/stderr reporting path
(``phpscan.reporting`` / ``phpscan.cli``), which this module does not
touch.

Design:

* One named logger tree rooted at ``phpscan`` (children such as
  ``phpscan.live`` and ``phpscan.host``), so every record is attributable
  to the component that produced it.
* Standard library only, standard levels (DEBUG / INFO / WARNING /
  ERROR / CRITICAL). No custom levels, no configuration at import time.
* Importing this module never touches the root logger: the package
  logger only gets a ``NullHandler``, so embedding phpscan as a library
  stays silent. Only the CLI calls :func:`configure`, which installs one
  stderr handler at the requested level.
"""

from __future__ import annotations

import logging
import re
import urllib.parse

LOGGER_NAME = "phpscan"

_LEVEL_VALUES = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

#: Levels accepted by ``--log-level`` and :func:`configure`.
LEVELS = tuple(_LEVEL_VALUES)

#: Default for the CLI: quiet enough that normal usage gains no noise.
DEFAULT_LEVEL = "WARNING"

FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
DATEFMT = "%H:%M:%S"

# Query keys that look credential-shaped are masked before a URL is logged.
_SENSITIVE_KEY = re.compile(r"(?i)(key|token|secret|pass|pwd|auth|session|signature|credential)")

_logger = logging.getLogger(LOGGER_NAME)
if not any(isinstance(h, logging.NullHandler) for h in _logger.handlers):
    _logger.addHandler(logging.NullHandler())


def get_logger(component=None):
    """Return the phpscan logger, or a child logger for a component.

    ``get_logger()`` returns the ``phpscan`` logger;
    ``get_logger("live")`` returns ``phpscan.live``.
    """
    if not component:
        return logging.getLogger(LOGGER_NAME)
    return logging.getLogger("%s.%s" % (LOGGER_NAME, component))


def _resolve(level):
    """Map a level name (case-insensitive) or a numeric level to its value."""
    if isinstance(level, bool):
        raise ValueError("unknown log level: %r" % (level,))
    if isinstance(level, int):
        if level in _LEVEL_VALUES.values():
            return level
        raise ValueError("unknown log level: %r" % (level,))
    key = str(level).upper()
    if key not in _LEVEL_VALUES:
        raise ValueError("unknown log level: %r (expected one of %s)" % (level, ", ".join(LEVELS)))
    return _LEVEL_VALUES[key]


def configure(level=DEFAULT_LEVEL):
    """Configure the phpscan logger for CLI use; returns the logger.

    Sets the level on the ``phpscan`` logger (children inherit it) and
    installs exactly one stderr handler, replacing any handler installed
    by an earlier call so the stream is always the current
    ``sys.stderr``. The root logger is never modified.

    Raises ``ValueError`` for an unknown level.
    """
    numeric = _resolve(level)
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(numeric)
    for handler in list(logger.handlers):
        if getattr(handler, "_phpscan_cli", False):
            logger.removeHandler(handler)
            handler.close()
    handler = logging.StreamHandler()  # binds the current sys.stderr
    handler.setLevel(numeric)
    handler.setFormatter(logging.Formatter(FORMAT, DATEFMT))
    setattr(handler, "_phpscan_cli", True)  # ownership marker; only configure() removes it
    logger.addHandler(handler)
    return logger


def redact_url(url):
    """Return a log-safe form of ``url``.

    Userinfo credentials (``user:password@host``) are removed and
    credential-shaped query values are masked, so a target URL can never
    leak a password, token or session identifier into a log line.
    """
    try:
        parts = urllib.parse.urlsplit(str(url))
        netloc = parts.netloc
        if "@" in netloc:
            host = parts.hostname or ""
            if ":" in host:  # IPv6 literal
                host = "[%s]" % host
            port = ""
            try:
                if parts.port:
                    port = ":%d" % parts.port
            except ValueError:
                port = ""
            netloc = "***@" + host + port
        query = parts.query
        if query:
            pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
            if pairs and any(_SENSITIVE_KEY.search(k) for k, _v in pairs):
                query = urllib.parse.urlencode(
                    [(k, "***" if _SENSITIVE_KEY.search(k) else v) for k, v in pairs], safe="*"
                )
        return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))
    except Exception:  # noqa: BLE001 - logging must never raise
        return "<redacted-url>"
