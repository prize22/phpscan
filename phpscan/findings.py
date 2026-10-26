"""Findings data model and serialization (JSON / SARIF / display)."""

from __future__ import annotations

import hashlib
import json

RULE_PREFIX = {
    "SQL Injection": "php.sqli",
    "Cross-Site Scripting": "php.xss",
    "Command Injection": "php.command",
    "Code Injection": "php.code-injection",
    "File Inclusion": "php.file-inclusion",
    "Path Traversal": "php.path-traversal",
    "Arbitrary File Write": "php.file-write",
    "Unsafe File Upload": "php.upload",
    "Server-Side Request Forgery": "php.ssrf",
    "Insecure Deserialization": "php.deserialization",
    "Open Redirect": "php.open-redirect",
    "Header Injection": "php.header-injection",
    "Information Disclosure": "php.information-disclosure",
    "Webshell / Backdoor": "php.webshell",
    "Hardcoded Secret": "php.secrets",
    "Dangerous Function": "php.dangerous-function",
}

CWE_BY_CATEGORY = {
    "SQL Injection": "CWE-89",
    "Cross-Site Scripting": "CWE-79",
    "Command Injection": "CWE-78",
    "Code Injection": "CWE-94",
    "File Inclusion": "CWE-98",
    "Path Traversal": "CWE-22",
    "Arbitrary File Write": "CWE-73",
    "Unsafe File Upload": "CWE-434",
    "Server-Side Request Forgery": "CWE-918",
    "Insecure Deserialization": "CWE-502",
    "Open Redirect": "CWE-601",
    "Header Injection": "CWE-113",
    "Information Disclosure": "CWE-200",
    "Webshell / Backdoor": "CWE-605",
    "Hardcoded Secret": "CWE-798",
    "Dangerous Function": "CWE-676",
}

OWASP_BY_CATEGORY = {
    "SQL Injection": "A03:2021-Injection",
    "Cross-Site Scripting": "A03:2021-Injection",
    "Command Injection": "A03:2021-Injection",
    "Code Injection": "A03:2021-Injection",
    "File Inclusion": "A01:2021-Broken Access Control",
    "Path Traversal": "A01:2021-Broken Access Control",
    "Arbitrary File Write": "A01:2021-Broken Access Control",
    "Unsafe File Upload": "A04:2021-Insecure Design",
    "Server-Side Request Forgery": "A10:2021-SSRF",
    "Insecure Deserialization": "A08:2021-Integrity Failures",
    "Open Redirect": "A01:2021-Broken Access Control",
    "Header Injection": "A03:2021-Injection",
    "Information Disclosure": "A01:2021-Broken Access Control",
    "Webshell / Backdoor": "A08:2021-Integrity Failures",
    "Hardcoded Secret": "A07:2021-Auth Failures",
    "Dangerous Function": "A05:2021-Security Misconfiguration",
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

STATUS_ORDER = {
    "VALIDATED": 0,
    "PARTIALLY_VALIDATED": 1,
    "UNCONFIRMED": 2,
    "RESEARCH_LEAD": 3,
    "SUPPRESSED": 4,
    "REJECTED": 5,
}


class Finding:
    def __init__(
        self,
        id=None,
        rule_id="",
        category="",
        title="",
        severity="",
        confidence=0.0,
        status="",
        file="",
        line=0,
        col=0,
        func="",
        source=None,
        sink=None,
        data_flow=None,
        evidence=None,
        validation=None,
        recommendation="",
        fingerprint="",
        cwe="",
        owasp="",
        reason="",
        note="",
        proof=None,
    ):
        self.id = id
        self.rule_id = rule_id
        self.category = category
        self.title = title
        self.severity = severity
        self.confidence = confidence
        self.status = status
        self.file = file
        self.line = line
        self.col = col
        self.func = func
        self.source = source or {}
        self.sink = sink or {}
        self.data_flow = data_flow or []
        self.evidence = evidence or []
        self.validation = validation or {}
        self.proof = proof if proof is not None else {}
        self.recommendation = recommendation
        self.fingerprint = fingerprint
        self.cwe = cwe or CWE_BY_CATEGORY.get(category, "")
        self.owasp = owasp or OWASP_BY_CATEGORY.get(category, "")
        self.reason = reason
        self.note = note

    def export(self):
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "status": self.status,
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "func": self.func,
            "source": self.source,
            "sink": self.sink,
            "data_flow": self.data_flow,
            "evidence": self.evidence,
            "validation": self.validation,
            "recommendation": self.recommendation,
            "fingerprint": self.fingerprint,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "reason": self.reason,
            "note": self.note,
            "proof": self.proof,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


def category_fingerprint(category, file, line, sink, source_key):
    base = "|".join([category or "-", file or "-", str(line or 0), sink or "-", source_key or "-"])
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:16]


def stable_fingerprint(category, file, func, sink, source_key):
    """Path-stable fingerprint for baselines: line numbers are excluded so
    forward edits in a file do not invalidate triaged baselines."""
    base = "|".join(
        [category or "-", (file or "-").replace("\\", "/"), (func or "-"), (sink or "-"), (source_key or "-")]
    )
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:16]


def load_findings(path):
    """Load scan output JSON: {'findings': [...], ...}."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    if isinstance(data, dict):
        flat = data.get("findings") or []
    elif isinstance(data, list):
        flat = data
    else:
        flat = []
    return [Finding.from_dict(x) for x in flat], data


def sarif_output(run_meta, findings):
    rules_map = {}
    results = []
    for f in findings:
        rules_map.setdefault(
            f.rule_id,
            {
                "id": f.rule_id,
                "name": f.category or f.rule_id,
                "shortDescription": {"text": f.title or f.category},
                "properties": {
                    "category": f.category,
                    "security-severity": sev_to_sec(f.severity),
                },
            },
        )
        results.append(
            {
                "ruleId": f.rule_id,
                "level": sarif_level(f.severity, f.status),
                "message": {"text": (f.title or "") + (". " + (f.reason or "") if f.reason else "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file or "-"},
                            "region": {"startLine": max(1, int(f.line or 1)), "startColumn": max(1, int(f.col or 1))},
                        },
                        "logicalLocations": ([{"fullyQualifiedName": f.func}] if f.func else []),
                    }
                ],
                "partialFingerprints": {"phpscanFingerprint/v2": f.fingerprint or ""},
                "properties": {
                    "status": f.status,
                    "confidence": round(f.confidence, 2),
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                    "dataFlow": f.data_flow,
                    "validation": f.validation,
                },
            }
        )
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "phpscan",
                        "informationUri": "https://github.com/phpscan/phpscan",
                        "semanticVersion": run_meta.get("version"),
                        "rules": list(rules_map.values()),
                    },
                },
                "results": results,
            }
        ],
    }


def sev_to_sec(sev):
    m = {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0", "LOW": "2.5", "INFO": "0.0"}
    return m.get(sev, "1.0")


def sarif_level(sev, status):
    if status == "SUPPRESSED":
        return "note"
    status_order = STATUS_ORDER.get(status, 2)
    if status_order >= 3:
        return "note"
    severity = (sev or "").upper()
    if severity == "CRITICAL" or severity == "HIGH":
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note"


def json_output(data):
    return json.dumps(data, indent=2, ensure_ascii=False)


def write_json(path, data):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json_output(data) + "\n")
