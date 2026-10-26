"""Attack-surface mapping derived from analysis results."""

from __future__ import annotations


def compute(findings, engine, sources_depth=12):
    files = sorted({f.file for f in findings})
    src_map = {}
    for f in findings:
        src = f.source.get("var", "")
        if src:
            key = src.split("[")[0].strip("$")
            c = src_map.get(key, 0)
            src_map[key] = c + 1
    cats = {}
    for f in findings:
        if f.status == "REJECTED":
            continue
        cats[f.category] = cats.get(f.category, 0) + 1
    entry_files = []
    for path in [ir.path for ir in engine.files]:
        base = path.replace("\\", "/").split("/")[-1].lower()
        if base in ("index.php", "front.php", "main.php", "bootstrap.php") or "controller" in base:
            entry_files.append(path)
    return {
        "files_with_findings": files,
        "source_contexts": dict(sorted(src_map.items(), key=lambda kv: -kv[1])[:sources_depth]),
        "categories": dict(sorted(cats.items(), key=lambda kv: -kv[1])),
        "entry_files": entry_files,
        "top_risks": [
            {"file": f.file, "line": f.line, "category": f.category, "severity": f.severity} for f in findings[:8]
        ],
    }
