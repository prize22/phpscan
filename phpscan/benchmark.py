"""Benchmark engine: run the eval corpus and compute metrics."""

from __future__ import annotations

import json
import os
import re
import time

from . import cli


def load_manifest(corpus_dir):
    path = os.path.join(corpus_dir, "manifest.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def source_comments_expect(file_path):
    """Per-file expected categories via 'phpscan: expect:' comments."""
    exp = []
    with open(file_path, "rb") as f:
        text = f.read().decode("utf-8", errors="replace")
    for m in re.finditer(
        r"phpscan:[ \t]*(clean|expect)"
        r"[ \t:=]+([A-Za-z /-]+)",
        text,
    ):
        kind = m.group(1).lower()
        cat = m.group(2).strip()
        if kind == "clean":
            exp.append(None)
        else:
            for part in cat.split("|"):
                exp.append(part.strip())
    return exp


def run_corpus(corpus_dir, out=None):
    """Runs scan over each PHP file in the corpus; metrics per category.

    Expectations come from manifest.json (file -> [category,...]) with
    an empty list meaning "clean: no accepted findings".

    Scanned subdirectories: vulnerable, clean, webshell (plus the v0.3.0
    expansion dirs patched/ and framework/ when present).
    """
    manifest = load_manifest(corpus_dir)
    tp = fp = fn = 0
    cat_stats = {}
    rows = []
    t0 = time.time()
    for d, is_vul in (
        (os.path.join(corpus_dir, "vulnerable"), True),
        (os.path.join(corpus_dir, "clean"), False),
        (os.path.join(corpus_dir, "webshell"), "webshell"),
        (os.path.join(corpus_dir, "patched"), False),
        (os.path.join(corpus_dir, "framework"), "mixed"),
    ):
        if not os.path.isdir(d):
            continue
        # framework/ is scanned as a whole directory so that inter-file
        # calls (controller -> helper) resolve inside one engine run.
        if os.path.basename(d) == "framework":
            payload, engine, files = _scan_one(d, corpus_dir)
            by_file = {}
            for fnd in payload["findings"]:
                by_file.setdefault(os.path.basename(fnd.get("file", "")), []).append(fnd)
            for name in sorted(os.listdir(d)):
                if not name.endswith((".php", ".phtml")):
                    continue
                path = os.path.join(d, name)
                exp = manifest.get(name) or manifest.get("framework/" + name) or []
                got = set()
                for fnd in by_file.get(name, []):
                    if fnd.get("status") == "VALIDATED":
                        got.add(fnd["category"])
                is_vul = bool(exp)
                if is_vul is True:
                    exps = set(e for e in exp if e is not None)
                    for e in sorted(exps):
                        cs = cat_stats.setdefault(e, {"tp": 0, "fp": 0, "fn": 0})
                        if e in got:
                            cs["tp"] += 1
                            tp += 1
                        else:
                            cs["fn"] += 1
                            fn += 1
                    for g in sorted(got - exps):
                        cs = cat_stats.setdefault(g + " (clean corpus)", {"tp": 0, "fp": 0, "fn": 0})
                        cs["fp"] += 1
                        fp += 1
                else:
                    for g in sorted(got):
                        cs = cat_stats.setdefault(g + " (clean corpus)", {"tp": 0, "fp": 0, "fn": 0})
                        cs["fp"] += 1
                        fp += 1
                rows.append({"file": "framework/" + name, "expected": sorted(exp or []), "got": sorted(got)})
            continue
        for name in sorted(os.listdir(d)):
            if not name.endswith((".php", ".phtml")):
                continue
            path = os.path.join(d, name)
            exp = manifest.get(name) or manifest.get("vulnerable/" + name) or manifest.get("clean/" + name) or []
            payload, engine, files = _scan_one(path, corpus_dir)
            got = set()
            for fnd in payload["findings"]:
                if fnd.get("status") == "VALIDATED":
                    got.add(fnd["category"])
            if is_vul == "mixed":
                is_vul = bool(exp)
            if is_vul is True:
                exps = set(e for e in exp if e is not None)
                for e in sorted(exps):
                    cs = cat_stats.setdefault(e, {"tp": 0, "fp": 0, "fn": 0})
                    if e in got:
                        cs["tp"] += 1
                        tp += 1
                    else:
                        cs["fn"] += 1
                        fn += 1
                for g in sorted(got - exps):
                    cs = cat_stats.setdefault(g, {"tp": 0, "fp": 0, "fn": 0})
                    cs["fp"] += 1
                    fp += 1
            elif is_vul is False:
                for g in sorted(got):
                    cs = cat_stats.setdefault(g + " (clean corpus)", {"tp": 0, "fp": 0, "fn": 0})
                    cs["fp"] += 1
                    fp += 1
            rows.append({"file": os.path.basename(d) + "/" + name, "expected": sorted(exp or []), "got": sorted(got)})
    prec = (tp / (tp + fp)) if (tp + fp) else 0.0
    rec = (tp / (tp + fn)) if (tp + fn) else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
    report = {
        "corpus": os.path.abspath(corpus_dir),
        "timing_ms": round((time.time() - t0) * 1000, 1),
        "totals": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(prec, 3),
            "recall": round(rec, 3),
            "f1": round(f1, 3),
        },
        "per_category": {k: v for k, v in cat_stats.items() if isinstance(v, dict)},
        "rows": rows,
    }
    text = "phpscan benchmark — %s\n" % report["corpus"]
    text += "tp=%s fp=%s fn=%s  precision=%.3f recall=%.3f f1=%.3f\n" % (tp, fp, fn, prec, rec, f1)
    text += "\nper category:\n"
    for cat, v in report["per_category"].items():
        text += "  %-32s tp=%-3s fp=%-3s fn=%-3s\n" % (cat, v["tp"], v["fp"], v["fn"])
    if out:
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        _write_json(out, report)
    print(text)
    return 0


def _write_json(path, report):
    with open(path + ".json", "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")


def _scan_one(path, target_dir):
    from types import SimpleNamespace

    args = SimpleNamespace(
        target=path,
        incremental=False,
        verbose=False,
        include_rejected=False,
        quiet=True,
        baseline=None,
        no_baseline=True,
        new_only=False,
    )
    payload, engine, files = cli.scan(target=path, args=args)
    return payload, engine, files
