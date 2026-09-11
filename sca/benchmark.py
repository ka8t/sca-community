"""
Benchmark mode — measures SCA's detection rate on its own fixtures.

Reuses the fixture validation infrastructure (sca/testing.py) and
produces a benchmark report with precision, recall, F1, broken down
by language and by rule_key.

Usage: ./run_audit.py --benchmark
"""
import json
import os
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from sca import SCRIPT_DIR, VERSION

logger = logging.getLogger("sca.benchmark")


def run_benchmark(config: dict = None) -> dict:
    """Run the full benchmark and print the results.

    Returns the results dict (also exported to JSON).
    """
    from sca.runner import AuditRunner
    from sca.config import load_config

    print(f"\n{'=' * 50}")
    print(f"  StaticCodeAudit Benchmark v{VERSION}")
    print(f"{'=' * 50}\n")

    # Create a runner to access the test methods
    if config is None:
        config = load_config(silent=True)
    config["tests"] = {"enabled": False}

    runner = AuditRunner(config=config, root_dir=str(SCRIPT_DIR), script_lang="en")

    # Load the fixtures
    fixtures_dir = str(SCRIPT_DIR / "tests" / "fixtures" / "generic")
    mapping = runner._load_fixtures_mapping(fixtures_dir)

    if not mapping:
        print("  Aucune fixture trouvee. Verifiez tests/fixtures/generic/")
        return {}

    # Collect the fixtures
    vuln_dir = os.path.join(fixtures_dir, "vulnerable")
    clean_dir = os.path.join(fixtures_dir, "clean")

    vulnerable_fixtures = []
    clean_fixtures = []

    for filename, info in mapping.items():
        if info["type"] == "vulnerable":
            filepath = os.path.join(vuln_dir, filename)
            if os.path.exists(filepath):
                vulnerable_fixtures.append((filepath, filename, info))
        elif info["type"] == "clean":
            filepath = os.path.join(clean_dir, filename)
            if os.path.exists(filepath):
                clean_fixtures.append((filepath, filename, info))

    total_vuln = len(vulnerable_fixtures)
    total_clean = len(clean_fixtures)
    print(f"  Fixtures : {total_vuln} vulnerables, {total_clean} clean\n")

    # Run the tests
    start = time.time()
    results = []

    print(f"  Test des fixtures vulnerables...")
    for filepath, filename, info in vulnerable_fixtures:
        result = runner._test_single_fixture(filepath, filename, "vulnerable", mapping)
        result["language"] = _detect_language(filename)
        results.append(result)

    print(f"  Test des fixtures clean...")
    for filepath, filename, info in clean_fixtures:
        result = runner._test_single_fixture(filepath, filename, "clean", mapping)
        result["language"] = _detect_language(filename)
        results.append(result)

    elapsed = time.time() - start

    # Compute the metrics
    metrics = _compute_metrics(results)
    by_lang = _group_by_language(results)
    fn_list = _get_false_negatives(results)
    fp_list = _get_false_positives(results)

    # Noise: clean fixtures with findings from other rules (cross-contamination)
    noise_count = sum(1 for r in results
                      if r["type"] == "clean" and r.get("detected") and r.get("status") == "pass")
    metrics["noise_count"] = noise_count

    # Display the report
    _print_report(metrics, by_lang, fn_list, fp_list, elapsed)

    # Export as JSON
    benchmark_data = {
        "version": "1.0",
        "tool_version": VERSION,
        "timestamp": datetime.now().isoformat(),
        "duration_seconds": round(elapsed, 1),
        "summary": metrics,
        "by_language": by_lang,
        "false_negatives": fn_list,
        "false_positives": fp_list,
    }

    output_path = SCRIPT_DIR / f"benchmark-results-{datetime.now().strftime('%Y-%m-%d')}.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_data, f, indent=2, ensure_ascii=False)

    print(f"\n  Export : {output_path}")

    return benchmark_data


def _detect_language(filename: str) -> str:
    """Detect a fixture's language from its file extension."""
    ext = os.path.splitext(filename)[1].lower()
    ext_map = {
        ".py": "python", ".js": "javascript", ".jsx": "javascript",
        ".ts": "javascript", ".tsx": "javascript", ".mjs": "javascript",
        ".java": "java", ".cs": "csharp", ".php": "php",
        ".html": "html", ".htm": "html", ".vue": "html",
        ".yml": "yaml", ".yaml": "yaml",
    }
    return ext_map.get(ext, "other")


def _compute_metrics(results: List[dict]) -> dict:
    """Compute precision, recall, and F1 from the results.

    For false positives, uses the strict metric: only cases where the
    EXPECTED rule fires on its clean fixture are counted (not cross-
    contamination from other rules).
    """
    tp = sum(1 for r in results if r["type"] == "vulnerable" and r.get("detected") and r.get("status") != "skip")
    fn = sum(1 for r in results if r["type"] == "vulnerable" and not r.get("detected") and r.get("status") != "skip")
    tn = sum(1 for r in results if r["type"] == "clean" and r.get("status") == "pass")
    fp = sum(1 for r in results if r["type"] == "clean" and r.get("status") == "fail")

    vuln_total = tp + fn
    clean_total = tn + fp

    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 100.0
    recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 100.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "vulnerable_total": vuln_total,
        "vulnerable_detected": tp,
        "clean_total": clean_total,
        "clean_passed": tn,
        "false_negatives": fn,
        "false_positives": fp,
        "precision": round(precision, 1),
        "recall": round(recall, 1),
        "f1_score": round(f1, 1),
    }


def _group_by_language(results: List[dict]) -> dict:
    """Break down the results by language."""
    by_lang = {}
    for r in results:
        if r.get("status") == "skip":
            continue
        lang = r.get("language", "other")
        if lang not in by_lang:
            by_lang[lang] = {"detected": 0, "total": 0, "fp": 0, "clean_total": 0}

        if r["type"] == "vulnerable":
            by_lang[lang]["total"] += 1
            if r.get("detected"):
                by_lang[lang]["detected"] += 1
        elif r["type"] == "clean":
            by_lang[lang]["clean_total"] += 1
            if r.get("status") == "fail":
                by_lang[lang]["fp"] += 1

    return by_lang


def _get_false_negatives(results: List[dict]) -> List[dict]:
    """List the false negatives (vulnerable fixtures not detected)."""
    return [
        {"fixture": r["filename"], "rule_key": r.get("rule_key", "?"), "language": r.get("language", "?")}
        for r in results
        if r["type"] == "vulnerable" and not r.get("detected") and r.get("status") != "skip"
    ]


def _get_false_positives(results: List[dict]) -> List[dict]:
    """List the false positives (the expected rule fires on its clean fixture)."""
    return [
        {"fixture": r["filename"], "rule_key": r.get("rule_key", "?"), "language": r.get("language", "?")}
        for r in results
        if r["type"] == "clean" and r.get("status") == "fail"
    ]


def _print_report(metrics: dict, by_lang: dict, fn_list: list, fp_list: list, elapsed: float):
    """Print the benchmark report to the console."""
    m = metrics

    print(f"  Detection : {m['vulnerable_detected']:>4d}/{m['vulnerable_total']:<4d} ({m['recall']:.1f}%)")
    print(f"  Faux pos. : {m['false_positives']:>4d}/{m['clean_total']:<4d} ({100 - m['precision']:.1f}%)")
    print(f"  Precision : {m['precision']:.1f}%")
    print(f"  Rappel    : {m['recall']:.1f}%")
    print(f"  Score F1  : {m['f1_score']:.1f}%")
    noise = m.get("noise_count", 0)
    if noise > 0:
        print(f"  Bruit     : {noise:>4d} (cross-contamination par d'autres regles)")

    if by_lang:
        print(f"\n  Par langage :")
        for lang in sorted(by_lang, key=lambda l: by_lang[l]["total"], reverse=True):
            d = by_lang[lang]
            if d["total"] > 0:
                rate = d["detected"] / d["total"] * 100
                print(f"    {lang:<14s} {d['detected']:>3d}/{d['total']:<3d} ({rate:5.1f}%)  FP: {d['fp']}")

    if fn_list:
        print(f"\n  Faux negatifs ({len(fn_list)}) :")
        for fn in fn_list[:15]:
            print(f"    - {fn['fixture']} -> {fn['rule_key']}")
        if len(fn_list) > 15:
            print(f"    ... et {len(fn_list) - 15} autres")

    if fp_list:
        print(f"\n  Faux positifs ({len(fp_list)}) :")
        for fp in fp_list[:10]:
            print(f"    - {fp['fixture']} -> {fp['rule_key']}")

    print(f"\n  Duree : {elapsed:.1f}s")
