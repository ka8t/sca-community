"""Phase 5 benchmark script — SCA dataflow engine.

Measures the engine's precision/recall/F1 on the SCA taint fixtures and on
a synthetic module-level mini-corpus.

Usage:
    python -m sca.dataflow.bench
    python -m sca.dataflow.bench --verbose
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class BenchResult:
    """Outcome of running one rule's fixtures (vulnerable + clean) through the engine."""
    rule_id: str
    vulnerable_detected: Optional[bool] = None  # None if fixture is absent
    vulnerable_findings: int = 0
    clean_ok: Optional[bool] = None              # None if fixture is absent
    clean_findings: int = 0
    skip_reason: str = ""                        # reason for skipping, if any


@dataclass
class BenchStats:
    """Aggregate confusion-matrix counters across a benchmark run."""
    tp: int = 0    # true positives (vuln detected)
    fn: int = 0    # false negatives (vuln missed)
    tn: int = 0    # true negatives (clean OK)
    fp: int = 0    # false positives (clean wrongly flagged)

    @property
    def precision(self) -> float:
        """TP / (TP + FP), or 0.0 if there is no positive prediction."""
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        """TP / (TP + FN), or 0.0 if there is no actual positive."""
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall, or 0.0 if both are 0."""
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def _check_inline_friendly(source: str) -> Tuple[bool, str]:
    """Detect whether a fixture is "module-level friendly" (not inside def/class).

    A fixture that places its sinks inside a `def` or `class` will not be
    analyzed by the Phase 5 engine (opacity — Choice SCA-3 / Phase 6 pending).
    """
    has_def = "\ndef " in source or source.startswith("def ")
    has_class = "\nclass " in source or source.startswith("class ")
    if has_def and has_class:
        return False, "contains both def and class"
    if has_def:
        return False, "contains def (FunctionDef opaque in Phase 5)"
    if has_class:
        return False, "contains class (ClassDef opaque in Phase 5)"
    return True, ""


_LANGUAGE_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".java": "java",
    ".cs": "csharp",
    ".php": "php",
}


def _detect_lang_dir(rule: dict) -> str:
    """Detect the target language of a compiled rule."""
    return rule.get("language", "python")


def run_bench_multilang(verbose: bool = False) -> Tuple[List[BenchResult], BenchStats]:
    """Phase 8 benchmark — multi-language fixtures (JS, Java, C#, PHP)."""
    from sca.rule_loader import _load_sca_rules
    from sca.executors.dataflow_taint import run_taint_rule

    root = Path(__file__).parent.parent.parent
    rules_dir = root / "sca/rules/builtin"
    vuln_dir = root / "tests/fixtures/generic/vulnerable"
    clean_dir = root / "tests/fixtures/generic/clean"

    # For each language, list the taint_*.sca rules
    LANG_PATHS = {
        "javascript": rules_dir / "javascript/security",
        "java": rules_dir / "java/security",
        "csharp": rules_dir / "csharp/security",
        "php": rules_dir / "php/security",
    }
    LANG_EXT = {"javascript": ".js", "java": ".java", "csharp": ".cs", "php": ".php"}

    results: List[BenchResult] = []
    stats = BenchStats()

    for language, dir_path in LANG_PATHS.items():
        rule_files = sorted(dir_path.glob("taint_*.sca")) if dir_path.exists() else []
        ext = LANG_EXT[language]
        for rule_file in rule_files:
            loaded = _load_sca_rules(rule_file, rules_dir, "builtin")
            if not loaded:
                continue
            rule = loaded[0]
            rule_id = rule.get("id", rule_file.stem)
            label = f"[{language}] {rule_id}"

            result = BenchResult(rule_id=label)

            vuln_fixture = vuln_dir / f"{rule_id}{ext}"
            clean_fixture = clean_dir / f"{rule_id}_clean{ext}"

            if vuln_fixture.exists():
                src = vuln_fixture.read_text()
                try:
                    findings = list(run_taint_rule(rule, src, filename=str(vuln_fixture), language=language))
                except Exception as exc:
                    findings = []
                    result.skip_reason = f"error: {exc}"
                result.vulnerable_findings = len(findings)
                result.vulnerable_detected = len(findings) >= 1
                if result.vulnerable_detected:
                    stats.tp += 1
                else:
                    stats.fn += 1

            if clean_fixture.exists():
                src = clean_fixture.read_text()
                try:
                    findings = list(run_taint_rule(rule, src, filename=str(clean_fixture), language=language))
                except Exception:
                    findings = []
                result.clean_findings = len(findings)
                result.clean_ok = len(findings) == 0
                if result.clean_ok:
                    stats.tn += 1
                else:
                    stats.fp += 1

            results.append(result)
            if verbose:
                v = ("✓" if result.vulnerable_detected else "✗") if result.vulnerable_detected is not None else "—"
                c = ("✓" if result.clean_ok else "✗") if result.clean_ok is not None else "—"
                print(f"  {label:40s}  vuln {v} ({result.vulnerable_findings})  clean {c} ({result.clean_findings})")

    return results, stats


def run_bench_sca_fixtures(verbose: bool = False) -> Tuple[List[BenchResult], BenchStats]:
    """Benchmark over SCA's 17 `taint_*.sca` rules and their fixtures."""
    from sca.rule_loader import _load_sca_rules
    from sca.executors.dataflow_taint import run_taint_rule

    root = Path(__file__).parent.parent.parent
    rules_dir = root / "sca/rules/builtin"
    vuln_dir = root / "tests/fixtures/generic/vulnerable"
    clean_dir = root / "tests/fixtures/generic/clean"

    rule_files = sorted((rules_dir / "python/security").glob("taint_*.sca"))
    results: List[BenchResult] = []
    stats = BenchStats()

    for rule_file in rule_files:
        loaded = _load_sca_rules(rule_file, rules_dir, "builtin")
        if not loaded:
            continue
        rule = loaded[0]
        rule_id = rule.get("id", rule_file.stem)

        result = BenchResult(rule_id=rule_id)

        vuln_fixture = vuln_dir / f"{rule_id}.py"
        clean_fixture = clean_dir / f"{rule_id}_clean.py"

        if vuln_fixture.exists():
            src = vuln_fixture.read_text()
            findings = list(run_taint_rule(rule, src, filename=str(vuln_fixture)))
            result.vulnerable_findings = len(findings)
            result.vulnerable_detected = len(findings) >= 1
            if result.vulnerable_detected:
                stats.tp += 1
            else:
                stats.fn += 1
                # Diagnostic: friendly or not?
                friendly, reason = _check_inline_friendly(src)
                if not friendly:
                    result.skip_reason = reason

        if clean_fixture.exists():
            src = clean_fixture.read_text()
            findings = list(run_taint_rule(rule, src, filename=str(clean_fixture)))
            result.clean_findings = len(findings)
            result.clean_ok = len(findings) == 0
            if result.clean_ok:
                stats.tn += 1
            else:
                stats.fp += 1

        results.append(result)
        if verbose:
            v = ("✓" if result.vulnerable_detected else "✗") if result.vulnerable_detected is not None else "—"
            c = ("✓" if result.clean_ok else "✗") if result.clean_ok is not None else "—"
            extra = f"  [{result.skip_reason}]" if result.skip_reason else ""
            print(f"  {rule_id:30s}  vuln {v} ({result.vulnerable_findings})  clean {c} ({result.clean_findings}){extra}")

    return results, stats


# ============================================================================
# Synthetic module-level mini-corpus (proof that the engine works)
# ============================================================================

SYNTHETIC_CORPUS = [
    # (rule_dict_factory, vulnerable_source, clean_source, expected_vuln_findings, label)
    (
        "sqli_basic",
        {
            "id": "sqli_basic",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"request\.(GET|POST)", "kind": "http"}],
            "sinks": [{"pattern": r"cursor\.execute\s*\(", "args": [0]}],
            "sanitizers": [{"pattern": r"psycopg2\.sql\.Identifier"}],
            "metadata": {"cwe": "CWE-89"},
        },
        "data = request.GET\ncursor.execute(data)\n",
        "data = 'fixed_query'\ncursor.execute(data)\n",
    ),
    (
        "xpath_injection",
        {
            "id": "xpath_inj",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"request\.args", "kind": "http"}],
            "sinks": [{"pattern": r"\.xpath\s*\("}],
            "sanitizers": [{"pattern": r"\bint\s*\("}],
            "metadata": {"cwe": "CWE-643"},
        },
        "q = request.args\ntree.xpath(q)\n",
        "q = request.args\nsafe = int(q)\ntree.xpath(safe)\n",
    ),
    (
        "command_injection",
        {
            "id": "cmdi",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"input", "kind": "stdin"}],
            "sinks": [{"pattern": r"subprocess\.(run|call|Popen)"}],
            "sanitizers": [{"pattern": r"shlex\.quote"}],
            "metadata": {"cwe": "CWE-78"},
        },
        "cmd = input()\nsubprocess.run(cmd)\n",
        "cmd = input()\nsafe = shlex.quote(cmd)\nsubprocess.run(safe)\n",
    ),
    (
        "path_traversal",
        {
            "id": "path_trav",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"request\.args\.get", "kind": "http"}],
            "sinks": [{"pattern": r"\bopen\s*\(", "args": [0]}],
            "metadata": {"cwe": "CWE-22"},
        },
        "name = request.args.get('f')\nopen(name)\n",
        "name = 'fixed.txt'\nopen(name)\n",
    ),
    (
        "log_injection",
        {
            "id": "logi",
            "mode": "taint",
            "severity": "MEDIUM",
            "sources": [{"pattern": r"request\.headers", "kind": "http"}],
            "sinks": [{"pattern": r"logger\.(info|warning|error|debug)"}],
            "metadata": {"cwe": "CWE-117"},
        },
        "ua = request.headers\nlogger.info(ua)\n",
        "ua = 'safe'\nlogger.info(ua)\n",
    ),
    (
        "fstring_propagation",
        {
            "id": "fstring",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"request\.GET", "kind": "http"}],
            "sinks": [{"pattern": r"cursor\.execute", "args": [0]}],
            "metadata": {"cwe": "CWE-89"},
        },
        "name = request.GET\nq = f'SELECT * FROM t WHERE name={name}'\ncursor.execute(q)\n",
        "q = 'SELECT 1'\ncursor.execute(q)\n",
    ),
    (
        "if_branch_taint",
        {
            "id": "branch",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"input", "kind": "stdin"}],
            "sinks": [{"pattern": r"cursor\.execute", "args": [0]}],
            "metadata": {"cwe": "CWE-89"},
        },
        "if cond:\n    x = input()\nelse:\n    x = 'safe'\ncursor.execute(x)\n",
        "if cond:\n    x = 'a'\nelse:\n    x = 'b'\ncursor.execute(x)\n",
    ),
    (
        "while_loop_taint",
        {
            "id": "loop",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"input", "kind": "stdin"}],
            "sinks": [{"pattern": r"cursor\.execute", "args": [0]}],
            "metadata": {"cwe": "CWE-89"},
        },
        "data = input()\nwhile cond:\n    cursor.execute(data)\n",
        "data = 'safe'\nwhile cond:\n    cursor.execute(data)\n",
    ),
]


def run_bench_synthetic(verbose: bool = False) -> BenchStats:
    """Benchmark over the synthetic, module-level mini-corpus."""
    from sca.executors.dataflow_taint import run_taint_rule

    stats = BenchStats()
    for label, rule_dict, vuln_src, clean_src in SYNTHETIC_CORPUS:
        vuln_findings = list(run_taint_rule(rule_dict, vuln_src))
        clean_findings = list(run_taint_rule(rule_dict, clean_src))
        if len(vuln_findings) >= 1:
            stats.tp += 1
        else:
            stats.fn += 1
        if len(clean_findings) == 0:
            stats.tn += 1
        else:
            stats.fp += 1
        if verbose:
            v = "✓" if len(vuln_findings) >= 1 else "✗"
            c = "✓" if len(clean_findings) == 0 else "✗"
            print(f"  {label:30s}  vuln {v} ({len(vuln_findings)})  clean {c} ({len(clean_findings)})")
    return stats


def _print_stats(name: str, stats: BenchStats) -> None:
    """Print a labeled TP/FN/TN/FP breakdown plus accuracy/precision/recall/F1."""
    total = stats.tp + stats.fn + stats.tn + stats.fp
    print(f"\n=== {name} ===")
    print(f"  TP (vuln détectés)    : {stats.tp}")
    print(f"  FN (vuln manqués)     : {stats.fn}")
    print(f"  TN (clean OK)         : {stats.tn}")
    print(f"  FP (clean alertés)    : {stats.fp}")
    if total:
        print(f"  Accuracy              : {(stats.tp + stats.tn) / total:.3f}")
    print(f"  Precision             : {stats.precision:.3f}")
    print(f"  Recall                : {stats.recall:.3f}")
    print(f"  F1                    : {stats.f1:.3f}")


def _print_diagnostic(results: List[BenchResult]) -> None:
    """Categorize the missed fixtures to guide Phase 6+ work."""
    print("\n=== Catalogue des cas ratés (catégorisation pour Phase 6+) ===")
    miss_categories: Dict[str, List[str]] = {}
    for r in results:
        if r.vulnerable_detected is False:
            cat = r.skip_reason or "other (likely needs inter-procedural)"
            miss_categories.setdefault(cat, []).append(r.rule_id)
    for cat, rule_ids in sorted(miss_categories.items()):
        print(f"\n  [{cat}] ({len(rule_ids)} cases)")
        for rid in rule_ids:
            print(f"    - {rid}")


def main() -> int:
    """CLI entry point: run the selected benchmark(s) and print their stats."""
    parser = argparse.ArgumentParser(description="Bench moteur dataflow SCA — multilangue")
    parser.add_argument("--verbose", "-v", action="store_true", help="Détail par règle")
    parser.add_argument("--synthetic-only", action="store_true", help="Bench synthétique seul")
    parser.add_argument("--sca-only", action="store_true", help="Bench fixtures Python SCA seul")
    parser.add_argument("--multilang-only", action="store_true", help="Bench fixtures non-Python seul")
    args = parser.parse_args()

    run_synth = not (args.sca_only or args.multilang_only)
    run_sca = not (args.synthetic_only or args.multilang_only)
    run_ml = not (args.synthetic_only or args.sca_only)

    if run_synth:
        print("=" * 70)
        print("Bench 1 : corpus synthétique Python module-level")
        print("=" * 70)
        synth_stats = run_bench_synthetic(verbose=args.verbose)
        _print_stats("Corpus synthétique", synth_stats)

    if run_sca:
        print("\n" + "=" * 70)
        print("Bench 2 : fixtures Python SCA (17 règles taint_*)")
        print("=" * 70)
        results, sca_stats = run_bench_sca_fixtures(verbose=args.verbose)
        _print_stats("Fixtures Python SCA", sca_stats)

    if run_ml:
        print("\n" + "=" * 70)
        print("Bench 3 : fixtures multilangues (JS, Java, C#, PHP) — Phase 8")
        print("=" * 70)
        ml_results, ml_stats = run_bench_multilang(verbose=args.verbose)
        _print_stats("Fixtures multilangues", ml_stats)

    return 0


if __name__ == "__main__":
    sys.exit(main())
