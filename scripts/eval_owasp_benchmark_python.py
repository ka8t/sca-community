"""Benchmark against OWASP BenchmarkPython (https://github.com/OWASP-Benchmark/BenchmarkPython).

Loads the 10 Python taint rules shipped in this edition, runs them via
`sca.executors.dataflow_taint.run_taint_rule`, compares against the
OWASP-provided labels, and reports F1 per category plus a macro
average. This is exactly how the F1 macro figure quoted in the README
is measured — clone OWASP-Benchmark/BenchmarkPython and run this script
yourself to reproduce it.

Note: this script calls `run_taint_rule` file by file, without going
through `sca.executors.dataflow_adapter.run_dataflow_taint_for_files` —
it does not exercise cross-file resolution (the persistent call graph),
since OWASP BenchmarkPython's cases are self-contained files with no
cross-file imports. Useful as a single-file-path regression check, not
as a validation of multi-hop call graph resolution.

Usage:
    python scripts/eval_owasp_benchmark_python.py \\
        [--sca-root /path/to/sca-community] \\
        [--benchmark /path/to/BenchmarkPython] \\
        [--json output.json]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_SCA_ROOT = ROOT
DEFAULT_BENCHMARK = ROOT.parent / "BenchmarkPython"


# Maps SCA taint rule_id -> OWASP Benchmark category.
RULE_TO_OWASP_CATEGORY: dict[str, str] = {
    "taint_sqli":            "sqli",
    "taint_xss":             "xss",
    "taint_rce":             "cmdi",
    "taint_codeinj":         "codeinj",
    "taint_path_traversal":  "pathtraver",
    "taint_xxe":             "xxe",
    "taint_xpathi":          "xpathi",
    "taint_ldap":            "ldapi",
    "taint_open_redirect":   "redirect",
    "taint_deserialization": "deserialization",
}

# Categories OWASP non couvertes par les regles taint SCA dataflow.
UNCOVERED_CATEGORIES = {"hash", "weakrand", "securecookie", "trustbound"}


@dataclass
class CategoryScore:
    category: str
    rule_id: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn


@dataclass
class BenchReport:
    by_category: list[CategoryScore] = field(default_factory=list)
    uncovered_counts: dict[str, int] = field(default_factory=dict)
    cases_in_corpus: int = 0
    cases_evaluated: int = 0
    failing_examples: list[dict] = field(default_factory=list)

    @property
    def macro_f1(self) -> float:
        if not self.by_category:
            return 0.0
        return sum(s.f1 for s in self.by_category) / len(self.by_category)

    @property
    def micro_precision(self) -> float:
        tp = sum(s.tp for s in self.by_category)
        fp = sum(s.fp for s in self.by_category)
        return tp / (tp + fp) if (tp + fp) else 0.0

    @property
    def micro_recall(self) -> float:
        tp = sum(s.tp for s in self.by_category)
        fn = sum(s.fn for s in self.by_category)
        return tp / (tp + fn) if (tp + fn) else 0.0

    @property
    def micro_f1(self) -> float:
        p, r = self.micro_precision, self.micro_recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def load_expected(benchmark_dir: Path) -> dict[str, tuple[str, bool]]:
    """test_id -> (category, is_truly_vulnerable)."""
    csv_path = benchmark_dir / "expectedresults-0.1.csv"
    out: dict[str, tuple[str, bool]] = {}
    with csv_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 4:
                continue
            test_id, category, is_vuln, _cwe = parts[0], parts[1], parts[2], parts[3]
            out[test_id] = (category, is_vuln.lower() == "true")
    return out


def load_taint_rules(sca_root: Path) -> dict[str, dict]:
    """Charge et compile les regles taint SCA builtin Python.

    Returns:
        rule_id -> compiled JSON rule dict
    """
    sys.path.insert(0, str(sca_root))
    from sca.dsl import parse_sca_file
    from sca.dsl.validator import validate_rule
    from sca.dsl.compiler import compile_to_json

    rules_dir = sca_root / "sca" / "rules" / "builtin" / "python" / "security"
    out: dict[str, dict] = {}
    for rule_id in RULE_TO_OWASP_CATEGORY:
        path = rules_dir / f"{rule_id}.sca"
        if not path.exists():
            print(f"WARN: rule file missing: {path}", file=sys.stderr)
            continue
        text = path.read_text(encoding="utf-8")
        parsed_list = parse_sca_file(text, filename=path.name)
        if not parsed_list:
            print(f"WARN: parse failed for {rule_id}", file=sys.stderr)
            continue
        parsed = parsed_list[0]
        errors = validate_rule(parsed)
        if errors:
            print(f"WARN: validation errors for {rule_id}: {errors}", file=sys.stderr)
            continue
        compiled = compile_to_json(parsed)
        out[rule_id] = compiled
    return out


def evaluate(
    rules: dict[str, dict],
    expected: dict[str, tuple[str, bool]],
    benchmark_dir: Path,
    *,
    collect_failures: int = 20,
) -> BenchReport:
    from sca.executors.dataflow_taint import run_taint_rule

    testcode = benchmark_dir / "testcode"

    cases_by_cat: dict[str, list[str]] = defaultdict(list)
    for test_id, (cat, _is_vuln) in expected.items():
        cases_by_cat[cat].append(test_id)

    report = BenchReport(cases_in_corpus=len(expected))
    for cat in UNCOVERED_CATEGORIES:
        report.uncovered_counts[cat] = len(cases_by_cat.get(cat, []))

    for rule_id, owasp_cat in RULE_TO_OWASP_CATEGORY.items():
        if rule_id not in rules:
            continue
        rule_json = rules[rule_id]
        score = CategoryScore(category=owasp_cat, rule_id=rule_id)

        for test_id in sorted(cases_by_cat.get(owasp_cat, [])):
            path = testcode / f"{test_id}.py"
            if not path.exists():
                continue
            content = path.read_text(encoding="utf-8")
            _, is_vuln = expected[test_id]
            try:
                findings = list(run_taint_rule(
                    rule_json, content, filename=str(path), language="python"
                ))
            except Exception as exc:
                print(f"ERROR running {rule_id} on {test_id}: {exc}",
                      file=sys.stderr)
                findings = []
            matched = bool(findings)

            if matched and is_vuln:
                score.tp += 1
            elif matched and not is_vuln:
                score.fp += 1
                if len(report.failing_examples) < collect_failures:
                    report.failing_examples.append({
                        "test_id": test_id, "category": owasp_cat,
                        "rule_id": rule_id, "kind": "FP",
                        "n_findings": len(findings),
                    })
            elif not matched and is_vuln:
                score.fn += 1
                if len(report.failing_examples) < collect_failures:
                    report.failing_examples.append({
                        "test_id": test_id, "category": owasp_cat,
                        "rule_id": rule_id, "kind": "FN",
                        "n_findings": 0,
                    })
            else:
                score.tn += 1
            report.cases_evaluated += 1

        report.by_category.append(score)

    return report


def render(report: BenchReport) -> str:
    rows = [
        f"Cases in corpus      : {report.cases_in_corpus}",
        f"Cases evaluated      : {report.cases_evaluated}",
        f"Categories covered   : {len(report.by_category)}",
        f"Categories uncovered : {len(report.uncovered_counts)} "
        f"({sum(report.uncovered_counts.values())} cases not evaluated)",
        "",
        f"{'category':16s} {'rule_id':24s} {'TP':>4s} {'FP':>4s} "
        f"{'TN':>4s} {'FN':>4s} {'P':>6s} {'R':>6s} {'F1':>6s}",
        "-" * 90,
    ]
    for s in sorted(report.by_category, key=lambda x: x.category):
        rows.append(
            f"{s.category:16s} {s.rule_id:24s} "
            f"{s.tp:>4d} {s.fp:>4d} {s.tn:>4d} {s.fn:>4d} "
            f"{s.precision:>6.3f} {s.recall:>6.3f} {s.f1:>6.3f}"
        )
    rows.append("-" * 90)
    rows.append(
        f"{'AGGREGATE':16s} {'(micro)':24s} "
        f"{'':>4s} {'':>4s} {'':>4s} {'':>4s} "
        f"{report.micro_precision:>6.3f} {report.micro_recall:>6.3f} "
        f"{report.micro_f1:>6.3f}"
    )
    rows.append(
        f"{'AGGREGATE':16s} {'(macro F1)':24s} "
        f"{'':>4s} {'':>4s} {'':>4s} {'':>4s} "
        f"{'':>6s} {'':>6s} {report.macro_f1:>6.3f}"
    )

    if report.uncovered_counts:
        rows.append("")
        rows.append("Categories non couvertes par dataflow (pour memoire) :")
        for cat, n in sorted(report.uncovered_counts.items()):
            rows.append(f"  {cat:16s} {n} cases")

    if report.failing_examples:
        rows.append("")
        rows.append(f"Echantillon de cas qui echouent "
                    f"(jusqu'a {len(report.failing_examples)}) :")
        for ex in report.failing_examples[:20]:
            rows.append(
                f"  {ex['kind']:2s} {ex['rule_id']:24s} "
                f"{ex['category']:16s} {ex['test_id']}"
            )
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--sca-root", type=Path, default=DEFAULT_SCA_ROOT,
                   help="Racine du repo Audit (avec sca/)")
    p.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    p.add_argument("--json", type=Path, default=None,
                   help="Write JSON report to this path")
    p.add_argument("--collect-failures", type=int, default=40,
                   help="Nombre max de cas FP/FN a lister")
    args = p.parse_args(argv)

    expected = load_expected(args.benchmark)
    rules = load_taint_rules(args.sca_root)
    print(f"Loaded {len(rules)} taint rules and {len(expected)} expected cases",
          file=sys.stderr)

    report = evaluate(rules, expected, args.benchmark,
                      collect_failures=args.collect_failures)
    print(render(report))

    if args.json:
        payload = {
            "cases_in_corpus": report.cases_in_corpus,
            "cases_evaluated": report.cases_evaluated,
            "macro_f1": report.macro_f1,
            "micro_precision": report.micro_precision,
            "micro_recall": report.micro_recall,
            "micro_f1": report.micro_f1,
            "by_category": [
                asdict(s) | {"precision": s.precision,
                             "recall": s.recall, "f1": s.f1}
                for s in report.by_category
            ],
            "uncovered_counts": report.uncovered_counts,
            "failing_examples": report.failing_examples,
        }
        args.json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
