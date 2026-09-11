"""
Data models — dataclasses and utility classes.
"""
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


@dataclass
class TaintFlow:
    """Trace of untrusted data propagation from a source to a sink."""
    category: str           # security
    rule_key: str           # ssrf, sql_injection, xss, ...
    language: str           # python, javascript, java, csharp, php
    source_file: str
    source_line: int
    source_expr: str        # e.g.: 'request.GET["q"]'
    source_kind: str        # http | cli | env | stdin | file | network
    sink_file: str
    sink_line: int
    sink_expr: str          # e.g.: 'cursor.execute(query)'
    chain: List[Tuple[int, str, str]] = field(default_factory=list)
    # chain = [(line, var_name, code_snippet), ...] in source -> sink order


@dataclass
class Finding:
    """A single detected issue."""
    category: str
    rule: str
    file: str
    line: int
    code: str
    severity: str  # HIGH, MEDIUM, LOW
    risk: str
    solution: str
    benefit: str
    # New fields
    context_before: str = ""  # Lines before
    context_after: str = ""   # Lines after
    file_type: str = "production"  # production, migration, test, config, vendor
    confidence: int = 100  # Score 0-100
    auto_fixable: bool = False
    fix_suggestion: str = ""  # Suggested fixed code
    rule_key: str = ""  # Rule key for i18n comparison (e.g.: "dom_manipulation_loop")
    committer: str = ""  # Git blame author (populated if --git-blame)
    # Rule engine + taint analysis
    # taint_flows: all flows traced by the taint engine for this finding.
    # Several taint rules can match the same sink (e.g. file_get_contents
    # is a sink for both taint_ssrf AND taint_path_traversal) — each rule
    # produces its own flow, all attached to the same finding.
    taint_flows: List[TaintFlow] = field(default_factory=list)
    # taint_flow: backward-compat alias — points to the first attached flow.
    # Kept so as not to break report.py / comparison.py which read f.taint_flow.
    taint_flow: Optional[TaintFlow] = None
    rule_source: str = "python"  # python | json_builtin | json_custom


@dataclass
class Category:
    """An audit category with its metadata."""
    key: str
    title: str
    icon: str
    risk_summary: str
    solution_summary: str
    benefit_summary: str
    findings: List[Finding] = field(default_factory=list)
    successes: List[str] = field(default_factory=list)


@dataclass
class ComparisonResult:
    """Result of comparing findings against a baseline."""
    new_findings: List[Finding] = field(default_factory=list)      # New issues
    resolved_findings: List[Finding] = field(default_factory=list)  # Resolved issues
    unchanged_findings: List[Finding] = field(default_factory=list) # Persisting issues
    baseline_date: str = ""
    baseline_totals: Dict[str, int] = field(default_factory=dict)


@dataclass
class TestResults:
    """Results of a unit test run."""
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    total: int = 0
    duration: float = 0.0
    coverage: float = 0.0
    failed_tests: List[str] = field(default_factory=list)
    error_tests: List[str] = field(default_factory=list)
    success_rate: float = 0.0


@dataclass
class FixtureValidation:
    """Results of validating audit fixtures (true/false positives/negatives)."""
    vulnerable_tested: int = 0
    vulnerable_detected: int = 0  # True positives
    vulnerable_missed: int = 0    # False negatives
    clean_tested: int = 0
    clean_passed: int = 0         # True negatives
    clean_false_positive: int = 0 # False positives
    details: List[Dict] = field(default_factory=list)

    @property
    def total(self) -> int:
        """Return the total number of fixtures tested (vulnerable + clean)."""
        return self.vulnerable_tested + self.clean_tested

    @property
    def success_rate(self) -> float:
        """Return the percentage of correctly classified fixtures."""
        if self.total == 0:
            return 0.0
        successes = self.vulnerable_detected + self.clean_passed
        return round((successes / self.total) * 100, 1)

    @property
    def is_valid(self) -> bool:
        """Return True if there are no false negatives and no false positives."""
        return self.vulnerable_missed == 0 and self.clean_false_positive == 0


class ProgressDisplay:
    """Dynamic display of parallel task progress."""

    def __init__(self, total: int, label: str = ""):
        """Initialize the progress counters and lock for a run of `total` tasks."""
        self.total = total
        self.label = label
        self.completed = 0
        self.running = set()
        self.results = {}  # name -> status (pass/fail/timeout)
        self.lock = threading.Lock()
        self._last_line_count = 0
        self._start_time = time.perf_counter()

    def start(self, name: str):
        """Mark a task as started."""
        with self.lock:
            self.running.add(name)
            self._refresh()

    def complete(self, name: str, status: str):
        """Mark a task as finished with the given status."""
        with self.lock:
            self.running.discard(name)
            self.results[name] = status
            self.completed += 1
            self._refresh()

    def _refresh(self):
        """Redraw the progress line in place."""
        pending = self.total - self.completed - len(self.running)
        elapsed = round(time.perf_counter() - self._start_time, 1)
        status_line = (
            f"   {self.label}: {self.completed}/{self.total} ✓ | "
            f"{len(self.running)} ⏳ | {pending} ⏸ | {elapsed}s"
        )
        # Clear the previous line and print the new one
        sys.stdout.write(f"\r{status_line}".ljust(80))
        sys.stdout.flush()

    def finish(self):
        """End the progress display and move to the next line."""
        sys.stdout.write("\n")
        sys.stdout.flush()

    def get_summary(self) -> Dict[str, int]:
        """Return a summary count of pass/fail/timeout results."""
        passed = sum(1 for s in self.results.values() if s == "pass")
        failed = sum(1 for s in self.results.values() if s == "fail")
        timeout = sum(1 for s in self.results.values() if s == "timeout")
        return {"passed": passed, "failed": failed, "timeout": timeout}
