"""Integrity check module — detects rule+fixture duplicates.

Extends what `--rules-match` doesn't cover:

1. Content duplicates (SHA-256): two fixtures with an identical hash
2. Suspicious naming with a language suffix: `name_python.py` when `name.py` exists
3. Mixed extensions per rule: `name.txt` AND `name.html` for the same rule
4. Builtin pattern collision: two rules with a strictly identical regex
5. Strict orphan fixtures: fixture whose inferred rule_id matches no rule
6. Builtin<->custom collision: a custom rule reuses a builtin rule_id

Usage: `./run_audit.py . --check-integrity`
See also: docs/FIXTURE-INTEGRITY.md (full convention).
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# Language suffixes that indicate suspicious naming
_LANG_SUFFIXES = ("_python", "_javascript", "_java", "_csharp", "_php", "_html")

# Extension -> canonical language mapping (used to check consistency)
_EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".ts": "javascript",
    ".tsx": "javascript", ".mjs": "javascript",
    ".java": "java",
    ".cs": "csharp",
    ".php": "php", ".inc": "php",
    ".html": "html", ".htm": "html", ".vue": "html", ".svelte": "html",
    ".yml": "yaml", ".yaml": "yaml",
}

# macOS Finder duplicate artifacts (gitignored but present on disk) -- pattern `name 2.ext`
_FINDER_DUP_RE = re.compile(r"\s\d+\.\w+$")


def _is_finder_dup(path: Path) -> bool:
    """Detect macOS Finder duplicate artifacts (`foo 2.py`, `bar 3.js`)."""
    return bool(_FINDER_DUP_RE.search(path.name))


def _iter_fixture_files(fixtures_dir: Path):
    """Iterate over fixture files, filtering out macOS Finder artifacts."""
    for sub in ("vulnerable", "clean"):
        d = fixtures_dir / sub
        if not d.exists():
            continue
        for f in d.iterdir():
            if f.is_file() and not _is_finder_dup(f):
                yield f


@dataclass
class IntegrityIssue:
    """A single detected integrity problem."""
    severity: str  # CRITICAL, WARNING, INFO
    category: str  # hash_duplicate, suspicious_suffix, mixed_extensions, ...
    message: str
    files: List[str] = field(default_factory=list)


@dataclass
class IntegrityReport:
    """Aggregated integrity check report."""
    issues: List[IntegrityIssue] = field(default_factory=list)
    rules_count: int = 0
    fixtures_count: int = 0

    def add(self, issue: IntegrityIssue):
        """Append an issue to the report."""
        self.issues.append(issue)

    def has_critical(self) -> bool:
        """Return True if any issue has CRITICAL severity."""
        return any(i.severity == "CRITICAL" for i in self.issues)

    def by_category(self) -> Dict[str, List[IntegrityIssue]]:
        """Group issues by category."""
        out: Dict[str, List[IntegrityIssue]] = defaultdict(list)
        for i in self.issues:
            out[i.category].append(i)
        return out


# =============================================================================
# CHECKS
# =============================================================================

def _file_sha256(path: Path) -> str:
    """Compute the SHA-256 hash of a file's content, streaming for large files."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def check_hash_duplicates(fixtures_dir: Path, report: IntegrityReport) -> None:
    """1. Detect fixtures with strictly identical content (SHA-256)."""
    by_hash: Dict[str, List[Path]] = defaultdict(list)
    for f in _iter_fixture_files(fixtures_dir):
        try:
            by_hash[_file_sha256(f)].append(f)
        except OSError:
            continue

    for digest, files in by_hash.items():
        if len(files) < 2:
            continue
        report.add(IntegrityIssue(
            severity="CRITICAL",
            category="hash_duplicate",
            message=f"{len(files)} fixtures partagent le même contenu (SHA-256 {digest[:12]}…)",
            files=[str(f.relative_to(fixtures_dir.parent.parent)) for f in files],
        ))


def _find_lang_suffix(stem: str) -> Optional[Tuple[str, str]]:
    """Return (suffix, base without suffix) if stem ends with a language suffix, else None."""
    for suffix in _LANG_SUFFIXES:
        if stem.endswith(suffix):
            return suffix, stem[:-len(suffix)]
    return None


def _add_suffix_collision(report: IntegrityReport, f: Path, d: Path,
                          canonical_name: str, suffix: str,
                          fixtures_dir: Path, suffix_note: str = "") -> None:
    """Record a CRITICAL issue for a fixture that duplicates a canonically-named one."""
    report.add(IntegrityIssue(
        severity="CRITICAL",
        category="suspicious_suffix",
        message=f"`{f.name}` doublonne `{canonical_name}` (suffixe `{suffix}`{suffix_note})",
        files=[str(f.relative_to(fixtures_dir.parent.parent)),
               str((d / canonical_name).relative_to(fixtures_dir.parent.parent))],
    ))


def _check_one_fixture_suffix(f: Path, all_names: Set[str], d: Path,
                              fixtures_dir: Path, report: IntegrityReport) -> None:
    """Check that a fixture's language suffix doesn't duplicate a canonical fixture."""
    stem, ext = f.stem, f.suffix

    # Case 1: vulnerable fixture -- `name_python.py` duplicating `name.py`
    match = _find_lang_suffix(stem)
    if match:
        suffix, canonical_stem = match
        canonical_name = canonical_stem + ext
        if canonical_name in all_names:
            _add_suffix_collision(report, f, d, canonical_name, suffix, fixtures_dir)
        return

    # Case 2: clean fixture -- `name_python_clean.py` duplicating `name_clean.py`
    if not stem.endswith("_clean"):
        return
    base = stem[:-len("_clean")]
    match = _find_lang_suffix(base)
    if not match:
        return
    suffix, canonical_base = match
    canonical_name = canonical_base + "_clean" + ext
    if canonical_name in all_names:
        _add_suffix_collision(report, f, d, canonical_name, suffix, fixtures_dir, " avant _clean")


def check_suspicious_suffix(fixtures_dir: Path, report: IntegrityReport) -> None:
    """2. Detect fixtures named `<name>_<lang>.<ext>` when `<name>.<ext>` also exists."""
    for sub in ("vulnerable", "clean"):
        d = fixtures_dir / sub
        if not d.exists():
            continue
        # Set of canonical names in the directory (filtered, no Finder dups)
        all_names = {f.name for f in d.iterdir() if f.is_file() and not _is_finder_dup(f)}
        for f in d.iterdir():
            if not f.is_file() or _is_finder_dup(f):
                continue
            _check_one_fixture_suffix(f, all_names, d, fixtures_dir, report)


def check_mixed_extensions(fixtures_dir: Path, rule_ids: Set[str],
                           report: IntegrityReport) -> None:
    """3. Detect rule_ids with multiple incompatible fixture extensions."""
    by_rule: Dict[str, Set[str]] = defaultdict(set)
    for f in _iter_fixture_files(fixtures_dir):
        stem = f.stem
        if stem.endswith("_clean"):
            stem = stem[:-len("_clean")]
        if stem in rule_ids:
            by_rule[stem].add(f.suffix.lower())

    # For each rule, warn if it has multiple incompatible extensions
    incompat_pairs = [
        ({".txt"}, {".html", ".htm", ".vue", ".svelte"}),
        ({".txt"}, {".py", ".js", ".java", ".cs", ".php"}),
    ]
    for rule_id, exts in by_rule.items():
        for set_a, set_b in incompat_pairs:
            ia = exts & set_a
            ib = exts & set_b
            if ia and ib:
                report.add(IntegrityIssue(
                    severity="WARNING",
                    category="mixed_extensions",
                    message=f"Rule `{rule_id}` a des fixtures avec extensions incompatibles : {sorted(ia | ib)}",
                    files=[],
                ))


def check_pattern_collision(rules_dir: Path, report: IntegrityReport) -> Set[str]:
    """4. Detect a strictly identical regex pattern shared between two different rules.

    Also returns the set of rule_ids found (used by the other checks).
    """
    # Map (language, pattern_text) → list of (rule_id, file_path)
    by_pattern: Dict[Tuple[str, str], List[Tuple[str, Path]]] = defaultdict(list)
    rule_ids: Set[str] = set()
    for sca_file in rules_dir.rglob("*.sca"):
        try:
            content = sca_file.read_text(encoding="utf-8")
        except OSError:
            continue
        # Lightweight extraction: rule + language + pattern
        rule_match = re.search(r"^\s*rule\s+(\w+)", content, re.M)
        lang_match = re.search(r"^\s*language\s+(\w+)", content, re.M)
        pat_match = re.search(r"^\s*pattern\s+(.+)$", content, re.M)
        if not rule_match:
            continue
        rule_id = rule_match.group(1)
        rule_ids.add(rule_id)
        if not (lang_match and pat_match):
            continue
        lang = lang_match.group(1)
        pat = pat_match.group(1).strip()
        by_pattern[(lang, pat)].append((rule_id, sca_file))

    for (lang, pat), entries in by_pattern.items():
        unique_rules = {rid for rid, _ in entries}
        if len(unique_rules) >= 2:
            report.add(IntegrityIssue(
                severity="WARNING",
                category="pattern_collision",
                message=f"Pattern identique pour {len(unique_rules)} règles ({lang}) : {pat[:60]}{'…' if len(pat) > 60 else ''}",
                files=[str(p.relative_to(rules_dir.parent.parent)) + f" ({rid})" for rid, p in entries],
            ))
    return rule_ids


def check_orphan_fixtures(fixtures_dir: Path, rule_ids: Set[str],
                          registry_keys: Set[str], report: IntegrityReport) -> None:
    """5. Detect fixtures whose inferred rule_id is neither in rule_ids nor in the registry."""
    for f in _iter_fixture_files(fixtures_dir):
        if f.name in registry_keys:
            continue
        stem = f.stem
        if stem.endswith("_clean"):
            stem = stem[:-len("_clean")]
        if stem in rule_ids:
            continue
            # Also infer without a suspicious language suffix
            cleaned_stem = stem
            for suffix in _LANG_SUFFIXES:
                if cleaned_stem.endswith(suffix):
                    cleaned_stem = cleaned_stem[:-len(suffix)]
                    break
            if cleaned_stem in rule_ids:
                continue  # already reported as suspicious_suffix
            report.add(IntegrityIssue(
                severity="WARNING",
                category="orphan_fixture",
                message=f"Fixture `{f.name}` ne correspond à aucune règle connue (stem `{stem}` non trouvé)",
                files=[str(f.relative_to(fixtures_dir.parent.parent))],
            ))


def check_builtin_custom_collision(builtin_rule_ids: Set[str],
                                    custom_rules_dir: Path,
                                    report: IntegrityReport) -> None:
    """6. Detect a custom rule_id colliding with a builtin rule_id."""
    if not custom_rules_dir or not custom_rules_dir.exists():
        return
    for sca_file in custom_rules_dir.rglob("*.sca"):
        try:
            content = sca_file.read_text(encoding="utf-8")
        except OSError:
            continue
        rule_match = re.search(r"^\s*rule\s+(\w+)", content, re.M)
        if not rule_match:
            continue
        rule_id = rule_match.group(1)
        if rule_id in builtin_rule_ids:
            report.add(IntegrityIssue(
                severity="CRITICAL",
                category="builtin_custom_collision",
                message=f"Custom rule `{rule_id}` collide avec un builtin",
                files=[str(sca_file)],
            ))


# =============================================================================
# ENTRY POINT
# =============================================================================

def run_integrity_checks() -> IntegrityReport:
    """Run all integrity checks and return the aggregated report."""
    from sca import SCRIPT_DIR, SCA_PACKAGE_DIR

    rules_dir = SCA_PACKAGE_DIR / "rules" / "builtin"
    fixtures_dir = SCRIPT_DIR / "tests" / "fixtures" / "generic"
    custom_rules_dir = SCRIPT_DIR / "custom-rules"

    report = IntegrityReport()

    # Pattern collision (and rule_id collection)
    rule_ids = check_pattern_collision(rules_dir, report)
    report.rules_count = len(rule_ids)

    # Load registry filenames to exclude explicitly mapped fixtures
    registry_keys: Set[str] = set()
    try:
        import sys as _sys
        _sys.path.insert(0, str(SCRIPT_DIR / "tests"))
        from registry import VULNERABLE_FIXTURES, CLEAN_FIXTURES  # type: ignore
        registry_keys = {v[0] for v in VULNERABLE_FIXTURES.values()}
        registry_keys |= {v[0] for v in CLEAN_FIXTURES.values()}
    except Exception:
        pass

    # Count fixtures (excluding macOS Finder artifacts)
    report.fixtures_count = sum(1 for _ in _iter_fixture_files(fixtures_dir))

    check_hash_duplicates(fixtures_dir, report)
    check_suspicious_suffix(fixtures_dir, report)
    check_mixed_extensions(fixtures_dir, rule_ids, report)
    check_orphan_fixtures(fixtures_dir, rule_ids, registry_keys, report)
    check_builtin_custom_collision(rule_ids, custom_rules_dir, report)

    return report


def print_report(report: IntegrityReport) -> None:
    """Print the report to stdout."""
    print()
    print("=" * 60)
    print("  Integrity Check")
    print("=" * 60)
    print()
    print(f"  Rules    : {report.rules_count}")
    print(f"  Fixtures : {report.fixtures_count}")
    print()

    if not report.issues:
        print("  ✓ Aucun problème d'intégrité détecté.")
        return

    by_cat = report.by_category()
    severity_icon = {"CRITICAL": "✗", "WARNING": "⚠", "INFO": "ℹ"}
    cat_label = {
        "hash_duplicate": "Doublons par contenu (SHA-256)",
        "suspicious_suffix": "Suffixes langage suspects",
        "mixed_extensions": "Extensions mixtes par règle",
        "pattern_collision": "Patterns regex identiques entre règles",
        "orphan_fixture": "Fixtures orphelines (rule_id inconnu)",
        "builtin_custom_collision": "Collisions rule_id builtin↔custom",
    }
    for cat in ("hash_duplicate", "suspicious_suffix", "mixed_extensions",
                "pattern_collision", "orphan_fixture", "builtin_custom_collision"):
        items = by_cat.get(cat, [])
        if not items:
            continue
        label = cat_label.get(cat, cat)
        print(f"  {severity_icon[items[0].severity]} {len(items)} — {label}")
        for issue in items:
            print(f"      • {issue.message}")
            for f in issue.files:
                print(f"          {f}")
        print()

    n_critical = sum(1 for i in report.issues if i.severity == "CRITICAL")
    n_warning = sum(1 for i in report.issues if i.severity == "WARNING")
    print(f"  Total : {n_critical} critique(s), {n_warning} warning(s)")
    print(f"  Exit code : {1 if report.has_critical() else 0}")
