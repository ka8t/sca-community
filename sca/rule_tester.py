"""
Quick test of a single custom rule against the project's files.

Loads only the requested rule, runs it against the files of the
matching language, and prints the findings without generating an
HTML report or a baseline.

Usage: ./run_audit.py /project --test-rule my_rule
"""
import os
import re
import time
import logging
from pathlib import Path
from typing import List, Optional

from sca.i18n import _t

logger = logging.getLogger("sca.rule_tester")


def test_rule(project_path: str, rule_id: str, rules_dir: str = None,
              target_file: str = None, verbose: bool = False,
              lang: str = "en") -> int:
    """Test a custom rule and print the results.

    Args:
        project_path: path of the audited project
        rule_id: identifier of the rule to test
        rules_dir: custom rules directory (default: audit-rules/)
        target_file: single file to test (optional)
        verbose: also print scanned files with no match
        lang: language for console messages

    Returns:
        number of findings detected
    """
    from pathlib import Path as _Path
    from sca.config import load_config
    from sca.rule_loader import load_rules_from_directory, _compile_rule_patterns
    from sca.utils import read_file

    # Load the config to know the languages and paths
    config = load_config(project_path=_Path(project_path), silent=True)

    # Look up the rule
    custom_dir = Path(project_path) / (rules_dir or "audit-rules")
    if not custom_dir.exists():
        print(f"  {_t('tester_dir_not_found', lang).format(dir=custom_dir)}")
        print(f"  {_t('tester_create_rule_hint', lang).format(rule_id=rule_id)}")
        return 0

    all_rules = load_rules_from_directory(custom_dir, source="json_custom")
    rule = None
    for r in all_rules:
        if r["id"] == rule_id:
            rule = r
            break

    if rule is None:
        print(f"  {_t('tester_rule_not_found', lang).format(rule_id=rule_id, dir=custom_dir)}")
        available = [r["id"] for r in all_rules]
        if available:
            print(f"  {_t('tester_rules_available', lang).format(list=', '.join(available))}")
        else:
            print(f"  {_t('tester_no_rules', lang).format(dir=custom_dir)}")
        return 0

    # Display the rule's info
    language = rule["language"]
    mode = rule.get("mode", "regex")
    severity = rule["severity"]
    patterns = rule.get("patterns", [])
    fc = rule.get("file_contains", {})

    print(f"\n  {_t('tester_rule_info', lang).format(rule_id=rule_id)}")
    print(f"  {_t('tester_lang_severity', lang).format(language=language, severity=severity)}")
    if patterns:
        for p in patterns:
            print(f"  {_t('tester_pattern_line', lang).format(pattern=p.get('pattern', '?'), scope=p.get('match', 'line'))}")
    if fc.get("has") or fc.get("not_has"):
        if fc.get("has"):
            print(f"  {_t('tester_requires_has', lang).format(list=', '.join(fc['has']))}")
        if fc.get("not_has"):
            print(f"  {_t('tester_requires_not_has', lang).format(list=', '.join(fc['not_has']))}")
    print()

    # Find the files to scan
    lang_ext_map = {
        "python": [".py"],
        "javascript": [".js", ".jsx", ".ts", ".tsx", ".mjs"],
        "java": [".java"],
        "csharp": [".cs"],
        "php": [".php", ".inc"],
        "html": [".html", ".htm"],
        "yaml": [".yml", ".yaml"],
    }
    extensions = tuple(lang_ext_map.get(language, []))
    if not extensions:
        print(f"  {_t('tester_lang_unsupported', lang).format(language=language)}")
        return 0

    include_paths = config.get("paths", {}).get("include", ["."])
    exclude_patterns = config.get("paths", {}).get("exclude", [])

    if target_file:
        files = [str(Path(project_path) / target_file)] if os.path.exists(
            str(Path(project_path) / target_file)) else []
        if not files:
            print(f"  {_t('tester_file_not_found', lang).format(file=target_file)}")
            return 0
    else:
        files = []
        for inc_path in include_paths:
            full = os.path.join(project_path, inc_path)
            if not os.path.exists(full):
                continue
            for root, _, filenames in os.walk(full):
                for fn in filenames:
                    if fn.endswith(extensions):
                        filepath = os.path.join(root, fn)
                        rel = os.path.relpath(filepath, project_path)
                        # Exclude
                        excluded = False
                        for exc in exclude_patterns:
                            if exc in rel:
                                excluded = True
                                break
                        if not excluded:
                            files.append(filepath)

    if not files:
        print(f"  {_t('tester_no_files', lang).format(extensions=', '.join(extensions))}")
        return 0

    print(f"  {_t('tester_scanning', lang).format(count=len(files))}\n")

    # Run the rule
    start = time.time()
    findings = []

    # Compile the file_contains patterns if needed
    if fc.get("has") or fc.get("not_has"):
        compiled_has = [re.compile(p) for p in fc.get("has", [])]
        compiled_not_has = [re.compile(p) for p in fc.get("not_has", [])]
        fc["_compiled_has"] = compiled_has
        fc["_compiled_not_has"] = compiled_not_has

    for filepath in files:
        all_lines = read_file(filepath)
        if not all_lines:
            if verbose:
                rel = os.path.relpath(filepath, project_path)
                print(f"    {_t('tester_file_empty', lang).format(file=rel)}")
            continue

        # Check file conditions (requires)
        if fc.get("_compiled_has") or fc.get("_compiled_not_has"):
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except Exception:
                continue

            skip = False
            for pat in fc.get("_compiled_has", []):
                if not pat.search(content):
                    skip = True
                    break
            if not skip:
                for pat in fc.get("_compiled_not_has", []):
                    if pat.search(content):
                        skip = True
                        break
            if skip:
                if verbose:
                    rel = os.path.relpath(filepath, project_path)
                    print(f"    {_t('tester_requires_not_met', lang).format(file=rel)}")
                continue

        # Run the regex patterns
        file_findings = []
        for p in patterns:
            compiled = p.get("_compiled")
            if compiled is None:
                continue

            match_scope = p.get("match", "line")
            compiled_with = p.get("_compiled_with")

            if match_scope == "line":
                for line_num, line in all_lines:
                    if compiled.search(line):
                        if compiled_with and not compiled_with.search(line):
                            continue
                        neg = p.get("_compiled_pattern-not")
                        if neg and neg.search(line):
                            continue
                        file_findings.append((line_num, line.strip()))

            elif match_scope.startswith("context-"):
                try:
                    window = int(match_scope.split("-")[1])
                except (IndexError, ValueError):
                    window = 6
                n_lines = len(all_lines)
                seen_lines = set()
                for start_idx in range(n_lines):
                    block_end = min(start_idx + window, n_lines)
                    block_text = "".join(
                        line for _, line in all_lines[start_idx:block_end]
                    )
                    if not block_text:
                        continue
                    m = compiled.search(block_text)
                    if not m:
                        continue
                    if compiled_with and not compiled_with.search(block_text):
                        continue
                    local_start = m.start()
                    start_line = all_lines[start_idx][0] + block_text.count(
                        "\n", 0, local_start
                    )
                    if start_line not in seen_lines:
                        seen_lines.add(start_line)
                        code = all_lines[start_line - 1][1].strip() if start_line - 1 < n_lines else ""
                        file_findings.append((start_line, code))

        if file_findings:
            rel = os.path.relpath(filepath, project_path)
            for line_num, code in file_findings:
                print(f"  {rel}:{line_num:<6d} — {code[:120]}")
                findings.append((rel, line_num, code))
        elif verbose:
            rel = os.path.relpath(filepath, project_path)
            print(f"    {_t('tester_no_match', lang).format(file=rel)}")

    elapsed = time.time() - start

    # Resume
    print()
    if findings:
        n_files = len(set(f[0] for f in findings))
        print(f"  {_t('tester_findings_summary', lang).format(count=len(findings), files=n_files, elapsed=f'{elapsed:.1f}')}")
    else:
        print(f"  {_t('tester_no_findings', lang).format(files=len(files), elapsed=f'{elapsed:.1f}')}")

    return len(findings)
