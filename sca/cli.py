"""
Interface en ligne de commande — parse_args, commandes et main.
"""
import os
import re
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

from sca import SCRIPT_DIR, SCA_PACKAGE_DIR, VERSION
from sca.config import load_config, validate_config, DEFAULT_CONFIG
from sca.debug import setup_debug, get_debug_level
from sca.dsl import parse_sca_file
from sca.i18n import _t, _set_script_lang, _get_script_lang
from sca.projects import _init_project_config
from sca.runner import AuditRunner

def _build_rule_metadata():
    """Build the rule_key mappings from the .sca files: category + i18n texts."""
    rules_dir = SCA_PACKAGE_DIR / "rules" / "builtin"
    cat_map = {}    # rule_key → category
    risk_map = {}   # rule_key → {lang: risk text}
    for sca_file in rules_dir.rglob("*.sca"):
        # Category = parent folder (security, arch, maintenance, ui, ux, cicd)
        parts = sca_file.relative_to(rules_dir).parts
        if len(parts) >= 2:
            category = parts[1]
        else:
            category = "security"
        try:
            nodes = parse_sca_file(sca_file.read_text(encoding="utf-8"), str(sca_file))
            for node in nodes:
                cat_map[node.id] = category
                if node.risk and hasattr(node.risk, 'texts'):
                    risk_map[node.id] = node.risk.texts
        except Exception:
            pass

    return cat_map, risk_map


# Cache (built once)
_RULE_METADATA_CACHE = None


def _get_rule_metadata():
    """Return (cat_map, risk_map), building and caching them on first call."""
    global _RULE_METADATA_CACHE
    if _RULE_METADATA_CACHE is None:
        _RULE_METADATA_CACHE = _build_rule_metadata()
    return _RULE_METADATA_CACHE


def _get_rule_category_map():
    """Return the rule_key → category mapping (cached)."""
    return _get_rule_metadata()[0]


def _check_is_binary() -> bool:
    """Detect whether running in the distributed binary (license_check present and non-source)."""
    import importlib.util
    if importlib.util.find_spec("sca.license_check") is None:
        return False
    try:
        import sca.license_check as _lc
        return not getattr(_lc, "_IS_SOURCE_MODE", True)
    except ImportError:
        return False


def parse_args():
    """Parse command-line arguments."""
    _is_binary = _check_is_binary()

    parser = argparse.ArgumentParser(
        description="Static code audit — Analyzes the codebase and generates an HTML report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  run_audit.py /path/to/project          Audit a project
  run_audit.py .                         Audit current directory
  run_audit.py /path/to/project --quick  Security only (fast)
  run_audit.py /path/to/project --init   Create audit.config.json
  run_audit.py . --sarif --fail-on-high  CI/CD mode
        """
    )

    # ── Common arguments (source + binary) ────────────────────────────────────
    common = parser.add_argument_group("Scan options")
    common.add_argument("--version", action="version",
                        version=f"{DEFAULT_CONFIG['brand']['tool_name']} v{VERSION}")
    common.add_argument("project_path", nargs="?", default=".",
                        help="Path to the project to audit (default: current directory)")
    common.add_argument("--lang", type=str, default="en",
                        choices=["fr", "en", "es", "de"],
                        help="Report and console language (default: en)")
    common.add_argument("--license-info", action="store_true",
                        help="Display current license status and exit")
    common.add_argument("--no-cache", action="store_true",
                        help="Disable rules compilation cache (.sca-cache/rules-*.pkl)")
    common.add_argument("--no-incremental", action="store_true",
                        help="Disable incremental analysis (re-scan all files even if unchanged)")
    common.add_argument("--no-parallel", action="store_true",
                        help="Disable parallel file scanning (force sequential)")

    # ── Output options ────────────────────────────────────────────────────────
    output = parser.add_argument_group("Output options")
    output.add_argument("--fail-on-high", action="store_true",
                        help="Exit code 1 if HIGH vulnerabilities found (CI/CD)")
    output.add_argument("--sarif", action="store_true",
                        help="Generate SARIF 2.1.0 export (GitHub/GitLab)")
    output.add_argument("--sbom", action="store_true",
                        help="Generate CycloneDX 1.5 SBOM (dependency inventory)")
    output.add_argument("--with-logs", action="store_true",
                        help="Save console output to log file in output directory")
    output.add_argument("--quiet", action="store_true",
                        help="Silent console mode — only errors and final result are shown")

    # ── Client features ───────────────────────────────────────────────────────
    client = parser.add_argument_group("Client features")
    client.add_argument("--init", action="store_true",
                        help="Create or modify audit.config.json (interactive)")
    client.add_argument("--custom-rules-match", action="store_true",
                        help=_t("custom_rules_match_help", "en"))
    client.add_argument("--with-tests", action="store_true",
                        help="Auto-detect and run project unit tests")
    client.add_argument("--with-deps", action="store_true",
                        help="Run dependency vulnerability scan (pip-audit, npm audit)")
    # ── Internal SCA developer tools (source only, absent from the binary) ────
    if not _is_binary:
        sca = parser.add_argument_group("SCA developer tools")
        sca.add_argument("--quick", "-q", action="store_true",
                         help="Quick mode (security only)")
        sca.add_argument("--severity", type=str, default=None, metavar="LEVELS",
                         help="Filter rules by severity level(s), comma-separated (e.g. CRITICAL,HIGH). Default: all levels")
        sca.add_argument("--list-rules", action="store_true",
                         help="List all audit rules by category")
        sca.add_argument("--debug", action="store_true",
                         help="Debug mode (detailed logs to stderr)")
        sca.add_argument("--rules-match", action="store_true",
                         help="Check that every rule has matching fixtures (vulnerable + clean)")
        sca.add_argument("--check-integrity", action="store_true",
                         help="Detect duplicates and integrity issues (rules + fixtures, builtin + custom). "
                              "Reports SHA-256 content duplicates, suspicious language-suffix naming, "
                              "mixed extensions, pattern collisions, orphan fixtures, builtin/custom rule_id collisions.")
        sca.add_argument("--simulate-binary", nargs="?", const="", metavar="CLIENT",
                         help="Simulate binary mode with license enforcement. "
                              "Optional: client name to load license from AuditDistrib/clients/CLIENT/license.key")
    else:
        # Default attributes for the binary (never exposed but expected by the rest of the code)
        parser.set_defaults(quick=False, severity=None, list_rules=False, debug=False,
                            rules_match=False, check_integrity=False, simulate_binary=None)

    return parser.parse_args()


def match_rules_fixtures():
    """Check that each .sca rule has its fixtures (vulnerable + clean).

    Source of truth: tests/registry.py (legacy fixtures with explicit mappings).
    Complemented by filename inference for new fixtures that follow the
    {rule_id}.ext / {rule_id}_clean.ext convention.
    """
    from pathlib import Path
    from sca import SCRIPT_DIR, SCA_PACKAGE_DIR
    from sca.dsl import compile_sca_to_json

    rules_dir     = SCA_PACKAGE_DIR / "rules" / "builtin"
    fixtures_base = SCRIPT_DIR / "tests" / "fixtures" / "generic"
    vuln_dir      = fixtures_base / "vulnerable"
    clean_dir     = fixtures_base / "clean"

    # 1. Collect all the rule_keys from the .sca files
    sca_rules = {}
    for sca_file in sorted(rules_dir.rglob("*.sca")):
        content = sca_file.read_text(encoding="utf-8")
        try:
            compiled = compile_sca_to_json(content, str(sca_file))
            for r in compiled:
                rel = sca_file.relative_to(rules_dir)
                sca_rules[r["id"]] = str(rel)
        except Exception:
            pass

    # 2a. Legacy fixtures: read the registry (source of truth for non-trivial mappings)
    sys.path.insert(0, str(SCRIPT_DIR / "tests"))
    try:
        from registry import VULNERABLE_FIXTURES, CLEAN_FIXTURES
        vuln_keys  = {v[2] for v in VULNERABLE_FIXTURES.values()}
        clean_keys = {v[2] for v in CLEAN_FIXTURES.values()}
    except ImportError:
        vuln_keys, clean_keys = set(), set()

    # 2b. New fixtures: inference by filename (convention {rule_id}.ext)
    #     Only if the stem matches a known rule_id (avoids false positives)
    for f in vuln_dir.iterdir():
        if f.is_file() and f.stem in sca_rules:
            vuln_keys.add(f.stem)
    for f in clean_dir.iterdir():
        if f.is_file():
            stem = f.stem
            key = stem[:-6] if stem.endswith("_clean") else stem
            if key in sca_rules:
                clean_keys.add(key)

    fixture_keys = vuln_keys | clean_keys

    # 3. Cross-reference
    rules_without_vuln = []
    rules_without_clean = []
    rules_without_any = []
    fixtures_without_rule = []

    for rule_id, path in sorted(sca_rules.items()):
        has_vuln = rule_id in vuln_keys
        has_clean = rule_id in clean_keys
        if not has_vuln and not has_clean:
            rules_without_any.append((rule_id, path))
        elif not has_vuln:
            rules_without_vuln.append((rule_id, path))
        elif not has_clean:
            rules_without_clean.append((rule_id, path))

    for key in sorted(fixture_keys):
        if key not in sca_rules:
            fixtures_without_rule.append(key)

    # 4. Display
    total = len(sca_rules)
    covered = total - len(rules_without_any)
    pct = covered / total * 100 if total > 0 else 0
    _lang = _get_script_lang()

    print(f"\n{'=' * 50}")
    print(f"  {_t('rules_match_title', _lang)}")
    print(f"{'=' * 50}\n")
    print(f"  {_t('rules_match_sca_count', _lang).format(count=total)}")
    print(f"  {_t('rules_match_covered', _lang).format(covered=covered, pct=f'{pct:.0f}')}")
    print(f"  {_t('rules_match_without_any', _lang).format(count=len(rules_without_any))}")

    if rules_without_any:
        print(f"\n  ❌ {_t('rules_match_no_fixture', _lang).format(count=len(rules_without_any))}")
        for rule_id, path in rules_without_any:
            print(f"     {rule_id}  ({path})")

    if rules_without_vuln:
        print(f"\n  ⚠️  {_t('rules_match_no_vuln', _lang).format(count=len(rules_without_vuln))}")
        for rule_id, path in rules_without_vuln:
            print(f"     {rule_id}  ({path})")

    if rules_without_clean:
        print(f"\n  ⚠️  {_t('rules_match_no_clean', _lang).format(count=len(rules_without_clean))}")
        for rule_id, path in rules_without_clean:
            print(f"     {rule_id}  ({path})")

    if fixtures_without_rule:
        print(f"\n  🔍 {_t('rules_match_orphan_fixtures', _lang).format(count=len(fixtures_without_rule))}")
        for key in fixtures_without_rule:
            print(f"     {key}")

    if not rules_without_any and not rules_without_vuln and not rules_without_clean:
        print(f"\n  ✅ {_t('rules_match_all_ok', _lang)}")

    print()














def list_rules(lang: str = "en", project_path_arg: str = None):
    """List all audit rules by category, with project-specific fixtures."""
    # Build the mapping dynamically from the .sca files
    rule_cat_map, risk_map = _get_rule_metadata()

    # Load the report locales for the translated names
    report_locale_path = SCRIPT_DIR / "locales" / "report" / f"{lang}.json"
    if not report_locale_path.exists():
        report_locale_path = SCRIPT_DIR / "locales" / "report" / "en.json"

    rules_i18n = {}
    category_titles = {}
    try:
        with open(report_locale_path, 'r', encoding='utf-8') as f:
            report_locale = json.load(f)
            rules_i18n = report_locale.get("rules", {})
            category_titles = report_locale.get("category_titles", {})
    except (json.JSONDecodeError, IOError):
        pass

    # Mapping folder name → display category key
    dir_to_display = {
        "security": "security",
        "arch": "architecture",
        "ui": "ui",
        "ux": "ux",
        "maintenance": "maintenance",
        "dependencies": "dependencies",
        "database": "database",
        "cicd": "cicd",
    }

    # Categories in display order (display key, folder keys, icon, enabled by default)
    categories = [
        ("security",     "🛡️",  True),
        ("architecture", "🏗️",  True),
        ("ui",           "🎨", True),
        ("ux",           "🧑‍💻", True),
        ("maintenance",  "🔧", True),
        ("dependencies", "📦", False),
        ("database",     "🗄️",  False),
        ("cicd",         "⚙️",  False),
    ]

    # Reverse mapping: display key → folder keys
    display_to_dirs = {}
    for dir_key, display_key in dir_to_display.items():
        display_to_dirs.setdefault(display_key, set()).add(dir_key)

    total_rules = len(rule_cat_map)
    rules_label = _t("rules_count", lang)
    print(f"\n📋 {_t('available_rules', lang)} ({total_rules} {rules_label}):\n")

    for cat_display, icon, enabled_default in categories:
        dir_keys = display_to_dirs.get(cat_display, {cat_display})
        # Rules for this category (sorted by rule_key)
        cat_rules = sorted(
            [(rk, rules_i18n.get(rk, {}))
             for rk, cat in rule_cat_map.items()
             if cat in dir_keys],
            key=lambda x: x[0]
        )

        title = category_titles.get(cat_display, cat_display.capitalize())
        suffix = ""
        if not enabled_default:
            suffix = f"  [{_t('disabled_by_default', lang)}]"

        print(f"{icon}  {title} ({len(cat_rules)} {rules_label}){suffix}")
        for rule_key, rule_data in cat_rules:
            # Name from the locales, otherwise risk text from the .sca file
            if isinstance(rule_data, dict) and rule_data.get("name"):
                name = rule_data["name"]
            elif rule_key in risk_map:
                # Fallback: translated risk text from the .sca file
                risk_text = risk_map[rule_key].get(lang, risk_map[rule_key].get("en", rule_key))
                # Truncate to 60 chars for display
                name = risk_text[:60] + "…" if len(risk_text) > 60 else risk_text
            else:
                name = rule_key
            print(f"   {rule_key:<40} {name}")
        print()

    # Project-specific fixtures
    if project_path_arg:
        project_path = Path(project_path_arg).resolve()
        config_path = project_path / "audit.config.json"
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                project_uuid = config.get("project", {}).get("id", "")
                if project_uuid:
                    from sca.projects import _get_project_dir
                    project_dir = _get_project_dir(project_uuid)
                else:
                    project_dir = None
                if project_dir is not None:
                    conftest_path = project_dir / "conftest.py"
                    fixtures_dir = project_dir / "fixtures"

                    if conftest_path.exists():
                        # Read the conftest to extract the fixtures
                        vuln_count = 0
                        clean_count = 0
                        rule_keys = set()
                        if (fixtures_dir / "vulnerable").exists():
                            vuln_count = len([f for f in (fixtures_dir / "vulnerable").rglob("*.*")])
                        if (fixtures_dir / "clean").exists():
                            clean_count = len([f for f in (fixtures_dir / "clean").rglob("*.*")])

                        # Extract the rule_keys from the conftest
                        with open(conftest_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        # Look for the 3rd element of each tuple (rule_key)
                        for match in re.findall(r'\(\s*"[^"]+"\s*,\s*"[^"]+"\s*,\s*"([^"]+)"\s*\)', content):
                            rule_keys.add(match)

                        print(f"--- {_t('project_fixtures', lang)} ({project_dir.name}) ---")
                        print(f"   {_t('list_rules_vuln_clean', lang).format(vuln=vuln_count, clean=clean_count)}")
                        if rule_keys:
                            print(f"   {_t('list_rules_rule_keys', lang)}: {', '.join(sorted(rule_keys))}")
                        print()
            except (json.JSONDecodeError, IOError):
                pass


def list_fixtures(profile: str = None):
    """List available fixture profiles."""
    base_fixtures_dir = str(SCRIPT_DIR / "tests" / "fixtures")

    if not os.path.exists(base_fixtures_dir):
        print(f"❌ {_t('fixtures_dir_not_found', 'en')}: {base_fixtures_dir}")
        return

    print(f"\n📁 {_t('fixtures_profiles', 'en')}\n")

    profiles = []
    for item in os.listdir(base_fixtures_dir):
        item_path = os.path.join(base_fixtures_dir, item)
        if os.path.isdir(item_path) and not item.startswith('.'):
            profiles.append(item)

    profiles.sort()

    for prof in profiles:
        if profile and prof != profile:
            continue

        profile_dir = os.path.join(base_fixtures_dir, prof)
        vulnerable_count = 0
        clean_count = 0
        categories = set()

        vuln_dir = os.path.join(profile_dir, "vulnerable")
        if os.path.exists(vuln_dir):
            for root, dirs, files in os.walk(vuln_dir):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
                for f in files:
                    if not f.startswith('.') and not f.endswith('.pyc'):
                        vulnerable_count += 1
                # Collect the categories (direct subdirectories)
                if root == vuln_dir:
                    categories.update(d for d in dirs)

        clean_dir = os.path.join(profile_dir, "clean")
        if os.path.exists(clean_dir):
            for root, dirs, files in os.walk(clean_dir):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
                for f in files:
                    if not f.startswith('.') and not f.endswith('.pyc'):
                        clean_count += 1
                if root == clean_dir:
                    categories.update(d for d in dirs)

        total = vulnerable_count + clean_count
        print(f"{prof}/ ({total} fixtures)")
        print(f"├── vulnerable/ ({vulnerable_count})")
        if categories:
            cat_list = sorted(categories)
            for i, cat in enumerate(cat_list):
                prefix = "│   └──" if i == len(cat_list) - 1 else "│   ├──"
                # Count files in this category
                cat_vuln = os.path.join(vuln_dir, cat) if os.path.exists(os.path.join(vuln_dir, cat)) else None
                count = 0
                if cat_vuln and os.path.exists(cat_vuln):
                    count += len([f for f in os.listdir(cat_vuln) if os.path.isfile(os.path.join(cat_vuln, f))])
                print(f"{prefix} {cat}/")
        print(f"└── clean/ ({clean_count})")
        print()


def _prompt(message: str, default: str = "", choices: list = None) -> str:
    """Display a prompt and return the answer (or the default)."""
    if choices:
        display = f"{message} [{'/'.join(choices)}]"
    elif default:
        display = f"{message} [{default}]"
    else:
        display = message
    try:
        answer = input(f"  {display}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    if not answer and default:
        return default
    if choices and answer and answer not in choices:
        print(f"    ⚠️  {_t('invalid_choice', _get_script_lang())}: {default}")
        return default
    return answer or default


def _prompt_list(message: str, defaults: list = None) -> list:
    """Display a prompt for a comma-separated list."""
    default_str = ", ".join(defaults) if defaults else ""
    answer = _prompt(message, default_str)
    if not answer:
        return defaults or []
    return [item.strip() for item in answer.split(",") if item.strip()]


def _prompt_multiselect(message: str, options: list, defaults: list = None, detected: list = None) -> list:
    """Display a numbered multi-select prompt.

    Shows numbered options, with auto-detected ones marked. The user enters
    comma-separated numbers.
    """
    detected = detected or []
    defaults = defaults or []
    lang = _get_script_lang()
    print(f"  {message}")
    for i, opt in enumerate(options, 1):
        marker = f"  ← {_t('interactive_detected', lang)}" if opt in detected else ""
        print(f"    [{i}] {opt}{marker}")
    default_indices = [str(options.index(d) + 1) for d in defaults if d in options]
    default_str = ",".join(default_indices)
    try:
        answer = input(f"  {_t('interactive_select_number', lang)} [{default_str}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    if not answer:
        return defaults
    result = []
    for part in answer.split(","):
        part = part.strip()
        if part.isdigit():
            idx = int(part) - 1
            if 0 <= idx < len(options):
                result.append(options[idx])
    return result if result else defaults


def _prompt_yes_no(message: str, default: bool = True) -> bool:
    """Display a yes/no prompt."""
    default_str = "Y/n" if default else "y/N"
    answer = _prompt(message, default_str)
    if answer in ("Y/n", "y/N"):
        return default
    return answer.lower() in ("y", "yes", "oui", "o", "ja", "si", "1")






def _text_to_regex(text: str) -> str:
    """Convert plain text into a regex pattern.

    The client types readable text, this function produces the correct regex:
      req.body.     → req\\.body\\.
      db.query(     → db\\.query\\s*\\(
      parseInt(     → parseInt\\s*\\(
      console.log(  → console\\.log\\s*\\(
      $._POST[      → \\$_POST\\[

    Rules:
      - . becomes \\.
      - ( becomes \\s*\\( (tolerates spaces before the parenthesis)
      - [ becomes \\[
      - ] becomes \\]
      - $ becomes \\$
      - * becomes \\*
      - + becomes \\+
      - ? becomes \\?
      - { and } become \\{ and \\}
      - If the text already contains \\ (manual regex), it is left untouched.
    """
    # If the text already contains backslashes, it's probably manual regex
    if '\\' in text:
        return text

    result = ""
    i = 0
    while i < len(text):
        c = text[i]
        if c == '.' :
            result += '\\.'
        elif c == '(':
            result += '\\s*\\('
        elif c == ')':
            result += '\\)'
        elif c == '[':
            result += '\\['
        elif c == ']':
            result += '\\]'
        elif c == '$':
            result += '\\$'
        elif c == '*':
            result += '\\*'
        elif c == '+':
            result += '\\+'
        elif c == '?':
            result += '\\?'
        elif c == '{':
            result += '\\{'
        elif c == '}':
            result += '\\}'
        else:
            result += c
        i += 1

    return result


def _match_custom_rules_fixtures(lang: str = "en"):
    """Check custom rule coverage against custom fixtures.

    Cross-references the rule_keys from {SCRIPT_DIR}/custom-rules/ with the
    fixtures present in {SCRIPT_DIR}/custom-fixtures/vulnerable/ and clean/.
    Prints rules without fixtures and fixtures without a matching rule.
    """
    from sca import SCRIPT_DIR
    from sca.dsl import compile_sca_to_json

    custom_rules_dir = SCRIPT_DIR / "custom-rules"
    custom_fixtures_dir = SCRIPT_DIR / "custom-fixtures"

    print(f"\n{'=' * 50}")
    print(f"  {_t('custom_rules_match_title', lang)}")
    print(f"{'=' * 50}\n")

    # 1. Collect the rule_keys from custom-rules/
    if not custom_rules_dir.exists():
        print(f"  {_t('custom_rules_no_rules', lang)}")
        print()
        return

    custom_rules = {}
    for sca_file in sorted(custom_rules_dir.rglob("*.sca")):
        content = sca_file.read_text(encoding="utf-8")
        try:
            compiled = compile_sca_to_json(content, str(sca_file))
            for r in compiled:
                rel = sca_file.relative_to(custom_rules_dir)
                custom_rules[r["id"]] = str(rel)
        except Exception:
            pass

    if not custom_rules:
        print(f"  {_t('custom_rules_no_rules', lang)}")
        print()
        return

    # 2. Collect the fixtures from custom-fixtures/
    vuln_dir = custom_fixtures_dir / "vulnerable"
    clean_dir = custom_fixtures_dir / "clean"

    vuln_stems: set[str] = set()
    clean_stems: set[str] = set()

    if not custom_fixtures_dir.exists():
        print(f"  {_t('custom_rules_no_fixtures', lang)}")
    else:
        if vuln_dir.exists():
            for f in vuln_dir.rglob("*"):
                if f.is_file():
                    vuln_stems.add(f.stem)
        if clean_dir.exists():
            for f in clean_dir.rglob("*"):
                if f.is_file():
                    clean_stems.add(f.stem)

    all_fixture_stems = vuln_stems | clean_stems

    # 3. Cross-reference
    rules_without_any = []
    rules_without_vuln = []
    rules_without_clean = []
    fixtures_without_rule = []

    for rule_id, path in sorted(custom_rules.items()):
        has_vuln = rule_id in vuln_stems
        has_clean = rule_id in clean_stems
        if not has_vuln and not has_clean:
            rules_without_any.append((rule_id, path))
        elif not has_vuln:
            rules_without_vuln.append((rule_id, path))
        elif not has_clean:
            rules_without_clean.append((rule_id, path))

    for stem in sorted(all_fixture_stems):
        if stem not in custom_rules:
            fixtures_without_rule.append(stem)

    # 4. Display
    total = len(custom_rules)
    covered = total - len(rules_without_any)
    pct = covered / total * 100 if total > 0 else 0

    print(f"  {_t('rules_match_sca_count', lang).format(count=total)}")
    print(f"  {_t('rules_match_covered', lang).format(covered=covered, pct=f'{pct:.0f}')}")
    print(f"  {_t('rules_match_without_any', lang).format(count=len(rules_without_any))}")

    if rules_without_any:
        print(f"\n  {_t('rules_match_no_fixture', lang).format(count=len(rules_without_any))}")
        for rule_id, path in rules_without_any:
            print(f"     {rule_id}  ({path})")

    if rules_without_vuln:
        print(f"\n  {_t('rules_match_no_vuln', lang).format(count=len(rules_without_vuln))}")
        for rule_id, path in rules_without_vuln:
            print(f"     {rule_id}  ({path})")

    if rules_without_clean:
        print(f"\n  {_t('rules_match_no_clean', lang).format(count=len(rules_without_clean))}")
        for rule_id, path in rules_without_clean:
            print(f"     {rule_id}  ({path})")

    if fixtures_without_rule:
        print(f"\n  {_t('rules_match_orphan_fixtures', lang).format(count=len(fixtures_without_rule))}")
        for stem in fixtures_without_rule:
            print(f"     {stem}")

    if not rules_without_any and not rules_without_vuln and not rules_without_clean:
        print(f"\n  {_t('custom_rules_all_covered', lang)}")

    print()


def _detect_languages_from_info(info: dict) -> list:
    """Extract the detected languages from the auto-detection info."""
    detected = []
    for t in info.get("type", []):
        t_lower = t.lower()
        if "python" in t_lower:
            detected.append("python")
        if "javascript" in t_lower or "typescript" in t_lower or "node" in t_lower:
            detected.append("javascript")
        if "java" in t_lower and "javascript" not in t_lower:
            detected.append("java")
        if "c#" in t_lower or "csharp" in t_lower or ".net" in t_lower:
            detected.append("csharp")
        if "php" in t_lower:
            detected.append("php")
    return list(dict.fromkeys(detected)) or ["python"]


def _recover_missing_required(config: dict, project_path: Path, lang: str = "en") -> dict:
    """Interactively recover missing `languages` or `paths.include` config values."""
    import json as _json
    from sca.projects import _auto_detect_project
    supported = ["python", "javascript", "html", "java", "csharp", "php", "yaml"]

    if not config.get("languages"):
        print(f"\n⚠️  {_t('config_languages_required', lang)}")
        print()
        info = _auto_detect_project(project_path)
        detected = _detect_languages_from_info(info)
        languages = _prompt_multiselect(
            _t('config_select_languages', lang), supported,
            defaults=detected, detected=detected
        )
        config["languages"] = [l for l in languages if l in supported] or detected
        _patch_config_file(project_path, {"languages": config["languages"]})
        print(f"   ✅ {_t('config_updated', lang)}")
        print()

    if not config.get("paths", {}).get("include"):
        print(f"\n⚠️  {_t('config_paths_required', lang)}")
        print()
        info = _auto_detect_project(project_path)
        default_paths = info.get("include_paths", ["src/"])
        paths = _prompt_list(_t('config_enter_paths', lang), default_paths)
        config.setdefault("paths", {})["include"] = paths or default_paths
        _patch_config_file(project_path, {"paths": {"include": config["paths"]["include"]}})
        print(f"   ✅ {_t('config_updated', lang)}")
        print()

    return config


def _patch_config_file(project_path: Path, patch: dict) -> None:
    """Merge patch into audit.config.json in place."""
    import json as _json
    from sca.config import _merge_config, _remove_comments
    config_path = project_path / "audit.config.json"
    if not config_path.exists():
        return
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            existing = _remove_comments(json.load(f))
        merged = _merge_config(existing, patch)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def _interactive_init(project_path: Path, lang: str = "en"):
    """Guided creation of audit.config.json via interactive prompts."""
    from sca.projects import _auto_detect_project, _generate_config_from_detection, _register_project

    dest_path = project_path / "audit.config.json"
    if dest_path.exists():
        print(f"⚠️  {_t('config_already_exists', lang)}: {dest_path}")
        if not _prompt_yes_no(_t('interactive_overwrite', lang), default=False):
            sys.exit(0)

    print(f"\n🔍 {_t('interactive_welcome', lang)}")
    print("=" * 50)

    # Auto-detection as a starting point
    info = _auto_detect_project(project_path)

    # §1 — Languages
    print(f"\n📋 1/7 — {_t('interactive_languages', lang)}")
    detected_langs = _detect_languages_from_info(info)
    supported = ["python", "javascript", "html", "java", "csharp", "php", "yaml"]
    languages = _prompt_multiselect(
        _t('interactive_languages_prompt', lang), supported,
        defaults=detected_langs, detected=detected_langs
    )
    languages = [l for l in languages if l in supported] or detected_langs

    # §2 — Paths
    print(f"\n📁 2/7 — {_t('interactive_paths', lang)}")
    include_paths = _prompt_list(_t('interactive_include_paths', lang), info.get("include_paths", ["src/"]))

    # §3 — Categories
    print(f"\n🏷️  3/7 — {_t('interactive_categories', lang)}")
    cats_default = {"security": True, "architecture": True, "ui": True, "ux": True,
                    "maintenance": True, "dependencies": False, "cicd": False}
    enabled_cats = {}
    for cat, default in cats_default.items():
        enabled_cats[cat] = _prompt_yes_no(f"  {cat}", default)

    # §4 — Report
    print(f"\n📊 4/7 — {_t('interactive_report', lang)}")
    report_lang = _prompt(_t('interactive_report_lang', lang), "en", choices=["fr", "en", "es", "de"])

    # §5 — Branding
    print(f"\n🏢 5/7 — {_t('interactive_brand', lang)}")
    project_name = _prompt(_t('interactive_project_name', lang), project_path.name)
    brand_prefix = _prompt(_t('interactive_prefix', lang), DEFAULT_CONFIG["brand"]["prefix"])

    # §6 — Tests
    print(f"\n🧪 6/7 — {_t('interactive_tests', lang)}")
    tests_enabled = _prompt_yes_no(_t('interactive_tests_enabled', lang), default=True)

    # §7 — Confirmation
    print(f"\n✅ 7/7 — {_t('interactive_summary', lang)}")
    print(f"    {_t('interactive_languages', lang)}: {', '.join(languages)}")
    print(f"    {_t('interactive_paths', lang)}: {', '.join(include_paths)}")
    print(f"    {_t('interactive_categories', lang)}: {', '.join(k for k, v in enabled_cats.items() if v)}")
    print(f"    {_t('interactive_report', lang)}: {report_lang}")
    print(f"    {_t('interactive_brand', lang)}: {project_name} ({brand_prefix})")
    print(f"    {_t('interactive_tests', lang)}: {_t('enabled', lang) if tests_enabled else _t('disabled', lang)}")
    print()

    if not _prompt_yes_no(_t('interactive_confirm', lang), default=True):
        print(f"❌ {_t('interactive_cancelled', lang)}")
        sys.exit(0)

    # Generate the config
    config = _generate_config_from_detection(project_path, info)
    config["languages"] = languages
    config["paths"]["include"] = include_paths
    config["project"]["name"] = project_name
    config["brand"]["prefix"] = brand_prefix
    config["reports"] = {
        "output_dir": "docs/audit-reports",
        "history_dir": "docs/audit-reports/audit-datas",
        "max_history": 10,
        "language": report_lang,
    }
    config["tests"]["enabled"] = tests_enabled
    config["categories"] = {}
    for cat, enabled in enabled_cats.items():
        weight = 3 if cat == "security" else 2 if cat in ("architecture", "dependencies", "cicd") else 1
        config["categories"][cat] = {"enabled": enabled, "weight": weight}

    # Write the file
    with open(dest_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    # Create the output directories
    (project_path / "docs" / "audit-reports").mkdir(parents=True, exist_ok=True)

    # Register the project
    _register_project(project_path, config)

    from sca.projects import _get_project_dir
    project_dir = _get_project_dir(config["project"]["id"])
    project_dir_label = project_dir.name if project_dir else config["project"]["id"][:8]
    print(f"\n✅ {_t('config_generated', lang)}: {dest_path}")
    print(f"✅ {_t('project_registered', lang)}: projects/{project_dir_label}/")




def _show_license_info(lang: str = "en") -> None:
    """Print the full status of the current license (tier, limits, features)."""
    import sys as _sys, os as _os
    print(f"[DBG] _show_license_info appelée")
    print(f"[DBG] _check_is_binary() = {_check_is_binary()}")
    print(f"[DBG] CWD = {Path.cwd()}")
    _lk = Path("license.key")
    print(f"[DBG] ./license.key = {'TROUVE ' + str(_lk.resolve()) if _lk.is_file() else 'ABSENT'}")
    print(f"[DBG] sys.executable = {_sys.executable}")
    _sys.stdout.flush()

    from datetime import date as _date

    sep = "=" * 48
    print()
    print(sep)
    print(f"  {_t('license_info_title', lang)}")
    print(sep)

    if not _check_is_binary():
        print(f"  {_t('license_info_source_mode', lang)}")
        print(sep)
        print()
        return

    # Diagnostic traces — displayed before reading the license
    import os as _os, sys as _sys
    print(f"  [diag] CWD            : {Path.cwd()}")
    print(f"  [diag] sys.executable : {_sys.executable}")
    print(f"  [diag] sys.argv[0]    : {_sys.argv[0] if _sys.argv else '(vide)'}")
    _lk = Path("license.key")
    print(f"  [diag] ./license.key  : {'TROUVE — ' + str(_lk.resolve()) if _lk.is_file() else 'ABSENT'}")
    print(f"  [diag] SCA_LICENSE_KEY: {'<defini>' if _os.environ.get('SCA_LICENSE_KEY') else '(absent)'}")
    print(sep)

    try:
        from sca.license_check import (
            verify_license, get_tier, get_max_files, get_max_custom_rules,
            get_exports, get_features, DEMO_MAX_FILES,
        )
        payload = verify_license()

        if payload is None:
            print(f"  {_t('license_info_no_license', lang)}")
            print(f"  {_t('license_info_tier', lang):<20} demo")
            print(f"  {_t('license_info_files', lang):<20} {DEMO_MAX_FILES}")
            print(sep)
            print()
            return

        tier = payload.get("tier", "?")
        licensee = payload.get("licensee", "?")
        email = payload.get("email", "?")
        issued = payload.get("issued_at", "?")
        expires = payload.get("expires_at")

        if expires:
            try:
                exp = _date.fromisoformat(expires)
                expired = exp < _date.today()
                exp_str = f"{expires}  ⚠️  {_t('license_info_expires_expired', lang)}" if expired else expires
            except ValueError:
                exp_str = expires
        else:
            exp_str = _t("license_info_expires_never", lang)

        max_files = get_max_files()
        max_rules = get_max_custom_rules()
        exports = get_exports()
        features = get_features()

        print(f"  {_t('license_info_tier', lang):<20} {tier}")
        print(f"  {_t('license_info_licensee', lang):<20} {licensee}")
        print(f"  {_t('license_info_email', lang):<20} {email}")
        print(f"  {_t('license_info_issued', lang):<20} {issued}")
        print(f"  {_t('license_info_expires', lang):<20} {exp_str}")
        print()
        files_str = _t("license_info_unlimited", lang) if max_files == 0 else str(max_files)
        rules_str = _t("license_info_unlimited", lang) if max_rules >= 999999 else str(max_rules)
        print(f"  {_t('license_info_files', lang):<20} {files_str}")
        print(f"  {_t('license_info_custom_rules', lang):<20} {rules_str}")
        print(f"  {_t('license_info_exports', lang):<20} {', '.join(exports)}")
        print()
        print(f"  {_t('license_info_features_active', lang):<20} {', '.join(features) if features else '—'}")
        print(sep)
        print()

    except ImportError:
        print(f"  {_t('license_info_source_mode', lang)}")
        print(sep)
        print()


def main():
    """Parse CLI arguments, dispatch the requested command, and run the audit."""
    # Footer: prints license info + fingerprint on exit from EVERY SCA
    # command (solves the 'machine ID problem' — the user gets their
    # challenge without a special command). Disable via SCA_NO_FOOTER=1
    # or auto-skip if stdout isn't a TTY (pipe/CI).
    try:
        from sca.license_footer import register_atexit_footer
        register_atexit_footer()
    except ImportError:
        pass  # robustness — doesn't break SCA if the module is missing

    args = parse_args()

    # --simulate-binary [CLIENT]: activates the license system like in the binary.
    # Patch _IS_SOURCE_MODE before load_config() so config.py and license_facade
    # treat this run as a binary (reads license.key, applies the tier limits).
    if getattr(args, "simulate_binary", None) is not None:
        import os as _os
        try:
            import sca.license_check as _lc
            _lc._IS_SOURCE_MODE = False

            # Production key from AuditDistrib/keys/secret.key (adjacent to the repo)
            if not _os.environ.get("SCA_LICENSE_SECRET"):
                from sca import SCRIPT_DIR
                _secret_path = SCRIPT_DIR.parent / "AuditDistrib" / "keys" / "secret.key"
                if _secret_path.is_file():
                    _lc._SECRET = bytes.fromhex(_secret_path.read_text(encoding="utf-8").strip())
        except (ImportError, Exception):
            pass

        # Load the license from AuditDistrib/clients/CLIENT/license.key
        if not _os.environ.get("SCA_LICENSE_KEY") and not Path("license.key").is_file():
            _client = Path(args.simulate_binary).name  # client name only (avoids path traversal)
            if _client:
                from sca import SCRIPT_DIR
                _client_lic = SCRIPT_DIR.parent / "AuditDistrib" / "clients" / _client / "license.key"
                if _client_lic.is_file():
                    _os.environ["SCA_LICENSE_KEY"] = _client_lic.read_text(encoding="utf-8")  # sca-ignore:taint_path_traversal — _client comes from Path(...).name (line 1024), which can contain neither "/" nor ".." (traversal already excluded)
                else:
                    print(f"  ⚠️  simulate-binary : licence introuvable pour '{_client}' ({_client_lic})")

    # Single language for console + report
    _set_script_lang(args.lang)

    # Resolve the project path
    project_path = Path(args.project_path).resolve()
    if not project_path.exists() or not project_path.is_dir():
        print(f"❌ {_t('directory_not_exists', args.lang)}: {project_path}")
        sys.exit(1)

    # --license-info mode: display the license status and exit
    if args.license_info:
        _show_license_info(args.lang)
        sys.exit(0)

    # --list-rules mode: list all rules by category
    if args.list_rules:
        list_rules(lang=args.lang, project_path_arg=str(project_path))
        sys.exit(0)

    # --rules-match mode: verify rule ↔ fixture coverage
    if args.rules_match:
        match_rules_fixtures()
        sys.exit(0)

    # --check-integrity mode: full duplicate detection for rules+fixtures
    if getattr(args, "check_integrity", False):
        from sca.integrity import run_integrity_checks, print_report
        report = run_integrity_checks()
        print_report(report)
        sys.exit(1 if report.has_critical() else 0)

    # --custom-rules-match mode: custom rules vs custom fixtures coverage
    if args.custom_rules_match:
        _match_custom_rules_fixtures(args.lang)
        sys.exit(0)

    # --init mode: create/modify audit.config.json (interactive)
    if args.init:
        _interactive_init(project_path, lang=args.lang)
        sys.exit(0)

    # --sarif and --sbom are mutually exclusive
    if args.sarif and args.sbom:
        print(f"❌ {_t('export_conflict_sarif_sbom', args.lang)}")
        sys.exit(1)

    # Check that audit.config.json exists
    config_path = str(project_path / "audit.config.json")
    if not Path(config_path).exists():
        _init_project_config(project_path, force_init=False, lang=args.lang)

    # Debug — enable via --debug (script) or SCA_DEBUG=level (binary + script)
    debug_level = "info" if args.debug else get_debug_level()
    if debug_level:
        setup_debug(debug_level)

    # Load the config
    config = load_config(config_path, project_path=project_path, lang=args.lang)

    # Apply the CLI language to the report
    config.setdefault("reports", {})["language"] = args.lang

    # Interactive recovery if required fields are missing (TTY only)
    import sys as _sys
    if _sys.stdin.isatty():
        config = _recover_missing_required(config, project_path, lang=args.lang)

    # Validate the config
    if not validate_config(config, project_path, lang=args.lang):
        sys.exit(1)

    # Validate and parse the --severity option
    _VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    severity_levels = None
    if args.severity:
        raw = [s.strip().upper() for s in args.severity.split(",") if s.strip()]
        invalid = [s for s in raw if s not in _VALID_SEVERITIES]
        if invalid:
            print(f"❌ Niveaux de sévérité invalides : {', '.join(invalid)}. Valeurs acceptées : {', '.join(sorted(_VALID_SEVERITIES))}")
            sys.exit(1)
        severity_levels = raw

    # CLI options stored for the report and the engine
    config["_cli_options"] = {
        "fail_on_high": args.fail_on_high,
        "sarif": args.sarif,
        "sbom": args.sbom,
        "debug": debug_level,
        "with_tests": args.with_tests,
        "with_deps": args.with_deps,
        "with_logs": args.with_logs,
        "quiet": args.quiet,
        "severity_levels": severity_levels,
        "no_cache": args.no_cache,
        "no_incremental": args.no_incremental,
        "no_parallel": args.no_parallel,
    }
    # Dataflow engine (Phase 7/8) — the only taint backend available
    # since the legacy taint_engine.py was removed.
    config["_use_dataflow_engine"] = True

    # Create and run the audit
    audit = AuditRunner(
        config=config,
        quick_mode=args.quick,
        script_lang=args.lang,
    )

    # License check (distributed binary only — ignored in source mode)
    if _check_is_binary():
        try:
            from sca.license_check import verify_license, DEMO_MAX_FILES, DEMO_CATEGORIES
            _license = verify_license()
            if _license is None:
                audit.demo_mode = True
                print()
                print("  ============================================")
                print(f"  {_t('cli_demo_mode', args.lang)}")
                print(f"  {_t('cli_demo_max_files', args.lang).format(count=DEMO_MAX_FILES)}")
                print(f"  {_t('cli_demo_categories', args.lang).format(list=', '.join(DEMO_CATEGORIES))}")
                print(f"  {_t('cli_demo_contact', args.lang)}")
                print("  ============================================")
                print()
                for _cat in list(audit.enabled_categories.keys()):
                    if _cat not in DEMO_CATEGORIES:
                        audit.enabled_categories[_cat] = False
            else:
                from sca.license_check import check_reseller_limits
                _limits = check_reseller_limits(_license)
                if not _limits["ok"]:
                    print(f"  ❌ {_limits['message']}")
                    sys.exit(1)
        except ImportError:
            pass

    high_count = audit.run()

    # Thresholds
    thresholds = config.get("thresholds", {})
    if args.fail_on_high or thresholds.get("max_high", 0) == 0:
        if high_count > thresholds.get("max_high", 0):
            print(f"\n❌ {audit.t_console('threshold_exceeded')}: {high_count} HIGH (max: {thresholds.get('max_high', 0)})")
            sys.exit(1)

    sys.exit(0)
