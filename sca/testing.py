"""
Testing mixin — unit test execution and fixture validation.
"""
import glob
import hashlib
import json
import os
import re
import copy
import logging
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Set
from concurrent.futures import ProcessPoolExecutor, as_completed

from sca import SCA_PACKAGE_DIR, SCRIPT_DIR, VERSION
from sca.models import TestResults, FixtureValidation, ProgressDisplay

logger = logging.getLogger("sca.testing")


def _test_fixture_core(filepath: str, filename: str, fixture_type: str,
                        fixtures_mapping: Dict, config: Dict, script_lang: str,
                        rule_cache_dir: Optional[Path],
                        py_exts: List[str], py_paths: List[str],
                        js_exts: List[str], js_paths: List[str],
                        html_exts: List[str], html_paths: List[str]) -> Dict:
    """Test a single fixture: run a mini-audit in a throwaway temp project
    containing only that one file, and check whether the expected rule
    fired (vulnerable) or stayed silent (clean).

    Module-level and picklable (no `self`) so it can be submitted directly
    to a `ProcessPoolExecutor` (Perf — real CPU-bound work: regex matching
    and, for taint-capable languages, a full worklist dataflow pass; a
    `ThreadPoolExecutor` serializes almost all of it on the GIL instead of
    using the available cores). `_test_single_fixture` is a thin `self`-bound
    wrapper kept for the sequential/retry code paths.
    """
    import tempfile
    import shutil
    # Late import to avoid circular imports
    from sca.runner import AuditRunner

    result = {
        "filename": filename,
        "type": fixture_type,
        "detected": False,
        "rule_key": None,
        "findings_count": 0,
        "status": "unknown"
    }

    # Rules requiring external tools — not testable in isolation
    EXTERNAL_TOOL_RULES = {"vulnerable_dependency"}
    # Rules whose required path (vendor/, etc.) is excluded by the default
    # `paths.exclude` glob. The rule is correctly detected in a functional
    # test that overrides the exclusion (see test_functional.py
    # TestISO27001A8Completion), but the mini-audit here only scans the
    # included paths, so the fixture is not testable in this context.
    EXCLUDED_PATH_RULES = {"unreviewed_vendor_code"}

    # Fetch the expected rule from the mapping (source: tests/registry.py).
    # If the fixture isn't explicitly mapped, infer the rule_key from the
    # naming convention: `{rule_id}.ext` (vulnerable) / `{rule_id}_clean.ext`
    # (clean). This avoids falling back to the legacy "any finding counts"
    # verdict, which produces phantom false positives (a clean fixture
    # triggering a DIFFERENT rule than the expected one being wrongly
    # counted as a false positive).
    if filename in fixtures_mapping:
        result["rule_key"] = fixtures_mapping[filename]["rule_key"]
        target_path = fixtures_mapping[filename]["target_path"]
        # Skip fixtures that require external tools
        if result["rule_key"] in EXTERNAL_TOOL_RULES:
            result["status"] = "skip"
            result["success"] = True
            result["fixture"] = filename
            return result
        # Skip fixtures whose expected path is excluded by default
        if result["rule_key"] in EXCLUDED_PATH_RULES:
            result["status"] = "skip"
            result["success"] = True
            result["fixture"] = filename
            return result
    else:
        # Convention-based inference: strip the extension, then _clean if present
        stem = os.path.splitext(filename)[0]
        if fixture_type == "clean" and stem.endswith("_clean"):
            stem = stem[:-len("_clean")]
        # Don't assign an empty or implausible rule name
        if stem and re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", stem):
            result["rule_key"] = stem
        # Guess the target_path from the extension and the configured paths
        ext = os.path.splitext(filename)[1]
        if ext in py_exts and py_paths:
            target_path = f"{py_paths[0].rstrip('/')}/{filename}"
        elif ext in js_exts and js_paths:
            target_path = f"{js_paths[0].rstrip('/')}/{filename}"
        elif ext in html_exts and html_paths:
            target_path = f"{html_paths[0].rstrip('/')}/{filename}"
        else:
            target_path = filename

    # Create a temporary project
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create the required structure
        target_full = os.path.join(tmp_dir, target_path)
        os.makedirs(os.path.dirname(target_full), exist_ok=True)

        # Copy the fixture
        shutil.copy(filepath, target_full)

        # Override the config for the mini-audit: paths.include based on target_path
        mini_config = copy.deepcopy(config)
        target_dir = os.path.dirname(target_path).split("/")[0] if os.path.dirname(target_path) else "."
        mini_config["paths"]["include"] = [f"{target_dir}/"]

        # The file cache is keyed by file path + mtime: each fixture is scanned
        # through a fresh, never-repeated tmp path, so it would never hit anyway.
        # Disabling it here avoids concurrent mini-audits (parallel pool workers)
        # racing to write the SAME file-hashes.json now that they share the real
        # project's rule cache dir (see rule_cache_dir below).
        mini_config.setdefault("_cli_options", {})["no_incremental"] = True

        # Make sure the file's language is enabled
        ext = os.path.splitext(filename)[1]
        ext_to_lang = {
            ".py": "python", ".js": "javascript", ".jsx": "javascript",
            ".ts": "javascript", ".tsx": "javascript", ".mjs": "javascript",
            ".html": "html", ".htm": "html", ".xhtml": "html", ".shtml": "html",
            ".vue": "html", ".svelte": "html", ".ejs": "html", ".hbs": "html",
            ".njk": "html", ".jinja": "html", ".jinja2": "html", ".twig": "html",
            ".liquid": "html", ".mustache": "html", ".phtml": "html", ".erb": "html",
            ".jsp": "html", ".asp": "html", ".aspx": "html", ".cshtml": "html",
            ".java": "java", ".cs": "csharp",
            ".php": "php", ".inc": "php",
            ".yml": "yaml", ".yaml": "yaml",
        }
        needed_lang = ext_to_lang.get(ext)
        if needed_lang:
            current_langs = list(mini_config.get("languages", []))
            if needed_lang not in current_langs:
                current_langs.append(needed_lang)
                mini_config["languages"] = current_langs

        # Create the directories required for the audit
        for path in mini_config["paths"]["include"]:
            os.makedirs(os.path.join(tmp_dir, path.rstrip("/")), exist_ok=True)

        # Run a minimal audit on this project (silent, all categories)
        mini_config["_silent"] = True
        mini_config.setdefault("categories", {})
        for cat in ("security", "architecture", "ui", "ux", "maintenance", "cicd"):
            mini_config["categories"].setdefault(cat, {})["enabled"] = True
        mini_audit = AuditRunner(config=mini_config, root_dir=tmp_dir, quick_mode=False, self_test=False, script_lang=script_lang)
        # Share the real audited project's rule cache instead of the throwaway
        # tmp_dir's (which would never be reused): every one of the ~1500
        # fixtures would otherwise reload and recompile the full rule set from
        # scratch. Safe across parallel workers: the cache key is content-
        # derived (rules directory hash) and writes are atomic (rename).
        mini_audit._rule_cache_dir_override = rule_cache_dir

        # Determine the expected rule category to target the audit
        is_dep_rule = result.get("rule_key") in ("unpinned_dependency", "vulnerable_dependency")

        # Run the audits based on the file type (generic + project rules)
        if is_dep_rule:
            mini_audit._check_dependency_tools = lambda: {"pip_audit": None, "npm": None}
            mini_audit._audit_dependencies()
        else:
            # Single rule engine — handles all categories and languages
            mini_audit._audit_rule_engine()

        # Count the findings
        total_findings = sum(len(cat.findings) for cat in mini_audit.categories.values())
        result["findings_count"] = total_findings
        result["detected"] = total_findings > 0

        # Check whether the expected rule was detected. Also look at
        # f.taint_flows: when the taint engine and a pattern engine
        # detect the same line, _integrate_taint_flow merges the flows
        # as an attribute of the pattern finding (avoids duplication in
        # production). Several taint rules can match the same sink (e.g.
        # file_get_contents is a sink for BOTH taint_ssrf and
        # taint_path_traversal), all accumulated in taint_flows. Without
        # this check, a correctly detected taint_X fixture would be
        # wrongly marked as a false negative.
        if result["rule_key"]:
            expected_key = result["rule_key"]
            rule_found = any(
                f.rule_key == expected_key
                or any(tf.rule_key == expected_key for tf in f.taint_flows)
                for cat in mini_audit.categories.values()
                for f in cat.findings
            )
            if fixture_type == "vulnerable":
                result["status"] = "pass" if rule_found else "fail"
            else:
                result["status"] = "pass" if not rule_found else "fail"
        else:
            if fixture_type == "vulnerable":
                result["status"] = "pass" if result["detected"] else "fail"
            else:
                result["status"] = "pass" if not result["detected"] else "fail"

        # Add the success key for the HTML report
        result["success"] = result["status"] == "pass"
        result["fixture"] = filename

        logger.debug("fixture=%s type=%s result=%s findings=%d",
                     filename, fixture_type, result["status"], total_findings)

    return result


class AuditTestingMixin:
    """Unit test execution and fixture validation methods."""

    # =========================================================================
    # UNIT TESTS
    # =========================================================================
    def _run_tests(self):
        """Run the unit tests and capture the results."""
        # The [n/N] numbering and the icon are emitted by AuditRunner.run()
        # via self.reporter.phase("tests").

        self.test_results = TestResults()
        tests_config = self.config.get("tests", {})
        tests_dir = tests_config.get("tests_dir", "tests/")

        try:
            # Sequential execution (parallelization disabled: shared DB)
            self._run_tests_sequential(tests_dir)

            # Add findings for the failed tests
            if self.test_results.failed > 0 and self.test_results.failed_tests:
                for test_name in self.test_results.failed_tests:
                    r = self._rule("test_failed")
                    self._add_finding(
                        "MAINTENANCE", r["name"], test_name.split("::")[0], 0,
                        test_name,
                        "HIGH", r["risk"], r["solution"], r["benefit"],
                        rule_key="test_failed"
                    )

            if self.test_results.errors > 0 and self.test_results.error_tests:
                for test_name in self.test_results.error_tests:
                    r = self._rule("test_error")
                    self._add_finding(
                        "MAINTENANCE", r["name"], test_name.split("::")[0], 0,
                        test_name,
                        "HIGH", r["risk"], r["solution"], r["benefit"],
                        rule_key="test_error"
                    )

            self.reporter.step(
                f"✅ {self.test_results.passed} {self.t_console('passed')}, "
                f"❌ {self.test_results.failed} {self.t_console('failed')}, "
                f"⏭️ {self.test_results.skipped} {self.t_console('skipped')}"
            )

        except subprocess.TimeoutExpired:
            self.reporter.warn(self.t_console("tests_timeout"))
            self.test_results = TestResults()
        except FileNotFoundError:
            self.reporter.warn(self.t_console("docker_unavailable"))
            self.test_results = TestResults()
        except Exception as e:
            self.reporter.warn(f"{self.t_console('tests_error')}: {e}")
            self.test_results = TestResults()

    def _auto_detect_test_command(self) -> Optional[str]:
        """Auto-detect the target project's test framework.

        Analyzes the configured languages and looks for matching test
        files. Returns the command to run, or None.
        """
        root = self.root_dir
        languages = self.config.get("languages", [])

        # Python: pytest or unittest
        if "python" in languages:
            tests_dir = None
            for d in ["tests", "test"]:
                if os.path.isdir(os.path.join(root, d)):
                    tests_dir = d
                    break
            if tests_dir is None and glob.glob(os.path.join(root, "test_*.py")):
                tests_dir = "."
            if tests_dir:
                # Check whether pytest is available
                if shutil.which("python3"):
                    return f"python3 -m pytest {tests_dir} -v --tb=short"
                if shutil.which("python"):
                    return f"python -m pytest {tests_dir} -v --tb=short"

        # JavaScript/TypeScript: npm test, jest, or vitest
        if "javascript" in languages:
            has_tests = (
                os.path.isdir(os.path.join(root, "__tests__"))
                or glob.glob(os.path.join(root, "**", "*.test.js"), recursive=True)
                or glob.glob(os.path.join(root, "**", "*.spec.js"), recursive=True)
                or glob.glob(os.path.join(root, "**", "*.test.ts"), recursive=True)
                or glob.glob(os.path.join(root, "**", "*.spec.ts"), recursive=True)
            )
            pkg_json_path = os.path.join(root, "package.json")
            if has_tests or os.path.exists(pkg_json_path):
                # Check scripts.test in package.json
                if os.path.exists(pkg_json_path):
                    try:
                        with open(pkg_json_path, "r", encoding="utf-8") as f:
                            pkg = json.load(f)
                        test_script = pkg.get("scripts", {}).get("test", "")
                        if test_script and "no test specified" not in test_script:
                            if shutil.which("npm"):
                                return "npm test"
                    except Exception:
                        pass
                # Fallback: jest or vitest
                if glob.glob(os.path.join(root, "jest.config.*")):
                    if shutil.which("npx"):
                        return "npx jest --passWithNoTests"
                if glob.glob(os.path.join(root, "vitest.config.*")):
                    if shutil.which("npx"):
                        return "npx vitest run"

        # Java: maven or gradle
        if "java" in languages:
            has_tests = (
                os.path.isdir(os.path.join(root, "src", "test"))
                or glob.glob(os.path.join(root, "**", "*Test.java"), recursive=True)
            )
            if has_tests:
                if os.path.exists(os.path.join(root, "pom.xml")) and shutil.which("mvn"):
                    return "mvn test -B"
                for gf in ["build.gradle", "build.gradle.kts"]:
                    if os.path.exists(os.path.join(root, gf)) and shutil.which("gradle"):
                        return "gradle test"

        # PHP: phpunit
        if "php" in languages:
            has_tests = (
                os.path.isdir(os.path.join(root, "tests"))
                or glob.glob(os.path.join(root, "**", "*Test.php"), recursive=True)
            )
            if has_tests:
                phpunit = os.path.join(root, "vendor", "bin", "phpunit")
                if os.path.exists(phpunit):
                    return "vendor/bin/phpunit"

        # C#: dotnet test
        if "csharp" in languages:
            has_tests = (
                glob.glob(os.path.join(root, "*.Tests"))
                or glob.glob(os.path.join(root, "**", "*Test.cs"), recursive=True)
            )
            if has_tests and shutil.which("dotnet"):
                return "dotnet test"

        return None

    def _run_tests_sequential(self, tests_dir: str):
        """Run the tests via the configured or auto-detected command."""
        tests_config = self.config.get("tests", {})
        command_template = tests_config.get("command", "")

        # Auto-detect if --with-tests and no explicit command
        if not command_template:
            cli_opts = self.config.get("_cli_options", {})
            if cli_opts.get("with_tests", False):
                detected = self._auto_detect_test_command()
                if detected:
                    command_template = detected
                    self.reporter.step(
                        f"{self.t_console('test_autodetected')}: {detected}",
                        icon="🔍",
                    )
                else:
                    self.reporter.warn(self.t_console("tests_no_framework_detected"))
                    return
            else:
                self.reporter.warn(self.t_console("tests_no_command"))
                return

        # Substitute {tests_dir} in the command, then split into a list (no shell=True)
        command_str = command_template.replace("{tests_dir}", tests_dir)
        # Also visible in the console (not just in debug)
        self.reporter.step(
            self.t_console("progress_test_command").format(cmd=command_str)
        )
        command_args = shlex.split(command_str)

        result = subprocess.run(
            command_args,
            capture_output=True,
            text=True,
            cwd=self.root_dir,
            timeout=300  # 5 minutes max
        )
        output = result.stdout + result.stderr
        # Check whether the command failed without producing pytest output
        if result.returncode != 0 and "passed" not in output and "failed" not in output:
            error_msg = result.stderr.strip().split("\n")[0] if result.stderr.strip() else f"exit code {result.returncode}"
            self.reporter.warn(f"{self.t_console('tests_command_failed')}: {error_msg}")
            return
        self._parse_pytest_output(output)

    def _parse_pytest_output(self, output: str):
        """Parse pytest output and update test_results.

        Looks for pytest's final summary line (=== X passed, Y failed in Zs ===)
        rather than summing every occurrence across the full output.
        """
        passed = 0
        failed = 0
        errors = 0
        skipped = 0
        duration = 0.0

        # Look for pytest's final summary line (last ===...=== line)
        summary_match = re.search(
            r'={2,}\s*(.*?)\s*={2,}\s*$',
            output, re.MULTILINE
        )
        summary_line = summary_match.group(1) if summary_match else ""

        if summary_line:
            # Parse the counters from the summary line only
            m = re.search(r'(\d+)\s+passed', summary_line)
            if m:
                passed = int(m.group(1))
            m = re.search(r'(\d+)\s+failed', summary_line)
            if m:
                failed = int(m.group(1))
            m = re.search(r'(\d+)\s+error', summary_line)
            if m:
                errors = int(m.group(1))
            m = re.search(r'(\d+)\s+skipped', summary_line)
            if m:
                skipped = int(m.group(1))
            m = re.search(r'in\s+([\d.]+)s', summary_line)
            if m:
                duration = float(m.group(1))

        # Fallback: count PASSED/FAILED lines if there's no summary
        if passed == 0 and failed == 0:
            passed = len(re.findall(r'\bPASSED\b', output))
            failed = len(re.findall(r'\bFAILED\b', output))
            errors = len(re.findall(r'\bERROR\b', output))

        self.test_results.passed = passed
        self.test_results.failed = failed
        self.test_results.errors = errors
        self.test_results.skipped = skipped
        self.test_results.duration = duration

        self.test_results.total = passed + failed + errors + skipped

        if self.test_results.total > 0:
            self.test_results.success_rate = round(
                (self.test_results.passed / self.test_results.total) * 100, 1
            )

        # Extract the names of the failed tests
        if failed > 0:
            failed_matches = re.findall(r'(tests/\S+::\S+)\s+FAILED', output)
            self.test_results.failed_tests = failed_matches[:10]

        if errors > 0:
            error_matches = re.findall(r'(tests/\S+::\S+)\s+ERROR', output)
            self.test_results.error_tests = error_matches[:10]

    # =========================================================================
    # FIXTURE VALIDATION
    # =========================================================================
    def _get_fixtures_dirs(self) -> List[str]:
        """Return the fixture directories for the project, based on its UUID."""
        fixtures_config = self.config.get("fixtures", {})
        include_generic = fixtures_config.get("include_generic", True)
        project_uuid = self.config.get("project", {}).get("id")

        script_dir = str(SCRIPT_DIR)
        dirs = []

        # Add the project-specific fixtures (via UUID) if any exist
        if project_uuid:
            from sca.projects import _get_project_dir
            project_dir = _get_project_dir(project_uuid)
            project_fixtures_dir = str(project_dir / "fixtures") if project_dir else None
            if project_fixtures_dir and os.path.exists(project_fixtures_dir):
                # Check that fixtures exist (vulnerable/ or clean/)
                has_fixtures = (
                    os.path.exists(os.path.join(project_fixtures_dir, "vulnerable")) or
                    os.path.exists(os.path.join(project_fixtures_dir, "clean"))
                )
                if has_fixtures:
                    dirs.append(project_fixtures_dir)

        # Add generic if requested or if there are no project fixtures
        if include_generic or not dirs:
            generic_dir = os.path.join(script_dir, "tests", "fixtures", "generic")
            if os.path.exists(generic_dir):
                dirs.append(generic_dir)

        return dirs

    def _validate_fixtures(self):
        """Validate audit rules against the test fixtures (parallelized).

        Per-fixture incremental (Perf): each fixture's cache entry is keyed
        on (its own mtime, its associated rule's .sca file mtime) — editing
        ONE rule during iterative fixing only re-tests that rule's 1-2
        fixtures, replaying every other fixture's cached verdict instead of
        re-running the full ~1500-fixture set. A change to the shared SCA
        engine (sca/ source) still forces a full revalidation: the engine is
        code common to every rule, so unlike a single .sca edit, its impact
        can't be safely scoped to "only these fixtures."
        """
        fixtures_config = self.config.get("fixtures", {})
        include_generic = fixtures_config.get("include_generic", True)
        project_uuid = self.config.get("project", {}).get("id")

        # Build the description of the fixtures in use (label = readable directory name)
        if project_uuid:
            from sca.projects import _get_project_dir
            project_dir = _get_project_dir(project_uuid)
            label = project_dir.name if project_dir else project_uuid[:8]
            profile_desc = f"{label} + generic" if include_generic else label
        else:
            profile_desc = "generic"

        fixtures_dirs = self._get_fixtures_dirs()
        if not fixtures_dirs:
            self.reporter.banner(
                f"🧪 {self.t_console('validating_fixtures')} ({profile_desc})..."
            )
            self.reporter.warn(self.t_console("no_fixtures_dir"))
            return

        self.fixture_validation = FixtureValidation()

        # Load the fixtures mapping from conftest (all dirs)
        fixtures_mapping = {}
        for fdir in fixtures_dirs:
            fixtures_mapping.update(self._load_fixtures_mapping(fdir))

        # Collect all the fixtures to test (with deduplication)
        fixtures_to_test = []
        seen_filenames = set()

        for fixtures_dir in fixtures_dirs:
            vulnerable_dir = os.path.join(fixtures_dir, "vulnerable")
            if os.path.exists(vulnerable_dir):
                self._collect_fixtures_recursive(vulnerable_dir, "vulnerable", fixtures_to_test, seen_filenames)

            clean_dir = os.path.join(fixtures_dir, "clean")
            if os.path.exists(clean_dir):
                self._collect_fixtures_recursive(clean_dir, "clean", fixtures_to_test, seen_filenames)

        if not fixtures_to_test:
            self.reporter.warn(self.t_console("no_fixtures_found"))
            return

        # ─── Per-fixture incremental cache (Perf) ───────────────────────
        # sca/rules/builtin is excluded from the engine hash: rule files are
        # already tracked individually (_build_rule_file_map + per-fixture
        # keys below) — including them here too would make editing ANY rule
        # invalidate the coarse engine gate as well, defeating the whole
        # point of per-rule scoping (profiles/ stays IN: a profile affects
        # several rules' taint behavior at once, not scopable per-fixture).
        engine_hash = hashlib.sha256(
            f"v{VERSION}:{self._hash_tree_mtime(SCA_PACKAGE_DIR, exclude=SCA_PACKAGE_DIR / 'rules')}"
            .encode("utf-8")
        ).hexdigest()
        rule_file_map = self._build_rule_file_map()
        cached_entries = self._load_fixture_validation_cache(engine_hash)

        fixture_keys: Dict[str, str] = {}
        still_need_testing = []
        reused_count = 0
        for filepath, filename, fixture_type in fixtures_to_test:
            rule_key = self._fixture_rule_key(filename, fixture_type, fixtures_mapping)
            rule_file = rule_file_map.get(rule_key) if rule_key else None
            current_key = self._fixture_cache_entry_key(filepath, rule_file)
            fixture_keys[filename] = current_key
            cached_entry = cached_entries.get(filename)
            if cached_entry is not None and cached_entry.get("key") == current_key:
                result = {
                    "filename": filename,
                    "type": fixture_type,
                    "status": cached_entry.get("status"),
                    "success": cached_entry.get("success"),
                    "findings_count": cached_entry.get("findings_count", 0),
                    "rule_key": cached_entry.get("rule_key"),
                }
                self._process_fixture_result(result, fixture_type)
                reused_count += 1
            else:
                still_need_testing.append((filepath, filename, fixture_type))

        # Pre-audit step (before the actual [n/N] phases).
        self.reporter.banner(
            f"🧪 {self.t_console('validating_fixtures')} ({profile_desc})..."
        )
        if reused_count:
            self.reporter.step(
                self.t_console("fixtures_cache_reused").format(
                    reused=reused_count, total=len(fixtures_to_test),
                    remaining=len(still_need_testing),
                ),
                icon="💾",
            )

        if not still_need_testing:
            self._print_fixture_validation_summary()
            self._save_fixture_validation_cache(engine_hash, fixture_keys)
            return

        # Parallelization configuration
        parallel_enabled = fixtures_config.get("parallel", True)
        max_workers = fixtures_config.get("parallel_workers", os.cpu_count() or 4)
        fixture_timeout = fixtures_config.get("fixture_timeout", 30)

        # Progress display
        progress = ProgressDisplay(len(still_need_testing), "Fixtures")

        # Map filename → (filepath, fixture_type) for sequential retries
        fixture_lookup = {fname: (fp, ft) for fp, fname, ft in still_need_testing}

        if parallel_enabled and len(still_need_testing) > 1:
            # Parallel execution with ProcessPoolExecutor (Perf — this is
            # CPU-bound work, a ThreadPoolExecutor would serialize almost
            # all of it on the GIL instead of using the available cores;
            # see _test_fixture_core's docstring). Values that don't change
            # per fixture are resolved once, outside the loop, then passed
            # explicitly to the module-level (picklable) worker function.
            # Failures not caught due to concurrency (timeout under load,
            # transient exception) are retried sequentially after the
            # parallel pass to guarantee a reliable diagnosis.
            rule_cache_dir = self._get_rule_cache_dir()
            failed_filenames = []
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                futures = {}
                for filepath, filename, fixture_type in still_need_testing:
                    future = executor.submit(
                        _test_fixture_core,
                        filepath, filename, fixture_type, fixtures_mapping,
                        self.config, self.script_lang, rule_cache_dir,
                        self._py_exts, self._py_paths, self._js_exts, self._js_paths,
                        self._html_exts, self._html_paths,
                    )
                    futures[future] = (filename, fixture_type)
                    progress.start(filename)

                for future in as_completed(futures, timeout=fixture_timeout * len(still_need_testing)):
                    filename, fixture_type = futures[future]
                    try:
                        result = future.result(timeout=fixture_timeout)
                        self._process_fixture_result(result, fixture_type)
                        status = "pass" if result.get("success", result.get("status") == "pass") else "fail"
                        progress.complete(filename, status)
                        if status == "fail" and result.get("status") != "skip":
                            failed_filenames.append(filename)
                    except Exception as e:
                        # Capture the actual exception (the old "timeout" label
                        # masked every error). Retry sequentially.
                        logger.warning(
                            "Fixture %s a échoué en parallèle (%s: %s) — retry séquentiel",
                            filename, type(e).__name__, str(e)[:100]
                        )
                        progress.complete(filename, "timeout")
                        failed_filenames.append(filename)

            # Sequential retry of failed fixtures (guarantees the diagnosis).
            # 2 passes to absorb non-deterministic flakiness: each fixture
            # that fails during the parallel pass gets 2 chances to confirm
            # its verdict before being marked a false negative.
            MAX_RETRIES = 2
            still_failing = list(failed_filenames)
            for retry_pass in range(MAX_RETRIES):
                if not still_failing:
                    break
                next_failing = []
                for filename in still_failing:
                    if filename not in fixture_lookup:
                        continue
                    filepath, fixture_type = fixture_lookup[filename]
                    try:
                        retry_result = self._test_single_fixture(
                            filepath, filename, fixture_type, fixtures_mapping
                        )
                    except Exception as e:
                        logger.warning(
                            "Retry %d/%d %s a aussi échoué (%s: %s)",
                            retry_pass + 1, MAX_RETRIES, filename,
                            type(e).__name__, str(e)[:100]
                        )
                        next_failing.append(filename)
                        continue
                    if retry_result.get("success"):
                        # The result now passes: rewrite + adjust the counters.
                        self._replace_fixture_result(filename, retry_result, fixture_type)
                    else:
                        # Still failing: retry on the next pass
                        next_failing.append(filename)
                still_failing = next_failing
        else:
            # Sequential execution (fallback)
            for filepath, filename, fixture_type in still_need_testing:
                progress.start(filename)
                result = self._test_single_fixture(filepath, filename, fixture_type, fixtures_mapping)
                self._process_fixture_result(result, fixture_type)
                status = "pass" if result.get("success", result.get("status") == "pass") else "fail"
                progress.complete(filename, status)

        progress.finish()

        self._print_fixture_validation_summary()
        self._save_fixture_validation_cache(engine_hash, fixture_keys)

    def _print_fixture_validation_summary(self):
        """Print the ✅/❌ summary line (and false positive/negative warnings)
        for the current `self.fixture_validation` — shared by a live run and
        a cache-hit skip so both paths report identically."""
        v = self.fixture_validation
        status = "✅" if v.is_valid else "❌"
        summary = self.t_console('fixtures_summary').format(
            rate=v.success_rate,
            detected=v.vulnerable_detected, tested=v.vulnerable_tested,
            clean_passed=v.clean_passed, clean_tested=v.clean_tested
        )
        self.reporter.step(f"{status} {summary}")

        if v.vulnerable_missed > 0:
            self.reporter.warn(
                self.t_console("false_negatives").format(count=v.vulnerable_missed)
            )
        if v.clean_false_positive > 0:
            self.reporter.warn(
                self.t_console("false_positives").format(count=v.clean_false_positive)
            )

    @staticmethod
    def _hash_tree_mtime(root: Path, exclude: Optional[Path] = None) -> str:
        """SHA-256 over every file's (relative path, mtime) under root — a
        cheap, content-agnostic change detector shared by the rule/fixture
        caches (mtime is enough: any real edit bumps it). `exclude`, if
        given, skips any file under that subtree."""
        if not root.exists():
            return ""
        entries = [
            f"{f.relative_to(root)}:{f.stat().st_mtime}"
            for f in root.rglob("*")
            if f.is_file() and (exclude is None or exclude not in f.parents)
        ]
        return hashlib.sha256("\n".join(sorted(entries)).encode("utf-8")).hexdigest()

    @staticmethod
    def _build_rule_file_map() -> Dict[str, Path]:
        """Map rule_id -> its .sca source file. A cheap regex scan (not a full
        DSL parse/compile — this only needs to know WHICH file a rule lives
        in, not its compiled content) so per-fixture cache keys can detect
        "did THIS rule's file change" without loading every rule."""
        builtin_dir = SCA_PACKAGE_DIR / "rules" / "builtin"
        result: Dict[str, Path] = {}
        if not builtin_dir.exists():
            return result
        rule_id_re = re.compile(r"^\s*rule\s+(\S+)", re.MULTILINE)
        for sca_file in builtin_dir.rglob("*.sca"):
            try:
                text = sca_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            m = rule_id_re.search(text)
            if m:
                result[m.group(1)] = sca_file
        return result

    @staticmethod
    def _fixture_rule_key(filename: str, fixture_type: str, fixtures_mapping: Dict) -> Optional[str]:
        """Resolve a fixture's expected rule_id: explicit registry mapping
        first, falling back to the `{rule_id}.ext` / `{rule_id}_clean.ext`
        naming convention (mirrors `_test_single_fixture`'s own inference)."""
        mapped = fixtures_mapping.get(filename, {}).get("rule_key")
        if mapped:
            return mapped
        stem = os.path.splitext(filename)[0]
        if fixture_type == "clean" and stem.endswith("_clean"):
            stem = stem[:-len("_clean")]
        if stem and re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", stem):
            return stem
        return None

    @staticmethod
    def _fixture_cache_entry_key(fixture_path: str, rule_file: Optional[Path]) -> str:
        """Per-fixture cache key: its own mtime + its rule's .sca file mtime.
        Either one changing invalidates just this single entry, not the
        whole fixture set."""
        try:
            fixture_mtime = Path(fixture_path).stat().st_mtime
        except OSError:
            fixture_mtime = 0.0
        rule_str = ""
        rule_mtime = 0.0
        if rule_file is not None:
            rule_str = str(rule_file)
            try:
                rule_mtime = rule_file.stat().st_mtime
            except OSError:
                pass
        payload = f"{fixture_path}:{fixture_mtime}:{rule_str}:{rule_mtime}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _fixture_validation_cache_file(self) -> Optional[Path]:
        cache_dir = self._get_rule_cache_dir()
        if cache_dir is None:
            return None
        return cache_dir / "fixture-validation.json"

    def _load_fixture_validation_cache(self, engine_hash: str) -> Dict[str, dict]:
        """Load the per-fixture cache entries, or {} if absent/stale/corrupt.
        A changed engine_hash invalidates everything at once (see class
        docstring on `_validate_fixtures` for why the engine can't be scoped
        more narrowly than "revalidate every fixture")."""
        cache_file = self._fixture_validation_cache_file()
        if cache_file is None or not cache_file.exists():
            return {}
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(data, dict) or data.get("engine_hash") != engine_hash:
            return {}
        entries = data.get("fixtures")
        return entries if isinstance(entries, dict) else {}

    def _save_fixture_validation_cache(self, engine_hash: str, fixture_keys: Dict[str, str]) -> None:
        """Persist one entry per fixture processed this run (reused or
        freshly tested) — sourced from `self.fixture_validation.details`,
        which both paths append to via `_process_fixture_result`."""
        cache_file = self._fixture_validation_cache_file()
        if cache_file is None:
            return
        fixtures_entries = {}
        for d in self.fixture_validation.details:
            filename = d.get("filename")
            if filename is None or filename not in fixture_keys:
                continue
            fixtures_entries[filename] = {
                "key": fixture_keys[filename],
                "status": d.get("status"),
                "success": d.get("success", d.get("status") == "pass"),
                "findings_count": d.get("findings_count", 0),
                "rule_key": d.get("rule_key"),
            }
        data = {"engine_hash": engine_hash, "fixtures": fixtures_entries}
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            tmp_file = cache_file.parent / f"{cache_file.name}.tmp"
            tmp_file.write_text(json.dumps(data), encoding="utf-8")
            tmp_file.replace(cache_file)
        except OSError as e:
            logger.warning("Impossible de sauvegarder le cache de validation des fixtures : %s", e)

    def _process_fixture_result(self, result: Dict, fixture_type: str):
        """Process a fixture's result and update the counters.
        Uses result["success"], which accounts for the expected rule_key
        (unlike "detected", which counts any finding)."""
        self.fixture_validation.details.append(result)
        # Don't count skipped fixtures (external tools required)
        if result.get("status") == "skip":
            return
        success = result.get("success", result.get("status") == "pass")
        if fixture_type == "vulnerable":
            self.fixture_validation.vulnerable_tested += 1
            if success:
                self.fixture_validation.vulnerable_detected += 1
            else:
                self.fixture_validation.vulnerable_missed += 1
        else:  # clean fixture
            self.fixture_validation.clean_tested += 1
            if success:
                self.fixture_validation.clean_passed += 1
            else:
                self.fixture_validation.clean_false_positive += 1

    def _replace_fixture_result(self, filename: str, new_result: Dict, fixture_type: str):
        """Replace a fixture's result with that of a sequential retry
        (corrects false FNs caused by pool-worker concurrency)."""
        # Update or append in details
        for i, existing in enumerate(self.fixture_validation.details):
            if existing.get("filename") == filename:
                self.fixture_validation.details[i] = new_result
                break
        else:
            self.fixture_validation.details.append(new_result)
            return  # No counter to fix up
        # Adjust the counters when moving from fail/timeout to success
        if new_result.get("status") == "skip":
            return
        new_success = new_result.get("success", new_result.get("status") == "pass")
        if not new_success:
            return
        if fixture_type == "vulnerable":
            self.fixture_validation.vulnerable_detected += 1
            self.fixture_validation.vulnerable_missed -= 1
        else:
            self.fixture_validation.clean_passed += 1
            self.fixture_validation.clean_false_positive -= 1

    def _collect_fixtures_recursive(self, base_dir: str, fixture_type: str,
                                     fixtures_to_test: List, seen_filenames: Set[str]):
        """Recursively collect fixtures from a directory and its subdirectories."""
        if not os.path.exists(base_dir):
            return

        for root, dirs, files in os.walk(base_dir):
            # Ignore hidden directories and __pycache__
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']

            for filename in files:
                if filename.startswith('.') or filename.endswith('.pyc'):
                    continue

                # Build a unique key based on the relative path
                rel_path = os.path.relpath(os.path.join(root, filename), base_dir)
                if rel_path in seen_filenames:
                    continue  # Skip if already added by a higher-priority profile

                seen_filenames.add(rel_path)
                filepath = os.path.join(root, filename)
                if os.path.isfile(filepath):
                    fixtures_to_test.append((filepath, filename, fixture_type))

    def _load_fixtures_mapping(self, fixtures_dir: str) -> Dict[str, Dict]:
        """Load the fixtures mapping (filename → rule_key).

        Current source of truth: tests/registry.py (see internal docs). For
        backward compatibility, also tries conftest.py in case an older
        installation still uses it.

        For fixtures following the `{rule_id}.ext` / `{rule_id}_clean.ext`
        convention, infers the rule_key from the filename when no explicit
        entry exists — useful for diagnostics and to avoid losing rule_key
        in fixture_validation.details.
        """
        mapping = {}

        # Candidates (registry.py takes priority, conftest.py is legacy)
        candidates = []
        d1 = os.path.dirname(fixtures_dir)              # e.g. tests/fixtures/
        d2 = os.path.dirname(d1)                        # e.g. tests/
        for parent in (d1, d2):
            for name in ("registry.py", "conftest.py"):
                p = os.path.join(parent, name)
                if p not in candidates:
                    candidates.append(p)

        for path in candidates:
            if not os.path.exists(path):
                continue
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                for fixture_type in ["VULNERABLE_FIXTURES", "CLEAN_FIXTURES"]:
                    pattern = rf'{fixture_type}\s*=\s*\{{([^}}]+)\}}'
                    match = re.search(pattern, content, re.DOTALL)
                    if match:
                        entries = re.findall(
                            r'"(\w+)":\s*\("([^"]+)",\s*"([^"]+)",\s*"([^"]+)"\)',
                            match.group(1)
                        )
                        for key, filename, target_path, rule_key in entries:
                            # First occurrence wins (registry.py is seen first)
                            mapping.setdefault(filename, {
                                "key": key,
                                "target_path": target_path,
                                "rule_key": rule_key,
                                "type": "vulnerable" if fixture_type == "VULNERABLE_FIXTURES" else "clean"
                            })
            except Exception as e:
                self.reporter.warn(f"{self.t_console('conftest_read_error')}: {e}")

        return mapping

    def _test_single_fixture(self, filepath: str, filename: str, fixture_type: str,
                             fixtures_mapping: Dict) -> Dict:
        """Test a single fixture (thin `self`-bound wrapper around
        `_test_fixture_core` — see that function for the actual logic and
        for why it's a module-level function instead of a method)."""
        return _test_fixture_core(
            filepath, filename, fixture_type, fixtures_mapping,
            self.config, self.script_lang, self._get_rule_cache_dir(),
            self._py_exts, self._py_paths, self._js_exts, self._js_paths,
            self._html_exts, self._html_paths,
        )
