"""
AuditRunner — main class composed from the mixins.
"""
import os
import sys
import time
import json
import shutil
import fnmatch
import logging
import importlib.util
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple

from sca import SCRIPT_DIR, VERSION
from sca.progress import Reporter
from sca.debug import (
    log_phase_start, log_phase_end, log_scan_stats,
    log_config_resolve, log_export, log_run_summary,
)

logger = logging.getLogger("sca.runner")
from sca.models import Finding, Category, ComparisonResult, TestResults, FixtureValidation
from sca.config import load_config, DEFAULT_CONFIG
from sca.i18n import get_verbose
from sca.utils import read_file, get_file_type, get_context, is_dependency, get_file_group
from sca.dependencies import AuditDependenciesMixin
from sca.database import AuditDatabaseMixin
from sca.testing import AuditTestingMixin
from sca.report import AuditReportMixin
from sca.cicd import AuditCICDMixin
from sca.comparison import AuditComparisonMixin
from sca.compliance import AuditComplianceMixin
from sca.rule_engine import AuditRuleEngineMixin


class AuditRunner(
    AuditDependenciesMixin,
    AuditDatabaseMixin,
    AuditCICDMixin,
    AuditTestingMixin,
    AuditReportMixin,
    AuditComparisonMixin,
    AuditComplianceMixin,
    AuditRuleEngineMixin,
):
    """Run the audit and generate the report."""

    def __init__(self, config: dict = None, root_dir: str = None,
                 quick_mode: bool = False, self_test: bool = False,
                 disabled_rules: List[str] = None, only_category: str = None,
                 script_lang: str = "en"):
        """Initialize the runner: config, i18n, branding, paths and categories for one audit run."""
        # Load the configuration (silent=True for internal calls)
        self.config = config or load_config(silent=True)

        # Ensure _license is present (absent when config is passed directly)
        if "_license" not in self.config:
            from sca.license_facade import get_license_info
            self.config["_license"] = get_license_info()

        # Load the translations
        self.script_lang = script_lang
        self.report_lang = self.config.get("reports", {}).get("language", "en")
        self.i18n_script = self._load_locale("script", self.script_lang)
        self.i18n_report = self._load_locale("report", self.report_lang)

        # Tool identity (configurable via brand)
        brand = self.config.get("brand", {})
        self.tool_name = brand.get("tool_name", DEFAULT_CONFIG["brand"]["tool_name"])
        self.tool_version = VERSION
        self.company_name = brand.get("company_name", DEFAULT_CONFIG["brand"]["company_name"])
        self.brand_prefix = brand.get("prefix", DEFAULT_CONFIG["brand"]["prefix"])

        # Root directory of the project being audited
        # Priority: 1. root_dir argument, 2. config's _project_path, 3. current directory
        self.root_dir = root_dir or self.config.get("_project_path") or os.getcwd()
        self.quick_mode = quick_mode
        self.self_test = self_test
        self.disabled_rules = set(disabled_rules or self.config.get("rules", {}).get("disabled", []))
        self.only_category = only_category
        self.verbose = get_verbose()
        self.demo_mode = self.config.get("_cli_options", {}).get("demo", False) or self.config.get("_demo_mode", False)

        # Project info from the config
        self.project_name = self.config.get("project", {}).get("name", self.tool_name)
        self.project_version = self.config.get("project", {}).get("version", "1.0")

        # Category weights for the health score
        self.category_weights = {
            "SECURITY": self.config.get("categories", {}).get("security", {}).get("weight", 3),
            "ARCH": self.config.get("categories", {}).get("architecture", {}).get("weight", 2),
            "UI": self.config.get("categories", {}).get("ui", {}).get("weight", 1),
            "UX": self.config.get("categories", {}).get("ux", {}).get("weight", 1),
            "MAINTENANCE": self.config.get("categories", {}).get("maintenance", {}).get("weight", 1),
            "DEPENDENCIES": self.config.get("categories", {}).get("dependencies", {}).get("weight", 2),
            "DATABASE": 2,  # Fixed weight for database (not in the standard categories)
            "CICD": self.config.get("categories", {}).get("cicd", {}).get("weight", 2),
        }

        # Enabled categories
        self.enabled_categories = {
            "SECURITY": self.config.get("categories", {}).get("security", {}).get("enabled", True),
            "ARCH": self.config.get("categories", {}).get("architecture", {}).get("enabled", True),
            "UI": self.config.get("categories", {}).get("ui", {}).get("enabled", True),
            "UX": self.config.get("categories", {}).get("ux", {}).get("enabled", True),
            "MAINTENANCE": self.config.get("categories", {}).get("maintenance", {}).get("enabled", True),
            "DEPENDENCIES": self.config.get("categories", {}).get("dependencies", {}).get("enabled", False),
            "DATABASE": self.config.get("database", {}).get("enabled", False),
            "CICD": self.config.get("categories", {}).get("cicd", {}).get("enabled", False),
        }

        self.now = datetime.now()
        self.timestamp = self.now.strftime("%Y-%m-%d-%H-%M")
        self.comparison: Optional[ComparisonResult] = None
        self.test_results: Optional[TestResults] = None
        self.fixture_validation: Optional[FixtureValidation] = None

        # Dependency statistics (stored for the HTML report)
        self.dependency_stats: Optional[dict] = None
        self.dependency_warnings: List[dict] = []

        # Database schema (stored in SCA-DATA, no separate file)
        self.database_schema: Optional[dict] = None
        self.database_stats: Optional[dict] = None

        # CI/CD statistics
        self.cicd_stats: Optional[dict] = None

        # Lines-of-code counter (excluding comments and blank lines)
        self._total_lines_code: int = 0
        self._counted_files: set = set()
        self._unique_files_scanned: set = set()

        # License LOC lever (restrictive AND with max_files).
        # `_loc_limit_reached` is raised during the scan as soon as the limit
        # is hit; subsequent files are skipped (truncate).
        self._loc_limit_reached: bool = False

        # Timing per audit category
        self.audit_timings: Dict[str, float] = {}

        # Output directories from the config
        reports_config = self.config.get("reports", {})
        output_dir = reports_config.get("output_dir")
        history_dir = reports_config.get("history_dir")

        if output_dir:
            if not os.path.isabs(output_dir):
                output_dir = os.path.join(self.root_dir, output_dir)
            if history_dir and not os.path.isabs(history_dir):
                history_dir = os.path.join(self.root_dir, history_dir)
            elif not history_dir:
                history_dir = os.path.join(output_dir, "audit-datas")
            self.reports_dir = output_dir
            self.datas_dir = history_dir
            os.makedirs(self.reports_dir, exist_ok=True)
            os.makedirs(self.datas_dir, exist_ok=True)
        else:
            # No reports config (e.g. unit tests) — no directories created
            self.reports_dir = self.root_dir
            self.datas_dir = self.root_dir

        # Output file paths
        self.report_path = os.path.join(self.reports_dir, f"{self.brand_prefix}-REPORT-{self.timestamp}.html")
        self.data_path = os.path.join(self.datas_dir, f"{self.brand_prefix}-DATA-{self.timestamp}.json")

        # Reporter — single entry point for user-facing output.
        # Three independent targets: console (--quiet), log file
        # (--with-logs), debug (coexists via sca.debug).
        cli_opts = self.config.get("_cli_options", {})
        self.with_logs = cli_opts.get("with_logs", False)
        self.quiet = cli_opts.get("quiet", False)
        self._log_path = None
        if self.with_logs:
            self._log_path = os.path.join(
                self.reports_dir,
                f"{self.brand_prefix}-LOGS-{self.timestamp}.log"
            )
        self.reporter = Reporter(
            t_console=self.t_console,
            quiet=self.quiet,
            log_file_path=self._log_path,
        )

        # Paths to include/exclude
        # Note: include can be None if not defined in config; we use ["."] as a fallback for tests
        include_paths = self.config.get("paths", {}).get("include")
        self.include_paths = include_paths if include_paths else ["."]
        self.exclude_patterns = self.config.get("paths", {}).get("exclude", [])
        # Always exclude SCA output directories (even if the project doesn't list them)
        for _forced in ("audit-reports/", "audit-datas/"):
            if _forced not in self.exclude_patterns:
                self.exclude_patterns.append(_forced)

        # Custom patterns from the config
        self.custom_patterns = self.config.get("rules", {}).get("custom_patterns", {})

        # Thresholds for the health bar
        self.health_thresholds = {
            "good": self.config.get("thresholds", {}).get("health_good", 90),
            "warning": self.config.get("thresholds", {}).get("health_warning", 70),
        }

        # Languages declared in the config — controls which rules run
        self._languages = set(self.config.get("languages") or [])
        all_paths = [p.rstrip("/") for p in self.include_paths]
        self._py_paths = all_paths if "python" in self._languages else []
        self._js_paths = all_paths if "javascript" in self._languages else []
        self._html_paths = all_paths if "html" in self._languages else []
        self._java_paths = all_paths if "java" in self._languages else []
        self._csharp_paths = all_paths if "csharp" in self._languages else []
        self._php_paths = all_paths if "php" in self._languages else []
        self._yaml_paths = all_paths if "yaml" in self._languages else []

        self.reporter.detail(self.t_console("log_config_loaded").format(
            count=len(self._languages), langs=", ".join(sorted(self._languages)),
            paths=len(self.include_paths)))
        self.reporter.detail(self.t_console("log_active_categories").format(
            cats=", ".join(k for k, v in self.enabled_categories.items() if v)))

        # Log config resolution (DETAIL level)
        config_path = self.config.get("_config_path", "audit.config.json")
        log_config_resolve("languages", list(self._languages), config_path)
        log_config_resolve("paths.include", self.include_paths, config_path)
        log_config_resolve("brand.prefix", self.brand_prefix, config_path)
        log_config_resolve("reports.language", self.report_lang,
                           config_path if self.config.get("reports", {}).get("language") else "default")

        # Language/framework versions (optional, for deprecated API rules)
        self._versions = self.config.get("versions") or {}

        # Load project-specific rules (if a rules.py module exists)
        self._load_project_rules()

        # Load compliance mappings (if the feature is available)
        if self._check_feature("compliance"):
            self._load_iso27001_mapping()
            self._load_asvs_mapping()
            self._load_nist_csf_mapping()
        else:
            self.iso27001_mapping = None
            self.asvs_mapping = None
            self.nist_csf_mapping = None
            logger.info("[license] Feature 'compliance' non disponible — conformité désactivée")

        # Load suppressions (.sca-suppress.json)
        self._suppressions = {}  # {(rule_key, rel_file): [code_hashes]}
        self._suppressed_count = 0
        self._load_suppressions()

        # Language → file extensions mapping
        self._py_exts = [".py"]
        self._js_exts = [".js", ".jsx", ".ts", ".tsx", ".mjs"]
        self._html_exts = [
            ".html", ".htm", ".xhtml", ".shtml",
            ".vue", ".svelte",
            ".ejs", ".hbs", ".njk",
            ".jinja", ".jinja2", ".twig", ".liquid", ".mustache",
            ".phtml", ".erb", ".jsp", ".asp", ".aspx", ".cshtml",
        ]
        self._java_exts = [".java"]
        self._csharp_exts = [".cs"]
        self._php_exts = [".php", ".inc"]
        self._yaml_exts = [".yml", ".yaml"]

        # Audit categories
        self.categories: Dict[str, Category] = {
            "SECURITY": Category(
                key="SECURITY",
                title=self.t_report("category_meta.SECURITY.title"),
                icon="🛡️",
                risk_summary=self.t_report("category_meta.SECURITY.risk"),
                solution_summary=self.t_report("category_meta.SECURITY.solution"),
                benefit_summary=self.t_report("category_meta.SECURITY.benefit"),
            ),
            "ARCH": Category(
                key="ARCH",
                title=self.t_report("category_meta.ARCH.title"),
                icon="🏗️",
                risk_summary=self.t_report("category_meta.ARCH.risk"),
                solution_summary=self.t_report("category_meta.ARCH.solution"),
                benefit_summary=self.t_report("category_meta.ARCH.benefit"),
            ),
            "UI": Category(
                key="UI",
                title=self.t_report("category_meta.UI.title"),
                icon="🎨",
                risk_summary=self.t_report("category_meta.UI.risk"),
                solution_summary=self.t_report("category_meta.UI.solution"),
                benefit_summary=self.t_report("category_meta.UI.benefit"),
            ),
            "UX": Category(
                key="UX",
                title=self.t_report("category_meta.UX.title"),
                icon="🔔",
                risk_summary=self.t_report("category_meta.UX.risk"),
                solution_summary=self.t_report("category_meta.UX.solution"),
                benefit_summary=self.t_report("category_meta.UX.benefit"),
            ),
            "MAINTENANCE": Category(
                key="MAINTENANCE",
                title=self.t_report("category_meta.MAINTENANCE.title"),
                icon="♻️",
                risk_summary=self.t_report("category_meta.MAINTENANCE.risk"),
                solution_summary=self.t_report("category_meta.MAINTENANCE.solution"),
                benefit_summary=self.t_report("category_meta.MAINTENANCE.benefit"),
            ),
            "DEPENDENCIES": Category(
                key="DEPENDENCIES",
                title=self.t_report("category_meta.DEPENDENCIES.title"),
                icon="📦",
                risk_summary=self.t_report("category_meta.DEPENDENCIES.risk"),
                solution_summary=self.t_report("category_meta.DEPENDENCIES.solution"),
                benefit_summary=self.t_report("category_meta.DEPENDENCIES.benefit"),
            ),
            "DATABASE": Category(
                key="DATABASE",
                title=self.t_report("category_meta.DATABASE.title"),
                icon="🗄️",
                risk_summary=self.t_report("category_meta.DATABASE.risk"),
                solution_summary=self.t_report("category_meta.DATABASE.solution"),
                benefit_summary=self.t_report("category_meta.DATABASE.benefit"),
            ),
            "CICD": Category(
                key="CICD",
                title=self.t_report("category_meta.CICD.title"),
                icon="⚙️",
                risk_summary=self.t_report("category_meta.CICD.risk"),
                solution_summary=self.t_report("category_meta.CICD.solution"),
                benefit_summary=self.t_report("category_meta.CICD.benefit"),
            ),
        }

    # =========================================================================
    # INTERNATIONALIZATION (i18n)
    # =========================================================================
    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """Recursively merge override into base (override wins)."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = AuditRunner._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def _load_locale(self, category: str, lang: str) -> dict:
        """Load a translation file from locales/{category}/{lang}.json,
        then merge project-specific locale overrides if they exist."""
        locales_dir = SCRIPT_DIR / "locales" / category
        locale_file = locales_dir / f"{lang}.json"

        # Fallback to "en" if the file doesn't exist
        if not locale_file.exists():
            locale_file = locales_dir / "en.json"

        data = {}
        if locale_file.exists():
            with open(locale_file, "r", encoding="utf-8") as f:
                data = json.load(f)

        # Merge with project-specific locales (overrides)
        project_id = self.config.get("project", {}).get("id", "")
        if project_id:
            from sca.projects import _get_project_dir
            project_dir = _get_project_dir(project_id)
            if project_dir is None:
                return data
            project_locale_dir = project_dir / "locales" / category
            project_locale_file = project_locale_dir / f"{lang}.json"
            if not project_locale_file.exists():
                project_locale_file = project_locale_dir / "en.json"
            if project_locale_file.exists():
                with open(project_locale_file, "r", encoding="utf-8") as f:
                    project_data = json.load(f)
                data = self._deep_merge(data, project_data)

        return data

    def t_console(self, key: str) -> str:
        """Translate a key for console messages."""
        return self._get_nested(self.i18n_script, key)

    def t_report(self, key: str) -> str:
        """Translate a key for the HTML report."""
        return self._get_nested(self.i18n_report, key)

    def _get_nested(self, data: dict, key: str) -> str:
        """Retrieve a value by key (supports dot notation, e.g. 'severity.high')."""
        keys = key.split(".")
        value = data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return key  # Fallback: return the key
        return value if value else key

    # =========================================================================
    # PROJECT-SPECIFIC RULES
    # =========================================================================
    _CATEGORY_TO_FUNC = {
        "SECURITY": "audit_security",
        "ARCH": "audit_architecture",
        "UI": "audit_ui",
        "UX": "audit_ux",
        "MAINTENANCE": "audit_maintenance",
    }

    def _load_project_rules(self):
        """Load the project-specific rules module from projects/{uuid}/rules.py."""
        self._project_rules_module = None
        project_id = self.config.get("project", {}).get("id", "")
        if not project_id:
            return

        from sca.projects import _get_project_dir
        project_dir = _get_project_dir(project_id)
        if project_dir is None:
            return
        rules_path = project_dir / "rules.py"
        if not rules_path.exists():
            return

        try:
            spec = importlib.util.spec_from_file_location(
                f"project_rules_{project_id[:8]}", str(rules_path)
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self._project_rules_module = module
            logger.info("Règles projet chargées: %s", rules_path)
        except Exception as e:
            logger.warning("Erreur chargement règles projet %s: %s", rules_path, e)

    def _run_project_rules(self, category_key: str):
        """Run the project-specific rules for a given category."""
        if not self._project_rules_module:
            return

        func_name = self._CATEGORY_TO_FUNC.get(category_key)
        if not func_name:
            return

        func = getattr(self._project_rules_module, func_name, None)
        if func:
            logger.detail(f"[projet] Règles spécifiques {category_key}...")
            func(self)

    # =========================================================================
    # MAIN EXECUTION
    # =========================================================================
    _PHASE_ICONS = {
        "rules": "🔧",
        "dependencies": "📦",
        "database": "🗄️",
        "tests": "🧪",
    }

    def _compute_phase_total(self) -> int:
        """Return the number of optional phases (excluding scan/taint, computed dynamically)."""
        total = 0
        cli_opts = self.config.get("_cli_options", {})
        if not self.quick_mode:
            if cli_opts.get("with_deps", False):
                total += 1
            if self.enabled_categories.get("DATABASE", False):
                total += 1
            if cli_opts.get("with_tests", False):
                total += 1
        return total

    def _run_phase(self, phase: str, cat_key: str, method, emit_phase: bool = True):
        """Run an audit phase with start/end markers and timing."""
        silent = self.config.get("_silent", False)
        logger.detail(f"[phase] Début {cat_key} ({phase})")
        findings_before = len(self.categories[cat_key].findings)
        if not silent and emit_phase:
            log_phase_start(phase)
            self.reporter.phase(phase, icon=self._PHASE_ICONS.get(phase, "→"))
        t0 = time.perf_counter()
        method()
        duration = time.perf_counter() - t0
        logger.detail(f"[phase] Fin {cat_key} : {len(self.categories[cat_key].findings) - findings_before} findings en {duration:.2f}s")
        self.audit_timings[phase] = round(duration, 2)
        findings_count = len(self.categories[cat_key].findings) - findings_before
        if not silent:
            new_findings = self.categories[cat_key].findings[findings_before:]
            sev_counts = {}
            for f in new_findings:
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            detail = ", ".join(f"{c} {s}" for s, c in sorted(sev_counts.items())) if sev_counts else ""
            log_phase_end(phase, duration, findings_count, detail)

    def run(self) -> int:
        """Run the full audit and return the count of HIGH findings."""
        logger.detail(f"[run] Démarrage audit : {self.tool_name} v{self.tool_version}")
        logger.detail(f"[run] Projet     : {self.project_name} ({self.root_dir})")
        logger.detail(f"[run] Langages   : {', '.join(sorted(self._languages))}")
        logger.detail(f"[run] Paths      : {self.include_paths}")
        logger.detail(f"[run] Demo mode  : {getattr(self, 'demo_mode', False)}")
        logger.detail(f"[run] Quick mode : {self.quick_mode}")
        _active = [k for k, v in self.enabled_categories.items() if v]
        _inactive = [k for k, v in self.enabled_categories.items() if not v]
        logger.detail(f"[run] Categories actives   : {', '.join(_active)}")
        logger.detail(f"[run] Categories inactives : {', '.join(_inactive) if _inactive else 'aucune'}")
        logger.detail(f"[run] Brand      : {self.tool_name} / {self.company_name} / {self.brand_prefix}")

        # Apply license/demo restrictions if defined in the config
        if self.config.get("_demo_mode"):
            _demo_cats = self.config.get("_demo_categories", [
                "SECURITY", "ARCH", "UI", "UX",
                "MAINTENANCE", "DEPENDENCIES", "CICD", "DATABASE",
            ])
            _demo_max = self.config.get("_demo_max_files", 50)
            self.reporter.banner("")
            self.reporter.banner("  ============================================")
            self.reporter.banner(f"  {self.t_console('cli_demo_mode')}")
            self.reporter.banner(f"  {self.t_console('demo_mode_license_required')}")
            self.reporter.banner(f"  {self.t_console('cli_demo_max_files').format(count=_demo_max)}")
            self.reporter.banner(f"  {self.t_console('cli_demo_categories').format(list=', '.join(_demo_cats))}")
            self.reporter.banner(f"  {self.t_console('cli_demo_contact')}")
            self.reporter.banner("  ============================================")
            self.reporter.banner("")
            for _cat in list(self.enabled_categories.keys()):
                if _cat not in _demo_cats:
                    self.enabled_categories[_cat] = False
            # File limit is handled directly in _find_files
        elif self.config.get("_license_data"):
            # Valid license — check reseller limits
            try:
                from sca.license_check import check_reseller_limits
                _limits = check_reseller_limits(self.config["_license_data"])
                if not _limits["ok"]:
                    self.reporter.error(_limits["message"])
                    import sys
                    sys.exit(1)
            except ImportError:
                pass
            # Restrict categories according to the license tier
            try:
                from sca.license_facade import get_allowed_categories
                _allowed = get_allowed_categories()
                for _cat in list(self.enabled_categories.keys()):
                    if _cat not in _allowed:
                        self.enabled_categories[_cat] = False
            except ImportError:
                pass

        if not self.config.get("_silent", False):
            self.reporter.banner(
                f"🔍 {self.tool_name} v{self.tool_version} — "
                f"{self.project_name} - {self.timestamp}"
            )
            self.reporter.banner("=" * 50)
            if self.with_logs:
                self.reporter.banner(
                    f"📄 {self.t_console('log_enabled').format(path=self._log_path)}"
                )

        # Initialize the phase counter [n/N] dynamically
        self.reporter.init_phases(self._compute_phase_total())

        t0_total = time.perf_counter()

        # Validate fixtures only in self-test or self-audit mode
        if self.self_test or self._is_self_audit():
            self._validate_fixtures()

        # Run audits according to the configuration
        def should_run(cat_key: str) -> bool:
            """Return True if this category should run, honoring --only-category."""
            if self.only_category:
                return cat_key.lower() == self.only_category.lower()
            return self.enabled_categories.get(cat_key, True)

        # Rule engine — the [n/N] numbering is handled by _audit_rule_engine
        self._run_phase("rules", "SECURITY", self._audit_rule_engine, emit_phase=False)
        for cat in ("SECURITY", "ARCH", "UI", "UX", "MAINTENANCE"):
            self._run_project_rules(cat)

        if not self.config.get("_silent", False):
            n_rules = len(getattr(self, "_cached_json_rules", {}))
            n_files = getattr(self, "_total_files_scanned", 0)
            self.reporter.step(self.t_console("log_rules_loaded").format(count=n_rules), icon="📊")
            self.reporter.step(self.t_console("log_files_scanned").format(count=n_files), icon="📁")
            _SEV_ICONS = {
                "CRITICAL": "⛔", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"
            }
            _SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            _CAP_DETAIL = 30  # max per CRITICAL/HIGH severity
            _CAP_OTHER  = 5   # max if no CRITICAL/HIGH

            for _cat_key, _cat in self.categories.items():
                if not _cat.findings:
                    continue
                total = len(_cat.findings)
                self.reporter.step(
                    self.t_console("log_findings_per_cat").format(
                        category=_cat_key, count=total
                    ),
                    icon="→",
                )

                # Group by severity
                _by_sev = {s: [] for s in _SEV_ORDER}
                for _f in _cat.findings:
                    _s = (getattr(_f, "severity", "MEDIUM") or "MEDIUM").upper()
                    _by_sev.setdefault(_s, _by_sev.get("MEDIUM", [])).append(_f) if _s not in _by_sev else _by_sev[_s].append(_f)

                # Severities to show in detail: CRITICAL+HIGH, otherwise 5 of the highest level
                _detail_sevs = [s for s in ("CRITICAL", "HIGH") if _by_sev.get(s)]
                if not _detail_sevs:
                    for _s in ("MEDIUM", "LOW", "INFO"):
                        if _by_sev.get(_s):
                            _detail_sevs = [_s]
                            break

                _n_capped = 0
                for _sev in _detail_sevs:
                    _cap = _CAP_DETAIL if _sev in ("CRITICAL", "HIGH") else _CAP_OTHER
                    _sorted = sorted(_by_sev[_sev], key=lambda _f: (getattr(_f, "file", ""), getattr(_f, "line", 0)))
                    for _f in _sorted[:_cap]:
                        _rk = getattr(_f, "rule_key", "") or ""
                        _fl = getattr(_f, "file", "?")
                        _ln = getattr(_f, "line", 0)
                        self.reporter.info(f"      {_SEV_ICONS.get(_sev, '•')} {_fl}:{_ln}  {_rk}")
                    if len(_sorted) > _cap:
                        _n_capped += len(_sorted) - _cap

                if _n_capped:
                    _capped_sev = _detail_sevs[-1] if _detail_sevs else ""
                    self.reporter.info(
                        f"      {self.t_console('log_findings_others').format(count=_n_capped)} {_capped_sev}"
                    )

                # Summary of severities not shown in detail
                _summary = [
                    f"{_SEV_ICONS[_s]} {len(_by_sev[_s])} {_s}"
                    for _s in _SEV_ORDER
                    if _by_sev.get(_s) and _s not in _detail_sevs
                ]
                if _summary:
                    self.reporter.info(f"      ↳ {' · '.join(_summary)}")

        if not self.quick_mode:
            # Dependencies only if --with-deps
            if self.config.get("_cli_options", {}).get("with_deps", False):
                self._run_phase("dependencies", "DEPENDENCIES", self._audit_dependencies)
                if not self.config.get("_silent", False):
                    n_dep = len(self.categories["DEPENDENCIES"].findings)
                    self.reporter.step(
                        self.t_console("log_deps_done").format(count=n_dep), icon="→"
                    )

            # CI/CD audit if enabled
            # CI/CD is handled by the rule engine (.sca YAML)

            # Database audit if enabled — DISABLED IN BINARY MODE.
            # The feature remains fully usable in dev/script mode (for internal
            # tests), but is never exposed to clients using the binary.
            from sca.cli import _check_is_binary
            if should_run("DATABASE") and not _check_is_binary():
                self._run_phase("database", "DATABASE", self._audit_database)
                if not self.config.get("_silent", False):
                    n_db = len(self.categories["DATABASE"].findings)
                    self.reporter.step(
                        self.t_console("log_db_done").format(count=n_db), icon="→"
                    )

            # Tests only if --with-tests is passed
            with_tests = self.config.get("_cli_options", {}).get("with_tests", False)
            if with_tests:
                if not self.config.get("_silent", False):
                    self.reporter.phase("tests", icon=self._PHASE_ICONS["tests"])
                t0 = time.perf_counter()
                self._run_tests()
                self.audit_timings["tests"] = round(time.perf_counter() - t0, 2)

        # Summary by category
        for cat_key, cat in self.categories.items():
            if cat.findings:
                self.reporter.detail(self.t_console("log_category_findings").format(cat=cat_key, count=len(cat.findings)))

        # Post-processing: adjust confidence of injection findings without taint
        self._adjust_injection_confidence()

        # Generate automatic successes (clean rules, healthy categories, coverage)
        self._generate_successes()

        _silent = self.config.get("_silent", False)

        # Find and compare against the latest baseline (automatic)
        latest_baseline = self._find_latest_baseline()
        if latest_baseline:
            if not _silent:
                self.reporter.step(self.t_console("log_step_baseline"), icon="📋")
            self._compare_with_baseline(latest_baseline)
        else:
            self.reporter.info(f"📋 {self.t_console('first_run')}")

        # Git blame resolution if enabled
        cli_opts = self.config.get("_cli_options", {})
        if cli_opts.get("git_blame"):
            if not _silent:
                self.reporter.step(self.t_console("log_step_git_blame"), icon="🕵️")
            self._resolve_git_blame()

        # Optional exports (SARIF, SBOM) — license gating
        if cli_opts.get("sarif"):
            if self._check_export("sarif"):
                if not _silent:
                    self.reporter.step(self.t_console("log_step_export_sarif"), icon="📋")
                self._export_sarif()
                if hasattr(self, '_sarif_path'):
                    self._log_export_size(self._sarif_path, "SARIF")
            else:
                tier = self.config.get("_license", {}).get("tier", "?")
                self.reporter.warn(self.t_console("export_unavailable_tier").format(format="SARIF", tier=tier))
        if cli_opts.get("sbom"):
            if self._check_export("sbom"):
                if not _silent:
                    self.reporter.step(self.t_console("log_step_export_sbom"), icon="📦")
                self._export_sbom()
                if hasattr(self, '_sbom_path'):
                    self._log_export_size(self._sbom_path, "SBOM")
            else:
                tier = self.config.get("_license", {}).get("tier", "?")
                self.reporter.warn(self.t_console("export_unavailable_tier").format(format="SBOM", tier=tier))

        # In demo mode, list the scanned files for verification
        if self.demo_mode:
            self.reporter.banner("")
            self.reporter.banner(
                f"  [demo] Fichiers scannes "
                f"({len(self._unique_files_scanned)}/"
                f"{self.config.get('_demo_max_files', 50)}) :"
            )
            for _f in sorted(self._unique_files_scanned):
                try:
                    _lines = sum(1 for _ in open(_f, encoding="utf-8", errors="ignore"))
                except Exception:
                    _lines = 0
                self.reporter.banner(f"    {self._rel(_f)} ({_lines} lignes)")
            self.reporter.banner("")

        # Audit time as of just before the JSON export/HTML report generation:
        # this value gets baked into those artifacts (so the report can show
        # its own generation time), covering everything up to here (baseline
        # comparison, git blame, SARIF/SBOM exports — on a large project these
        # can far exceed the rule scan time). It's re-captured a second time
        # right before the final console message below, since JSON export +
        # HTML generation + cleanup still happen after this point and would
        # otherwise be silently missing from the number shown to the user.
        self.audit_timings["total"] = round(time.perf_counter() - t0_total, 2)

        # Export the JSON data (after "total": see comment above)
        if not _silent:
            self.reporter.step(self.t_console("log_step_export_json"), icon="📦")
        self._export_json()
        self._log_export_size(self.data_path, "JSON")

        # Generate the full HTML report
        report_html = self._generate_report()
        self._log_export_size(self.report_path, "HTML")

        # In demo mode, also generate an anonymized report
        if self.demo_mode:
            if not _silent:
                self.reporter.step(self.t_console("log_step_demo_report"), icon="🎯")
            self._generate_demo_report(report_html)

        # Cleanup of old reports (retention)
        if not _silent:
            self.reporter.step(self.t_console("log_step_cleanup"), icon="🧹")
        self._cleanup_old_reports()

        # Count findings by severity
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        high_verified = 0  # HIGH with confidence >= 80 (verified taint or non-injection)
        for cat in self.categories.values():
            for f in cat.findings:
                if f.severity in sev_counts:
                    sev_counts[f.severity] += 1
                if f.severity == "HIGH" and f.confidence >= 80:
                    high_verified += 1
        high_count = high_verified  # Only verified HIGH findings count for --fail-on-high
        total_findings = sum(sev_counts.values())

        # Summary score — weighted by severity
        # Penalties: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFO=0
        # Each success = 1 reward point
        _score_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        penalty = sum(
            _score_weights.get(f.severity.upper(), 1)
            for cat in self.categories.values()
            for f in cat.findings
        )
        total_successes = sum(len(c.successes) for c in self.categories.values())
        total_weight = penalty + total_successes
        score = round(total_successes / total_weight * 100) if total_weight > 0 else 100

        # Log structured summary
        log_run_summary({
            "duration": self.audit_timings.get("total", 0),
            "files_scanned": getattr(self, "_total_files_scanned", 0),
            "total_findings": total_findings,
            "critical": sev_counts["CRITICAL"],
            "high": sev_counts["HIGH"],
            "medium": sev_counts["MEDIUM"],
            "low": sev_counts["LOW"],
            "info": sev_counts["INFO"],
            "score": score,
        })

        self.reporter.detail(self.t_console("log_total_duration").format(duration=self.audit_timings.get("total", 0)))
        self.reporter.detail(self.t_console("log_report").format(path=self._rel(self.report_path)))
        self.reporter.detail(self.t_console("log_data").format(path=self._rel(self.data_path)))
        # Final results — always visible, even in --quiet
        self.reporter.result("")
        self.reporter.result(f"✅ {self.t_console('report_generated')} : {self.report_path}")
        self.reporter.result(f"📦 {self.t_console('data_saved')} : {self.data_path}")
        if hasattr(self, '_sarif_path'):
            self.reporter.result(f"📋 SARIF : {self._sarif_path}")
        if hasattr(self, '_sbom_path'):
            self.reporter.result(f"📦 SBOM : {self._sbom_path}")
        if self.demo_mode:
            self.reporter.result(f"🎯 {self.t_console('demo_report_generated')} : {self._demo_report_path}")
        # Re-capture "total" right before display: the earlier value (line
        # ~757) was frozen before JSON export/HTML report generation/cleanup
        # so those steps could be baked into the exported artifacts — but it
        # means that same value, if reused here unchanged, would silently
        # under-report the console total by however long that post-processing
        # took. This second capture reflects the *true* end-to-end wall time.
        self.audit_timings["total"] = round(time.perf_counter() - t0_total, 2)
        self.reporter.result(
            f"⏱️  {self.t_console('audit_duration')}: "
            f"{self.audit_timings.get('total', 0)}s"
        )
        if high_count > 0:
            self.reporter.result(f"⚠️  {high_count} {self.t_console('vulnerabilities_found')} !")

        # Close the log file and display its path
        if self.with_logs and self._log_path:
            self.reporter.result(f"\n📄 {self.t_console('log_file_saved')} : {self._log_path}")
        self.reporter.close()

        return high_count

    # =========================================================================
    # FILE UTILITIES (wrappers around sca.utils)
    # =========================================================================
    def _read_file(self, filepath: str) -> list:
        """Read a file and return its lines with line numbers.
        Counts code lines (excluding comments and blank lines) once per unique file.
        """
        lines = read_file(filepath)
        # Count LOC only once per unique file
        if filepath not in self._counted_files:
            self._counted_files.add(filepath)
            ext = os.path.splitext(filepath)[1].lower()
            in_block_comment = False
            code_lines = 0
            for _, content in lines:
                stripped = content.strip()
                if not stripped:
                    continue
                # Handle multi-line comments (JS, Java, C#, PHP, CSS)
                if ext in ('.js', '.jsx', '.ts', '.tsx', '.mjs', '.java', '.cs', '.php', '.css'):
                    if in_block_comment:
                        if '*/' in stripped:
                            in_block_comment = False
                        continue
                    if stripped.startswith('/*'):
                        if '*/' not in stripped or stripped.endswith('*/') and stripped != '*/':
                            in_block_comment = '*/' not in stripped
                        continue
                    if stripped.startswith('//'):
                        continue
                # HTML comments
                elif ext in ('.html', '.htm', '.vue', '.svelte', '.jinja', '.jinja2'):
                    if stripped.startswith('<!--') and ('-->' in stripped or stripped.endswith('-->')):
                        continue
                    if in_block_comment:
                        if '-->' in stripped:
                            in_block_comment = False
                        continue
                    if stripped.startswith('<!--'):
                        in_block_comment = True
                        continue
                # Python, YAML comments
                elif ext in ('.py', '.yml', '.yaml'):
                    if stripped.startswith('#'):
                        continue
                code_lines += 1
            self._total_lines_code += code_lines
        return lines

    def _load_suppressions(self):
        """Load suppressions from audit.config.json (rules.suppress) and .sca-suppress.json."""
        no_suppress = self.config.get("_cli_options", {}).get("no_suppress", False)
        if no_suppress:
            logger.detail("[suppress] Suppressions desactivees (--no-suppress)")
            return

        # 1. Load from audit.config.json → rules.suppress
        config_entries = self.config.get("rules", {}).get("suppress", [])
        for entry in config_entries:
            self._add_suppression(entry)

        # 2. Load from .sca-suppress.json (backward compatibility)
        suppress_path = self.config.get("_cli_options", {}).get("suppress_file")
        if not suppress_path:
            suppress_path = os.path.join(self.root_dir, ".sca-suppress.json")

        if os.path.exists(suppress_path):
            try:
                with open(suppress_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for entry in data.get("suppressions", []):
                    self._add_suppression(entry)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("[suppress] Erreur lecture %s : %s", suppress_path, e)

        total = sum(len(v) for v in self._suppressions.values())
        if total > 0:
            logger.info("[suppress] %d suppression(s) chargee(s)", total)

    def _add_suppression(self, entry: dict):
        """Add a suppression entry to the registry."""
        rule_key = entry.get("rule_key", "")
        file_path = entry.get("file", "")
        code_hash = entry.get("code_hash")
        if rule_key and file_path:
            key = (rule_key, file_path)
            if key not in self._suppressions:
                self._suppressions[key] = []
            self._suppressions[key].append(code_hash)

    def _is_suppressed(self, rule_key: str, rel_path: str, code: str) -> bool:
        """Check whether a finding is suppressed via .sca-suppress.json."""
        key = (rule_key, rel_path)
        if key not in self._suppressions:
            return False
        import zlib
        code_hash = zlib.crc32(code[:50].encode("utf-8")) & 0xFFFFFFFF if code else 0
        for stored_hash in self._suppressions[key]:
            if stored_hash is None:
                return True  # null = all occurrences
            if stored_hash == code_hash:
                return True
        return False

    # =========================================================================
    # POST-PROCESSING: confidence of injection findings
    # =========================================================================

    # Data-flow dependent categories: the vulnerability only exists if
    # untrusted data reaches a dangerous function. A regex alone
    # cannot confirm this → confidence capped at 60 without a taint trace.
    _INJECTION_RULE_PREFIXES = (
        "sql_injection", "taint_sqli",
        "xss_", "taint_xss",
        "ssrf", "taint_ssrf",
        "path_traversal", "taint_path",
        "ssti", "taint_ssti",
        "ldap_injection", "taint_ldap",
        "xpath_injection", "taint_xpathi",
        "xxe_injection", "taint_xxe",
        "command_injection", "unvalidated_input", "taint_rce", "os_system",
        "dangerous_eval", "taint_codeinj",
        "prompt_injection", "llm_output_to_sink",
        "insecure_deserialization", "taint_deserialization", "unsafe_deserialization",
    )

    def _adjust_injection_confidence(self):
        """Adjust confidence of injection findings that have no taint trace.

        Injection categories are data-flow dependent: they only make sense
        if untrusted data reaches a sink. A regex match without a
        propagation trace is a signal, not a conclusion — confidence is
        capped at 60.

        Findings with a taint_flow keep their confidence (90-95).
        """
        def _is_injection(f):
            """Return True if finding f belongs to an injection-prone rule family."""
            return bool(f.rule_key) and any(
                f.rule_key.startswith(p) for p in self._INJECTION_RULE_PREFIXES
            )

        # Locations (file, line) where an injection is CONFIRMED by the
        # taint engine. A regex injection finding at the same location is then
        # redundant (taint already proved it) → it is removed (dedup).
        taint_locs = {
            (f.file, f.line)
            for cat in self.categories.values()
            for f in cat.findings
            if getattr(f, "taint_flow", None) and _is_injection(f)
        }

        adjusted = removed = 0
        for cat in self.categories.values():
            kept = []
            for f in cat.findings:
                if _is_injection(f) and not getattr(f, "taint_flow", None):
                    if (f.file, f.line) in taint_locs:
                        removed += 1
                        continue  # dedup: covered by a taint finding at the same location
                    if f.confidence > 60:
                        f.confidence = 60
                        adjusted += 1
                kept.append(f)
            cat.findings[:] = kept
        if adjusted or removed:
            logger.info(
                "[post] injection sans taint : %d plafonnées à 60, %d supprimées (dédup taint)",
                adjusted, removed,
            )

    def _check_feature(self, feature: str) -> bool:
        """Check whether a feature is available in the current license."""
        features = self.config.get("_license", {}).get("features", [])
        return feature in features

    def _check_export(self, export_format: str) -> bool:
        """Check whether an export format is allowed by the license."""
        exports = self.config.get("_license", {}).get("exports", [])
        return export_format in exports

    def _rel(self, filepath: str) -> str:
        """Return the path relative to the audited project."""
        return os.path.relpath(filepath, self.root_dir)

    def _is_self_audit(self) -> bool:
        """Detect whether the tool is auditing itself (sca/ present in the paths)."""
        include = self.config.get("paths", {}).get("include", [])
        return any("sca" in p for p in include)

    def _is_excluded(self, filepath: str) -> bool:
        """Check whether a file matches an exclusion pattern."""
        rel_path = os.path.relpath(filepath, self.root_dir)
        for pattern in self.exclude_patterns:
            # Pattern with ** (e.g. "**/node_modules/**", "**/fixtures/**")
            if fnmatch.fnmatch(rel_path, pattern):
                return True
            # Simple folder pattern (e.g. "alembic/", "vendor/")
            # → matches if the folder appears in the path
            clean = pattern.rstrip("/")
            if clean and (f"/{clean}/" in f"/{rel_path}" or rel_path.startswith(f"{clean}/")):
                return True
            # Extension pattern (e.g. "*.min.js")
            if fnmatch.fnmatch(os.path.basename(filepath), pattern):
                return True
        return False

    def _get_loc_limit(self) -> Optional[int]:
        """Return the effective LOC limit (None = unlimited).

        Demo mode: `_demo_max_loc`. License: `max_loc` from the blob (0 = infinite).
        Used by `_scan_single_file` (rule_engine) for truncating the scan.
        """
        if self.config.get("_demo_mode"):
            return self.config.get("_demo_max_loc")
        license_max = self.config.get("_license", {}).get("max_loc", 0)
        return license_max if license_max > 0 else None

    def _check_loc_limit_reached(self) -> bool:
        """Check whether the LOC limit is reached. Updates the flag and returns True if exceeded.

        The flag is sticky: once set, it stays set for the rest of the audit.
        """
        if self._loc_limit_reached:
            return True
        loc_limit = self._get_loc_limit()
        if loc_limit and self._total_lines_code >= loc_limit:
            self._loc_limit_reached = True
            logger.info(
                "[license] Limite LOC atteinte : %s ≥ %s — scan tronqué",
                self._total_lines_code, loc_limit,
            )
            return True
        return False

    def _find_files(self, pattern, paths: list) -> list:
        """Find files matching the pattern (str) or a list of extensions.

        Automatically applies self.exclude_patterns (glob, folder, extension).
        File limit: demo (_demo_max_files), or license (max_files > 0).
        """
        files = []
        found = 0
        excluded = 0
        # File limit: demo takes priority, otherwise license
        if self.config.get("_demo_mode"):
            file_limit = self.config.get("_demo_max_files")
        else:
            license_max = self.config.get("_license", {}).get("max_files", 0)
            file_limit = license_max if license_max > 0 else None

        if isinstance(pattern, list):
            extensions = tuple(pattern)
        else:
            extensions = None

        # Perf — pre-prune excluded subfolders to prevent
        # `os.walk` from descending into `node_modules/`, `.venv/`,
        # `__pycache__/`, etc. Aligned with _find_dockerfile_files, which
        # already did this (but via _matches_any_exclude). We use
        # _matches_any_exclude for folder consistency (the other helper
        # `_is_excluded` is calibrated for file paths).
        from sca.rule_engine import _matches_any_exclude
        excludes_for_prune = self.config.get("paths", {}).get("exclude", [])

        for path in paths:
            full_path = os.path.join(self.root_dir, path)
            if not os.path.exists(full_path):
                continue
            for root, dirs, filenames in os.walk(full_path):
                # Prune: remove excluded subfolders so that os.walk
                # doesn't descend into them (in-place modification of `dirs`).
                rel_root = os.path.relpath(root, self.root_dir)
                if excludes_for_prune:
                    dirs[:] = [
                        d for d in dirs
                        if not _matches_any_exclude(
                            os.path.join(rel_root, d) if rel_root != "." else d,
                            excludes_for_prune,
                        )
                    ]
                for filename in filenames:
                    # File limit (demo or license) → break out
                    if file_limit and len(self._unique_files_scanned) >= file_limit:
                        break

                    filepath = os.path.join(root, filename)

                    # Check the match
                    if extensions:
                        if not filename.endswith(extensions):
                            continue
                    elif pattern != "*" and not filename.endswith(pattern):
                        continue

                    found += 1

                    # Check exclusion (file — ext patterns, basename, etc.)
                    if self._is_excluded(filepath):
                        excluded += 1
                        logger.trace(self.t_console("log_excluded").format(file=self._rel(filepath)))
                        continue

                    files.append(filepath)
                    self._unique_files_scanned.add(filepath)

                # File limit → also break out of os.walk
                if file_limit and len(self._unique_files_scanned) >= file_limit:
                    break

        # Update the counters
        self._total_files_found = getattr(self, "_total_files_found", 0) + found
        self._total_files_excluded = getattr(self, "_total_files_excluded", 0) + excluded
        self._total_files_scanned = len(self._unique_files_scanned)
        _pat = pattern if isinstance(pattern, str) else ",".join(pattern[:3])
        logger.detail(f"[files] Pattern={_pat} : {found} trouvés, {excluded} exclus, {len(files)} retenus (total unique: {self._total_files_scanned})")
        return files

    def _get_file_type(self, filepath: str) -> str:
        """Determine the file type."""
        return get_file_type(filepath)

    def _get_context(self, filepath: str, line: int, context_size: int = 2) -> Tuple[str, str]:
        """Retrieve the before/after context lines."""
        return get_context(filepath, line, context_size)

    # =========================================================================
    # FINDINGS
    # =========================================================================
    def _add_finding(self, category: str, rule: str, file: str, line: int,
                     code: str, severity: str, risk: str, solution: str, benefit: str,
                     confidence: int = 100, auto_fixable: bool = False, fix_suggestion: str = "",
                     rule_key: str = ""):
        """Add a detected issue as a finding."""
        # Check if the rule is disabled
        if rule_key and rule_key in self.disabled_rules:
            logger.detail(f"Règle désactivée, finding ignoré: {rule_key}")
            return
        # Suppression via .sca-suppress.json
        rel_path = self._rel(file)
        if rule_key and self._is_suppressed(rule_key, rel_path, code):
            self._suppressed_count += 1
            logger.detail(f"Finding supprime (.sca-suppress.json): {rule_key} dans {rel_path}:{line}")
            return
        # Inline suppression: # sca-ignore (all rules) or # sca-ignore:rule_key (targeted)
        if "# sca-ignore" in code:
            ignore_marker = code.split("# sca-ignore")[-1].strip()
            if not ignore_marker or ignore_marker.startswith(":") and rule_key in ignore_marker:
                logger.detail(f"Ligne ignorée (sca-ignore): {rule_key} dans {file}:{line}")
                return
        logger.detail(self.t_console("log_finding").format(severity=severity, rule=rule_key or rule, file=rel_path, line=line))
        file_type = self._get_file_type(rel_path)
        context_before, context_after = self._get_context(file, line)

        self.categories[category].findings.append(Finding(
            category=category,
            rule=rule,
            file=rel_path,
            line=line,
            code=code.strip()[:200],
            severity=severity,
            risk=risk,
            solution=solution,
            benefit=benefit,
            context_before=context_before[:300],
            context_after=context_after[:300],
            file_type=file_type,
            confidence=confidence,
            auto_fixable=auto_fixable,
            fix_suggestion=fix_suggestion[:500] if fix_suggestion else "",
            rule_key=rule_key
        ))

    def _add_success(self, category: str, message: str):
        """Add a passed validation as a success."""
        self.categories[category].successes.append(message)

    def _generate_successes(self):
        """Automatically generate successes after all audits (3 sources)."""
        # Rules that produced at least one finding
        fired_keys = {
            f.rule_key
            for cat in self.categories.values()
            for f in cat.findings
            if f.rule_key
        }

        # Deduplication: don't add a message already present in the same category
        added = {(k, s) for k, v in self.categories.items() for s in v.successes}

        def _add(cat, msg):
            """Add msg as a success for cat, skipping duplicates."""
            if msg and (cat, msg) not in added:
                self._add_success(cat, msg)
                added.add((cat, msg))

        # Source 3 — HIGH/CRITICAL rule with no finding at all → its benefit becomes a success
        rules = getattr(self, "_cached_json_rules", {})
        for rule_id, rule_data in rules.items():
            sev = rule_data.get("severity", "").upper()
            if sev not in ("HIGH", "CRITICAL"):
                continue
            if rule_id in fired_keys:
                continue
            cat = rule_data.get("category", "SECURITY").upper()
            if cat not in self.categories:
                continue
            benefit = self._resolve_i18n(rule_data.get("benefit", {}))
            if benefit:
                _add(cat, benefit)

        # Source 1 — category with findings but no CRITICAL or HIGH
        for cat_key, cat in self.categories.items():
            if not self.enabled_categories.get(cat_key, True):
                continue
            n_crit = sum(1 for f in cat.findings if f.severity == "CRITICAL")
            n_high = sum(1 for f in cat.findings if f.severity == "HIGH")
            if cat.findings and n_crit == 0 and n_high == 0:
                msg = self.t_report("success_cat_no_critical").format(cat=cat_key)
                _add(cat_key, msg)

        # Source 2 — tests/fixtures coverage >= 80%
        if self.test_results and self.test_results.success_rate >= 80:
            msg = self.t_report("success_tests_coverage").format(rate=self.test_results.success_rate)
            _add("MAINTENANCE", msg)
        if self.fixture_validation and self.fixture_validation.success_rate >= 80:
            msg = self.t_report("success_fixtures_coverage").format(rate=self.fixture_validation.success_rate)
            _add("MAINTENANCE", msg)

    def _rule(self, rule_key: str) -> dict:
        """Return the translations of a rule (name, risk, solution, benefit, key)."""
        rule_data = self.t_report(f"rules.{rule_key}")
        if isinstance(rule_data, dict):
            # Add the rule key for i18n comparison
            return {**rule_data, "key": rule_key}
        # Fallback if the rule doesn't exist
        return {"name": rule_key, "risk": "", "solution": "", "benefit": "", "key": rule_key}

    def _add_rule_finding(self, category: str, rule_key: str, file: str, line: int,
                          code: str, severity: str, confidence: int = 100,
                          auto_fixable: bool = False, fix_suggestion: str = ""):
        """Add a detected issue using a translated rule."""
        r = self._rule(rule_key)
        self._add_finding(
            category=category, rule=r["name"], file=file, line=line,
            code=code, severity=severity, risk=r["risk"], solution=r["solution"],
            benefit=r["benefit"], confidence=confidence, auto_fixable=auto_fixable,
            fix_suggestion=fix_suggestion, rule_key=rule_key
        )

    def _log_export_size(self, file_path: str, fmt: str = ""):
        """Log the size of an exported file (path relative to the project)."""
        try:
            size = os.path.getsize(file_path)
            log_export(self._rel(file_path), size / 1024, fmt)
        except OSError:
            pass

    # =========================================================================
    # GIT BLAME
    # =========================================================================
    def _resolve_git_blame(self):
        """Resolve the git committer for each finding via git blame."""
        # Check that git is available
        if not shutil.which("git"):
            self.reporter.warn(self.t_console("git_blame_no_git"))
            return

        # Check that the project is a git repo
        try:
            result = subprocess.run(
                ["git", "-C", self.root_dir, "rev-parse", "--is-inside-work-tree"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                self.reporter.warn(self.t_console("git_blame_no_repo"))
                return
        except Exception:
            self.reporter.warn(self.t_console("git_blame_no_repo"))
            return

        # Cache by (file, line) to avoid redundant calls
        blame_cache: Dict[tuple, str] = {}
        resolved = 0
        total = sum(len(cat.findings) for cat in self.categories.values())

        for cat in self.categories.values():
            for f in cat.findings:
                if f.line <= 0:
                    continue
                cache_key = (f.file, f.line)
                if cache_key in blame_cache:
                    f.committer = blame_cache[cache_key]
                    resolved += 1
                    continue

                # Resolve via git blame
                filepath = os.path.join(self.root_dir, f.file)
                if not os.path.exists(filepath):
                    blame_cache[cache_key] = ""
                    continue

                try:
                    result = subprocess.run(
                        ["git", "-C", self.root_dir, "blame", "--porcelain",
                         f"-L{f.line},{f.line}", "--", f.file],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        # Extract "author <name>" from the porcelain format
                        for line in result.stdout.splitlines():
                            if line.startswith("author "):
                                committer = line[7:].strip()
                                # Ignore "Not Committed Yet" authors
                                if committer and "Not Committed" not in committer:
                                    f.committer = committer
                                    blame_cache[cache_key] = committer
                                    resolved += 1
                                break
                        else:
                            blame_cache[cache_key] = ""
                    else:
                        blame_cache[cache_key] = ""
                except Exception:
                    blame_cache[cache_key] = ""

        logger.info("Git blame: %d/%d findings resolved", resolved, total)

    # _list_data_files is inherited from AuditDatabaseMixin (sca/database.py)
    # — handles the current prefix AND the legacy "AUDIT-DATA-"
