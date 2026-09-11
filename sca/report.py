"""
Report mixin — generates the HTML report.
"""
import os
import re
import json
import base64
import logging
from typing import List, Dict, Optional

from sca import SCRIPT_DIR

logger = logging.getLogger("sca.report")


class AuditReportMixin:
    """Methods for generating the HTML report."""

    # =========================================================================
    # REPORT GENERATION
    # =========================================================================
    def _compute_report_data(self):
        """Compute all data needed for the report (findings, stats, score)."""
        # Collect all findings by severity
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for cat in self.categories.values():
            for f in cat.findings:
                severity = f.severity if f.severity in by_severity else "MEDIUM"
                by_severity[severity].append(f)

        # Statistics
        total_critical = len(by_severity["CRITICAL"])
        total_high = len(by_severity["HIGH"])
        total_medium = len(by_severity["MEDIUM"])
        total_low = len(by_severity["LOW"])
        total_info = len(by_severity["INFO"])
        total_findings = total_critical + total_high + total_medium + total_low + total_info
        total_successes = sum(len(c.successes) for c in self.categories.values())

        # Statistics by group (business code / dependencies)
        all_findings = [f for sev in by_severity.values() for f in sev]
        total_business = sum(1 for f in all_findings if not self._is_dependency(f.file))
        total_deps = sum(1 for f in all_findings if self._is_dependency(f.file))

        # Statistics by category
        by_category = {}
        for cat_key, cat in self.categories.items():
            by_category[cat_key] = {
                "total": len(cat.findings),
                "critical": sum(1 for f in cat.findings if f.severity == "CRITICAL"),
                "high": sum(1 for f in cat.findings if f.severity == "HIGH"),
                "medium": sum(1 for f in cat.findings if f.severity == "MEDIUM"),
                "low": sum(1 for f in cat.findings if f.severity == "LOW"),
                "info": sum(1 for f in cat.findings if f.severity == "INFO"),
            }

        # Top 10 problematic files — score weighted by severity + breakdown
        _sev_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        file_scores = {}
        file_sev = {}
        for f in all_findings:
            sev = f.severity.upper()
            file_scores[f.file] = file_scores.get(f.file, 0) + _sev_weights.get(sev, 1)
            if f.file not in file_sev:
                file_sev[f.file] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            if sev in file_sev[f.file]:
                file_sev[f.file][sev] += 1
        top_files = [(fp, sc, file_sev.get(fp, {})) for fp, sc in
                     sorted(file_scores.items(), key=lambda x: -x[1])[:10]]

        # Health score — based only on SECURITY findings
        # Logarithmic formula weighted by LOC: 100 / (1 + P / (20 × LOC_factor))
        # LOC_factor = max(1, LOC / 1000) — normalizes by project size
        # Penalties by severity: CRITICAL:10, HIGH:5, MEDIUM:2, LOW:1
        security_penalties = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        security_cat = self.categories.get("SECURITY")
        health_penalty_detail = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        total_penalty = 0
        if security_cat:
            for f in security_cat.findings:
                sev = f.severity if f.severity in security_penalties else "MEDIUM"
                penalty = security_penalties[sev]
                health_penalty_detail[sev] += 1
                total_penalty += penalty
        loc = getattr(self, '_total_lines_code', 0)
        loc_factor = max(1, loc / 1000)
        health_score = int(100 / (1 + total_penalty / (20 * loc_factor))) if total_penalty > 0 else 100

        # Score breakdown for the severity radar
        health_severity_detail = {}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = health_penalty_detail[sev]
            sev_penalty = count * security_penalties[sev]
            health_severity_detail[sev] = {
                "count": count,
                "penalty_each": security_penalties[sev],
                "penalty_total": sev_penalty,
            }

        return (by_severity, total_critical, total_high, total_medium, total_low, total_info,
                total_findings, total_successes, health_score,
                total_business, total_deps, by_category, top_files,
                health_severity_detail, health_penalty_detail, total_penalty)

    def _generate_report(self):
        """Compute report data, render the HTML, linkify acronyms and write the report file."""
        self.reporter.info(f"\n📄 {self.t_console('generating_report')}...")
        logger.detail(f"[report] Démarrage génération rapport")
        logger.detail(f"[report] Demo mode  : {getattr(self, 'demo_mode', False)}")
        logger.detail(f"[report] Langue     : {self.report_lang}")
        logger.detail(f"[report] Branding   : {self.tool_name} / {self.company_name}")
        logger.detail(f"[report] Output dir : {self.reports_dir}")
        logger.detail("Report: loading templates and resources")

        self.reporter.step(self.t_console("log_step_report_data"), icon="📊")
        by_severity, total_critical, total_high, total_medium, total_low, total_info, \
            total_findings, total_successes, health_score, \
            total_business, total_deps, by_category, top_files, \
            health_severity_detail, health_penalty_detail, total_penalty = self._compute_report_data()

        # Load history for the trend chart
        history = self._load_history()

        # Generate HTML
        self.reporter.step(self.t_console("log_step_report_html"), icon="🧩")
        html = self._generate_html(by_severity, total_critical, total_high, total_medium, total_low, total_info,
                                   total_findings, total_successes, health_score,
                                   total_business, total_deps, by_category, top_files,
                                   history, health_severity_detail, health_penalty_detail, total_penalty)

        # Global acronym linkification across the whole HTML
        self.reporter.step(self.t_console("log_step_report_linkify"), icon="🔗")
        html = self._linkify_acronyms_in_html(html)

        self.reporter.step(self.t_console("log_step_report_write"), icon="💾")
        with open(self.report_path, 'w', encoding='utf-8') as f:
            f.write(html)

        return html

    def _generate_demo_report(self, source_html: str):
        """Generate a sanitized demo report from the full report's HTML."""

        # Sanitize a copy of the full HTML
        html = self._sanitize_for_demo(source_html)

        # Determine the output path: projects/<slug>/ (readable)
        project_id = self.config.get("project", {}).get("id", "")
        from sca import SCRIPT_DIR
        from sca.projects import _get_project_dir
        demo_dir = _get_project_dir(project_id) if project_id else None
        if demo_dir is None:
            demo_dir = SCRIPT_DIR / "projects" / (project_id[:8] if project_id else "unknown")
        os.makedirs(demo_dir, exist_ok=True)

        demo_filename = f"{self.brand_prefix}-REPORT-{self.timestamp}-demo.html"
        self._demo_report_path = os.path.join(demo_dir, demo_filename)

        with open(self._demo_report_path, 'w', encoding='utf-8') as f:
            f.write(html)

        self._log_export_size(self._demo_report_path, "HTML (demo)")

    def _sanitize_for_demo(self, html: str) -> str:
        """Anonymize sensitive data in the HTML report for demo mode.

        Strategy: keep everything visible (show the features), but
        anonymize the identifying data of the audited project.
        """
        import re as _re

        project_name = self.project_name or "my-project"
        demo_label = f"DEMO - {project_name}"

        # 1. Replace the exact project path first (before the generic regex)
        #    /Users/xxx/Documents/Code/customer-project → DEMO - CUSTOMER-PROJECT
        if self.root_dir:
            html = html.replace(self.root_dir, demo_label)

        # 2. Anonymize remaining absolute paths (/Users/xxx/... or /home/xxx/...)
        #    → DEMO - {project_name}/rest/of/path
        html = _re.sub(
            r'(?:/Users/[^/]+|/home/[^/]+)/(?:[^\s<"\']+/)*',
            f'{demo_label}/',
            html
        )

        # 3. Anonymize findings:

        # 3a. File path → path_to/{filename}:## (mask the full path + line number)
        def _anon_finding_file(m):
            """Replace a finding's file path with a masked path_to/{filename}:##."""
            full = m.group(1)  # e.g. "app/features/admin/config/service.py:811"
            # Extract the file name (without path or line number)
            path_part = full.split(":")[0]
            filename = path_part.rsplit("/", 1)[-1] if "/" in path_part else path_part
            return f'<span class="finding-file">path_to/{filename}:##</span>'

        html = _re.sub(
            r'<span class="finding-file">([^<]+)</span>',
            _anon_finding_file,
            html
        )

        # 3b. Code snippet → --- Detected Source Code ---
        html = _re.sub(
            r'(<pre class="finding-code"><code>)[^<]+(</code></pre>)',
            r'\1--- Detected Source Code ---\2',
            html
        )

        # 3c. Solution → first 20 characters + ...
        def _anon_solution(m):
            """Truncate a finding's solution text to its first 20 characters."""
            prefix = m.group(1)   # <p class="finding-solution"><strong>...</strong>
            text = m.group(2)     # solution text
            suffix = m.group(3)   # </p>
            # Decode common HTML entities to count correctly
            truncated = text[:20].rstrip() + " ..." if len(text) > 20 else text
            return f'{prefix}{truncated}{suffix}'

        html = _re.sub(
            r'(<p class="finding-solution"><strong>[^<]+</strong>\s*)([^<]+)(</p>)',
            _anon_solution,
            html
        )

        # 3d. Good practices: path → path_to/{filename}
        #     Targets <li> elements containing a relative path (e.g. app/features/admin/router.py: message)
        def _anon_success_item(m):
            """Replace a success item's file path with a masked path_to/{filename}."""
            path_part = m.group(1)  # e.g. "app/features/admin/router.py"
            message = m.group(2)    # e.g. "Admin routes protected..."
            filename = path_part.rsplit("/", 1)[-1] if "/" in path_part else path_part
            return f'<li>path_to/{filename}: {message}</li>'

        html = _re.sub(
            r'<li>([a-zA-Z0-9_./\\-]+\.\w+):\s*(.+?)</li>',
            _anon_success_item,
            html
        )

        # 4. Anonymize individual failed/error test names
        #    <div class="test-failed-item">test_name</div> → test_***
        html = _re.sub(
            r'(<div class="test-failed-item">)[^<]+(</div>)',
            r'\1test_***\2',
            html
        )

        # 5. Top 10 Problematic Files: anonymize paths (hm-dir, hm-fname) and score
        html = _re.sub(r'(<span class="hm-dir">)[^<]*(</span>)', r'\1path_to/\2', html)
        html = _re.sub(r'(<span class="hm-fname">)[^<]+(</span>)',
                       lambda m: f'{m.group(1)}file_{m.group(2)}', html)
        html = _re.sub(r'(<span class="hm-score"[^>]*>)\d+(</span>)', r'\1XX\2', html)
        html = _re.sub(r'(<span class="hm-chip [^"]+">)\d+( \w+</span>)', r'\1N\2', html)

        # 6. Fixtures table: anonymize "Expected rule" and truncate "Fixture"
        #    "Expected rule" column (3rd <td>) → "------"
        #    "Fixture" column (1st <td><code>) → first 10 characters + "..."
        def _anon_fixture_row(m):
            """Anonymize a fixture table row: truncate the fixture name and mask the expected rule."""
            row = m.group(0)
            # Truncate the fixture name inside <td><code>...</code></td>
            def _trunc_fixture(mc):
                """Truncate the fixture name inside a <td><code> cell."""
                name = mc.group(1)
                truncated = name[:10] + "..." if len(name) > 10 else name
                return f'<td><code>{truncated}</code></td>'
            row = _re.sub(r'<td><code>([^<]+)</code></td>', _trunc_fixture, row, count=1)
            # Replace the "Expected rule" description (plain text in the 3rd <td>)
            # The 3rd <td> contains the rule text (without a <span> tag)
            parts = row.split('</td>')
            if len(parts) >= 4:
                # parts[2] = "                    <td>Potential N+1 Query"
                td_idx = parts[2].rfind('<td>')
                if td_idx != -1:
                    parts[2] = parts[2][:td_idx] + '<td>------'
            row = '</td>'.join(parts)
            return row

        html = _re.sub(
            r'<tr>\s*<td><code>[^<]+</code></td>.*?</tr>',
            _anon_fixture_row,
            html,
            flags=_re.DOTALL
        )

        return html

    # Extension -> MIME type mapping for logos
    _LOGO_MIME_TYPES = {
        ".svg": "image/svg+xml",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
    }

    def _load_logo(self, logo_path):
        """Load a client logo and return (data_uri, mime_type), or (None, None) on error."""
        if os.path.isabs(logo_path):
            resolved = logo_path
        else:
            resolved = os.path.join(self.root_dir, logo_path)
        ext = os.path.splitext(resolved)[1].lower()
        mime = self._LOGO_MIME_TYPES.get(ext)
        if not mime:
            self.reporter.warn(self.t_console('logo_unsupported_format').format(ext=ext))
            return (None, None)
        try:
            with open(resolved, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("ascii")
                return (f"data:{mime};base64,{b64}", mime)
        except (FileNotFoundError, OSError):
            self.reporter.warn(self.t_console('logo_not_found').format(path=resolved))
            return (None, None)

    def _generate_html(self, by_severity, total_critical, total_high, total_medium, total_low, total_info,
                       total_findings, total_successes, health_score,
                       total_business: int = 0, total_deps: int = 0,
                       by_category: dict = None, top_files: list = None,
                       history: list = None,
                       health_severity_detail: dict = None,
                       health_penalty_detail: dict = None,
                       total_penalty: int = 0) -> str:
        """Generate the report's HTML."""
        by_category = by_category or {}
        top_files = top_files or []
        history = history or []
        health_severity_detail = health_severity_detail or {}
        health_penalty_detail = health_penalty_detail or {}

        # Mapping from category keys to i18n keys (used for charts and successes)
        cat_i18n_map = {
            "SECURITY": "security",
            "ARCH": "architecture",
            "DEPENDENCIES": "dependencies",
            "UI": "ui",
            "UX": "ux",
            "MAINTENANCE": "maintenance",
            "DATABASE": "database",
            "CICD": "cicd"
        }

        date_str = self.now.strftime("%d/%m/%Y à %H:%M")

        # Load external resources
        chartjs_lib = self._load_template("chart.min.js", "vendor")
        css = self._load_asset("report.css")
        js = self._load_asset("report.js")
        charts_js_template = self._load_asset("charts.js")

        # Load the client logo or the default favicons
        brand_logo = self.config.get("brand", {}).get("logo")
        favicon_data = ""
        favicon_header_data = ""
        favicon_type = "image/svg+xml"

        if brand_logo:
            logo_uri, logo_mime = self._load_logo(brand_logo)
            if logo_uri:
                favicon_data = logo_uri
                favicon_header_data = logo_uri
                favicon_type = logo_mime

        if not favicon_data:
            # Fallback: tool's default favicons
            script_dir = str(SCRIPT_DIR)
            for name, attr in [("favicon.svg", "favicon_data"), ("favicon-white.svg", "favicon_header_data")]:
                path = os.path.join(script_dir, "assets", name)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        b64 = base64.b64encode(f.read().encode("utf-8")).decode("ascii")
                        uri = f"data:image/svg+xml;base64,{b64}"
                        if attr == "favicon_data":
                            favicon_data = uri
                        else:
                            favicon_header_data = uri
                except FileNotFoundError:
                    pass

        # Prepare history data for the trend chart
        history_labels = []
        history_high = []
        history_medium = []
        history_low = []
        history_tests_rate = []
        history_tests_passed = []
        history_tests_failed = []
        history_db_tables = []
        history_db_columns = []
        history_db_changes = []
        for h in history:
            parts = h["timestamp"].split("-")
            if len(parts) >= 3:
                history_labels.append(f"{parts[2]}/{parts[1]}")  # DD/MM
            else:
                history_labels.append(h["timestamp"])
            history_high.append(h["totals"].get("HIGH", 0))
            history_medium.append(h["totals"].get("MEDIUM", 0))
            history_low.append(h["totals"].get("LOW", 0))
            # Test data
            tests_h = h.get("tests", {})
            history_tests_rate.append(tests_h.get("success_rate", 0))
            history_tests_passed.append(tests_h.get("passed", 0))
            history_tests_failed.append(tests_h.get("failed", 0))
            # Database data
            db_h = h.get("database", {})
            history_db_tables.append(db_h.get("tables", 0))
            history_db_columns.append(db_h.get("columns", 0))
            history_db_changes.append(db_h.get("changes", 0))

        # Data for the charts (injected as JSON)
        # Test data for the chart
        tests_chart_data = {
            "passed": self.test_results.passed if self.test_results else 0,
            "failed": self.test_results.failed if self.test_results else 0,
            "errors": self.test_results.errors if self.test_results else 0,
            "skipped": self.test_results.skipped if self.test_results else 0,
            "successRate": self.test_results.success_rate if self.test_results else 0
        }

        # Fixture data for the chart
        fixtures_chart_data = {
            "truePositives": self.fixture_validation.vulnerable_detected if self.fixture_validation else 0,
            "trueNegatives": self.fixture_validation.clean_passed if self.fixture_validation else 0,
            "falseNegatives": self.fixture_validation.vulnerable_missed if self.fixture_validation else 0,
            "falsePositives": self.fixture_validation.clean_false_positive if self.fixture_validation else 0,
            "successRate": self.fixture_validation.success_rate if self.fixture_validation else 0
        }

        # DATABASE data for the chart
        database_chart_data = {
            "enabled": self.database_schema is not None,
            "tables": self.database_stats.get("tables_count", 0) if self.database_stats else 0,
            "columns": self.database_stats.get("columns_count", 0) if self.database_stats else 0,
            "indexes": self.database_stats.get("indexes_count", 0) if self.database_stats else 0,
            "enums": self.database_stats.get("enums_count", 0) if self.database_stats else 0,
            "changes": self.database_stats.get("changes", {
                "added": {"tables": 0, "columns": 0, "indexes": 0},
                "dropped": {"tables": 0, "columns": 0, "indexes": 0},
                "modified": {"columns": 0}
            }) if self.database_stats else {
                "added": {"tables": 0, "columns": 0, "indexes": 0},
                "dropped": {"tables": 0, "columns": 0, "indexes": 0},
                "modified": {"columns": 0}
            }
        }

        # DEPENDENCIES data for the chart
        dep_stats = self.dependency_stats or {}
        dependencies_chart_data = {
            "enabled": dep_stats.get("total_scanned", 0) > 0,
            "vulnerable": dep_stats.get("vulnerable", 0),
            "unpinned": dep_stats.get("unpinned", 0),
            "ok": dep_stats.get("ok", 0),
            "total": dep_stats.get("total_scanned", 0)
        }

        # ISO 27001 COMPLIANCE data for the charts (computed early for chart_data)
        compliance_enabled = self.config.get("compliance", {}).get("iso27001", {}).get("enabled", True)
        compliance_chart_data = {"enabled": False}
        if compliance_enabled and self.iso27001_mapping:
            self._compliance_data = self._compute_iso27001_compliance()
            cd = self._compliance_data
            compliance_chart_data = {
                "enabled": True,
                "total": cd["total_controls"],
                "covered": cd["covered_controls"],
                "withFindings": cd["with_findings"],
                "notCovered": cd["total_controls"] - cd["covered_controls"],
                "coveragePct": cd["coverage_pct"],
                "themes": {
                    tk: {
                        "covered": tv["covered"],
                        "total": tv["total"],
                        "withFindings": tv["with_findings"],
                        "findingCount": tv["finding_count"]
                    }
                    for tk, tv in cd["themes"].items()
                }
            }
        else:
            self._compliance_data = None

        # ASVS data for the charts (computed early for chart_data)
        asvs_enabled = self.config.get("compliance", {}).get("asvs", {}).get("enabled", True)
        asvs_chart_data = {"enabled": False}
        if asvs_enabled and self.asvs_mapping:
            self._asvs_data = self._compute_asvs_compliance()
            ad = self._asvs_data
            asvs_chart_data = {
                "enabled": True,
                "total": ad["total_requirements"],
                "covered": ad["covered_requirements"],
                "withFindings": ad["with_findings"],
                "notCovered": ad["total_requirements"] - ad["covered_requirements"],
                "coveragePct": ad["coverage_pct"],
                "chapters": {
                    ck: {
                        "covered": cv["covered"],
                        "total": cv["total"],
                        "withFindings": cv["with_findings"],
                        "findingCount": cv["finding_count"]
                    }
                    for ck, cv in ad["chapters"].items()
                },
                "levels": ad["levels"],
            }
        else:
            self._asvs_data = None

        # NIST CSF 2.0 data for the charts (computed early for chart_data)
        nist_enabled = self.config.get("compliance", {}).get("nist_csf", {}).get("enabled", True)
        nist_chart_data = {"enabled": False}
        if nist_enabled and self.nist_csf_mapping:
            self._nist_data = self._compute_nist_csf_compliance()
            nd = self._nist_data
            nist_chart_data = {
                "enabled": True,
                "total": nd["total_subcategories"],
                "covered": nd["covered_subcategories"],
                "withFindings": nd["with_findings"],
                "notCovered": nd["total_subcategories"] - nd["covered_subcategories"],
                "coveragePct": nd["coverage_pct"],
                "functions": {
                    fk: {
                        "name": fv["name"],
                        "covered": fv["covered"],
                        "total": fv["total"],
                        "withFindings": fv["with_findings"],
                        "findingCount": fv["finding_count"],
                    }
                    for fk, fv in nd["by_function"].items()
                },
            }
        else:
            self._nist_data = None

        # Compliance Score (Option A: score separate from the security health_score)
        # Weighted average of the 3 matrices ISO 27001 / ASVS / NIST CSF
        compliance_score_data = {"enabled": False, "score": 0, "standards": []}
        compliance_pcts = []
        if self._compliance_data:
            iso_pct = self._compliance_data.get("coverage_pct", 0)
            compliance_pcts.append(iso_pct)
            compliance_score_data["standards"].append({"key": "iso27001", "label": "ISO 27001", "pct": iso_pct})
        if self._asvs_data:
            asvs_pct = self._asvs_data.get("coverage_pct", 0)
            compliance_pcts.append(asvs_pct)
            compliance_score_data["standards"].append({"key": "asvs", "label": "OWASP ASVS", "pct": asvs_pct})
        if self._nist_data:
            nist_pct = self._nist_data.get("coverage_pct", 0)
            compliance_pcts.append(nist_pct)
            compliance_score_data["standards"].append({"key": "nist", "label": "NIST CSF", "pct": nist_pct})
        if compliance_pcts:
            compliance_score_data["enabled"] = True
            compliance_score_data["score"] = round(sum(compliance_pcts) / len(compliance_pcts), 1)
        self._compliance_score_data = compliance_score_data

        chart_data = {
            "severity": {"CRITICAL": total_critical, "HIGH": total_high, "MEDIUM": total_medium, "LOW": total_low, "INFO": total_info},
            "categories": {
                self.t_report(f"category_titles.{cat_i18n_map.get(k, k.lower())}"): v["total"]
                for k, v in by_category.items()
            },
            "categoryKeyMap": {
                self.t_report(f"category_titles.{cat_i18n_map.get(k, k.lower())}"): k
                for k in by_category.keys()
            },
            "codeVsDeps": {"business": total_business, "deps": total_deps},
            "healthScore": health_score,
            "tests": tests_chart_data,
            "fixtures": fixtures_chart_data,
            "dependencies": dependencies_chart_data,
            "database": database_chart_data,
            "compliance": compliance_chart_data,
            "asvs": asvs_chart_data,
            "nist": nist_chart_data,
            "complianceScore": compliance_score_data,
            "healthPenalty": total_penalty,
            "healthSeverity": {
                sev: {
                    "label": self.t_report(f"severity.{sev.lower()}"),
                    "count": sd["count"],
                    "penaltyEach": sd["penalty_each"],
                    "penaltyTotal": sd["penalty_total"],
                }
                for sev, sd in health_severity_detail.items()
            },
            "history": {
                "labels": history_labels,
                "high": history_high,
                "medium": history_medium,
                "low": history_low,
                "testsRate": history_tests_rate,
                "testsPassed": history_tests_passed,
                "testsFailed": history_tests_failed,
                "dbTables": history_db_tables,
                "dbColumns": history_db_columns,
                "dbChanges": history_db_changes
            },
            "i18n": {
                "critical": self.t_report("chart_labels.critical"),
                "high": self.t_report("chart_labels.high"),
                "medium": self.t_report("chart_labels.medium"),
                "low": self.t_report("chart_labels.low"),
                "info": self.t_report("chart_labels.info"),
                "issues": self.t_report("chart_labels.issues"),
                "businessCode": self.t_report("chart_labels.business_code"),
                "dependencies": self.t_report("chart_labels.dependencies"),
                "total": self.t_report("chart_labels.total"),
                "passed": self.t_report("chart_labels.passed"),
                "failed": self.t_report("chart_labels.failed"),
                "errors": self.t_report("chart_labels.errors"),
                "skipped": self.t_report("chart_labels.skipped"),
                "success": self.t_report("chart_labels.success"),
                "validated": self.t_report("chart_labels.validated"),
                "tables": self.t_report("chart_labels.tables"),
                "columns": self.t_report("chart_labels.columns"),
                "indexes": self.t_report("chart_labels.indexes"),
                "additions": self.t_report("chart_labels.additions"),
                "deletions": self.t_report("chart_labels.deletions"),
                "stable": self.t_report("chart_labels.stable"),
                "successRate": self.t_report("chart_labels.success_rate"),
                "testsPassed": self.t_report("chart_labels.tests_passed"),
                "rate": self.t_report("chart_labels.rate"),
                "count": self.t_report("chart_labels.count"),
                "structure": self.t_report("chart_labels.structure"),
                "changes": self.t_report("chart_labels.changes"),
                "vulnerable": self.t_report("chart_labels.vulnerable"),
                "unpinned": self.t_report("chart_labels.unpinned"),
                "depsOk": self.t_report("chart_labels.deps_ok"),
                "scanned": self.t_report("chart_labels.scanned"),
                "complianceCoverage": self.t_report("chart_labels.compliance_coverage"),
                "complianceCovered": self.t_report("chart_labels.compliance_covered"),
                "complianceFindings": self.t_report("chart_labels.compliance_findings"),
                "complianceNotCovered": self.t_report("chart_labels.compliance_not_covered"),
                "complianceCoverageChart": self.t_report("chart_labels.compliance_coverage_chart"),
                "complianceThemeChart": self.t_report("chart_labels.compliance_theme_chart"),
                "complianceStatusChart": self.t_report("chart_labels.compliance_status_chart"),
                "complianceTheme_organizational": self.t_report("chart_labels.compliance_theme_organizational"),
                "complianceTheme_people": self.t_report("chart_labels.compliance_theme_people"),
                "complianceTheme_physical": self.t_report("chart_labels.compliance_theme_physical"),
                "complianceTheme_technological": self.t_report("chart_labels.compliance_theme_technological"),
                "asvsCoverage": self.t_report("chart_labels.asvs_coverage"),
                "asvsCovered": self.t_report("chart_labels.asvs_covered"),
                "asvsFindings": self.t_report("chart_labels.asvs_findings"),
                "asvsNotCovered": self.t_report("chart_labels.asvs_not_covered"),
                "asvsCoverageChart": self.t_report("chart_labels.asvs_coverage_chart"),
                "asvsChapterChart": self.t_report("chart_labels.asvs_chapter_chart"),
                "asvsStatusChart": self.t_report("chart_labels.asvs_status_chart"),
                "nistCoverage": self.t_report("chart_labels.nist_coverage"),
                "nistCovered": self.t_report("chart_labels.nist_covered"),
                "nistFindings": self.t_report("chart_labels.nist_findings"),
                "nistNotCovered": self.t_report("chart_labels.nist_not_covered"),
                "nistCoverageChart": self.t_report("chart_labels.nist_coverage_chart"),
                "nistFunctionChart": self.t_report("chart_labels.nist_function_chart"),
                "nistStatusChart": self.t_report("chart_labels.nist_status_chart"),
                "complianceCoverageBar": self.t_report("chart_labels.compliance_coverage_bar"),
                "healthPenalty": self.t_report("chart_labels.health_penalty"),
                "healthSeverityChart": self.t_report("chart_labels.health_severity_chart"),
                "taintFlows": self.t_report("taint_trace_summary"),
                "taintEntryPoint": self.t_report("taint_entry_point"),
                "taintImpactPoint": self.t_report("taint_impact_point"),
                "taintByRule": "Flows par règle",
                "taintPython": "Python",
                "taintBuiltin": "Builtin",
                "taintCustom": "Custom",
                "findingsByLangSeverity": self.t_report("chart_labels.findings_by_lang_severity")
            },
            "taint": self._get_taint_chart_data(),
            "languageSeverity": self._get_language_severity_data()
        }

        # Inject the data into the charts.js template
        charts_js = charts_js_template.replace("{{CHART_DATA}}", json.dumps(chart_data))


        # Generate the test results section
        tests_html = ""
        if self.test_results and self.test_results.total > 0:
            tr = self.test_results
            # Compute the progress bar widths
            total = tr.total if tr.total > 0 else 1
            passed_pct = (tr.passed / total) * 100
            failed_pct = (tr.failed / total) * 100
            errors_pct = (tr.errors / total) * 100
            skipped_pct = (tr.skipped / total) * 100

            # List of failed tests
            failed_list_html = ""
            failed_list_tpl = self._load_template("tests-failed-list.html")
            failed_item_tpl = self._load_template("test-failed-item.html")
            if tr.failed_tests:
                items = "".join(failed_item_tpl.replace("{{test}}", self._escape(test)) for test in tr.failed_tests)
                failed_list_html += failed_list_tpl.replace("{{icon}}", "❌").replace("{{title}}", self.t_report("tests_labels.failed_tests")).replace("{{items}}", items)
            if tr.error_tests:
                items = "".join(failed_item_tpl.replace("{{test}}", self._escape(test)) for test in tr.error_tests)
                failed_list_html += failed_list_tpl.replace("{{icon}}", "⚠️").replace("{{title}}", self.t_report("tests_labels.error_tests")).replace("{{items}}", items)

            tests_html = self._load_template("tests-section.html")
            tests_html = tests_html.replace("{{i18n_toc}}", self.t_report("toc"))
            tests_html = tests_html.replace("{{i18n_unit_tests}}", self.t_report("tests"))
            tests_html = tests_html.replace("{{i18n_passed}}", self.t_report("tests_labels.passed"))
            tests_html = tests_html.replace("{{i18n_failed}}", self.t_report("tests_labels.failed"))
            tests_html = tests_html.replace("{{i18n_errors}}", self.t_report("tests_labels.errors"))
            tests_html = tests_html.replace("{{i18n_skipped}}", self.t_report("tests_labels.skipped"))
            tests_html = tests_html.replace("{{i18n_success_rate}}", self.t_report("tests_labels.success_rate"))
            tests_html = tests_html.replace("{{passed}}", str(tr.passed))
            tests_html = tests_html.replace("{{failed}}", str(tr.failed))
            tests_html = tests_html.replace("{{errors}}", str(tr.errors))
            tests_html = tests_html.replace("{{skipped}}", str(tr.skipped))
            tests_html = tests_html.replace("{{success_rate}}", str(tr.success_rate))
            tests_html = tests_html.replace("{{passed_pct}}", f"{passed_pct:.1f}")
            tests_html = tests_html.replace("{{failed_pct}}", f"{failed_pct:.1f}")
            tests_html = tests_html.replace("{{errors_pct}}", f"{errors_pct:.1f}")
            tests_html = tests_html.replace("{{skipped_pct}}", f"{skipped_pct:.1f}")
            tests_html = tests_html.replace("{{failed_list}}", failed_list_html)
            tests_html += f'<p class="tests-duration">⏱️ {self.t_report("tests_labels.duration")} : {tr.duration:.1f}s</p>'

        # Generate the fixture validation section
        fixtures_html = ""
        if self.fixture_validation and self.fixture_validation.total > 0:
            fv = self.fixture_validation
            validity_class = "valid" if fv.is_valid else "invalid"
            validity_icon = "✅" if fv.is_valid else "❌"
            validity_text = self.t_report("fixtures_all_correct") if fv.is_valid else self.t_report("fixtures_some_incorrect")

            # Per-fixture details (limited to the first 10 failures)
            details_html = ""
            failures = [d for d in fv.details if not d.get("success", True)]
            successes = [d for d in fv.details if d.get("success", True)]

            if failures:
                fixture_detail_tpl = self._load_template("fixture-detail.html")
                # Replace the i18n placeholders once
                fixture_detail_tpl = fixture_detail_tpl.replace("{{i18n_expected}}", self.t_report("fixture_expected"))
                fixture_detail_tpl = fixture_detail_tpl.replace("{{i18n_actual}}", self.t_report("fixture_actual"))
                fixture_detail_tpl = fixture_detail_tpl.replace("{{i18n_rule}}", self.t_report("fixture_rule"))
                items_html = ""
                for detail in failures[:10]:
                    fixture_type = self.t_report("fixture_type_vulnerable") if detail.get("type") == "vulnerable" else "clean"
                    expected = self.t_report("fixture_expected_detected") if detail.get("type") == "vulnerable" else self.t_report("fixture_expected_ignored")
                    actual = self.t_report("fixture_expected_ignored") if detail.get("type") == "vulnerable" else self.t_report("fixture_expected_detected")
                    item = fixture_detail_tpl.replace("{{fixture}}", self._escape(detail.get("fixture", "")))
                    item = item.replace("{{type}}", fixture_type)
                    item = item.replace("{{expected}}", expected)
                    item = item.replace("{{actual}}", actual)
                    rk = detail.get("rule_key", "")
                    translated_rule = self._rule(rk).get("name", rk) if rk else ""
                    item = item.replace("{{rule}}", self._escape(translated_rule))
                    items_html += item
                more_html = ""
                if len(failures) > 10:
                    more_tpl = self._load_template("fixtures-more.html")
                    more_html = more_tpl.replace("{{i18n_more_failures}}", self.t_report("fixtures_more_failures").replace("{{count}}", str(len(failures) - 10)))
                wrapper_tpl = self._load_template("fixtures-failures-wrapper.html")
                wrapper_tpl = wrapper_tpl.replace("{{i18n_detection_failures}}", self.t_report("fixtures_detection_failures"))
                details_html += wrapper_tpl.replace("{{items}}", items_html).replace("{{more}}", more_html)

            # Generate the full fixtures list
            fixtures_list_html = self._generate_fixtures_list()

            fixtures_html = self._load_template("fixtures-section.html")
            fixtures_html = fixtures_html.replace("{{i18n_toc}}", self.t_report("toc"))
            fixtures_html = fixtures_html.replace("{{i18n_fixtures_validation}}", self.t_report("fixtures_validation"))
            fixtures_html = fixtures_html.replace("{{i18n_fixtures_explanation}}", self.t_report("fixtures_explanation"))
            fixtures_html = fixtures_html.replace("{{i18n_vulnerable_detected}}", self.t_report("fixtures_vulnerable_detected"))
            fixtures_html = fixtures_html.replace("{{i18n_clean_validated}}", self.t_report("fixtures_clean_validated"))
            fixtures_html = fixtures_html.replace("{{i18n_true_positives}}", self.t_report("fixtures_true_positives"))
            fixtures_html = fixtures_html.replace("{{i18n_true_positives_desc}}", self.t_report("fixtures_true_positives_desc"))
            fixtures_html = fixtures_html.replace("{{i18n_true_negatives}}", self.t_report("fixtures_true_negatives"))
            fixtures_html = fixtures_html.replace("{{i18n_true_negatives_desc}}", self.t_report("fixtures_true_negatives_desc"))
            fixtures_html = fixtures_html.replace("{{i18n_false_negatives}}", self.t_report("fixtures_false_negatives"))
            fixtures_html = fixtures_html.replace("{{i18n_false_negatives_desc}}", self.t_report("fixtures_false_negatives_desc"))
            fixtures_html = fixtures_html.replace("{{i18n_false_positives}}", self.t_report("fixtures_false_positives"))
            fixtures_html = fixtures_html.replace("{{i18n_false_positives_desc}}", self.t_report("fixtures_false_positives_desc"))
            fixtures_html = fixtures_html.replace("{{validity_class}}", validity_class)
            fixtures_html = fixtures_html.replace("{{validity_icon}}", validity_icon)
            fixtures_html = fixtures_html.replace("{{validity_text}}", validity_text)
            fixtures_html = fixtures_html.replace("{{vulnerable_detected}}", str(fv.vulnerable_detected))
            fixtures_html = fixtures_html.replace("{{vulnerable_total}}", str(fv.vulnerable_tested))
            fixtures_html = fixtures_html.replace("{{clean_passed}}", str(fv.clean_passed))
            fixtures_html = fixtures_html.replace("{{clean_total}}", str(fv.clean_tested))
            fixtures_html = fixtures_html.replace("{{vulnerable_missed}}", str(fv.vulnerable_missed))
            fixtures_html = fixtures_html.replace("{{clean_false_positive}}", str(fv.clean_false_positive))
            fixtures_html = fixtures_html.replace("{{details}}", details_html)
            fixtures_html = fixtures_html.replace("{{fixtures_list}}", fixtures_list_html)

        # Generate the sections by severity
        sections_html = ""
        severity_meta = {
            "CRITICAL": {"icon": "💀", "title": self.t_report("severity.critical"), "badge": "badge-critical"},
            "HIGH": {"icon": "🚨", "title": self.t_report("severity.high"), "badge": "badge-high"},
            "MEDIUM": {"icon": "⚠️", "title": self.t_report("severity.medium"), "badge": "badge-medium"},
            "LOW": {"icon": "ℹ️", "title": self.t_report("severity.low"), "badge": "badge-low"},
            "INFO": {"icon": "📝", "title": self.t_report("severity.info"), "badge": "badge-info"},
        }

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            findings = by_severity[severity]
            meta = severity_meta[severity]

            # Split findings by group (dependencies / business code)
            deps_findings = [f for f in findings if self._is_dependency(f.file)]
            business_findings = [f for f in findings if not self._is_dependency(f.file)]

            finding_tpl = self._load_template("finding-item.html")
            group_tpl = self._load_template("findings-group.html")
            cat_group_tpl = self._load_template("findings-category-group.html")
            rule_group_tpl = self._load_template("findings-rule-group.html")
            section_tpl = self._load_template("severity-section.html")

            # Category order (consistent with runner.py)
            category_order = ["SECURITY", "ARCH", "UI", "UX", "MAINTENANCE", "DEPENDENCIES", "DATABASE", "CICD"]

            def render_finding_item(f):
                """Generate the HTML for a single finding."""
                item = finding_tpl.replace("{{severity_class}}", severity.lower())
                item = item.replace("{{i18n_risk}}", self.t_report("finding_risk"))
                item = item.replace("{{i18n_solution}}", self.t_report("finding_solution"))
                item = item.replace("{{i18n_suppress_title}}", self.t_report("suppress_button_title"))
                item = item.replace("{{rule}}", self._escape(f.rule))
                item = item.replace("{{rule_key}}", self._escape(getattr(f, "rule_key", "") or ""))
                import zlib
                code_hash = zlib.crc32(f.code[:50].encode("utf-8")) & 0xFFFFFFFF if f.code else 0
                item = item.replace("{{code_hash}}", str(code_hash))
                # Category badge
                cat_i18n_key = cat_i18n_map.get(f.category, f.category.lower())
                item = item.replace("{{category_icon}}", self.categories[f.category].icon if f.category in self.categories else "")
                item = item.replace("{{category_name}}", self.t_report(f"category_titles.{cat_i18n_key}"))
                item = item.replace("{{file}}", self._escape(f.file))
                item = item.replace("{{line}}", str(f.line))
                # Code with context: lines before (greyed out) + detected line (highlighted) + lines after (greyed out)
                if f.context_before:
                    ctx_lines = f.context_before.rstrip().split("\n")
                    ctx_before_html = "".join(
                        f'<div class="finding-code-context">{self._escape(l)}</div>' for l in ctx_lines if l.strip()
                    )
                else:
                    ctx_before_html = ""
                if f.context_after:
                    ctx_lines = f.context_after.strip().split("\n")
                    ctx_after_html = "".join(
                        f'<div class="finding-code-context">{self._escape(l)}</div>' for l in ctx_lines if l.strip()
                    )
                else:
                    ctx_after_html = ""
                item = item.replace("{{context_before_html}}", ctx_before_html)
                item = item.replace("{{code}}", self._escape(f.code))
                item = item.replace("{{context_after_html}}", ctx_after_html)
                # Git blame committer (conditional)
                if f.committer:
                    committer_html = f' <span class="finding-committer" title="{self.t_report("finding_committer")}">👤 {self._escape(f.committer)}</span>'
                else:
                    committer_html = ""
                item = item.replace("{{committer_display}}", committer_html)

                # Language badge (inferred from the file extension)
                lang = self._lang_label(f.file)
                lang_html = f' <span class="finding-badge finding-badge-lang">{self._escape(lang)}</span>' if lang else ""
                item = item.replace("{{language_badge}}", lang_html)

                # CSS class for findings with taint propagation
                has_taint = getattr(f, "taint_flow", None) is not None
                item = item.replace("{{taint_class}}", "has-taint" if has_taint else "")

                # Taint badge + rule source (rules engine)
                badges_html = ""
                if has_taint:
                    badge_label = self.t_report("taint_badge_traced")
                    badges_html += f' <span class="finding-badge finding-badge-taint" title="{badge_label}">🔬 {badge_label}</span>'
                if getattr(f, "rule_source", "python") == "json_custom":
                    badge_label = self.t_report("taint_badge_custom")
                    badges_html += f' <span class="finding-badge finding-badge-custom" title="{badge_label}">📜 {badge_label}</span>'
                elif getattr(f, "rule_source", "python") == "json_builtin":
                    badge_label = self.t_report("taint_badge_builtin")
                    badges_html += f' <span class="finding-badge finding-badge-builtin" title="{badge_label}">🛡️ {badge_label}</span>'
                item = item.replace("{{taint_badges}}", badges_html)

                # Taint propagation trace block (collapsible)
                taint_html = ""
                if getattr(f, "taint_flow", None):
                    flow = f.taint_flow
                    chain_items = ""
                    impact_label = self.t_report("taint_impact_point")
                    for step_line, step_var, step_code in flow.chain:
                        # Sink steps are already displayed in the taint-sink block below
                        if step_var in ("__sink__", "Sink"):
                            continue
                        chain_items += f'<div class="taint-step"><span class="taint-line">L{step_line}</span> <span class="taint-var">{self._escape(step_var)}</span> <code>{self._escape(step_code)}</code></div>'

                    kind_label = self.t_report(f"taint_kind_{flow.source_kind}")
                    trace_summary = self.t_report("taint_trace_summary")
                    entry_label = self.t_report("taint_entry_point")

                    taint_html = (
                        f'<details class="taint-trace">'
                        f'<summary>🔬 {trace_summary} ({kind_label})</summary>'
                        f'<div class="taint-source"><strong>🟢 {entry_label}</strong> L{flow.source_line}: <code>{self._escape(flow.source_expr)}</code></div>'
                        f'<div class="taint-chain">{chain_items}</div>'
                        f'<div class="taint-sink"><strong>🔴 {impact_label}</strong> L{flow.sink_line}: <code>{self._escape(flow.sink_expr)}</code></div>'
                        f'</details>'
                    )
                # Perf/UX: the `fix suggestion` block only depends on `rule_key`,
                # so it is now rendered ONCE per group (cf. render_findings)
                # instead of being duplicated for each finding. Same for the
                # playbook below. ~20% HTML savings on projects with
                # many findings of the same type.

                item = item.replace("{{taint_trace}}", taint_html)

                # risk / solution / playbook / fix-suggestion: moved to
                # the group level (cf. render_findings) to avoid
                # duplication — these texts only depend on rule_key
                # (empirically verified: 0 variation across 234
                # rule_key × {risk, solution, benefit} pairs).

                return item

            def render_findings(findings_list):
                """Generate the HTML for a list of findings, grouped by rule type.

                Perf/UX: `risk`, `solution`, `playbook` and `fix suggestion`
                depend only on `rule_key` — they are rendered ONCE at the
                top of the group instead of being duplicated under each
                finding. On an audit with many findings of the same type
                (xss_innerhtml x268), this saves ~40% HTML and reads far
                more clearly (the rule text is shown once, followed by the
                list of occurrences).
                """
                # Group by rule (translated rule name).
                by_rule: dict = {}
                rule_order: list = []
                # rule_name → (rule_key, first finding) — to reproduce the
                # group's risk/solution from the 1st finding (fields
                # uniform per rule_key, verified on 78 rule_keys × 3220
                # customer-project findings: 0 variation).
                rule_first_by_name: dict = {}
                for f in findings_list:
                    rule_name = f.rule
                    if rule_name not in by_rule:
                        by_rule[rule_name] = []
                        rule_order.append(rule_name)
                        rule_first_by_name[rule_name] = f
                    by_rule[rule_name].append(f)

                i18n_risk = self.t_report("finding_risk")
                i18n_solution = self.t_report("finding_solution")

                html = ""
                for rule_name in rule_order:
                    rule_findings = by_rule[rule_name]
                    first = rule_first_by_name[rule_name]
                    rk = getattr(first, "rule_key", "") or ""
                    # Shared group block (risk + solution + playbook + fix), generated once.
                    shared_html = ""
                    # <details open> cards to align visually with
                    # playbook/fix (consistent UX: all shared blocks
                    # in the group share the same card format with summary).
                    if first.risk:
                        shared_html += (
                            f'<details class="finding-risk-block" open>'
                            f'<summary>⚠️ {i18n_risk}</summary>'
                            f'<p>{self._linkify_acronyms(self._escape(first.risk))}</p>'
                            f'</details>'
                        )
                    if first.solution:
                        shared_html += (
                            f'<details class="finding-solution-block" open>'
                            f'<summary>🛠️ {i18n_solution}</summary>'
                            f'<p>{self._linkify_acronyms(self._escape(first.solution))}</p>'
                            f'</details>'
                        )
                    if rk:
                        playbook_html = self._render_playbook_inline(rk)
                        if playbook_html:
                            shared_html += playbook_html
                        fix_html = self._generate_fix_suggestion(rk)
                        if fix_html:
                            shared_html += fix_html
                    items_html = "".join(render_finding_item(f) for f in rule_findings)
                    group = rule_group_tpl.replace("{{rule_name}}", self._escape(rule_name))
                    group = group.replace("{{count}}", str(len(rule_findings)))
                    group = group.replace("{{content}}", shared_html + items_html)
                    html += group
                return html

            def render_by_category(findings_list):
                """Group findings by category and generate the HTML."""
                if not findings_list:
                    return None
                by_cat = {}
                for f in findings_list:
                    by_cat.setdefault(f.category, []).append(f)
                html = ""
                for cat_key in category_order:
                    if cat_key not in by_cat:
                        continue
                    cat_findings = by_cat[cat_key]
                    cat_i18n_key = cat_i18n_map.get(cat_key, cat_key.lower())
                    cat_icon = self.categories[cat_key].icon if cat_key in self.categories else ""
                    cat_title = self.t_report(f"category_titles.{cat_i18n_key}")
                    cat_html = render_findings(cat_findings)
                    group = cat_group_tpl.replace("{{category_key}}", cat_key)
                    group = group.replace("{{icon}}", cat_icon)
                    group = group.replace("{{title}}", cat_title)
                    group = group.replace("{{count}}", str(len(cat_findings)))
                    group = group.replace("{{content}}", cat_html)
                    html += group
                return html

            # Generate the sub-groups (closed by default)
            if findings:
                sub_groups_html = ""

                # Business code group (with sub-groups by category)
                business_html = render_by_category(business_findings) if business_findings else f'<p class="empty-group">{self.t_report("no_issues_business")}</p>'
                business_group = group_tpl.replace("{{icon}}", "📦").replace("{{title}}", self.t_report("stats.business_code"))
                business_group = business_group.replace("{{count}}", str(len(business_findings)))
                business_group = business_group.replace("{{content}}", business_html)
                sub_groups_html += business_group

                # Dependencies group (with sub-groups by category)
                deps_html = render_by_category(deps_findings) if deps_findings else f'<p class="empty-group">{self.t_report("no_issues_deps")}</p>'
                deps_group = group_tpl.replace("{{icon}}", "🔗").replace("{{title}}", self.t_report("stats.dependencies"))
                deps_group = deps_group.replace("{{count}}", str(len(deps_findings)))
                deps_group = deps_group.replace("{{content}}", deps_html)
                sub_groups_html += deps_group

                findings_html = sub_groups_html
            else:
                findings_html = f'<p class="empty-section">✅ {self.t_report("no_issues_category")}</p>'

            section = section_tpl.replace("{{severity_class}}", severity.lower())
            section = section.replace("{{severity_id}}", f"section-{severity}")
            section = section.replace("{{icon}}", meta['icon'])
            section = section.replace("{{severity}}", meta['title'])
            section = section.replace("{{count}}", str(len(findings)))
            section = section.replace("{{issues_label}}", self.t_report("issues_count_label"))
            section = section.replace("{{content}}", findings_html)
            sections_html += section

        # Successes section by category
        successes_html = ""
        successes_tpl = self._load_template("successes-section.html")
        for cat in self.categories.values():
            if cat.successes:
                items = "".join(
                    f'<div class="success-item">{self._escape(s)}</div>'
                    for s in cat.successes
                )
                cat_i18n_key = cat_i18n_map.get(cat.key, cat.key.lower())
                translated_title = self.t_report(f"category_titles.{cat_i18n_key}")
                section = successes_tpl.replace("{{icon}}", cat.icon)
                section = section.replace("{{category}}", translated_title)
                section = section.replace("{{cat_key}}", cat.key.lower())
                section = section.replace("{{count}}", str(len(cat.successes)))
                section = section.replace("{{i18n_validation_count}}", self.t_report("validation_count"))
                section = section.replace("{{items}}", items)
                successes_html += section

        # Baseline comparison section
        comparison_html = ""
        if self.comparison:
            comp = self.comparison
            finding_mini_tpl = self._load_template("finding-mini.html")

            # New issues (regressions)
            new_items = ""
            for f in sorted(comp.new_findings, key=lambda x: (x.severity != "HIGH", x.severity != "MEDIUM", x.file)):
                item = finding_mini_tpl.replace("{{severity_class}}", f.severity.lower())
                item = item.replace("{{badge_class}}", f.severity.lower())
                item = item.replace("{{badge_text}}", f.severity)
                item = item.replace("{{rule}}", self._escape(f.rule))
                item = item.replace("{{file}}", self._escape(f.file))
                item = item.replace("{{line}}", str(f.line))
                new_items += item

            # Resolved issues
            resolved_items = ""
            for f in sorted(comp.resolved_findings, key=lambda x: (x.severity != "HIGH", x.severity != "MEDIUM", x.file)):
                item = finding_mini_tpl.replace("{{severity_class}}", "resolved")
                item = item.replace("{{badge_class}}", "success")
                item = item.replace("{{badge_text}}", f"✓ {f.severity}")
                item = item.replace("{{rule}}", self._escape(f.rule))
                item = item.replace("{{file}}", self._escape(f.file))
                item = item.replace("{{line}}", str(f.line))
                resolved_items += item

            # Delta calculation
            baseline_high = comp.baseline_totals.get("HIGH", 0)
            baseline_medium = comp.baseline_totals.get("MEDIUM", 0)
            baseline_low = comp.baseline_totals.get("LOW", 0)
            delta_high = total_high - baseline_high
            delta_medium = total_medium - baseline_medium
            delta_low = total_low - baseline_low

            delta_tpl = self._load_template("delta.html")
            def format_delta(d):
                """Format a numeric delta with a colored +/- indicator."""
                if d > 0:
                    return delta_tpl.replace("{{class}}", "negative").replace("{{value}}", f"+{d}")
                elif d < 0:
                    return delta_tpl.replace("{{class}}", "positive").replace("{{value}}", str(d))
                return delta_tpl.replace("{{class}}", "neutral").replace("{{value}}", "±0")

            # "Baseline → Current" totals: all severities (CRITICAL to INFO),
            # to stay consistent with total_findings shown everywhere else
            # in the report (RETEX Reviewer R14/R16/R20 — the numbers didn't
            # match because this total only counted HIGH/MEDIUM/LOW).
            baseline_total = sum(comp.baseline_totals.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
            current_total = total_findings
            total_delta = current_total - baseline_total
            new_count = len(comp.new_findings)
            resolved_count = len(comp.resolved_findings)

            if total_delta < 0 or (total_delta == 0 and resolved_count > new_count):
                trend_class = "improved"
                trend_icon = "📈"
                trend_label = self.t_report("comparison_trend_improved")
            elif total_delta > 0 or (total_delta == 0 and new_count > resolved_count):
                trend_class = "regressed"
                trend_icon = "📉"
                trend_label = self.t_report("comparison_trend_regressed")
            else:
                trend_class = "stable"
                trend_icon = "➖"
                trend_label = self.t_report("comparison_trend_stable")

            trend_detail_parts = []
            if resolved_count > 0:
                trend_detail_parts.append(f"{resolved_count} {self.t_report('comparison_resolved_short')}")
            if new_count > 0:
                trend_detail_parts.append(f"{new_count} {self.t_report('comparison_new_short')}")
            trend_detail = " · ".join(trend_detail_parts) if trend_detail_parts else self.t_report("comparison_no_change")

            comparison_html = self._load_template("comparison-full.html")
            comparison_html = comparison_html.replace("{{i18n_comparison}}", self.t_report("comparison"))
            comparison_html = comparison_html.replace("{{i18n_toc}}", self.t_report("toc"))
            comparison_html = comparison_html.replace("{{i18n_new_issues}}", self.t_report("new_issues"))
            comparison_html = comparison_html.replace("{{i18n_resolved_issues}}", self.t_report("resolved_issues"))
            comparison_html = comparison_html.replace("{{i18n_baseline}}", self.t_report("comparison_baseline"))
            comparison_html = comparison_html.replace("{{i18n_current}}", self.t_report("comparison_current"))
            comparison_html = comparison_html.replace("{{trend_class}}", trend_class)
            comparison_html = comparison_html.replace("{{trend_icon}}", trend_icon)
            comparison_html = comparison_html.replace("{{trend_label}}", trend_label)
            comparison_html = comparison_html.replace("{{trend_detail}}", trend_detail)
            comparison_html = comparison_html.replace("{{baseline_date}}", comp.baseline_date)
            comparison_html = comparison_html.replace("{{baseline_total}}", str(baseline_total))
            comparison_html = comparison_html.replace("{{current_total}}", str(current_total))
            comparison_html = comparison_html.replace("{{baseline_high}}", str(baseline_high))
            comparison_html = comparison_html.replace("{{baseline_medium}}", str(baseline_medium))
            comparison_html = comparison_html.replace("{{baseline_low}}", str(baseline_low))
            comparison_html = comparison_html.replace("{{total_high}}", str(total_high))
            comparison_html = comparison_html.replace("{{total_medium}}", str(total_medium))
            comparison_html = comparison_html.replace("{{total_low}}", str(total_low))
            comparison_html = comparison_html.replace("{{delta_high}}", format_delta(delta_high))
            comparison_html = comparison_html.replace("{{delta_medium}}", format_delta(delta_medium))
            comparison_html = comparison_html.replace("{{delta_low}}", format_delta(delta_low))
            comparison_html = comparison_html.replace("{{new_count}}", str(new_count))
            comparison_html = comparison_html.replace("{{resolved_count}}", str(resolved_count))
            comparison_html = comparison_html.replace("{{new_items}}", new_items if new_items else f'<p class="empty">{self.t_report("no_new_issues")}</p>')
            comparison_html = comparison_html.replace("{{resolved_items}}", resolved_items if resolved_items else f'<p class="empty">{self.t_report("no_resolved_issues")}</p>')

        # Health bar color (thresholds from config)
        if health_score >= self.health_thresholds["good"]:
            health_class = "good"
        elif health_score >= self.health_thresholds["warning"]:
            health_class = "warning"
        else:
            health_class = "danger"

        # Generate the audit parameters summary
        audit_params_html = self._generate_audit_params_summary()

        # Generate the heatmap of problematic files
        heatmap_html = ""
        heatmap_tpl = self._load_template("heatmap-item.html")
        if top_files:
            max_count = top_files[0][1] if top_files else 1
            for rank, (filepath, count, sev_breakdown) in enumerate(top_files, 1):
                heat_pct = (count / max_count) * 100 if max_count > 0 else 0
                # Split file name and directory
                parts = filepath.rsplit("/", 1)
                fname = parts[-1]
                fdir = (parts[0] + "/") if len(parts) > 1 else ""
                if len(fdir) > 40:
                    fdir = "..." + fdir[-37:]
                # Severity chips — only non-zero severities
                chips_html = ""
                for sev, cls in [("CRITICAL", "chip-critical"), ("HIGH", "chip-high"),
                                  ("MEDIUM", "chip-medium"), ("LOW", "chip-low")]:
                    n = sev_breakdown.get(sev, 0)
                    if n > 0:
                        chips_html += f'<span class="hm-chip {cls}">{n} {sev.capitalize()}</span>'
                item = heatmap_tpl.replace("{{heat_pct}}", f"{heat_pct:.0f}")
                item = item.replace("{{rank}}", str(rank))
                item = item.replace("{{filepath}}", self._escape(filepath))
                item = item.replace("{{fname}}", self._escape(fname))
                item = item.replace("{{fdir}}", self._escape(fdir))
                item = item.replace("{{count}}", str(count))
                item = item.replace("{{chips}}", chips_html)
                item = item.replace("{{i18n_severity_score}}", self.t_report("severity_score"))
                heatmap_html += item

        # Generate the textual explanation of the health calculation
        health_explanation_html = self._generate_health_explanation(
            health_score, health_severity_detail, total_penalty
        )

        # Final assembly - use the template
        html = self._load_template("report-base.html")

        # Compute colors for tests and fixtures
        tests_color = ""
        if self.test_results:
            if self.test_results.success_rate == 100:
                tests_color = "color-success"
            elif self.test_results.success_rate < 90:
                tests_color = "color-danger"
            else:
                tests_color = "color-warning"

        fixtures_color = "color-success" if self.fixture_validation and self.fixture_validation.is_valid else "color-danger"

        # i18n replacements
        html = html.replace("{{lang}}", self.report_lang)
        html = html.replace("{{lang_label}}", self.t_report("lang_label"))
        html = html.replace("{{i18n_title}}", f"{self.tool_name} — {self.t_report('title')}")
        html = html.replace("{{i18n_toc}}", self.t_report("toc"))
        html = html.replace("{{i18n_generated_on}}", self.t_report("generated_on"))
        html = html.replace("{{i18n_summary}}", self.t_report("summary"))
        html = html.replace("{{i18n_health_score}}", self.t_report("health_score"))
        html = html.replace("{{i18n_visualization}}", self.t_report("visualization"))
        html = html.replace("{{i18n_findings}}", self.t_report("findings"))
        html = html.replace("{{i18n_validations}}", self.t_report("validations"))
        html = html.replace("{{i18n_validations_intro}}", self.t_report("validations_intro"))
        html = html.replace("{{i18n_comparison}}", self.t_report("comparison"))
        html = html.replace("{{i18n_top_files}}", self.t_report("top_files"))
        html = html.replace("{{i18n_top_files_subtitle}}", self.t_report("top_files_subtitle"))
        html = html.replace("{{i18n_severity_distribution}}", self.t_report("severity_distribution"))
        html = html.replace("{{i18n_severity_distribution_subtitle}}", self.t_report("severity_distribution_subtitle"))
        html = html.replace("{{i18n_by_category}}", self.t_report("by_category"))
        html = html.replace("{{i18n_by_category_subtitle}}", self.t_report("by_category_subtitle"))
        html = html.replace("{{i18n_findings_by_lang_severity}}", self.t_report("chart_labels.findings_by_lang_severity"))
        html = html.replace("{{i18n_code_vs_deps}}", self.t_report("code_vs_deps"))
        html = html.replace("{{i18n_tests}}", self.t_report("tests"))
        html = html.replace("{{i18n_fixtures}}", self.t_report("fixtures"))
        html = html.replace("{{i18n_custom_rules_nav}}", self.t_report("custom_rules_nav"))
        html = html.replace("{{i18n_fixtures_nav}}", self.t_report("fixtures_nav"))
        html = html.replace("{{i18n_database_schema}}", self.t_report("database_schema"))
        html = html.replace("{{i18n_tests_evolution}}", self.t_report("tests_evolution"))
        html = html.replace("{{i18n_findings_evolution}}", self.t_report("findings_evolution"))
        html = html.replace("{{i18n_database_evolution}}", self.t_report("database_evolution"))
        html = html.replace("{{i18n_parameters}}", self.t_report("parameters"))
        html = html.replace("{{i18n_cli_options}}", self.t_report("audit_params.cli_options"))
        html = html.replace("{{i18n_navigation}}", self.t_report("navigation"))
        html = html.replace("{{i18n_print_version}}", self.t_report("print_version"))
        # Severity labels
        html = html.replace("{{i18n_severity_high}}", self.t_report("severity.high"))
        html = html.replace("{{i18n_severity_medium}}", self.t_report("severity.medium"))
        html = html.replace("{{i18n_severity_low}}", self.t_report("severity.low"))
        html = html.replace("{{i18n_severity_info}}", self.t_report("severity.info"))
        # Stats labels
        html = html.replace("{{i18n_business_code}}", self.t_report("stats.business_code"))
        html = html.replace("{{i18n_dependencies}}", self.t_report("stats.dependencies"))
        html = html.replace("{{i18n_tables}}", self.t_report("stats.tables"))
        html = html.replace("{{i18n_columns}}", self.t_report("stats.columns"))
        html = html.replace("{{i18n_indexes}}", self.t_report("stats.indexes"))
        html = html.replace("{{i18n_enums}}", self.t_report("stats.enums"))
        html = html.replace("{{i18n_additions}}", self.t_report("stats.additions"))
        html = html.replace("{{i18n_deletions}}", self.t_report("stats.deletions"))
        html = html.replace("{{i18n_modified}}", self.t_report("stats.modified"))
        html = html.replace("{{i18n_stability}}", self.t_report("stats.stability"))
        # Additional i18n
        html = html.replace("{{i18n_header}}", self.t_report("header"))
        html = html.replace("{{i18n_top_files_nav}}", self.t_report("top_files_nav"))
        html = html.replace("{{i18n_chart_subtitle_findings}}", self.t_report("chart_subtitles.findings_history"))
        html = html.replace("{{i18n_chart_subtitle_tests}}", self.t_report("chart_subtitles.tests_history"))
        html = html.replace("{{i18n_chart_subtitle_database}}", self.t_report("chart_subtitles.database_history"))
        html = html.replace("{{i18n_audit_duration}}", self.t_report("audit_duration"))
        html = html.replace("{{i18n_level_executive}}", self.t_report("level_executive"))
        html = html.replace("{{i18n_level_detail}}", self.t_report("level_detail"))
        html = html.replace("{{audit_total_time}}", str(self.audit_timings.get("total", 0)))
        # LOC and files
        html = html.replace("{{total_lines_code}}", f"{getattr(self, '_total_lines_code', 0):,}".replace(",", " "))
        _tfs = getattr(self, '_total_files_scanned', 0)
        _ufs = len(getattr(self, '_unique_files_scanned', set()))
        self.reporter.detail(f"[debug-report] _total_files_scanned={_tfs}, _unique_files_scanned={_ufs}")
        html = html.replace("{{total_files_scanned}}", f"{_ufs:,}".replace(",", " "))
        html = html.replace("{{i18n_lines_of_code}}", self.t_report("lines_of_code"))
        html = html.replace("{{i18n_files_scanned}}", self.t_report("files_scanned"))
        # Health section
        html = html.replace("{{health_explanation_html}}", health_explanation_html)

        # Replacements
        html = html.replace("{{project_name}}", self.project_name)
        html = html.replace("{{timestamp}}", self.timestamp)
        html = html.replace("{{project_version}}", self.project_version)
        html = html.replace("{{tool_version}}", self.tool_version)
        project_version_display = f"v{self.project_version} " if self.project_version else ""
        html = html.replace("{{project_version_display}}", project_version_display)
        html = html.replace("{{tool_name}}", self.tool_name)
        html = html.replace("{{company_name}}", self.company_name)

        # Demo mode
        _is_demo = getattr(self, "demo_mode", False)
        html = html.replace("{{demo_display}}", "" if _is_demo else "display:none")
        html = html.replace("{{demo_body_class}}", "demo-mode" if _is_demo else "")
        html = html.replace("{{demo_banner_text}}", self.t_report("demo_banner") if _is_demo else "")
        html = html.replace("{{demo_watermark_text}}", self.t_report("demo_watermark") if _is_demo else "")
        html = html.replace("{{demo_footer_text}}", self.t_report("demo_footer") if _is_demo else "")

        # Severity filter banner
        _severity_levels = self.config.get("_cli_options", {}).get("severity_levels")
        if _severity_levels:
            _banner_text = self.t_report("severity_filter_banner").replace("{levels}", ", ".join(_severity_levels))
            html = html.replace("{{severity_filter_banner}}", f'<div class="severity-filter-banner">{_banner_text}</div>')
        else:
            html = html.replace("{{severity_filter_banner}}", "")

        # Project UUID and description
        project_uuid = self.config.get("project", {}).get("id", "")
        project_description = self.config.get("project", {}).get("description", "")
        if project_uuid:
            project_uuid_short = project_uuid[:8]
            uuid_badge = f'<span class="uuid-badge">[{project_uuid_short}]</span> '
        else:
            uuid_badge = ""
        html = html.replace("{{project_uuid_badge}}", uuid_badge)

        if project_description:
            desc_html = f'<div class="project-description">{self._escape(project_description)}</div>'
        else:
            desc_html = ""
        html = html.replace("{{project_description_html}}", desc_html)

        html = html.replace("{{date_str}}", date_str)
        html = html.replace("{{css}}", css)
        html = html.replace("{{audit_params_html}}", audit_params_html)
        html = html.replace("{{total_high}}", str(total_high))
        html = html.replace("{{total_medium}}", str(total_medium))
        html = html.replace("{{total_low}}", str(total_low))

        # Executive summary i18n
        html = html.replace("{{i18n_exec_trend}}", self.t_report("exec_trend") or "Tendance")
        html = html.replace("{{i18n_exec_recommendations}}", self.t_report("exec_recommendations") or "Recommandations prioritaires")

        # Trend (baseline comparison)
        exec_trend_html = self._build_exec_trend(total_high, total_medium, total_low)
        html = html.replace("{{exec_trend_html}}", exec_trend_html)

        # Priority recommendations (business language)
        exec_recs_html = self._build_exec_recommendations(total_high, total_medium, total_low, total_findings, health_score)
        html = html.replace("{{exec_recommendations_html}}", exec_recs_html)

        # Security context (ZeroDayClock)
        threat_html = self._build_threat_context(total_high, total_medium)
        html = html.replace("{{threat_context_html}}", threat_html)
        html = html.replace("{{total_findings}}", str(total_findings))
        html = html.replace("{{total_successes}}", str(total_successes))
        html = html.replace("{{total_business}}", str(total_business))
        html = html.replace("{{total_deps}}", str(total_deps))
        html = html.replace("{{tests_color}}", tests_color)
        html = html.replace("{{tests_rate}}", str(self.test_results.success_rate if self.test_results else 0))
        html = html.replace("{{tests_total}}", str(self.test_results.total if self.test_results else 0))
        html = html.replace("{{fixtures_color}}", fixtures_color)
        html = html.replace("{{fixtures_rate}}", str(self.fixture_validation.success_rate if self.fixture_validation else 0))
        html = html.replace("{{fixtures_total}}", str(self.fixture_validation.total if self.fixture_validation else 0))

        # DATABASE replacements
        db_stats = self.database_stats or {}
        db_changes = db_stats.get("changes", {"added": {}, "dropped": {}, "modified": {}})
        db_added = sum([
            db_changes.get("added", {}).get("tables", 0),
            db_changes.get("added", {}).get("columns", 0),
            db_changes.get("added", {}).get("indexes", 0)
        ])
        db_dropped = sum([
            db_changes.get("dropped", {}).get("tables", 0),
            db_changes.get("dropped", {}).get("columns", 0),
            db_changes.get("dropped", {}).get("indexes", 0)
        ])
        db_modified = db_changes.get("modified", {}).get("columns", 0)
        db_total_changes = db_added + db_dropped + db_modified
        db_total_elements = db_stats.get("tables_count", 0) + db_stats.get("columns_count", 0) + db_stats.get("indexes_count", 0)
        db_stability = 100 if db_total_elements == 0 else max(0, round(100 - (db_total_changes / max(1, db_total_elements) * 100)))
        db_stability_color = "success" if db_stability >= 90 else "medium" if db_stability >= 70 else "high"
        # Database section: visible ONLY in dev/script mode.
        # In the binary: the `<!--DEV_ONLY_DB-->...<!--/DEV_ONLY_DB-->` blocks are
        # removed from the final HTML (cf. wrap_branded post-processing below).
        database_display = "" if self.database_schema else "display:none"

        # Dependencies section
        dep_stats = self.dependency_stats or {}
        dependencies_display = "" if dep_stats.get("total_scanned", 0) > 0 else "display:none"
        html = html.replace("{{dependencies_display}}", dependencies_display)
        html = html.replace("{{deps_total_scanned}}", str(dep_stats.get("total_scanned", 0)))
        html = html.replace("{{deps_vulnerable}}", str(dep_stats.get("vulnerable", 0)))
        html = html.replace("{{deps_unpinned}}", str(dep_stats.get("unpinned", 0)))
        html = html.replace("{{deps_ok}}", str(dep_stats.get("ok", 0)))
        html = html.replace("{{i18n_dependencies_title}}", self.t_report("category_titles.dependencies"))
        html = html.replace("{{i18n_deps_scanned}}", self.t_report("deps_scanned"))
        html = html.replace("{{i18n_deps_vulnerable}}", self.t_report("deps_vulnerable"))
        html = html.replace("{{i18n_deps_unpinned}}", self.t_report("deps_unpinned"))
        html = html.replace("{{i18n_deps_ok}}", self.t_report("deps_ok"))

        # Dependency warnings
        dep_warnings = dep_stats.get("warnings", [])
        if dep_warnings:
            warnings_title = self.t_report("deps_warnings_title")
            items_html = ""
            for w in dep_warnings:
                tool = self._escape(w.get("tool", ""))
                msg = self._escape(w.get("message", ""))
                wtype = w.get("type", "")
                wfile = w.get("file", "")
                file_info = f" — <code>{self._escape(wfile)}</code>" if wfile else ""
                # Determine explanation and solution based on type
                if wtype == "tool_missing":
                    explanation = ""
                    fix = self.t_report("deps_warn_tool_missing_fix")
                elif wtype == "scan_error" and "Timeout" in w.get("message", ""):
                    explanation = self.t_report("deps_warn_timeout")
                    fix = self.t_report("deps_warn_timeout_fix")
                elif wtype == "scan_error" and "No matching distribution" in w.get("message", ""):
                    explanation = self.t_report("deps_warn_no_distribution")
                    fix = self.t_report("deps_warn_no_distribution_fix")
                else:
                    explanation = ""
                    fix = self.t_report("deps_warn_generic_fix")
                # Build the HTML for each warning
                detail_parts = []
                if explanation:
                    detail_parts.append(f'<br><em>{self._linkify_acronyms(self._escape(explanation))}</em>')
                if fix:
                    detail_parts.append(f'<br><strong style="color:#2d7d46;">&#x2192; {self._linkify_acronyms(self._escape(fix))}</strong>')
                detail_html = "".join(detail_parts)
                items_html += (
                    f'<li style="margin-bottom:0.6rem;">'
                    f'<strong>{tool}</strong>{file_info} : {msg}'
                    f'{detail_html}</li>\n'
                )
            deps_warnings_html = (
                f'<div class="callout callout-warning" style="margin-top:1rem;">'
                f'<span class="callout-icon">⚠️</span>'
                f'<div><strong>{warnings_title}</strong>'
                f'<ul style="margin:0.5rem 0 0 0;padding-left:1.2rem;">{items_html}</ul>'
                f'</div></div>'
            )
        else:
            deps_warnings_html = ""
        html = html.replace("{{deps_warnings_html}}", deps_warnings_html)

        # Dependency findings (detailed list in the section)
        deps_findings_list = self.categories["DEPENDENCIES"].findings if "DEPENDENCIES" in self.categories else []
        if deps_findings_list:
            items_html = ""
            for f in deps_findings_list:
                severity_color = "#e74c3c" if f.severity == "HIGH" else "#f39c12" if f.severity == "MEDIUM" else "#3498db"
                severity_icon = "🔴" if f.severity == "HIGH" else "🟠" if f.severity == "MEDIUM" else "🔵"
                items_html += (
                    f'<li style="margin-bottom:0.8rem;">'
                    f'{severity_icon} <strong>{self._escape(f.rule)}</strong>'
                    f' — <code>{self._escape(f.file)}:{f.line}</code>'
                    f'<br><code style="background:#f3f4f6;padding:2px 6px;border-radius:3px;">{self._escape(f.code)}</code>'
                    f'<br><em style="color:#4b5563;">{self._linkify_acronyms(self._escape(f.risk))}</em>'
                    f'<br><strong style="color:#2d7d46;">&#x2192; {self._linkify_acronyms(self._escape(f.solution))}</strong>'
                    f'</li>'
                )
            deps_findings_title = self.t_report("deps_findings_title")
            deps_findings_html = (
                f'<div class="callout callout-error" style="margin-top:1rem;border-left:4px solid #e74c3c;'
                f'background:#fef2f2;border-radius:8px;padding:1rem;">'
                f'<span class="callout-icon" style="font-size:1.2rem;">❌</span> '
                f'<strong>{deps_findings_title}</strong>'
                f'<ul style="margin:0.5rem 0 0 0;padding-left:1.2rem;">{items_html}</ul>'
                f'</div>'
            )
        else:
            deps_findings_html = ""
        html = html.replace("{{deps_findings_html}}", deps_findings_html)

        html = html.replace("{{database_display}}", database_display)

        # Taint section (charts) — reuses data already computed in chart_data
        taint_findings = [f for cat in self.categories.values() for f in cat.findings if getattr(f, "taint_flow", None)]
        taint_display = "" if taint_findings else "display:none"
        html = html.replace("{{taint_display}}", taint_display)

        # Tests/fixtures charts — hidden if --with-tests is not used
        cli_opts = self.config.get("_cli_options", {})
        with_tests = cli_opts.get("with_tests", False)
        tests_chart_display = "" if with_tests else "display:none"
        html = html.replace("{{tests_chart_display}}", tests_chart_display)
        html = html.replace("{{i18n_taint_trace_summary}}", self.t_report("taint_trace_summary"))
        html = html.replace("{{db_tables}}", str(db_stats.get("tables_count", 0)))
        html = html.replace("{{db_columns}}", str(db_stats.get("columns_count", 0)))
        html = html.replace("{{db_indexes}}", str(db_stats.get("indexes_count", 0)))
        html = html.replace("{{db_enums}}", str(db_stats.get("enums_count", 0)))
        html = html.replace("{{db_added}}", str(db_added))
        html = html.replace("{{db_dropped}}", str(db_dropped))
        html = html.replace("{{db_modified}}", str(db_modified))
        html = html.replace("{{db_stability}}", str(db_stability))
        html = html.replace("{{db_stability_color}}", db_stability_color)

        # CI/CD section
        cicd_stats = self.cicd_stats or {}
        cicd_display = "" if cicd_stats.get("files_scanned", 0) > 0 else "display:none"
        html = html.replace("{{cicd_display}}", cicd_display)
        html = html.replace("{{cicd_files_scanned}}", str(cicd_stats.get("files_scanned", 0)))
        html = html.replace("{{cicd_findings}}", str(cicd_stats.get("findings", 0)))
        html = html.replace("{{i18n_cicd_title}}", self.t_report("category_titles.cicd"))
        html = html.replace("{{i18n_cicd_files_scanned}}", self.t_report("cicd_files_scanned"))
        html = html.replace("{{i18n_cicd_findings}}", self.t_report("cicd_findings_label"))

        html = html.replace("{{health_score}}", str(health_score))
        html = html.replace("{{health_class}}", health_class)
        # Reading legend for the score bars (health + compliance) — same
        # thresholds as health_class above, for a consistent color scale
        # between the 2 bars and the 2 gauges (RETEX Reviewer R01/R02/R03)
        score_legend = (self.t_report("score_legend") or "").format(
            good=self.health_thresholds["good"],
            warning=self.health_thresholds["warning"],
        )
        html = html.replace("{{score_legend}}", score_legend)
        html = html.replace("{{heatmap_html}}", heatmap_html if heatmap_html else f'<p class="empty">{self.t_report("no_problematic_files")}</p>')
        custom_rules_html = self._generate_custom_rules_section()
        html = html.replace("{{custom_rules_html}}", custom_rules_html)
        html = html.replace("{{category_examples_html}}", self._generate_category_examples_html())
        html = html.replace("{{tests_html}}", tests_html)
        html = html.replace("{{fixtures_html}}", fixtures_html)
        html = html.replace("{{fixtures_display}}", "" if fixtures_html else "display:none")
        html = html.replace("{{sections_html}}", sections_html)
        html = html.replace("{{comparison_html}}", comparison_html)
        html = html.replace("{{comparison_display}}", "" if comparison_html else "display:none")
        html = html.replace("{{successes_html}}", successes_html if successes_html else f'<p class="empty">{self.t_report("no_problems")}</p>')

        # SLA by severity (optional — enabled via sla config or by default)
        sla_config = self.config.get("sla", {})
        sla_enabled = sla_config.get("enabled", False)
        if sla_enabled:
            sla_defaults = {
                "CRITICAL": {"delay": "24h", "escalation": "CISO / CTO"},
                "HIGH": {"delay": "48h", "escalation": "CTO / Security Lead"},
                "MEDIUM": {"delay": "2 weeks", "escalation": "Tech Lead"},
                "LOW": {"delay": "3 months", "escalation": "Quarterly review"},
            }
            sla_rules = sla_config.get("rules", sla_defaults)
            sla_t = self.i18n_report.get("sla", {})
            sla_col_severity = sla_t.get("col_severity", "Severity")
            sla_col_delay = sla_t.get("col_delay", "Max delay")
            sla_col_escalation = sla_t.get("col_escalation", "Escalation")
            sla_rows = []
            severity_classes = {"CRITICAL": "severity-critical", "HIGH": "severity-high", "MEDIUM": "severity-medium", "LOW": "severity-low"}
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev in sla_rules:
                    rule = sla_rules[sev]
                    cls = severity_classes.get(sev, "")
                    count = len(by_severity.get(sev, []))
                    count_badge = f' <span class="badge badge-count">{count}</span>' if count > 0 else ""
                    sla_rows.append(
                        f'<tr><td class="{cls}">{sev}{count_badge}</td>'
                        f'<td>{rule.get("delay", "")}</td>'
                        f'<td>{rule.get("escalation", "")}</td></tr>'
                    )
            sla_html = (
                f'<p>{sla_t.get("description", "")}</p>'
                f'<table class="sla-table"><thead><tr>'
                f'<th>{sla_col_severity}</th><th>{sla_col_delay}</th><th>{sla_col_escalation}</th>'
                f'</tr></thead><tbody>{"".join(sla_rows)}</tbody></table>'
            )
            html = html.replace("{{sla_display}}", "")
        else:
            sla_html = ""
            html = html.replace("{{sla_display}}", "display:none")
        html = html.replace("{{sla_html}}", sla_html)
        html = html.replace("{{i18n_sla_title}}", self.i18n_report.get("sla", {}).get("title", "SLA"))

        # Git Blame section (conditional)
        git_blame_title = self.t_report("git_blame_section_title")
        html = html.replace("{{i18n_git_blame_title}}", git_blame_title)

        # Collect committers
        committer_counts = {}  # committer → {"HIGH": n, "MEDIUM": n, ...}
        has_blame = False
        for cat in self.categories.values():
            for f in cat.findings:
                if f.committer:
                    has_blame = True
                    if f.committer not in committer_counts:
                        committer_counts[f.committer] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
                    if f.severity in committer_counts[f.committer]:
                        committer_counts[f.committer][f.severity] += 1

        if has_blame and committer_counts:
            # Generate the authors table
            blame_i18n = self.i18n_report.get("git_blame", {})
            col_author = blame_i18n.get("col_author", "Author")
            col_total = blame_i18n.get("col_total", "Total")
            rows = ""
            for author in sorted(committer_counts, key=lambda a: sum(committer_counts[a].values()), reverse=True):
                counts = committer_counts[author]
                total = sum(counts.values())
                rows += f'<tr><td>{self._escape(author)}</td>'
                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                    c = counts[sev]
                    rows += f'<td class="{"sev-highlight" if c > 0 else ""}">{c}</td>'
                rows += f'<td><strong>{total}</strong></td></tr>'

            git_blame_html = (
                f'<table class="findings-table"><thead><tr>'
                f'<th>{col_author}</th>'
                f'<th>CRITICAL</th><th>HIGH</th><th>MEDIUM</th><th>LOW</th><th>INFO</th>'
                f'<th>{col_total}</th>'
                f'</tr></thead><tbody>{rows}</tbody></table>'
            )
            html = html.replace("{{git_blame_display}}", "")
        else:
            git_blame_html = ""
            html = html.replace("{{git_blame_display}}", "display:none")
        html = html.replace("{{git_blame_html}}", git_blame_html)

        # ISO 27001 compliance section (conditional — data already computed for chart_data)
        compliance_title = self.i18n_report.get("compliance", {}).get("title", "ISO 27001 Compliance Matrix")
        html = html.replace("{{i18n_compliance_title}}", compliance_title)

        # Helpers for physically gating the compliance sections
        import re as _re

        def _keep_block(html_str: str, prefix: str) -> str:
            """Keep the content: just strip the START/END markers."""
            return (html_str
                    .replace("{{" + prefix + "_TOC_START}}", "")
                    .replace("{{" + prefix + "_TOC_END}}", "")
                    .replace("{{" + prefix + "_NAV_START}}", "")
                    .replace("{{" + prefix + "_NAV_END}}", "")
                    .replace("{{" + prefix + "_SECTION_START}}", "")
                    .replace("{{" + prefix + "_SECTION_END}}", ""))

        def _remove_block(html_str: str, prefix: str) -> str:
            """Physically remove the START..END blocks (TOC, nav, section)."""
            for kind in ("TOC", "NAV", "SECTION"):
                pattern = _re.compile(
                    r"\{\{" + prefix + "_" + kind + r"_START\}\}.*?\{\{"
                    + prefix + "_" + kind + r"_END\}\}\s*",
                    _re.DOTALL,
                )
                html_str = pattern.sub("", html_str)
            return html_str

        # Compliance Score gauge + bar chart (Option A + B2)
        # Displayed only if at least one compliance matrix is computed
        compliance_score_data = getattr(self, "_compliance_score_data", {"enabled": False})
        if compliance_score_data.get("enabled"):
            compliance_score_pct = compliance_score_data.get("score", 0)
            html = html.replace("{{compliance_score}}", str(compliance_score_pct))
            if compliance_score_pct >= self.health_thresholds["good"]:
                compliance_class = "good"
            elif compliance_score_pct >= self.health_thresholds["warning"]:
                compliance_class = "warning"
            else:
                compliance_class = "danger"
            html = html.replace("{{compliance_class}}", compliance_class)
            html = html.replace(
                "{{i18n_compliance_score}}",
                self.t_report("compliance_score") or "Compliance Score",
            )
            for marker in ("COMPLIANCE_SCORE_BAR_START", "COMPLIANCE_SCORE_BAR_END",
                           "COMPLIANCE_SCORE_GAUGE_START", "COMPLIANCE_SCORE_GAUGE_END"):
                html = html.replace("{{" + marker + "}}", "")
        else:
            for prefix in ("COMPLIANCE_SCORE_BAR", "COMPLIANCE_SCORE_GAUGE"):
                pattern = _re.compile(
                    r"\{\{" + prefix + r"_START\}\}.*?\{\{" + prefix + r"_END\}\}\s*",
                    _re.DOTALL,
                )
                html = pattern.sub("", html)

        # Section ISO 27001
        if self._compliance_data:
            compliance_html = self._generate_compliance_html(self._compliance_data)
            html = html.replace("{{compliance_html}}", compliance_html)
            html = html.replace("{{compliance_covered}}", str(self._compliance_data.get("covered_controls", 0)))
            html = html.replace("{{compliance_total}}", str(self._compliance_data.get("total_controls", 0)))
            html = _keep_block(html, "COMPLIANCE")
        else:
            html = _remove_block(html, "COMPLIANCE")

        # Section ASVS v5.0.0
        asvs_title = self.i18n_report.get("asvs", {}).get("title", "OWASP ASVS v5.0.0 Compliance")
        html = html.replace("{{i18n_asvs_title}}", asvs_title)

        if self._asvs_data:
            asvs_html = self._generate_asvs_html(self._asvs_data)
            html = html.replace("{{asvs_html}}", asvs_html)
            html = html.replace("{{asvs_covered}}", str(self._asvs_data.get("covered_requirements", 0)))
            html = html.replace("{{asvs_total}}", str(self._asvs_data.get("total_requirements", 0)))
            html = _keep_block(html, "ASVS")
        else:
            html = _remove_block(html, "ASVS")

        # Section NIST CSF 2.0
        nist_title = self.i18n_report.get("nist", {}).get("title", "NIST CSF 2.0 Compliance")
        html = html.replace("{{i18n_nist_title}}", nist_title)

        if self._nist_data:
            nist_html = self._generate_nist_csf_html(self._nist_data)
            html = html.replace("{{nist_html}}", nist_html)
            html = html.replace("{{nist_covered}}", str(self._nist_data.get("covered_subcategories", 0)))
            html = html.replace("{{nist_total}}", str(self._nist_data.get("total_subcategories", 0)))
            html = _keep_block(html, "NIST")
        else:
            html = _remove_block(html, "NIST")

        # Localized glossary
        glossary_data = self.i18n_report.get("glossary", {})
        glossary_acronyms = glossary_data.get("acronyms", {})
        if glossary_acronyms:
            col_acr = glossary_data.get("col_acronym", "Acronym")
            col_mean = glossary_data.get("col_meaning", "Meaning")
            col_desc = glossary_data.get("col_description", "Description")
            rows = []
            for key in sorted(glossary_acronyms.keys()):
                acr = glossary_acronyms[key]
                rows.append(
                    f'<tr id="acr-{key}">'
                    f'<td class="glossary-term"><strong>{acr["term"]}</strong></td>'
                    f'<td class="glossary-full">{acr["full"]}</td>'
                    f'<td class="glossary-desc">{acr["desc"]}</td>'
                    f'</tr>'
                )
            glossary_html = (
                f'<!-- GLOSSARY_NO_LINKIFY -->'
                f'<table class="glossary-table"><thead><tr>'
                f'<th>{col_acr}</th><th>{col_mean}</th><th>{col_desc}</th>'
                f'</tr></thead><tbody>{"".join(rows)}</tbody></table>'
                f'<!-- /GLOSSARY_NO_LINKIFY -->'
            )
        else:
            glossary_html = ""
        html = html.replace("{{glossary_html}}", glossary_html)
        html = html.replace("{{i18n_glossary_title}}", glossary_data.get("title", "Glossary"))
        html = html.replace("{{i18n_glossary_subtitle}}", glossary_data.get("subtitle", ""))

        # Finding suppression — panel buttons
        html = html.replace("{{i18n_suppress_download}}", self.t_report("suppress_download"))
        html = html.replace("{{i18n_suppress_copy}}", self.t_report("suppress_copy"))
        html = html.replace("{{i18n_suppress_clear}}", self.t_report("suppress_clear"))

        html = html.replace("{{chartjs_lib}}", chartjs_lib)
        html = html.replace("{{js}}", js)
        html = html.replace("{{charts_js}}", charts_js)
        html = html.replace("{{favicon_data}}", favicon_data)
        html = html.replace("{{favicon_header_data}}", favicon_header_data)
        html = html.replace("{{favicon_type}}", favicon_type)

        # CSS override injection for custom brand colors
        brand = self.config.get("brand", {})
        brand_css_vars = ""
        primary = brand.get("primary_color")
        accent = brand.get("accent_color")
        if primary and primary != "#1e3a5f":
            brand_css_vars += f"--primary: {primary}; "
        if accent and accent != "#2c5282":
            brand_css_vars += f"--primary-light: {accent}; "
        if brand_css_vars:
            html = html.replace("</head>", f"<style>:root {{ {brand_css_vars}}}</style>\n</head>")

        # In the binary: fully removes the `<!--DEV_ONLY_DB-->...<!--/DEV_ONLY_DB-->` blocks
        # so that the "DB schema" feature stays invisible (CSS + DOM + i18n) on the client side.
        from sca.cli import _check_is_binary
        if _check_is_binary():
            import re as _re
            html = _re.sub(r"<!--DEV_ONLY_DB-->.*?<!--/DEV_ONLY_DB-->", "",
                           html, flags=_re.DOTALL)

        return html

    def _generate_health_explanation(self, health_score: int, severity_detail: dict, total_penalty: int) -> str:
        """Generate the textual explanation of the health score calculation."""
        method_label = self.t_report("health_method")
        # Explicit title indicating which dashboard metric this
        # text refers to — without it, there's no way to tell whether it relates
        # to the score gauge or the penalty chart (RETEX Reviewer R07)
        heading = (self.t_report("health_explanation_heading") or "How is the {label} calculated?").format(
            label=self.t_report("health_score")
        )
        return f'<div class="health-explanation"><h4 class="health-explanation-title">ℹ️ {heading}</h4><p class="health-method">{method_label}</p></div>'

    def _generate_audit_params_summary(self) -> str:
        """Generate the HTML summarizing the audit parameters."""
        # Load the template
        template_path = os.path.join(str(SCRIPT_DIR), "templates", "audit-params.html")
        with open(template_path, "r", encoding="utf-8") as f:
            template = f.read()

        # Prepare the values
        languages_list = ", ".join(f"<code>{l}</code>" for l in sorted(self._languages)) if self._languages else f"<em>{self.t_report('none')}</em>"

        # Extensions scanned per language
        ext_map = {}
        if "python" in self._languages:
            ext_map["python"] = self._py_exts
        if "javascript" in self._languages:
            ext_map["javascript"] = self._js_exts
        if "html" in self._languages:
            ext_map["html"] = self._html_exts
        if ext_map:
            ext_parts = []
            for lang, exts in ext_map.items():
                ext_parts.append(f"<code>{lang}</code>: {', '.join(f'<code>{e}</code>' for e in exts)}")
            extensions_list = "<br>".join(ext_parts)
        else:
            extensions_list = f"<em>{self.t_report('none')}</em>"

        # Paths include — full list
        include_list = " ".join(f"<code>{p}</code>" for p in self.include_paths) or f"<em>{self.t_report('all')}</em>"

        # Paths exclude — full list (no truncation)
        exclude_list = " ".join(f"<code>{p}</code>" for p in self.exclude_patterns)
        if not exclude_list:
            exclude_list = f"<em>{self.t_report('none')}</em>"

        mode_label = self.t_report("mode_quick") if self.quick_mode else self.t_report("mode_full")
        disabled_list = ", ".join(f"<code>{r}</code>" for r in sorted(self.disabled_rules)) if self.disabled_rules else f"<em>{self.t_report('none')}</em>"
        only_cat = f"<code>{self.only_category}</code>" if self.only_category else f"<em>{self.t_report('all')}</em>"

        cat_labels = {
            "SECURITY": self.t_report("categories.security"),
            "ARCH": self.t_report("categories.architecture"),
            "UI": self.t_report("categories.ui"),
            "UX": self.t_report("categories.ux"),
            "MAINTENANCE": self.t_report("categories.maintenance")
        }
        categories_html = ""
        cat_badge_tpl = self._load_template("category-badge.html")
        for cat_key, cat_label in cat_labels.items():
            enabled = self.enabled_categories.get(cat_key, True)
            weight = self.category_weights.get(cat_key, 1)
            status = "✓" if enabled else "✗"
            status_class = "enabled" if enabled else "disabled"
            badge = cat_badge_tpl.replace("{{class}}", status_class)
            badge = badge.replace("{{status}}", status)
            badge = badge.replace("{{label}}", cat_label)
            badge = badge.replace("{{weight}}", str(weight))
            categories_html += badge + " "

        # Prepare project values
        project_conf = self.config.get("project", {})
        project_name = project_conf.get("name", "") or ""
        project_version = f"<code>v{project_conf.get('version')}</code>" if project_conf.get("version") else ""
        project_description = project_conf.get("description", "") or f"<em>{self.t_report('none')}</em>"
        project_id = project_conf.get("id", "") or f"<em>{self.t_report('none')}</em>"
        project_path = self.root_dir or ""

        # Generate the CLI options checklist
        cli_opts = self.config.get("_cli_options", {})
        cli_option_tpl = self._load_template("cli-option-item.html")
        cli_options_def = [
            ("--quick", self.quick_mode, "cli_options_desc.quick"),
            ("--fail-on-high", cli_opts.get("fail_on_high", False), "cli_options_desc.fail_on_high"),
            ("--sarif", cli_opts.get("sarif", False), "cli_options_desc.sarif"),
            ("--sbom", cli_opts.get("sbom", False), "cli_options_desc.sbom"),
            ("--lang", True, "cli_options_desc.report_lang"),
            ("--debug", cli_opts.get("debug") is not None, "cli_options_desc.debug"),
            ("--with-tests", cli_opts.get("with_tests", False), "cli_options_desc.with_tests"),
            ("--with-deps", cli_opts.get("with_deps", False), "cli_options_desc.with_deps"),
            ("--severity", bool(cli_opts.get("severity_levels")), "cli_options_desc.severity"),
        ]
        cli_options_html = ""
        for flag, active, desc_key in cli_options_def:
            item = cli_option_tpl.replace("{{option_class}}", "active" if active else "inactive")
            item = item.replace("{{option_check}}", "✅" if active else "⬜")
            # Add the value for options with an argument
            flag_display = flag
            if flag == "--only-category" and self.only_category:
                flag_display = f"{flag} {self.only_category}"
            elif flag == "--disable-rule" and self.disabled_rules:
                flag_display = f"{flag} ({len(self.disabled_rules)})"
            elif flag == "--script-lang":
                flag_display = f"{flag} {self.script_lang}"
            elif flag == "--report-lang":
                report_lang = self.config.get("reports", {}).get("language", "en")
                flag_display = f"{flag} {report_lang}"
            elif flag == "--severity" and cli_opts.get("severity_levels"):
                flag_display = f"{flag} {','.join(cli_opts['severity_levels'])}"
            elif flag == "--debug" and cli_opts.get("debug"):
                flag_display = f"{flag}={cli_opts['debug']}"
            elif flag == "--debug-format" and cli_opts.get("debug_format"):
                flag_display = f"{flag}={cli_opts['debug_format']}"
            elif flag == "--output":
                flag_display = f"{flag} {self.reports_dir}"
            item = item.replace("{{option_flag}}", flag_display)
            desc = self.t_report(desc_key)
            if flag == "--severity" and cli_opts.get("severity_levels"):
                desc = desc.replace("{levels}", ", ".join(cli_opts["severity_levels"]))
            item = item.replace("{{option_desc}}", desc)
            cli_options_html += item

        # Replace the placeholders
        return (template
                .replace("{{i18n_parameters}}", self.t_report("parameters"))
                .replace("{{i18n_project_info}}", self.t_report("audit_params.project_info"))
                .replace("{{i18n_project_name}}", self.t_report("audit_params.project_name"))
                .replace("{{i18n_project_description}}", self.t_report("audit_params.project_description"))
                .replace("{{i18n_project_id}}", self.t_report("audit_params.project_id"))
                .replace("{{i18n_project_path}}", self.t_report("audit_params.project_path"))
                .replace("{{project_name}}", project_name)
                .replace("{{project_version}}", project_version)
                .replace("{{project_description}}", project_description)
                .replace("{{project_id}}", project_id)
                .replace("{{project_path}}", project_path)
                .replace("{{i18n_audit_scope}}", self.t_report("audit_scope"))
                .replace("{{i18n_languages}}", self.t_report("audit_params.languages"))
                .replace("{{languages}}", languages_list)
                .replace("{{i18n_scanned_extensions}}", self.t_report("audit_params.scanned_extensions"))
                .replace("{{scanned_extensions}}", extensions_list)
                .replace("{{i18n_analyzed_dirs}}", self.t_report("audit_params.analyzed_dirs"))
                .replace("{{i18n_excluded_patterns}}", self.t_report("audit_params.excluded_patterns"))
                .replace("{{i18n_mode}}", self.t_report("audit_params.mode"))
                .replace("{{i18n_filtered_category}}", self.t_report("audit_params.filtered_category"))
                .replace("{{i18n_disabled_rules}}", self.t_report("audit_params.disabled_rules"))
                .replace("{{i18n_categories}}", self.t_report("audit_params.categories"))
                .replace("{{i18n_cli_options}}", self.t_report("audit_params.cli_options"))
                .replace("{{include_paths}}", include_list)
                .replace("{{exclude_patterns}}", exclude_list)
                .replace("{{mode}}", mode_label)
                .replace("{{only_category}}", only_cat)
                .replace("{{disabled_rules}}", disabled_list)
                .replace("{{categories}}", categories_html)
                .replace("{{cli_options_html}}", cli_options_html))

    def _generate_fixtures_list(self) -> str:
        """Generate the detailed table of tested fixtures."""
        if not self.fixture_validation or not self.fixture_validation.details:
            return ""

        # Load the template
        template_path = os.path.join(str(SCRIPT_DIR), "templates", "fixtures-list.html")
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template = f.read()
        except FileNotFoundError:
            return ""

        # Generate the table rows
        rows_html = ""
        type_span_tpl = self._load_template("fixture-type-span.html")
        status_span_tpl = self._load_template("fixture-status-span.html")
        for detail in sorted(self.fixture_validation.details, key=lambda d: (d.get("type", ""), d.get("fixture", ""))):
            fixture_name = self._escape(detail.get("fixture", ""))
            fixture_type = detail.get("type", "")
            rule_key = detail.get("rule_key", "")
            expected_rule = self._escape(self._rule(rule_key).get("name", rule_key)) if rule_key else ""
            success = detail.get("success", False)

            # Type (Vulnerable / Clean)
            if fixture_type == "vulnerable":
                type_html = type_span_tpl.replace("{{class}}", "vulnerable").replace("{{label}}", self.t_report("fixtures_type_vulnerable"))
                status_ok = f"✓ {self.t_report('fixtures_status_detected')}"
                status_fail = f"✗ {self.t_report('fixtures_status_missed')}"
            else:
                type_html = type_span_tpl.replace("{{class}}", "clean").replace("{{label}}", self.t_report("fixtures_type_clean"))
                status_ok = f"✓ {self.t_report('fixtures_status_ok')}"
                status_fail = f"✗ {self.t_report('fixtures_status_false_positive')}"

            # Status
            if success:
                status_html = status_span_tpl.replace("{{class}}", "ok").replace("{{label}}", status_ok)
            else:
                status_html = status_span_tpl.replace("{{class}}", "fail").replace("{{label}}", status_fail)

            rows_html += f"""
                <tr>
                    <td><code>{fixture_name}</code></td>
                    <td>{type_html}</td>
                    <td>{expected_rule}</td>
                    <td>{status_html}</td>
                </tr>"""

        # Replace the placeholders
        detail_title = self.t_report("fixtures_detail_title").replace("{{total}}", str(self.fixture_validation.total))
        return (template
                .replace("{{i18n_detail_title}}", detail_title)
                .replace("{{i18n_fixture}}", self.t_report("fixtures_table_fixture"))
                .replace("{{i18n_type}}", self.t_report("fixtures_table_type"))
                .replace("{{i18n_expected_rule}}", self.t_report("fixtures_table_expected_rule"))
                .replace("{{i18n_status}}", self.t_report("fixtures_table_status"))
                .replace("{{rows}}", rows_html))

    def _build_exec_trend(self, total_high, total_medium, total_low):
        """Build the trend HTML for the executive summary."""
        if not self.comparison:
            return f'<div class="exec-trend-item"><span class="exec-trend-icon">📋</span> {self.t_report("exec_first_audit") or "Premier audit — baseline créée"}</div>'

        new = len(self.comparison.new_findings)
        resolved = len(self.comparison.resolved_findings)
        persistent = len(self.comparison.unchanged_findings)

        new_icon = "🔴" if new > 0 else "⚪"
        resolved_icon = "🟢" if resolved > 0 else "⚪"

        html = f'<div class="exec-trend-item"><span class="exec-trend-icon">{new_icon}</span><span class="exec-trend-value">{new}</span> {self.t_report("exec_new_issues") or "nouveaux problèmes"}</div>'
        html += f'<div class="exec-trend-item"><span class="exec-trend-icon">{resolved_icon}</span><span class="exec-trend-value">{resolved}</span> {self.t_report("exec_resolved") or "résolus"}</div>'
        html += f'<div class="exec-trend-item"><span class="exec-trend-icon">⚪</span><span class="exec-trend-value">{persistent}</span> {self.t_report("exec_persistent") or "persistants"}</div>'
        return html

    def _build_threat_context(self, total_high: int, total_medium: int) -> str:
        """Generate the threat-context block (ZeroDayClock) for the executive summary.

        These figures are general industry statistics (source: Zero Day
        Clock), not a calculation derived from CVEs actually detected in
        the audited code — the text must say so explicitly, otherwise the
        reader cannot tell if it is contextualized to their audit or
        generic (RETEX Reviewer R19).
        """
        if total_high == 0 and total_medium == 0:
            return ""

        # ZeroDayClock data (source: zerodayclock.com, CC-BY-4.0)
        tte_label = self.t_report("threat_tte") or "Time-to-Exploit (TTE)"
        exposure_label = self.t_report("threat_exposure") or "Exposure window"
        context_label = self.t_report("threat_context") or "Threat context"
        disclaimer = self.t_report("threat_disclaimer") or "General industry statistics (Zero Day Clock), not specific to this codebase."
        source = self.t_report("threat_source") or "Source: Zero Day Clock (zerodayclock.com) — 83,000+ CVEs tracked"

        # Exposure risk calculation
        # MTTR median = 74 days, TTE median 2024 = 4 hours
        # If HIGH > 0, the organization is exposed for 99.9% of the cycle
        if total_high > 0:
            risk_level = self.t_report("threat_level_critical") or "critical"
            risk_color = "#ef4444"
            tpl = self.t_report("threat_risk_high_text") or (
                "{count} {severity_label} — {tte_label}: 4h (2024). "
                "{exposure_label}: 74 days (median MTTR). "
                "28% of vulnerabilities exploited within 24h of disclosure."
            )
            risk_text = tpl.format(
                count=total_high, severity_label=self.t_report("severity.high"),
                tte_label=tte_label, exposure_label=exposure_label,
            )
        else:
            risk_level = self.t_report("threat_level_elevated") or "elevated"
            risk_color = "#f59e0b"
            tpl = self.t_report("threat_risk_medium_text") or (
                "{count} {severity_label} — {exposure_label}: 55 days median. "
                "Remediation recommended before next release cycle."
            )
            risk_text = tpl.format(
                count=total_medium, severity_label=self.t_report("severity.medium"),
                exposure_label=exposure_label,
            )

        return (
            f'<div class="threat-context" style="border-left:4px solid {risk_color};'
            f'background:{risk_color}10;padding:12px 16px;border-radius:0 8px 8px 0;margin:12px 0;">'
            f'<strong>{context_label}</strong> '
            f'<span style="font-size:12px;color:{risk_color}">({risk_level})</span><br>'
            f'<span style="font-size:13px;color:var(--gray-700)">{risk_text}</span>'
            f'<br><span style="font-size:11px;color:var(--gray-500)">{disclaimer} {source}</span></div>'
        )

    def _compute_top_priority_rules(self, limit: int = 3) -> list:
        """Rank rules with CRITICAL/HIGH findings by a priority score
        combining severity, the rule's average confidence, the number of
        occurrences in the project, and the presence of a verified taint
        flow — 4 criteria computable statically, without human input.
        Network exposure, authentication prerequisites and defense in
        depth (WAF) — also requested by Reviewer — cannot be determined by
        static analysis and require a manual second pass with the
        engineering teams (RETEX Reviewer R15, out of scope for this
        calculation, see docs/ROADMAP.md)."""
        severity_weight = {"CRITICAL": 100, "HIGH": 70}
        by_rule: dict = {}
        for cat in self.categories.values():
            for f in cat.findings:
                if f.severity not in severity_weight or not f.rule_key:
                    continue
                entry = by_rule.setdefault(f.rule_key, {
                    "rule_key": f.rule_key, "rule": f.rule, "severity": f.severity,
                    "count": 0, "confidence_sum": 0, "taint_verified": False,
                })
                entry["count"] += 1
                entry["confidence_sum"] += f.confidence
                if getattr(f, "taint_flow", None):
                    entry["taint_verified"] = True

        ranked = []
        for entry in by_rule.values():
            avg_confidence = entry["confidence_sum"] / entry["count"]
            occurrence_factor = min(entry["count"], 10)
            taint_bonus = 1.5 if entry["taint_verified"] else 1.0
            score = severity_weight[entry["severity"]] * (avg_confidence / 100) * (1 + occurrence_factor / 10) * taint_bonus
            ranked.append({
                "rule_key": entry["rule_key"],
                "rule": entry["rule"],
                "count": entry["count"],
                "taint_verified": entry["taint_verified"],
                "score": round(score, 1),
            })
        ranked.sort(key=lambda e: e["score"], reverse=True)
        return ranked[:limit]

    def _format_priority_rule_list(self, ranked_rules: list) -> str:
        """Format the priority rule list for insertion into an executive
        recommendation: "rule (N occurrence(s), verified flow)"."""
        occ_label = self.t_report("priority_occurrences_label") or "occurrence(s)"
        taint_label = self.t_report("priority_taint_verified_label") or "verified flow"
        parts = []
        for r in ranked_rules:
            part = f"{self._escape(r['rule'])} ({r['count']} {occ_label}"
            if r["taint_verified"]:
                part += f", {taint_label}"
            part += ")"
            parts.append(part)
        return ", ".join(parts)

    def _build_exec_recommendations(self, total_high, total_medium, total_low, total_findings, health_score):
        """Build the priority recommendations in business language."""
        recs = []

        if total_high > 0:
            # "High risk" label (HIGH), not "critical" (CRITICAL) — this
            # text is triggered by total_high, not total_critical
            # (RETEX Reviewer R15)
            top_rules = self._compute_top_priority_rules(limit=3)
            if top_rules:
                rec_high_tpl = self.t_report("exec_rec_high_ranked") or (
                    "Fix the {count} high-risk vulnerabilities as a priority — "
                    "short-term exploitation risk. Fix first: {rules}."
                )
                recs.append(('p1', rec_high_tpl.format(count=total_high, rules=self._format_priority_rule_list(top_rules))))
            else:
                rec_high_tpl = self.t_report("exec_rec_high") or "Fix the {count} high-risk vulnerabilities as a priority — short-term exploitation risk"
                recs.append(('p1', rec_high_tpl.format(count=total_high)))

        taint_findings = sum(1 for cat in self.categories.values() for f in cat.findings if getattr(f, "taint_flow", None))
        if taint_findings > 0:
            recs.append(('p1', self.t_report("exec_rec_taint") or f"{taint_findings} vulnérabilités avec chemin d'exploitation vérifié — priorité absolue"))

        if total_medium > 20:
            recs.append(('p2', self.t_report("exec_rec_medium") or f"Planifier la correction des {total_medium} risques modérés dans le prochain sprint"))
        elif total_medium > 0:
            recs.append(('p3', self.t_report("exec_rec_medium_low") or f"{total_medium} risques modérés à traiter progressivement"))

        if health_score < 50:
            recs.append(('p1', self.t_report("exec_rec_health_critical") or "Score de santé critique — intervention urgente recommandée"))
        elif health_score < 80:
            recs.append(('p2', self.t_report("exec_rec_health_warning") or "Score de santé en amélioration — maintenir l'effort de correction"))

        if not recs:
            recs.append(('p3', self.t_report("exec_rec_good") or "Bon niveau de sécurité — maintenir les bonnes pratiques"))

        # Sort by priority (P1 before P2 before P3) — the recs are added
        # in the order of the business checks above, not in priority
        # order (RETEX Reviewer R29)
        recs.sort(key=lambda r: r[0])

        html = ""
        for priority, text in recs[:4]:
            html += f'<div class="exec-rec-item"><span class="exec-rec-priority {priority}">P{priority[1]}</span> {text}</div>'
        return html

    def _generate_custom_rules_section(self) -> str:
        """Generate the Custom Rules section — always shown, with an empty state if there are no rules."""
        lang = self.report_lang

        # Loaded custom rules
        all_rules = getattr(self, "_cached_json_rules", {})
        custom_rules = sorted(
            [r for r in all_rules.values() if r.get("_source") == "json_custom"],
            key=lambda r: r["id"]
        )
        count = len(custom_rules)

        # Findings by custom rule
        all_findings = []
        for cat in self.categories.values():
            all_findings.extend(cat.findings)
        findings_by_rule: dict = {}
        for f in all_findings:
            if getattr(f, "rule_source", "") == "json_custom":
                findings_by_rule.setdefault(f.rule_key, []).append(f)

        # Counter badge
        if count:
            count_badge = f'<span class="badge badge-info">{count}</span>'
        else:
            count_badge = '<span class="badge badge-neutral">0</span>'

        if not count:
            body_html = (
                '<div class="custom-rules-empty">'
                '<div class="custom-rules-empty-icon">📜</div>'
                f'<p class="custom-rules-empty-title">{self.t_report("custom_rules_none")}</p>'
                f'<p class="custom-rules-empty-desc">{self.t_report("custom_rules_none_desc")}</p>'
                '<code class="custom-rules-cmd">custom-rules/&lt;lang&gt;/&lt;category&gt;/&lt;rule_id&gt;.sca</code>'
                '</div>'
            )
        else:
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            cards = ""
            for rule in custom_rules:
                rule_id = rule["id"]
                sev = rule.get("severity", "INFO").upper()
                n = len(findings_by_rule.get(rule_id, []))
                risk = rule.get("risk", {})
                desc = risk.get(lang) or risk.get("en", "")

                if n:
                    sev_class = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "low"}.get(sev, "low")
                    findings_badge = f'<span class="badge badge-{sev_class}">{n}</span>'
                else:
                    findings_badge = f'<span class="badge badge-neutral">{self.t_report("custom_rules_no_findings")}</span>'

                cards += (
                    '<div class="custom-rule-card">'
                    '<div class="custom-rule-header">'
                    f'<code class="custom-rule-id">{self._escape(rule_id)}</code>'
                    f'<span class="sev-tag sev-{sev.lower()}">{sev}</span>'
                    f'<span class="custom-rule-lang">{self._escape(rule.get("language", ""))}</span>'
                    f'<span class="custom-rule-cat">{self._escape(rule.get("category", ""))}</span>'
                    f'<span class="custom-rule-findings">{findings_badge}</span>'
                    '</div>'
                    + (f'<p class="custom-rule-desc">{self._escape(desc)}</p>' if desc else "")
                    + '</div>'
                )
            body_html = f'<div class="custom-rules-list">{cards}</div>'

        tpl = self._load_template("custom-rules-section.html")
        return (tpl
            .replace("{{i18n_custom_rules_nav}}", self.t_report("custom_rules_nav"))
            .replace("{{i18n_toc}}", self.t_report("toc"))
            .replace("{{custom_rules_count_badge}}", count_badge)
            .replace("{{custom_rules_body}}", body_html)
        )

    def _get_taint_chart_data(self):
        """Build the chart data for the taint analysis."""
        stats = getattr(self, "_rule_engine_stats", {})
        all_findings = []
        for cat in self.categories.values():
            all_findings.extend(cat.findings)

        taint_findings = [f for f in all_findings if getattr(f, "taint_flow", None)]
        by_rule = {}
        for f in taint_findings:
            key = f.rule_key
            by_rule[key] = by_rule.get(key, 0) + 1

        by_source = {"python": 0, "json_builtin": 0, "json_custom": 0}
        for f in all_findings:
            src = getattr(f, "rule_source", "python")
            if src in by_source:
                by_source[src] += 1

        return {
            "enabled": len(taint_findings) > 0,
            "totalFlows": len(taint_findings),
            "byRule": by_rule,
            "bySource": by_source,
            "builtin_loaded": stats.get("builtin_loaded", 0),
            "custom_loaded": stats.get("custom_loaded", 0),
        }

    def _load_playbook(self):
        """Load the remediation playbook from docs/remediation-playbook.json."""
        if hasattr(self, "_playbook_data"):
            return self._playbook_data
        import json
        playbook_path = SCRIPT_DIR / "docs" / "remediation-playbook.json"
        if not playbook_path.exists():
            self._playbook_data = {}
            return self._playbook_data
        try:
            with open(playbook_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._playbook_data = data.get("rules", {})
        except Exception:
            self._playbook_data = {}
        return self._playbook_data

    def _render_playbook_inline(self, rule_key: str) -> str:
        """Generate the inline playbook HTML for a rule_key."""
        playbook = self._load_playbook()
        entry = playbook.get(rule_key)
        if not entry:
            return ""

        steps = entry.get("steps", [])
        refs = entry.get("references", {})
        benefit = entry.get("benefit", "")

        if not steps and not refs:
            return ""

        # Label i18n
        label = self.t_report("playbook_link")

        # Steps
        steps_html = ""
        for step in steps:
            icon = {"diagnostic": "🔍", "code_change": "🔧", "verification": "✅"}.get(step.get("type"), "▸")
            steps_html += f'<li>{icon} {self._escape(step["action"])}</li>'

        # References
        refs_html = ""
        if refs.get("cwe"):
            cwe = refs["cwe"]
            if isinstance(cwe, list):
                cwe = ", ".join(cwe)
            url = refs.get("cwe_url", "")
            refs_html += f'<a href="{url}" target="_blank" class="playbook-ref">{cwe}</a> '
        if refs.get("cve"):
            cves = refs["cve"]
            if isinstance(cves, str):
                cves = [cves]
            for c in cves:
                nvd_url = f'https://nvd.nist.gov/vuln/detail/{c}'
                refs_html += f'<a href="{nvd_url}" target="_blank" class="playbook-ref">{c}</a> '
        if refs.get("owasp"):
            refs_html += f'<span class="playbook-ref">{refs["owasp"]}</span> '
        if refs.get("iso27001"):
            iso_list = ", ".join(refs["iso27001"][:3])
            refs_html += f'<span class="playbook-ref">ISO {iso_list}</span>'
        if refs.get("wcag"):
            wcag_list = refs["wcag"]
            if isinstance(wcag_list, str):
                wcag_list = [wcag_list]
            for w in wcag_list[:3]:
                # W3C Understanding link (slug "1-1-1" from "1.1.1")
                slug = w.replace(".", "-")
                url = f'https://www.w3.org/WAI/WCAG21/Understanding/{slug}'
                refs_html += f'<a href="{url}" target="_blank" class="playbook-ref">WCAG {w}</a> '

        # Benefit
        benefit_html = f'<p class="playbook-benefit">💡 {self._escape(benefit)}</p>' if benefit else ""

        return (
            f'<details class="playbook-details">'
            f'<summary>📋 {label}</summary>'
            f'<ol class="playbook-steps">{steps_html}</ol>'
            f'{benefit_html}'
            f'<div class="playbook-refs">{refs_html}</div>'
            f'</details>'
        )

    def _generate_fix_suggestion(self, rule_key: str) -> str:
        """Generate a before/after code block from the compiled .sca rule."""
        # Look for fix_before/fix_after in the compiled rule
        compiled = getattr(self, "_cached_json_rules", {})
        rule = compiled.get(rule_key, {})
        before = rule.get("fix_before", "")
        after = rule.get("fix_after", "")
        if not before and not after:
            return ""
        rule_name = self._rule(rule_key).get("name", rule_key) if rule_key else rule_key
        lbl = self.t_report("taint_fix_title") if hasattr(self, "t_report") else "Correction"
        return (
            f'<details class="taint-fix">'
            f'<summary>🔧 {lbl} — {rule_name}</summary>'
            f'<div class="fix-before"><strong>❌ {self.t_report("taint_fix_before")}</strong>'
            f'<pre><code>{self._escape(before)}</code></pre></div>'
            f'<div class="fix-after"><strong>✅ {self.t_report("taint_fix_after")}</strong>'
            f'<pre><code>{self._escape(after)}</code></pre></div>'
            f'</details>'
        )

    def _generate_taint_fix(self, flow, finding) -> str:
        """Generate a before/after code block for a finding (taint or not)."""
        rule_key = getattr(flow, "rule_key", "") or getattr(finding, "rule_key", "") or ""
        return self._generate_fix_suggestion(rule_key)

    def _generate_category_examples_html(self) -> str:
        """For each major category, illustrate the most frequent issue with a
        real instance detected in the audited project plus the generic fix
        from the .sca rule (fix_before/fix_after) — not an automatic fix
        of the client's code, which remains forbidden (RETEX Reviewer R22).
        """
        compiled = getattr(self, "_cached_json_rules", {})
        cat_i18n_map = {
            "SECURITY": ("security", "🔒"),
            "ARCH": ("architecture", "🏗️"),
            "UI": ("ui", "🎨"),
            "UX": ("ux", "🧭"),
            "MAINTENANCE": ("maintenance", "🔧"),
        }

        detected_label = self.t_report("category_example_detected") or "Detected in your code"
        fix_label = self.t_report("category_example_fix") or "How to fix this type of pattern"
        occurrences_tpl = self.t_report("category_example_occurrences") or "{count} occurrence(s) detected in this category"
        bridge_tpl = self.t_report("category_example_bridge") or (
            "This rule flags a broader principle than just this snippet: {solution}. "
            "The example below illustrates the general fix principle, not necessarily your exact case."
        )

        blocks = ""
        for cat_key, (cat_i18n_key, icon) in cat_i18n_map.items():
            cat = self.categories.get(cat_key)
            if not cat or not cat.findings:
                continue

            counts: dict = {}
            example_by_rule: dict = {}
            for f in cat.findings:
                if not f.rule_key:
                    continue
                rule = compiled.get(f.rule_key, {})
                if not rule.get("fix_before") or not rule.get("fix_after"):
                    continue
                counts[f.rule_key] = counts.get(f.rule_key, 0) + 1
                example_by_rule.setdefault(f.rule_key, f)

            if not counts:
                continue

            top_rule_key = max(counts, key=counts.get)
            count = counts[top_rule_key]
            finding = example_by_rule[top_rule_key]
            rule = compiled.get(top_rule_key, {})
            rule_i18n = self._rule(top_rule_key)
            rule_name = rule_i18n.get("name", top_rule_key)
            cat_title = self.t_report(f"category_titles.{cat_i18n_key}")
            solution = rule_i18n.get("solution", "")
            bridge_html = (
                f'<p class="category-example-bridge">{self._escape(bridge_tpl.format(solution=solution))}</p>'
                if solution else ""
            )

            blocks += f"""
            <div class="category-example">
                <h4>{icon} {self._escape(cat_title)} — {self._escape(rule_name)}</h4>
                <p class="category-example-meta">{occurrences_tpl.format(count=count)} — {self._escape(finding.file)}:{finding.line}</p>
                <div class="fix-before"><strong>❌ {detected_label}</strong>
                <pre><code>{self._escape(finding.code)}</code></pre></div>
                {bridge_html}
                <div class="fix-after"><strong>✅ {fix_label}</strong>
                <pre><code>{self._escape(rule.get('fix_after', ''))}</code></pre></div>
            </div>
            """

        if not blocks:
            return ""

        title = self.t_report("category_examples_title") or "Representative examples by category"
        subtitle = self.t_report("category_examples_subtitle") or (
            "The most frequent issue in each category, with a real instance "
            "from this codebase and the generic fix for this type of pattern."
        )
        return f"""
        <div class="section category-examples-section" id="section-category-examples" data-nav-section="{title}">
            <h2 class="section-title">🎓 {title} <a href="#sommaire" class="back-to-toc">↑ {self.t_report("toc")}</a></h2>
            <p class="chart-subtitle">{subtitle}</p>
            {blocks}
        </div>
        """

    def _get_language_severity_data(self) -> dict:
        """Compute the number of findings per language and per severity."""
        matrix: dict = {}
        for cat in self.categories.values():
            for f in cat.findings:
                lang = self._lang_label(f.file) or "Other"
                sev = f.severity.upper()
                if lang not in matrix:
                    matrix[lang] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
                if sev in matrix[lang]:
                    matrix[lang][sev] += 1
        return dict(sorted(matrix.items(), key=lambda x: sum(x[1].values()), reverse=True))

    _LANG_LABELS = {
        ".py": "Python", ".pyw": "Python",
        ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
        ".ts": "TypeScript", ".tsx": "TypeScript",
        ".java": "Java",
        ".cs": "C#",
        ".php": "PHP",
        ".html": "HTML", ".htm": "HTML",
        ".yml": "YAML", ".yaml": "YAML",
    }

    def _lang_label(self, file: str) -> str:
        """Return the language label from the file extension."""
        from pathlib import Path
        p = Path(file)
        if p.name.lower() == "dockerfile":
            return "Dockerfile"
        return self._LANG_LABELS.get(p.suffix.lower(), "")

    def _escape(self, text: str) -> str:
        """Escape HTML special characters."""
        if text is None:
            return ""
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

    def _linkify_acronyms(self, text: str) -> str:
        """Replace known acronyms with links to the glossary, with a tooltip.

        Works on plain text (already escaped via _escape()).
        For full HTML, use _linkify_acronyms_in_html() instead.
        """
        glossary = self.i18n_report.get("glossary", {}).get("acronyms", {})
        if not glossary:
            return text
        # Mapping term → (key, full description)
        term_to_info = {}
        for key, acr in glossary.items():
            tooltip = f'{acr["full"]} — {acr["desc"]}'
            term_to_info[acr["term"]] = (key, self._escape(tooltip))
        # Sort by descending length (HTTP/HTTPS before HTTP, SHA-1 before SHA)
        sorted_terms = sorted(term_to_info.keys(), key=len, reverse=True)
        for term in sorted_terms:
            escaped = re.escape(term)
            key, tooltip = term_to_info[term]
            # Whole word, not already inside an HTML link
            pattern = r'(?<![>\w/])' + escaped + r'(?![<\w])'
            replacement = f'<a href="#acr-{key}" class="glossary-link" data-tooltip="{tooltip}">{term}</a>'
            text = re.sub(pattern, replacement, text)
        return text

    def _linkify_acronyms_in_html(self, html: str) -> str:
        """Apply acronym linkification to the report's full HTML.

        Processes only the visible text content — ignores HTML tags,
        <script>, <style>, <code>, <pre> blocks and existing <a> links.
        Uses a single-pass replacement (one combined regex) to avoid
        nested HTML artifacts in the data-tooltip attributes.
        """
        glossary = self.i18n_report.get("glossary", {}).get("acronyms", {})
        if not glossary:
            return html

        # Prepare the term → HTML link mapping, sorted by descending length
        term_to_link = {}
        sorted_terms = []
        for key, acr in glossary.items():
            tooltip = f'{acr["full"]} — {acr["desc"]}'
            escaped_tooltip = self._escape(tooltip)
            term = acr["term"]
            link = f'<a href="#acr-{key}" class="glossary-link" data-tooltip="{escaped_tooltip}">{term}</a>'
            term_to_link[term] = link
            sorted_terms.append(term)
        sorted_terms.sort(key=len, reverse=True)

        # Combined regex: all terms in a single pass (no double replacement)
        all_terms = '|'.join(re.escape(t) for t in sorted_terms)
        combined_pattern = re.compile(r'(?<![\w/])(' + all_terms + r')(?![\w])')

        def replacer(match):
            """Return the HTML link for a matched acronym term."""
            return term_to_link[match.group(0)]

        # Split the HTML into segments: tags/comments vs text
        segments = re.split(r'(<[^>]+>|<!--.*?-->)', html)

        # Tags whose content must not be processed
        skip_tags = {'script', 'style', 'code', 'pre', 'a'}
        skip_depth = 0
        glossary_skip = False  # Glossary zone excluded from linkification

        for i, segment in enumerate(segments):
            if segment.startswith('<'):
                # Glossary markers (no linkification within the glossary itself)
                if segment == '<!-- GLOSSARY_NO_LINKIFY -->':
                    glossary_skip = True
                    continue
                if segment == '<!-- /GLOSSARY_NO_LINKIFY -->':
                    glossary_skip = False
                    continue
                tag_match = re.match(r'<(/?)(\w+)', segment)
                if tag_match:
                    is_closing = tag_match.group(1) == '/'
                    tag_name = tag_match.group(2).lower()
                    if tag_name in skip_tags:
                        if is_closing:
                            skip_depth = max(0, skip_depth - 1)
                        elif not segment.endswith('/>'):
                            skip_depth += 1
                continue

            # Text content — process only outside the blocks to skip
            if skip_depth > 0 or glossary_skip or not segment.strip():
                continue

            # Single-pass replacement: all terms in a single regex
            segments[i] = combined_pattern.sub(replacer, segments[i])

        return ''.join(segments)

    def _load_asset(self, filename: str) -> str:
        """Load a CSS/JS asset, preferring the .min.* version if available."""
        base = filename.rsplit(".", 1)
        min_name = f"{base[0]}.min.{base[1]}" if len(base) == 2 else filename
        templates_dir = os.path.join(str(SCRIPT_DIR), "templates")
        if os.path.exists(os.path.join(templates_dir, min_name)):
            return self._load_template(min_name)
        return self._load_template(filename)

    def _load_template(self, filename: str, subdir: str = None) -> str:
        """Load a template file from the templates/ or vendor/ directory."""
        script_dir = str(SCRIPT_DIR)
        if subdir == "vendor":
            base_dir = os.path.join(script_dir, "vendor")
        else:
            base_dir = os.path.join(script_dir, "templates")
        filepath = os.path.join(base_dir, filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            self.reporter.warn(f"{self.t_console('template_not_found')}: {filepath}")
            return f"/* {filename} not found */"

    def _is_dependency(self, filepath: str) -> bool:
        """Determine whether a file is part of the external dependencies."""
        dependency_patterns = [
            '/vendor/', '/lib/', '/node_modules/',
            '/dist/', '/build/', '/assets/vendor/',
            '.min.js', '.bundle.js',
            # External tools
            '/alembic/', 'alembic/',
        ]
        # Dependency declaration files
        dep_filenames = [
            'requirements.txt', 'pyproject.toml', 'package.json',
            'package-lock.json', 'poetry.lock', 'pipfile', 'pipfile.lock',
        ]
        filepath_lower = filepath.lower()
        basename = os.path.basename(filepath_lower)
        if basename in dep_filenames:
            return True
        return any(pattern in filepath_lower for pattern in dependency_patterns)

    def _get_file_group(self, filepath: str) -> str:
        """Return the file's group: 'deps' or 'business'."""
        return "deps" if self._is_dependency(filepath) else "business"
