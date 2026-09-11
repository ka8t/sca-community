"""
Compliance mixin — ISO/IEC 27001:2022 Annex A and OWASP ASVS v5.0.0 coverage matrices.
"""
import json
import logging
from pathlib import Path

from sca import SCA_PACKAGE_DIR

logger = logging.getLogger("sca.compliance")


class AuditComplianceMixin:
    """Computation and rendering of the ISO 27001, ASVS, and NIST CSF compliance matrices."""

    # =========================================================================
    # MAPPING LOADING
    # =========================================================================
    def _load_iso27001_mapping(self):
        """Load the ISO 27001 mapping from sca/iso27001_mapping.json."""
        mapping_path = SCA_PACKAGE_DIR / "iso27001_mapping.json"
        self.iso27001_mapping = None

        if not mapping_path.exists():
            logger.warning("Mapping ISO 27001 introuvable: %s", mapping_path)
            return

        try:
            with open(mapping_path, "r", encoding="utf-8") as f:
                self.iso27001_mapping = json.load(f)
            logger.info("Mapping ISO 27001 chargé: %d contrôles", len(self.iso27001_mapping.get('controls', {})))
        except Exception as e:
            logger.warning("Erreur chargement mapping ISO 27001: %s", e)
            self.iso27001_mapping = None

    # =========================================================================
    # SHARED CORE vs FRAMEWORK-SPECIFIC (RETEX Reviewer R06)
    # =========================================================================
    def _rule_referential_scope(self) -> dict:
        """Classify each mapped rule_key as "shared" (mapped in ≥2 of ISO27001/
        ASVS/NIST CSF) or "specific" (mapped in only one). A shared rule earns
        compliance points in several frameworks at once — a framework's real
        differentiating value lies in its compliance on rules specific to it
        (RETEX Reviewer R06). Result is cached on the instance (same for ISO/
        ASVS/NIST within a given audit)."""
        cached = getattr(self, "_rule_referential_scope_cache", None)
        if cached is not None:
            return cached
        iso_rules = set(self.iso27001_mapping.get("mapping", {}).keys()) if self.iso27001_mapping else set()
        asvs_rules = set(self.asvs_mapping.get("mapping", {}).keys()) if self.asvs_mapping else set()
        nist_rules = set(self.nist_csf_mapping.get("mapping", {}).keys()) if self.nist_csf_mapping else set()
        scope = {}
        for rk in iso_rules | asvs_rules | nist_rules:
            n = (rk in iso_rules) + (rk in asvs_rules) + (rk in nist_rules)
            scope[rk] = "shared" if n >= 2 else "specific"
        self._rule_referential_scope_cache = scope
        return scope

    def _split_shared_vs_specific(self, testable_item_to_rules: dict, findings_by_rule: dict) -> dict:
        """Split testable items (control/requirement/subcategory → rule_keys)
        into shared vs specific groups and compute, for each, the share with
        no active finding ("compliance"). An item is "shared" if at least one
        of its rules is shared with another framework."""
        rule_scope = self._rule_referential_scope()
        shared_total = shared_clean = specific_total = specific_clean = 0
        for rule_keys in testable_item_to_rules.values():
            is_shared = any(rule_scope.get(rk) == "shared" for rk in rule_keys)
            has_finding = any(rk in findings_by_rule for rk in rule_keys)
            if is_shared:
                shared_total += 1
                shared_clean += 0 if has_finding else 1
            else:
                specific_total += 1
                specific_clean += 0 if has_finding else 1
        return {
            "shared_total": shared_total,
            "shared_clean": shared_clean,
            "shared_clean_pct": round(shared_clean / shared_total * 100) if shared_total else 0,
            "specific_total": specific_total,
            "specific_clean": specific_clean,
            "specific_clean_pct": round(specific_clean / specific_total * 100) if specific_total else 0,
        }

    # =========================================================================
    # COVERAGE COMPUTATION
    # =========================================================================
    def _compute_iso27001_compliance(self) -> dict:
        """Compute the ISO 27001 coverage matrix from the current findings.

        Returns a dict with:
        - total_controls: total number of Annex A controls
        - covered_controls: number of controls covered by at least one SCA rule
        - coverage_pct: coverage percentage
        - themes: dict per theme (organizational/people/physical/technological)
        - controls: detailed list of each control with status and findings
        """
        if not self.iso27001_mapping:
            return {}

        controls = self.iso27001_mapping.get("controls", {})
        mapping = self.iso27001_mapping.get("mapping", {})

        # Collect all findings with their rule_key
        all_findings = []
        for cat in self.categories.values():
            all_findings.extend(cat.findings)

        # Build a rule_key → list of findings index
        findings_by_rule = {}
        for f in all_findings:
            if f.rule_key:
                if f.rule_key not in findings_by_rule:
                    findings_by_rule[f.rule_key] = []
                findings_by_rule[f.rule_key].append(f)

        # Compute the covered controls (= at least one SCA rule is mapped)
        # and the controls with findings (= at least one finding detected)
        control_details = {}
        covered_set = set()
        with_findings_set = set()

        # First, invert the mapping: control → list of rule_keys
        control_to_rules = {}
        for rule_key, control_ids in mapping.items():
            for ctrl_id in control_ids:
                if ctrl_id not in control_to_rules:
                    control_to_rules[ctrl_id] = []
                control_to_rules[ctrl_id].append(rule_key)

        for ctrl_id, ctrl_info in controls.items():
            rules_for_ctrl = control_to_rules.get(ctrl_id, [])
            is_covered = len(rules_for_ctrl) > 0
            finding_count = 0
            severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

            for rule_key in rules_for_ctrl:
                if rule_key in findings_by_rule:
                    for f in findings_by_rule[rule_key]:
                        finding_count += 1
                        if f.severity in severities:
                            severities[f.severity] += 1

            if is_covered:
                covered_set.add(ctrl_id)
            if finding_count > 0:
                with_findings_set.add(ctrl_id)

            # Status: "findings" (issues found), "covered" (testable, no finding), "not_covered" (no SCA rule)
            if finding_count > 0:
                status = "findings"
            elif is_covered:
                status = "covered"
            else:
                status = "not_covered"

            control_details[ctrl_id] = {
                "id": ctrl_id,
                "name": ctrl_info["name"],
                "theme": ctrl_info["theme"],
                "status": status,
                "rules_count": len(rules_for_ctrl),
                "finding_count": finding_count,
                "severities": severities,
            }

        # Aggregation by theme
        themes = {}
        for theme in ("organizational", "people", "physical", "technological"):
            theme_controls = [c for c in control_details.values() if c["theme"] == theme]
            themes[theme] = {
                "total": len(theme_controls),
                "covered": sum(1 for c in theme_controls if c["status"] != "not_covered"),
                "with_findings": sum(1 for c in theme_controls if c["status"] == "findings"),
                "finding_count": sum(c["finding_count"] for c in theme_controls),
            }

        total = len(controls)
        covered = len(covered_set)
        # coverage_pct = APPLICABILITY rate (share of Annex A that a SAST
        # tool can technically test), not a compliance rate — controls
        # with no mapped rule (not_covered) are out of SAST scope by
        # nature (organizational, physical, HR) and not a coverage
        # failure. clean_pct measures, among the testable ones, the share
        # with no active finding (RETEX Reviewer R25/R26).
        coverage_pct = round(covered / total * 100) if total > 0 else 0
        clean_count = covered - len(with_findings_set)
        clean_pct = round(clean_count / covered * 100) if covered > 0 else 0
        shared_vs_specific = self._split_shared_vs_specific(control_to_rules, findings_by_rule)

        return {
            "total_controls": total,
            "covered_controls": covered,
            "coverage_pct": coverage_pct,
            "clean_controls": clean_count,
            "clean_pct": clean_pct,
            "with_findings": len(with_findings_set),
            "themes": themes,
            "controls": control_details,
            **shared_vs_specific,
        }

    # =========================================================================
    # HTML GENERATION — applicability/compliance dual-bar block
    # =========================================================================
    def _score_class(self, pct: float) -> str:
        """Return the good/warning/danger CSS class, using the same thresholds
        as the health bar (self.health_thresholds) for a consistent color
        scale across the report (RETEX Reviewer R02/R03/R23/R25/R26)."""
        if pct >= self.health_thresholds["good"]:
            return "good"
        if pct >= self.health_thresholds["warning"]:
            return "warning"
        return "danger"

    def _pct_or_na(self, pct: int, denom: int) -> str:
        """Format a percentage, or "N/A" if the denominator is 0 — a ratio
        X/0 is not "0%", it is undetermined (RETEX Reviewer R31)."""
        if denom <= 0:
            return self.t_report("compliance_na_label") or "N/A"
        return f"{pct}%"

    def _render_compliance_dual_bars(self, total: int, covered: int, clean: int) -> str:
        """Render a framework's 2 summary bars: SAST applicability rate
        (testable/total) and compliance rate among the testable (no active
        finding/testable). Separating them avoids counting controls outside
        the SAST scope (N/A) as compliance failures (RETEX Reviewer R25/R26)."""
        applicability_pct = round(covered / total * 100) if total > 0 else 0
        clean_pct = round(clean / covered * 100) if covered > 0 else 0
        applicability_label = self.t_report("compliance_applicability_label") or "SAST applicability"
        applicability_unit = self.t_report("compliance_applicability_unit") or "testable"
        clean_label = self.t_report("compliance_clean_label") or "Compliance among testable"
        clean_unit = self.t_report("compliance_clean_unit") or "clean"
        applicability_class = self._score_class(applicability_pct) if total > 0 else "na"
        clean_class = self._score_class(clean_pct) if covered > 0 else "na"
        applicability_display = self._pct_or_na(applicability_pct, total)
        clean_display = self._pct_or_na(clean_pct, covered)
        return f"""
            <div class="compliance-coverage">
                <span class="compliance-coverage-label">{applicability_label}</span>
                <span class="compliance-coverage-value">{covered}/{total} {applicability_unit} ({applicability_display})</span>
            </div>
            <div class="health-track"><div class="health-fill {applicability_class}" style="width: {applicability_pct if total > 0 else 0}%"></div></div>
            <div class="compliance-coverage compliance-coverage-secondary">
                <span class="compliance-coverage-label">{clean_label}</span>
                <span class="compliance-coverage-value">{clean}/{covered} {clean_unit} ({clean_display})</span>
            </div>
            <div class="health-track"><div class="health-fill {clean_class}" style="width: {clean_pct if covered > 0 else 0}%"></div></div>
        """

    def _render_shared_specific_breakdown(self, data: dict) -> str:
        """Render the secondary block: compliance split between the "common
        core" (controls covered by a rule also mapped in another framework —
        a single fix earns points everywhere) and the "specific" part
        (controls covered only by rules unique to this framework — its true
        differentiating value). RETEX Reviewer R06.
        """
        if not data.get("shared_total") and not data.get("specific_total"):
            return ""
        shared_label = self.t_report("compliance_shared_label") or "Common core compliance (shared with other frameworks)"
        specific_label = self.t_report("compliance_specific_label") or "Framework-specific compliance (differentiating)"
        unit = self.t_report("compliance_clean_unit") or "clean"
        shared_display = self._pct_or_na(data["shared_clean_pct"], data["shared_total"])
        specific_display = self._pct_or_na(data["specific_clean_pct"], data["specific_total"])
        return f"""
            <div class="compliance-shared-specific">
                <div class="compliance-coverage compliance-coverage-tertiary">
                    <span class="compliance-coverage-label">{shared_label}</span>
                    <span class="compliance-coverage-value">{data['shared_clean']}/{data['shared_total']} {unit} ({shared_display})</span>
                </div>
                <div class="compliance-coverage compliance-coverage-tertiary">
                    <span class="compliance-coverage-label">{specific_label}</span>
                    <span class="compliance-coverage-value">{data['specific_clean']}/{data['specific_total']} {unit} ({specific_display})</span>
                </div>
            </div>
        """

    # =========================================================================
    # HTML GENERATION
    # =========================================================================
    def _generate_compliance_html(self, compliance_data: dict) -> str:
        """Generate the HTML for the ISO 27001 compliance section."""
        if not compliance_data:
            return ""

        comp_t = self.i18n_report.get("compliance", {})
        title = comp_t.get("title", "ISO 27001 Compliance Matrix")
        subtitle = comp_t.get("subtitle", "")
        disclaimer = comp_t.get("disclaimer", "")
        col_control = comp_t.get("col_control", "Control")
        col_name = comp_t.get("col_name", "Name")
        col_status = comp_t.get("col_status", "Status")
        col_findings = comp_t.get("col_findings", "Findings")
        col_rules = comp_t.get("col_rules", "Rules")
        status_covered = comp_t.get("status_covered", "Covered")
        status_not_covered = comp_t.get("status_not_covered", "Not applicable")
        status_findings = comp_t.get("status_findings", "Issues found")
        theme_labels = comp_t.get("themes", {})

        total = compliance_data["total_controls"]
        covered = compliance_data["covered_controls"]
        clean = compliance_data["clean_controls"]

        # SAST applicability bars + compliance among the testable
        html = f"""
        <div class="compliance-summary">
            <p class="compliance-disclaimer">{self._linkify_acronyms(disclaimer)}</p>
            {self._render_compliance_dual_bars(total, covered, clean)}
            {self._render_shared_specific_breakdown(compliance_data)}
        </div>
        """

        # Chart titles from the chart_labels i18n labels
        chart_labels = self.i18n_report.get("chart_labels", {})
        coverage_chart_title = chart_labels.get("compliance_coverage_chart", "Overall Coverage (%)")
        theme_chart_title = chart_labels.get("compliance_theme_chart", "Coverage by Theme (%)")
        status_chart_title = chart_labels.get("compliance_status_chart", "Controls Status (count)")

        # Grid of 3 Chart.js charts — the radar (4 axes, poorly readable)
        # was removed: it exactly duplicated complianceThemeChart below,
        # same data (coverage by theme), less readable (RETEX Reviewer R23)
        html += f"""
        <div class="charts-grid compliance-charts-grid">
            <div class="chart-card">
                <h3>📋 {coverage_chart_title}</h3>
                <div class="chart-container"><canvas id="complianceCoverageChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>📊 {theme_chart_title}</h3>
                <div class="chart-container"><canvas id="complianceThemeChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>📊 {status_chart_title}</h3>
                <div class="chart-container"><canvas id="complianceStatusChart"></canvas></div>
            </div>
        </div>
        """

        # Table by theme
        theme_order = [
            ("organizational", "🏢"),
            ("people", "👥"),
            ("physical", "🏗️"),
            ("technological", "💻"),
        ]

        controls = compliance_data["controls"]
        for theme_key, theme_icon in theme_order:
            theme_name = theme_labels.get(theme_key, theme_key.capitalize())
            theme_data = compliance_data["themes"][theme_key]
            theme_controls = sorted(
                [c for c in controls.values() if c["theme"] == theme_key],
                key=lambda c: c["id"]
            )

            html += f"""
            <div class="compliance-theme compliance-accordion open">
                <h4 onclick="this.parentElement.classList.toggle('open')">
                    {theme_icon} {theme_name}
                    <span class="compliance-theme-badge">{theme_data['covered']}/{theme_data['total']}</span>
                    <span class="compliance-toggle">▶</span>
                </h4>
                <div class="compliance-accordion-content">
                <table class="compliance-matrix">
                    <thead><tr>
                        <th>{col_control}</th>
                        <th>{col_name}</th>
                        <th>{col_status}</th>
                        <th>{col_rules}</th>
                        <th>{col_findings}</th>
                    </tr></thead>
                    <tbody>
            """

            for ctrl in theme_controls:
                status = ctrl["status"]
                if status == "findings":
                    badge_class = "compliance-findings"
                    badge_text = status_findings
                elif status == "covered":
                    badge_class = "compliance-covered"
                    badge_text = status_covered
                else:
                    badge_class = "compliance-not-covered"
                    badge_text = status_not_covered

                finding_text = str(ctrl["finding_count"]) if ctrl["finding_count"] > 0 else "—"

                html += f"""
                        <tr class="{badge_class}-row">
                            <td class="compliance-ctrl-id">{ctrl['id']}</td>
                            <td>{self._linkify_acronyms(ctrl['name'])}</td>
                            <td><span class="compliance-badge {badge_class}">{badge_text}</span></td>
                            <td class="compliance-count">{ctrl['rules_count']}</td>
                            <td class="compliance-count">{finding_text}</td>
                        </tr>"""

            html += """
                    </tbody>
                </table>
                </div>
            </div>
            """

        return html

    # =========================================================================
    # NIST CSF 2.0 — LOADING
    # =========================================================================
    def _load_nist_csf_mapping(self):
        """Load the NIST CSF 2.0 mapping from sca/nist_csf_mapping.json."""
        mapping_path = SCA_PACKAGE_DIR / "nist_csf_mapping.json"
        self.nist_csf_mapping = None

        if not mapping_path.exists():
            return

        try:
            with open(mapping_path, "r", encoding="utf-8") as f:
                self.nist_csf_mapping = json.load(f)
            logger.info("Mapping NIST CSF charge: %d regles mappees", len(self.nist_csf_mapping.get('mapping', {})))
        except Exception as e:
            logger.warning("Erreur chargement mapping NIST CSF: %s", e)
            self.nist_csf_mapping = None

    def _compute_nist_csf_compliance(self) -> dict:
        """Compute the NIST CSF 2.0 coverage from the current findings.

        Returns a dict with:
        - total_subcategories: number of subcategories in the curated framework (with metadata)
        - covered_subcategories: number testable (≥1 SCA rule mapped, independent of the audited project)
        - with_findings: number with at least one finding
        - coverage_pct: SAST applicability percentage
        - by_function: dict per function (GV/ID/PR/DE/RS/RC) with covered, total, with_findings, finding_count
        - subcategories: detailed dict per subcategory {id, function, category, name, status, rules_count, finding_count}
        """
        if not self.nist_csf_mapping:
            return {}

        mapping = self.nist_csf_mapping.get("mapping", {})
        subcategories_meta = self.nist_csf_mapping.get("subcategories", {})
        functions = self.nist_csf_mapping.get("functions", {})

        # Collect the detected rule_keys with their findings
        rule_findings: dict = {}  # rule_key → count
        for cat in self.categories.values():
            for f in cat.findings:
                if f.rule_key:
                    rule_findings[f.rule_key] = rule_findings.get(f.rule_key, 0) + 1

        # Invert the mapping: subcat → list of rule_keys
        subcat_rules: dict = {}
        for rule_key, subcats in mapping.items():
            for subcat in subcats:
                subcat_rules.setdefault(subcat, []).append(rule_key)

        # Build the detailed subcategories dict — we iterate over the
        # curated framework (subcategories_meta) rather than only the
        # mapped subcategories, so that those with no SCA rule also show
        # up as "not_covered" (symmetry with ISO27001/ASVS, RETEX Reviewer
        # R31). "covered"/testable = ≥1 SCA rule mapped, independent of
        # the audited project — not "≥1 rule triggered", which conflated
        # applicability and compliance (applicability dropped to 0 on
        # any project with no NIST finding).
        subcategories = {}
        covered_subcats = set()
        with_findings_subcats = set()
        for subcat_id, meta in subcategories_meta.items():
            rules_for_subcat = subcat_rules.get(subcat_id, [])
            is_covered = len(rules_for_subcat) > 0
            findings_count = sum(rule_findings.get(rk, 0) for rk in rules_for_subcat)
            if is_covered:
                covered_subcats.add(subcat_id)
            if findings_count > 0:
                status = "findings"
                with_findings_subcats.add(subcat_id)
            elif is_covered:
                status = "covered"
            else:
                status = "not_covered"
            subcategories[subcat_id] = {
                "id": subcat_id,
                "function": meta.get("function", subcat_id.split(".")[0]),
                "category": meta.get("category", ""),
                "name": meta.get("name", ""),
                "status": status,
                "rules_count": len(rules_for_subcat),
                "finding_count": findings_count,
            }

        # By function
        by_function = {}
        for func_code, func_info in functions.items():
            func_subcats = {s for s in subcategories_meta if s.startswith(func_code + ".")}
            func_covered = func_subcats & covered_subcats
            func_with_findings = func_subcats & with_findings_subcats
            func_finding_count = sum(
                subcategories[s]["finding_count"] for s in func_subcats
            )
            by_function[func_code] = {
                "name": func_info["name"],
                "total": len(func_subcats),
                "covered": len(func_covered),
                "with_findings": len(func_with_findings),
                "finding_count": func_finding_count,
                "subcategories": sorted(func_subcats),
            }

        total = len(subcategories_meta)
        covered = len(covered_subcats)
        # See the equivalent comment in _compute_iso27001_compliance:
        # coverage_pct = SAST applicability, clean_pct = compliance among the testable
        clean_count = covered - len(with_findings_subcats)
        clean_pct = round(clean_count / covered * 100) if covered > 0 else 0
        shared_vs_specific = self._split_shared_vs_specific(subcat_rules, rule_findings)
        return {
            "total_subcategories": total,
            "covered_subcategories": covered,
            "with_findings": len(with_findings_subcats),
            "coverage_pct": round(covered / total * 100, 1) if total else 0,
            "clean_subcategories": clean_count,
            "clean_pct": clean_pct,
            **shared_vs_specific,
            "by_function": by_function,
            "subcategories": subcategories,
        }

    def _generate_nist_csf_html(self, nist_data: dict) -> str:
        """Generate the HTML for the NIST CSF 2.0 compliance section."""
        if not nist_data:
            return ""

        nist_t = self.i18n_report.get("nist", {})
        title = nist_t.get("title", "NIST CSF 2.0 Compliance Matrix")
        disclaimer = nist_t.get("disclaimer", "")
        col_id = nist_t.get("col_id", "ID")
        col_name = nist_t.get("col_name", "Subcategory")
        col_status = nist_t.get("col_status", "Status")
        col_rules = nist_t.get("col_rules", "Rules")
        col_findings = nist_t.get("col_findings", "Findings")
        status_covered = nist_t.get("status_covered", "Covered")
        status_not_covered = nist_t.get("status_not_covered", "Not applicable")
        status_findings = nist_t.get("status_findings", "Issues found")
        function_labels = nist_t.get("functions", {})

        total = nist_data["total_subcategories"]
        covered = nist_data["covered_subcategories"]
        clean = nist_data["clean_subcategories"]

        # SAST applicability bars + compliance among the testable
        html = f"""
        <div class="compliance-summary">
            <p class="compliance-disclaimer">{self._linkify_acronyms(disclaimer)}</p>
            {self._render_compliance_dual_bars(total, covered, clean)}
            {self._render_shared_specific_breakdown(nist_data)}
        </div>
        """

        # Chart titles from chart_labels
        chart_labels = self.i18n_report.get("chart_labels", {})
        coverage_chart_title = chart_labels.get("nist_coverage_chart", "Overall Coverage (%)")
        function_chart_title = chart_labels.get("nist_function_chart", "Coverage by Function (%)")
        status_chart_title = chart_labels.get("nist_status_chart", "Subcategories Status (count)")

        # Grid of 3 Chart.js charts — radar removed, duplicate of
        # nistFunctionChart (RETEX Reviewer R23)
        html += f"""
        <div class="charts-grid compliance-charts-grid">
            <div class="chart-card">
                <h3>📋 {coverage_chart_title}</h3>
                <div class="chart-container"><canvas id="nistCoverageChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>📊 {function_chart_title}</h3>
                <div class="chart-container"><canvas id="nistFunctionChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>📊 {status_chart_title}</h3>
                <div class="chart-container"><canvas id="nistStatusChart"></canvas></div>
            </div>
        </div>
        """

        # Table by NIST CSF function (6 functions)
        function_order = [
            ("GV", "🏛️"),
            ("ID", "🔍"),
            ("PR", "🛡️"),
            ("DE", "📡"),
            ("RS", "🚨"),
            ("RC", "🔄"),
        ]

        subcategories = nist_data["subcategories"]
        for func_code, func_icon in function_order:
            if func_code not in nist_data["by_function"]:
                continue
            func_data = nist_data["by_function"][func_code]
            func_name = function_labels.get(func_code, func_data["name"])
            func_subcats = sorted(
                [s for s in subcategories.values() if s["function"] == func_code],
                key=lambda s: s["id"],
            )
            if not func_subcats:
                continue

            html += f"""
            <div class="compliance-theme compliance-accordion open">
                <h4 onclick="this.parentElement.classList.toggle('open')">
                    {func_icon} {func_code} — {func_name}
                    <span class="compliance-theme-badge">{func_data['covered']}/{func_data['total']}</span>
                    <span class="compliance-toggle">▶</span>
                </h4>
                <div class="compliance-accordion-content">
                <table class="compliance-matrix">
                    <thead><tr>
                        <th>{col_id}</th>
                        <th>{col_name}</th>
                        <th>{col_status}</th>
                        <th>{col_rules}</th>
                        <th>{col_findings}</th>
                    </tr></thead>
                    <tbody>
            """

            for subcat in func_subcats:
                status = subcat["status"]
                if status == "findings":
                    badge_class = "compliance-findings"
                    badge_text = status_findings
                elif status == "covered":
                    badge_class = "compliance-covered"
                    badge_text = status_covered
                else:
                    badge_class = "compliance-not-covered"
                    badge_text = status_not_covered

                finding_text = str(subcat["finding_count"]) if subcat["finding_count"] > 0 else "—"

                html += f"""
                        <tr class="{badge_class}-row">
                            <td class="compliance-ctrl-id">{subcat['id']}</td>
                            <td>{self._linkify_acronyms(subcat['name'])}</td>
                            <td><span class="compliance-badge {badge_class}">{badge_text}</span></td>
                            <td class="compliance-count">{subcat['rules_count']}</td>
                            <td class="compliance-count">{finding_text}</td>
                        </tr>"""

            html += """
                    </tbody>
                </table>
                </div>
            </div>
            """

        return html

    # =========================================================================
    # OWASP ASVS v5.0.0 — LOADING
    # =========================================================================
    def _load_asvs_mapping(self):
        """Load the ASVS mapping from sca/asvs_mapping.json."""
        mapping_path = SCA_PACKAGE_DIR / "asvs_mapping.json"
        self.asvs_mapping = None

        if not mapping_path.exists():
            logger.warning("Mapping ASVS introuvable: %s", mapping_path)
            return

        try:
            with open(mapping_path, "r", encoding="utf-8") as f:
                self.asvs_mapping = json.load(f)
            logger.info("Mapping ASVS chargé: %d requirements détaillés", len(self.asvs_mapping.get('requirements', {})))
        except Exception as e:
            logger.warning("Erreur chargement mapping ASVS: %s", e)
            self.asvs_mapping = None

    # =========================================================================
    # OWASP ASVS v5.0.0 — COVERAGE COMPUTATION
    # =========================================================================
    def _compute_asvs_compliance(self) -> dict:
        """Compute the ASVS v5.0.0 coverage matrix from the current findings.

        Returns a dict with:
        - total_requirements: total number of ASVS requirements (348)
        - covered_requirements: number of requirements covered by at least one SCA rule
        - coverage_pct: coverage percentage
        - with_findings: number of requirements with active findings
        - chapters: dict per chapter (V1-V17) with total/covered/with_findings/finding_count
        - levels: dict per level (L1/L2/L3) with total/covered/coverage_pct
        - requirements: detail of each SAST-detectable requirement
        """
        if not self.asvs_mapping:
            return {}

        chapters = self.asvs_mapping.get("chapters", {})
        requirements = self.asvs_mapping.get("requirements", {})
        mapping = self.asvs_mapping.get("mapping", {})

        # Collect all findings with their rule_key
        all_findings = []
        for cat in self.categories.values():
            all_findings.extend(cat.findings)

        findings_by_rule = {}
        for f in all_findings:
            if f.rule_key:
                if f.rule_key not in findings_by_rule:
                    findings_by_rule[f.rule_key] = []
                findings_by_rule[f.rule_key].append(f)

        # Invert the mapping: requirement → list of rule_keys
        req_to_rules = {}
        for rule_key, req_ids in mapping.items():
            for req_id in req_ids:
                if req_id not in req_to_rules:
                    req_to_rules[req_id] = []
                req_to_rules[req_id].append(rule_key)

        # Compute the coverage for each detailed requirement
        req_details = {}
        covered_set = set()
        with_findings_set = set()

        for req_id, req_info in requirements.items():
            rules_for_req = req_to_rules.get(req_id, [])
            is_covered = len(rules_for_req) > 0
            finding_count = 0

            for rule_key in rules_for_req:
                if rule_key in findings_by_rule:
                    finding_count += len(findings_by_rule[rule_key])

            if is_covered:
                covered_set.add(req_id)
            if finding_count > 0:
                with_findings_set.add(req_id)

            if finding_count > 0:
                status = "findings"
            elif is_covered:
                status = "covered"
            else:
                status = "not_covered"

            req_details[req_id] = {
                "id": req_id,
                "name": req_info["name"],
                "chapter": req_info["chapter"],
                "level": req_info.get("level", "L1"),
                "status": status,
                "rules_count": len(rules_for_req),
                "finding_count": finding_count,
            }

        # Aggregation by chapter (total = chapter count, not just the detailed ones)
        chapter_data = {}
        for ch_key, ch_info in chapters.items():
            ch_reqs = [r for r in req_details.values() if r["chapter"] == ch_key]
            chapter_data[ch_key] = {
                "total": ch_info["count"],
                "covered": sum(1 for r in ch_reqs if r["status"] != "not_covered"),
                "with_findings": sum(1 for r in ch_reqs if r["status"] == "findings"),
                "finding_count": sum(r["finding_count"] for r in ch_reqs),
            }

        # Aggregation by level
        levels_data = {}
        for level in ("L1", "L2", "L3"):
            level_reqs = [r for r in req_details.values() if r["level"] == level]
            total_level = len(level_reqs)
            covered_level = sum(1 for r in level_reqs if r["status"] != "not_covered")
            levels_data[level] = {
                "total": total_level,
                "covered": covered_level,
                "coverage_pct": round(covered_level / total_level * 100) if total_level > 0 else 0,
            }

        total = self.asvs_mapping.get("total_requirements", 348)
        covered = len(covered_set)
        # See the equivalent comment in _compute_iso27001_compliance:
        # coverage_pct = SAST applicability, clean_pct = compliance among the testable
        coverage_pct = round(covered / total * 100) if total > 0 else 0
        clean_count = covered - len(with_findings_set)
        clean_pct = round(clean_count / covered * 100) if covered > 0 else 0
        shared_vs_specific = self._split_shared_vs_specific(req_to_rules, findings_by_rule)

        return {
            "total_requirements": total,
            "covered_requirements": covered,
            "coverage_pct": coverage_pct,
            "clean_requirements": clean_count,
            "clean_pct": clean_pct,
            "with_findings": len(with_findings_set),
            **shared_vs_specific,
            "chapters": chapter_data,
            "levels": levels_data,
            "requirements": req_details,
        }

    # =========================================================================
    # OWASP ASVS v5.0.0 — HTML GENERATION
    # =========================================================================
    def _generate_asvs_html(self, asvs_data: dict) -> str:
        """Generate the HTML for the ASVS v5.0.0 compliance section."""
        if not asvs_data:
            return ""

        asvs_t = self.i18n_report.get("asvs", {})
        disclaimer = asvs_t.get("disclaimer", "")
        col_requirement = asvs_t.get("col_requirement", "Requirement")
        col_name = asvs_t.get("col_name", "Name")
        col_level = asvs_t.get("col_level", "Level")
        col_status = asvs_t.get("col_status", "Status")
        col_findings = asvs_t.get("col_findings", "Findings")
        col_rules = asvs_t.get("col_rules", "Rules")
        status_covered = asvs_t.get("status_covered", "Covered")
        status_not_covered = asvs_t.get("status_not_covered", "Not applicable")
        status_findings = asvs_t.get("status_findings", "Issues found")

        total = asvs_data["total_requirements"]
        covered = asvs_data["covered_requirements"]
        clean = asvs_data["clean_requirements"]

        # SAST applicability bars + compliance among the testable
        html = f"""
        <div class="compliance-summary">
            <p class="compliance-disclaimer">{self._linkify_acronyms(disclaimer)}</p>
            {self._render_compliance_dual_bars(total, covered, clean)}
            {self._render_shared_specific_breakdown(asvs_data)}
        </div>
        """

        # Chart titles
        chart_labels = self.i18n_report.get("chart_labels", {})
        coverage_chart_title = chart_labels.get("asvs_coverage_chart", "Overall Coverage (%)")
        chapter_chart_title = chart_labels.get("asvs_chapter_chart", "Coverage by Chapter (%)")
        status_chart_title = chart_labels.get("asvs_status_chart", "Requirements Status (count)")

        # Grid of 3 Chart.js charts — radar removed, duplicate of
        # asvsChapterChart (RETEX Reviewer R23)
        html += f"""
        <div class="charts-grid compliance-charts-grid">
            <div class="chart-card">
                <h3>🔰 {coverage_chart_title}</h3>
                <div class="chart-container"><canvas id="asvsCoverageChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>📊 {chapter_chart_title}</h3>
                <div class="chart-container"><canvas id="asvsChapterChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>📊 {status_chart_title}</h3>
                <div class="chart-container"><canvas id="asvsStatusChart"></canvas></div>
            </div>
        </div>
        """

        # Chapters (17) — icon per chapter
        chapter_icons = {
            "V1": "🛡️", "V2": "✅", "V3": "🌐", "V4": "🔌", "V5": "📁",
            "V6": "🔑", "V7": "🔒", "V8": "👤", "V9": "🎟️", "V10": "🔗",
            "V11": "🔐", "V12": "📡", "V13": "⚙️", "V14": "💾", "V15": "🏗️",
            "V16": "📝", "V17": "📹",
        }

        chapters = self.asvs_mapping.get("chapters", {})
        req_details = asvs_data.get("requirements", {})

        for ch_key in sorted(chapters.keys(), key=lambda k: int(k[1:])):
            ch_info = chapters[ch_key]
            ch_data = asvs_data["chapters"].get(ch_key, {})
            ch_icon = chapter_icons.get(ch_key, "📋")
            ch_name = f"{ch_key} — {ch_info['name']}"
            ch_covered = ch_data.get("covered", 0)
            ch_total = ch_data.get("total", 0)

            # Requirements for this chapter (only the detailed ones)
            ch_reqs = sorted(
                [r for r in req_details.values() if r["chapter"] == ch_key],
                key=lambda r: r["id"]
            )

            # No table if no detailed requirement
            if not ch_reqs:
                html += f"""
                <div class="compliance-theme compliance-accordion open">
                    <h4 onclick="this.parentElement.classList.toggle('open')">
                        {ch_icon} {ch_name}
                        <span class="compliance-theme-badge">{ch_covered}/{ch_total}</span>
                        <span class="compliance-toggle">▶</span>
                    </h4>
                    <div class="compliance-accordion-content">
                        <p class="empty-group">{status_not_covered}</p>
                    </div>
                </div>
                """
                continue

            html += f"""
            <div class="compliance-theme compliance-accordion open">
                <h4 onclick="this.parentElement.classList.toggle('open')">
                    {ch_icon} {ch_name}
                    <span class="compliance-theme-badge">{ch_covered}/{ch_total}</span>
                    <span class="compliance-toggle">▶</span>
                </h4>
                <div class="compliance-accordion-content">
                <table class="compliance-matrix">
                    <thead><tr>
                        <th>{col_requirement}</th>
                        <th>{col_name}</th>
                        <th>{col_level}</th>
                        <th>{col_status}</th>
                        <th>{col_rules}</th>
                        <th>{col_findings}</th>
                    </tr></thead>
                    <tbody>
            """

            for req in ch_reqs:
                status = req["status"]
                if status == "findings":
                    badge_class = "compliance-findings"
                    badge_text = status_findings
                elif status == "covered":
                    badge_class = "compliance-covered"
                    badge_text = status_covered
                else:
                    badge_class = "compliance-not-covered"
                    badge_text = status_not_covered

                finding_text = str(req["finding_count"]) if req["finding_count"] > 0 else "—"
                level = req.get("level", "L1")
                level_class = f"asvs-level-{level.lower()}"

                html += f"""
                        <tr class="{badge_class}-row">
                            <td class="compliance-ctrl-id">{req['id']}</td>
                            <td>{self._linkify_acronyms(req['name'])}</td>
                            <td><span class="asvs-level-badge {level_class}">{level}</span></td>
                            <td><span class="compliance-badge {badge_class}">{badge_text}</span></td>
                            <td class="compliance-count">{req['rules_count']}</td>
                            <td class="compliance-count">{finding_text}</td>
                        </tr>"""

            html += """
                    </tbody>
                </table>
                </div>
            </div>
            """

        return html
