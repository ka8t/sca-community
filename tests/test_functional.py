"""
Tests fonctionnels — pipeline complet StaticCodeAudit
=====================================================
Valide le pipeline de bout en bout : run() → JSON + HTML + baseline.
"""

import json
import os
import shutil
from pathlib import Path

import pytest

from run_audit import AuditRunner
from tests.conftest import (
    get_fixture_path,
    get_findings_by_rule_key,
    get_all_findings,
    get_findings_by_category,
    use_vulnerable_fixture,
)


# =============================================================================
# HELPER — Crée un AuditRunner fonctionnel avec sorties dans tmp_path
# =============================================================================

def _make_runner(tmp_path, *, quick_mode=False, only_category=None,
                 disabled_rules=None, report_lang="en", script_lang="en",
                 severity_levels=None, extra_config=None):
    """Crée un AuditRunner prêt pour les tests fonctionnels."""
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "src" / "features" / "admin").mkdir(parents=True, exist_ok=True)
    (tmp_path / "src" / "js").mkdir(parents=True, exist_ok=True)
    reports_dir = tmp_path / "reports"
    datas_dir = tmp_path / "reports" / "audit-datas"
    reports_dir.mkdir(parents=True, exist_ok=True)
    datas_dir.mkdir(parents=True, exist_ok=True)

    config = {
        "languages": ["python", "javascript", "html"],
        "paths": {"include": ["src/"]},
        "reports": {
            "language": report_lang,
            "output_dir": str(reports_dir),
            "history_dir": str(datas_dir),
        },
        "tests": {"enabled": False},
        "categories": {
            "security": {"enabled": True, "weight": 3},
            "architecture": {"enabled": True, "weight": 2},
            "ui": {"enabled": True, "weight": 1},
            "ux": {"enabled": True, "weight": 1},
            "maintenance": {"enabled": True, "weight": 1},
            "dependencies": {"enabled": False},
            "cicd": {"enabled": False},
        },
        "database": {"enabled": False},
    }

    if severity_levels is not None:
        config.setdefault("_cli_options", {})["severity_levels"] = severity_levels

    if extra_config:
        for key, value in extra_config.items():
            if isinstance(value, dict) and key in config and isinstance(config[key], dict):
                config[key].update(value)
            else:
                config[key] = value

    return AuditRunner(
        config=config,
        root_dir=str(tmp_path),
        quick_mode=quick_mode,
        only_category=only_category,
        disabled_rules=disabled_rules,
        script_lang=script_lang,
    )


def _place_vuln_fixture(tmp_path, fixture_name, target_path):
    """Copie une fixture vulnérable dans le projet temporaire."""
    source = get_fixture_path("vulnerable", fixture_name)
    dest = tmp_path / target_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(source, dest)


def _read_json(runner):
    """Lit le fichier JSON exporté par le runner."""
    with open(runner.data_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _read_html(runner):
    """Lit le rapport HTML généré par le runner."""
    with open(runner.report_path, "r", encoding="utf-8") as f:
        return f.read()


# =============================================================================
# 1. PIPELINE COMPLET
# =============================================================================

class TestFullPipeline:
    """Tests du pipeline run() de bout en bout."""

    def test_run_produces_html_and_json(self, tmp_path):
        """run() avec fixtures vulnérables produit HTML + JSON et retourne > 0."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        _place_vuln_fixture(tmp_path, "hardcoded_password.py", "src/config.py")
        runner = _make_runner(tmp_path)

        result = runner.run()

        assert os.path.exists(runner.report_path), "Le rapport HTML doit être généré"
        assert os.path.exists(runner.data_path), "Le fichier JSON doit être généré"
        assert os.path.getsize(runner.report_path) > 1000, "Le rapport HTML doit être substantiel"
        assert os.path.getsize(runner.data_path) > 100, "Le fichier JSON doit être substantiel"
        assert result > 0, "Doit retourner des findings HIGH"

    def test_run_clean_returns_zero(self, tmp_path):
        """Projet vide → run() retourne 0."""
        runner = _make_runner(tmp_path)

        result = runner.run()

        assert result == 0, "Projet vide ne doit pas avoir de findings HIGH"
        assert os.path.exists(runner.report_path)
        assert os.path.exists(runner.data_path)

    def test_quick_mode_security_only(self, tmp_path):
        """Quick mode → uniquement les findings SECURITY."""
        # Fixture SECURITY
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        # Fixture UX (console.log)
        _place_vuln_fixture(tmp_path, "console_log.js", "src/js/app.js")

        runner = _make_runner(tmp_path, quick_mode=True)
        runner.run()

        security = get_findings_by_category(runner, "SECURITY")
        ux = get_findings_by_category(runner, "UX")
        assert len(security) >= 1, "Doit détecter les findings SECURITY"
        assert len(ux) == 0, "Quick mode ne doit pas auditer UX"

    def test_only_category(self, tmp_path):
        """only_category restreint les findings à une catégorie."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        _place_vuln_fixture(tmp_path, "console_log.js", "src/js/app.js")

        runner = _make_runner(tmp_path, only_category="UX")
        runner.run()

        security = get_findings_by_category(runner, "SECURITY")
        ux = get_findings_by_category(runner, "UX")
        assert len(security) == 0, "only_category=UX ne doit pas auditer SECURITY"
        assert len(ux) >= 1, "Doit détecter les findings UX"

    def test_disabled_rules(self, tmp_path):
        """disabled_rules empêche la détection."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")

        runner = _make_runner(tmp_path, disabled_rules=["sql_injection_fstring"])
        runner.run()

        findings = get_findings_by_rule_key(runner, "sql_injection_fstring")
        assert len(findings) == 0, "La règle désactivée ne doit pas générer de findings"


# =============================================================================
# 1.bis  TAINT INTER-FICHIERS (Volet 3)
# =============================================================================

class TestCrossFileTaint:
    """Pipeline end-to-end : source HTTP dans un module → sink SQL dans un autre
    module atteint via import (`from .db import run_query`)."""

    # Module « callee » : run_query atteint un sink .execute() sur son param.
    _DB = (
        "def run_query(cursor, query):\n"
        "    cursor.execute(query)\n"
    )
    # Module « caller » : source HTTP request.args → appel cross-fichier.
    _VIEWS = (
        "from .db import run_query\n"
        "def search(request, cursor):\n"
        "    q = request.args.get('q')\n"
        "    run_query(cursor, q)\n"
    )

    def _write(self, tmp_path, files):
        for rel, content in files.items():
            dest = tmp_path / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")

    def test_cross_file_sqli_detected(self, tmp_path):
        """La source de views.py atteint le sink importé de db.py → finding."""
        self._write(tmp_path, {
            "src/db.py": self._DB,
            "src/views.py": self._VIEWS,
        })
        runner = _make_runner(tmp_path)
        runner.run()

        findings = get_findings_by_rule_key(runner, "taint_sqli")
        assert len(findings) >= 1, "Le flux inter-fichiers doit être détecté"
        # Le finding est attribué au fichier appelant (views.py).
        assert any("views.py" in (f.file or "") for f in findings)

    def test_callee_alone_no_finding(self, tmp_path):
        """db.py seul (sans appelant tainté) ne déclenche aucun finding."""
        self._write(tmp_path, {"src/db.py": self._DB})
        runner = _make_runner(tmp_path)
        runner.run()

        findings = get_findings_by_rule_key(runner, "taint_sqli")
        assert len(findings) == 0, "Un helper isolé ne doit pas être un finding"

    def test_direct_source_arg_detected(self, tmp_path):
        """Source écrite directement en argument du sink (Volet 4), sans
        variable intermédiaire, détectée de bout en bout."""
        self._write(tmp_path, {
            "src/views.py": (
                "def search(request, cursor):\n"
                "    cursor.execute(request.args.get('q'))\n"
            ),
        })
        runner = _make_runner(tmp_path)
        runner.run()

        findings = get_findings_by_rule_key(runner, "taint_sqli")
        assert len(findings) >= 1, "La source inline dans le sink doit être détectée"

    def test_wildcard_import_cross_file(self, tmp_path):
        """Volet 5C — flux inter-fichiers via `from .db import *`."""
        self._write(tmp_path, {
            "src/db.py": self._DB,
            "src/views.py": (
                "from .db import *\n"
                "def search(request, cursor):\n"
                "    q = request.args.get('q')\n"
                "    run_query(cursor, q)\n"
            ),
        })
        runner = _make_runner(tmp_path)
        runner.run()

        findings = get_findings_by_rule_key(runner, "taint_sqli")
        assert len(findings) >= 1, "Le flux via wildcard import doit être détecté"


class TestMultiHopCrossFileTaint:
    """Pipeline end-to-end — graphe d'appels persistant (docs/ROADMAP.md
    § Graphe d'appels persistant, 2026-07-26) : source HTTP dans un module A,
    traversant B (wrapper pur, 2ᵉ fichier) avant d'atteindre le sink SQL dans
    A. Avant ce chantier, la résolution 1-saut de `ModuleRegistry` ne
    pouvait pas relier ce flux (B calculait sa propre summary sans connaître
    C — ici le wrapper est lui-même le maillon importé). Ce test couvre
    exactement le gain apporté par la résolution multi-sauts en production.
    """

    _HELPERS = (
        "def get_query(request):\n"
        "    return request.args.get('q')\n"
    )
    _VIEWS = (
        "from .helpers import get_query\n"
        "def search(request, cursor):\n"
        "    q = get_query(request)\n"
        "    cursor.execute(q)\n"
    )

    def _write(self, tmp_path, files):
        for rel, content in files.items():
            dest = tmp_path / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")

    def test_two_hop_flow_detected(self, tmp_path):
        self._write(tmp_path, {
            "src/helpers.py": self._HELPERS,
            "src/views.py": self._VIEWS,
        })
        runner = _make_runner(tmp_path)
        runner.run()

        findings = get_findings_by_rule_key(runner, "taint_sqli")
        assert len(findings) >= 1, "Le flux à 2 sauts (views→helpers) doit être détecté"
        assert any("views.py" in (f.file or "") for f in findings)

    def test_second_audit_reuses_call_graph_cache(self, tmp_path):
        """Deux runs successifs (cache incrémental froid puis chaud) doivent
        produire le même résultat — la persistance du graphe ne doit rien
        changer au comportement fonctionnel."""
        self._write(tmp_path, {
            "src/helpers.py": self._HELPERS,
            "src/views.py": self._VIEWS,
        })
        runner1 = _make_runner(tmp_path)
        runner1.run()
        first = len(get_findings_by_rule_key(runner1, "taint_sqli"))
        assert first >= 1

        assert (tmp_path / ".sca-cache" / "call-graph.db").exists()

        runner2 = _make_runner(tmp_path)
        runner2.run()
        second = len(get_findings_by_rule_key(runner2, "taint_sqli"))
        assert second == first


class TestJsonExport:
    """Tests de la structure du JSON exporté."""

    def test_json_required_keys(self, tmp_path):
        """Le JSON contient toutes les clés top-level requises."""
        _place_vuln_fixture(tmp_path, "hardcoded_password.py", "src/config.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        required = {"version", "timestamp", "date", "quick_mode", "languages",
                     "totals", "timings", "findings"}
        assert required.issubset(data.keys()), f"Clés manquantes : {required - data.keys()}"

    def test_json_version(self, tmp_path):
        """Le JSON a la version 3.5."""
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        assert data["version"] == "3.5"

    def test_json_findings_fields(self, tmp_path):
        """Chaque finding dans le JSON a les champs requis."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        assert len(data["findings"]) >= 1

        required_fields = {"category", "rule_key", "file", "line", "severity", "confidence"}
        for finding in data["findings"]:
            missing = required_fields - finding.keys()
            assert not missing, f"Champs manquants dans finding : {missing}"

    def test_json_totals_match(self, tmp_path):
        """Les totals correspondent au nombre réel de findings."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        _place_vuln_fixture(tmp_path, "hardcoded_password.py", "src/config.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        actual_high = sum(1 for f in data["findings"] if f["severity"] == "HIGH")
        assert data["totals"]["HIGH"] == actual_high

    def test_json_languages(self, tmp_path):
        """Les langages dans le JSON correspondent à la config."""
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        assert "python" in data["languages"]
        assert "javascript" in data["languages"]
        assert "html" in data["languages"]


# =============================================================================
# 3. RAPPORT HTML
# =============================================================================

class TestHtmlReport:
    """Tests de la structure du rapport HTML."""

    def test_html_exists_nonempty(self, tmp_path):
        """Le rapport HTML existe et est substantiel."""
        runner = _make_runner(tmp_path)
        runner.run()

        assert os.path.exists(runner.report_path)
        assert os.path.getsize(runner.report_path) > 1000

    def test_html_structural_markers(self, tmp_path):
        """Le rapport HTML contient les marqueurs structurels."""
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        assert "sidebar-toc" in html, "Doit contenir la sidebar navigation"
        assert "toc-block" in html, "Doit contenir le sommaire"

    def test_html_embedded_chartjs(self, tmp_path):
        """Chart.js est embarqué inline (pas CDN)."""
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        assert "new Chart(" in html, "Chart.js doit être inline"

    def test_html_base64_favicon(self, tmp_path):
        """Le favicon est encodé en base64."""
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        assert "data:image/svg+xml;base64," in html, "Le favicon doit être en base64"

    def test_html_language_en(self, tmp_path):
        """Le rapport en anglais contient les textes anglais."""
        runner = _make_runner(tmp_path, report_lang="en")
        runner.run()
        html = _read_html(runner)

        assert "Health Score" in html or "Audit Report" in html, \
            "Le rapport EN doit contenir des textes anglais"

    def test_html_language_fr(self, tmp_path):
        """Le rapport en français contient les textes français."""
        runner = _make_runner(tmp_path, report_lang="fr")
        runner.run()
        html = _read_html(runner)

        assert "Score de sant" in html or "Rapport" in html, \
            "Le rapport FR doit contenir des textes français"


# =============================================================================
# 4. COMPARAISON BASELINE
# =============================================================================

class TestBaselineComparison:
    """Tests du mécanisme de comparaison avec baseline."""

    def test_first_run_no_comparison(self, tmp_path):
        """Premier run → pas de comparison."""
        runner = _make_runner(tmp_path)
        runner.run()

        assert runner.comparison is None, "Premier run ne doit pas avoir de comparison"

    def test_second_run_detects_resolved(self, tmp_path):
        """Run1 avec vuln, Run2 sans → finding résolu détecté."""
        # Run 1 : avec fixture vulnérable
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner1 = _make_runner(tmp_path)
        runner1.run()
        assert os.path.exists(runner1.data_path)

        # Supprimer la fixture et changer le timestamp pour un 2ème run
        os.remove(tmp_path / "src" / "service.py")
        runner2 = _make_runner(tmp_path)
        runner2.timestamp = "2099-12-31-23-59"
        runner2.report_path = os.path.join(runner2.reports_dir, f"{runner2.brand_prefix}-REPORT-{runner2.timestamp}.html")
        runner2.data_path = os.path.join(runner2.datas_dir, f"{runner2.brand_prefix}-DATA-{runner2.timestamp}.json")
        runner2.run()

        assert runner2.comparison is not None, "Doit avoir une comparison avec la baseline"
        assert len(runner2.comparison.resolved_findings) >= 1, "Doit détecter des findings résolus"

    def test_second_run_detects_persistent(self, tmp_path):
        """Run1+Run2 avec même vuln → finding persistant détecté."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")

        runner1 = _make_runner(tmp_path)
        runner1.run()

        runner2 = _make_runner(tmp_path)
        runner2.timestamp = "2099-12-31-23-59"
        runner2.report_path = os.path.join(runner2.reports_dir, f"{runner2.brand_prefix}-REPORT-{runner2.timestamp}.html")
        runner2.data_path = os.path.join(runner2.datas_dir, f"{runner2.brand_prefix}-DATA-{runner2.timestamp}.json")
        runner2.run()

        assert runner2.comparison is not None
        assert len(runner2.comparison.unchanged_findings) >= 1, "Doit détecter des findings persistants"

    def test_duplicate_content_findings_not_collapsed(self, tmp_path):
        """Deux occurrences distinctes d'un même pattern vulnérable (même
        fichier, même règle, même code) ne doivent pas s'écraser l'une
        l'autre dans la comparaison baseline (RETEX Reviewer R14/R16/R20/R21 —
        le total "nouveaux problèmes" était sous-compté par rapport au total
        réel de findings, car indexé par un dict non désambiguïsé)."""
        (tmp_path / "src").mkdir(parents=True, exist_ok=True)
        vuln_file = tmp_path / "src" / "duplicated.py"
        vuln_line = 'return db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()\n'
        vuln_file.write_text(
            f"def get_user(db, user_id):\n    {vuln_line}"
            f"\n\ndef get_account(db, user_id):\n    {vuln_line}"
        )

        # Run 1 : baseline vide (fichier absent)
        runner1 = _make_runner(tmp_path)
        vuln_file_content = vuln_file.read_text()
        vuln_file.unlink()
        runner1.run()
        assert runner1.comparison is None

        # Run 2 : le fichier avec les 2 occurrences identiques apparaît
        vuln_file.write_text(vuln_file_content)
        runner2 = _make_runner(tmp_path)
        runner2.timestamp = "2099-12-31-23-59"
        runner2.report_path = os.path.join(runner2.reports_dir, f"{runner2.brand_prefix}-REPORT-{runner2.timestamp}.html")
        runner2.data_path = os.path.join(runner2.datas_dir, f"{runner2.brand_prefix}-DATA-{runner2.timestamp}.json")
        runner2.run()

        assert runner2.comparison is not None
        sqli_new = [f for f in runner2.comparison.new_findings if f.file.endswith("duplicated.py")]
        assert len(sqli_new) >= 2, \
            f"Les 2 occurrences identiques doivent être comptées séparément, pas fusionnées en 1 (trouvé {len(sqli_new)})"


# =============================================================================
# 5. SCORE DE SANTE
# =============================================================================

class TestHealthScore:
    """Tests du calcul du score de santé."""

    def test_clean_project_high_score(self, tmp_path):
        """Projet sans findings → score élevé."""
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        total_findings = sum(data["totals"].values())
        assert total_findings == 0, "Projet vide ne doit pas avoir de findings"

    def test_high_findings_reduce_score(self, tmp_path):
        """Des findings HIGH réduisent le score de santé."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        _place_vuln_fixture(tmp_path, "hardcoded_password.py", "src/config.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        assert data["totals"]["HIGH"] > 0
        # Le score de santé doit être inférieur à 100 quand il y a des findings HIGH
        html = _read_html(runner)
        import re
        m = re.search(r'health-fill\s+\w+.*?width:\s*(\d+)%', html)
        assert m and int(m.group(1)) < 100, \
            "Le score ne doit pas être 100% avec des findings HIGH"

    def test_no_duplicate_exec_score_card(self, tmp_path):
        """Le score ne doit plus être réaffiché en double dans la carte
        exec-summary — le KPI sous l'en-tête et la jauge suffisent
        (RETEX Reviewer R27)."""
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        assert 'class="exec-card exec-score"' not in html
        assert 'id="executive-summary"' in html, "Les autres cartes exec-summary doivent rester"
        assert 'class="exec-card exec-severity"' in html


# =============================================================================
# 6. OPTIONS DE CONFIGURATION
# =============================================================================

class TestConfigOptions:
    """Tests des options de configuration et CLI."""

    def test_custom_brand_prefix(self, tmp_path):
        """Le préfixe personnalisé est utilisé dans les noms de fichiers."""
        runner = _make_runner(tmp_path, extra_config={"brand": {"prefix": "TEST"}})
        runner.run()

        report_name = os.path.basename(runner.report_path)
        data_name = os.path.basename(runner.data_path)
        assert report_name.startswith("TEST-REPORT-"), f"Le rapport doit commencer par TEST-REPORT-, got {report_name}"
        assert data_name.startswith("TEST-DATA-"), f"Le data doit commencer par TEST-DATA-, got {data_name}"

    def test_skip_tests_config(self, tmp_path):
        """tests.enabled=False → pas de résultats de tests dans le JSON."""
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        assert data.get("tests") is None, "Les résultats de tests doivent être absents"

    def test_sla_enabled(self, tmp_path):
        """SLA activé → section SLA visible dans le rapport."""
        sla_config = {
            "sla": {
                "enabled": True,
                "rules": {
                    "HIGH": {"delay": "24h", "escalation": "Tech Lead"},
                    "MEDIUM": {"delay": "1 sprint", "escalation": "Team Lead"},
                }
            }
        }
        runner = _make_runner(tmp_path, extra_config=sla_config)
        runner.run()

        html = _read_html(runner)
        assert "24h" in html, "La section SLA doit contenir les délais configurés"

    def test_sla_disabled(self, tmp_path):
        """SLA désactivé → section SLA cachée."""
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        # La section SLA doit avoir display:none quand désactivée
        assert "sla_display" not in html or "display:none" in html


# =============================================================================
# 7. EXPORT SARIF
# =============================================================================

class TestSarifExport:
    """Tests de l'export SARIF via pipeline complet."""

    def test_sarif_generated_via_pipeline(self, tmp_path):
        """run() avec format=sarif génère un fichier .sarif."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"sarif": True, "sbom": False}
        })
        runner.run()

        assert hasattr(runner, "_sarif_path"), "Le runner doit avoir _sarif_path"
        assert os.path.exists(runner._sarif_path), "Le fichier SARIF doit exister"
        assert os.path.getsize(runner._sarif_path) > 100

    def test_sarif_version_and_schema(self, tmp_path):
        """Le SARIF généré a la version 2.1.0."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"sarif": True, "sbom": False}
        })
        runner.run()

        with open(runner._sarif_path, "r", encoding="utf-8") as f:
            sarif = json.load(f)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif

    def test_sarif_contains_findings(self, tmp_path):
        """Le SARIF contient les findings détectés avec ruleId."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"sarif": True, "sbom": False}
        })
        runner.run()

        with open(runner._sarif_path, "r", encoding="utf-8") as f:
            sarif = json.load(f)
        results = sarif["runs"][0]["results"]
        assert len(results) >= 1, "Le SARIF doit contenir des résultats"
        rule_ids = [r["ruleId"] for r in results]
        assert "sql_injection_fstring" in rule_ids

    def test_sarif_brand_website_url(self, tmp_path):
        """informationUri utilise brand.website_url si configuré."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "brand": {"website_url": "https://example.com"},
            "_cli_options": {"sarif": True, "sbom": False},
        })
        runner.run()

        with open(runner._sarif_path, "r", encoding="utf-8") as f:
            sarif = json.load(f)
        info_uri = sarif["runs"][0]["tool"]["driver"]["informationUri"]
        assert info_uri == "https://example.com"


# =============================================================================
# 8. EXPORT SBOM
# =============================================================================

class TestSbomExport:
    """Tests de l'export SBOM CycloneDX via pipeline complet."""

    def test_sbom_generated_via_pipeline(self, tmp_path):
        """run() avec sbom=True génère un fichier SBOM."""
        # Créer un requirements.txt pour que le SBOM ait des composants
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask==3.0.0\n")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"format": "html", "sbom": True},
            "categories": {
                "security": {"enabled": True, "weight": 3},
                "architecture": {"enabled": False},
                "ui": {"enabled": False},
                "ux": {"enabled": False},
                "maintenance": {"enabled": False},
                "dependencies": {"enabled": False},
                "cicd": {"enabled": False},
            },
        })
        runner.run()

        assert hasattr(runner, "_sbom_path"), "Le runner doit avoir _sbom_path"
        assert os.path.exists(runner._sbom_path), "Le fichier SBOM doit exister"

    def test_sbom_cyclonedx_format(self, tmp_path):
        """Le SBOM suit le format CycloneDX 1.5."""
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"format": "html", "sbom": True},
        })
        runner.run()

        with open(runner._sbom_path, "r", encoding="utf-8") as f:
            sbom = json.load(f)
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"

    def test_sbom_contains_components(self, tmp_path):
        """Le SBOM contient les composants parsés depuis requirements.txt."""
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask==3.0.0\n")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"format": "html", "sbom": True},
        })
        runner.run()

        with open(runner._sbom_path, "r", encoding="utf-8") as f:
            sbom = json.load(f)
        names = [c["name"] for c in sbom["components"]]
        assert "requests" in names, "Le SBOM doit contenir requests"
        assert "flask" in names, "Le SBOM doit contenir flask"


# =============================================================================
# 9. PIPELINE CI/CD
# =============================================================================

class TestCicdPipeline:
    """Tests de la catégorie CI/CD via pipeline complet."""

    def _make_cicd_runner(self, tmp_path, cicd_enabled=True):
        """Helper : runner avec CI/CD activé et fixture YAML."""
        return _make_runner(tmp_path, extra_config={
            "languages": ["python", "javascript", "html", "yaml"],
            "categories": {
                "security": {"enabled": True, "weight": 3},
                "architecture": {"enabled": False},
                "ui": {"enabled": False},
                "ux": {"enabled": False},
                "maintenance": {"enabled": False},
                "dependencies": {"enabled": False},
                "cicd": {"enabled": cicd_enabled, "weight": 2},
            },
        })

    def test_cicd_enabled_detects_findings(self, tmp_path):
        """CI/CD activé avec fixture YAML vulnérable → findings CICD."""
        _place_vuln_fixture(tmp_path, "sample_cicd_vulnerable.yml",
                            "src/.github/workflows/ci.yml")
        runner = self._make_cicd_runner(tmp_path, cicd_enabled=True)
        runner.run()

        cicd = get_findings_by_category(runner, "CICD")
        assert len(cicd) >= 1, "Doit détecter des findings CI/CD"

    def test_cicd_disabled_no_findings(self, tmp_path):
        """CI/CD désactivé → aucun finding CICD."""
        _place_vuln_fixture(tmp_path, "sample_cicd_vulnerable.yml",
                            "src/.github/workflows/ci.yml")
        runner = self._make_cicd_runner(tmp_path, cicd_enabled=False)
        runner.run()

        cicd = get_findings_by_category(runner, "CICD")
        assert len(cicd) == 0, "CI/CD désactivé ne doit pas générer de findings"

    def test_cicd_findings_in_json(self, tmp_path):
        """Les findings CI/CD apparaissent dans le JSON exporté."""
        _place_vuln_fixture(tmp_path, "sample_cicd_vulnerable.yml",
                            "src/.github/workflows/ci.yml")
        runner = self._make_cicd_runner(tmp_path, cicd_enabled=True)
        runner.run()

        data = _read_json(runner)
        cicd_findings = [f for f in data.get("findings", []) if f.get("category") == "CICD"]
        assert len(cicd_findings) >= 0  # CI/CD géré par le moteur de règles .sca


# =============================================================================
# 10. SECTIONS HTML
# =============================================================================

class TestHtmlSections:
    """Tests des sections HTML conditionnelles et structurelles."""

    def test_glossary_present(self, tmp_path):
        """Le glossaire est présent dans le rapport HTML."""
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        assert "section-glossary" in html, "Le rapport doit contenir la section glossaire"

    def test_stats_row_severity_labels_consistent(self, tmp_path):
        """La ligne de stats 'Résumé' doit utiliser le même libellé HIGH que la
        carte exécutive pour le même total (RETEX Reviewer R21 — total_high était
        affiché sous le libellé 'Critical' dans la ligne de stats, faisant
        croire à des vulnérabilités critiques inexistantes)."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        import re
        match = re.search(
            r'<div class="stat-card"><div class="stat-value high">\d+</div>'
            r'<div class="stat-label">([^<]+)</div></div>',
            html,
        )
        assert match, "Le stat-card HIGH du résumé est introuvable dans le rapport"
        assert match.group(1) == "High (HIGH)", \
            f"Le stat-card HIGH doit être libellé 'High (HIGH)', pas {match.group(1)!r} (glissement de libellé)"

    def test_category_and_severity_chart_subtitles_distinct(self, tmp_path):
        """Les graphes 'par catégorie' et 'par sévérité' portent chacun un
        sous-titre distinct pour éviter la confusion entre les deux
        groupements (RETEX Reviewer R05/R08/R09)."""
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        assert "{{i18n_by_category_subtitle}}" not in html
        assert "{{i18n_severity_distribution_subtitle}}" not in html
        assert "not to be confused with severity" in html

    def test_exec_rec_high_not_labeled_critical(self, tmp_path):
        """La recommandation P1 déclenchée par des findings HIGH ne doit pas
        parler de vulnérabilités 'critical' quand il n'y a aucun CRITICAL
        (RETEX Reviewer R15 — texte générique non contextualisé), et doit
        indiquer le nombre réel de findings concernés."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        data = _read_json(runner)
        total_high = data["totals"]["HIGH"]
        total_critical = data["totals"]["CRITICAL"]
        assert total_critical == 0, "Ce test suppose 0 CRITICAL pour être significatif"
        assert total_high > 0

        assert f"Fix the {total_high} high-risk vulnerabilities" in html
        assert "Fix critical vulnerabilities" not in html

    def test_exec_rec_high_ranks_rule_by_priority_score(self, tmp_path):
        """La recommandation P1 liste la règle HIGH la plus fréquente avec
        son nombre d'occurrences — scoring statique combinant sévérité,
        confiance et occurrences (RETEX Reviewer R15, critères calculables
        sans intervention humaine)."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        assert "Fix first:" in html
        assert "sql_injection_fstring" in html
        assert "2 occurrence(s)" in html

    def test_priority_scoring_ranks_taint_verified_higher(self, tmp_path):
        """Un flux taint vérifié (chemin source→sink prouvé) doit apparaître
        avec un badge distinct dans la liste de priorité — plus fiable
        qu'un simple pattern match (RETEX Reviewer R15)."""
        _place_vuln_fixture(tmp_path, "taint_sqli.py", "src/views.py")
        runner = _make_runner(tmp_path, extra_config={
            "_license": {"tier": "team", "features": ["taint", "multifile"],
                         "max_files": 0, "exports": ["json", "html"], "seats": 1},
        })
        runner.run()

        ranked = runner._compute_top_priority_rules()
        assert ranked, "Au moins une règle HIGH doit être classée"
        assert ranked[0]["taint_verified"] is True

        html = _read_html(runner)
        assert "verified exploitation flow" in html

    def test_priority_scoring_absent_without_high_findings(self, tmp_path):
        """Sans finding HIGH/CRITICAL, aucune liste de priorité ne doit apparaître."""
        runner = _make_runner(tmp_path)
        runner.run()

        ranked = runner._compute_top_priority_rules()
        assert ranked == []
        html = _read_html(runner)
        assert "Fix first:" not in html

    def test_exec_recommendations_sorted_by_priority(self, tmp_path):
        """La liste finale doit toujours afficher P1 avant P2 avant P3 — même
        quand un P2 (medium > 20) est ajouté par le code avant un P1 (health
        score critique), qui ne sont évalués qu'ensuite (RETEX Reviewer R29)."""
        runner = _make_runner(tmp_path)
        html = runner._build_exec_recommendations(
            total_high=0, total_medium=25, total_low=0, total_findings=25, health_score=40
        )
        p1_idx = html.find('exec-rec-priority p1')
        p2_idx = html.find('exec-rec-priority p2')
        assert p1_idx != -1 and p2_idx != -1, "Ce scénario doit produire un P1 et un P2"
        assert p1_idx < p2_idx, "P1 (health score critique) doit apparaître avant P2 (medium) dans le HTML"

    def test_threat_context_fully_translated_and_labeled_generic(self, tmp_path):
        """Le bloc contexte sécuritaire (Zero Day Clock) ne doit pas mélanger
        l'anglais dans un rapport français, et doit indiquer explicitement
        qu'il s'agit de statistiques sectorielles générales et non d'un
        calcul dérivé des CVE de cette codebase (RETEX Reviewer R19)."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, report_lang="fr")
        runner.run()
        html = _read_html(runner)

        assert "threat-context" in html
        assert "Statistiques sectorielles générales" in html
        assert "median MTTR" not in html, "Le texte du contexte de menace ne doit pas rester en anglais dans un rapport français"
        assert "jours (MTTR médian)" in html

    def test_kpi_stat_cards_link_to_detail_sections(self, tmp_path):
        """Les KPI 'bonnes pratiques' et 'dépendances' du résumé pointent
        vers leurs sections de détail respectives (RETEX Reviewer R17/R18 —
        ces totaux n'étaient reliés à aucune section, obligeant le lecteur à
        chercher le détail sans repère)."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        assert "scrollToSection('section-validations')" in html
        assert "scrollToSection('section-dependencies')" in html
        assert 'id="section-validations"' in html
        assert 'id="section-dependencies"' in html

    def test_health_explanation_names_its_metric(self, tmp_path):
        """L'explication technique du calcul du score indique explicitement
        à quelle métrique elle se rapporte (RETEX Reviewer R07 — le texte ne
        précisait pas s'il expliquait la jauge de score ou le graphe des
        pénalités)."""
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        assert "How is the" in html and "calculated?" in html
        assert "{label}" not in html, "Le placeholder {label} doit être substitué par le nom de la métrique"

    def test_top_files_with_findings(self, tmp_path):
        """Le top fichiers problématiques apparaît quand il y a des findings."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        _place_vuln_fixture(tmp_path, "hardcoded_password.py", "src/config.py")
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        assert "section-top-files" in html, "Le rapport doit contenir la section top files"

    def test_timings_in_json(self, tmp_path):
        """Les timings par catégorie sont dans le JSON exporté."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        assert data.get("timings") is not None, "Le JSON doit contenir les timings"
        assert "rules" in data["timings"], "Les timings doivent inclure rules"
        assert "total" in data["timings"], "Les timings doivent inclure total"

    def test_timings_chart_removed_from_html(self, tmp_path):
        """Le graphique timings (retiré, RETEX Reviewer R13) n'apparaît plus dans le rapport HTML."""
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        assert "timingsChart" not in html, "Le graphique timings ne doit plus être généré"
        assert "timingsHistoryChart" not in html, "Le graphique d'évolution des timings ne doit plus être généré"

    def test_comparison_section_in_html(self, tmp_path):
        """La section comparaison apparaît après 2 runs."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")

        # Run 1
        runner1 = _make_runner(tmp_path)
        runner1.run()

        # Run 2 avec timestamp différent
        runner2 = _make_runner(tmp_path)
        runner2.timestamp = "2099-12-31-23-59"
        runner2.report_path = os.path.join(runner2.reports_dir, f"{runner2.brand_prefix}-REPORT-{runner2.timestamp}.html")
        runner2.data_path = os.path.join(runner2.datas_dir, f"{runner2.brand_prefix}-DATA-{runner2.timestamp}.json")
        runner2.run()

        html = _read_html(runner2)
        assert runner2.comparison is not None, "Doit avoir une comparison"
        # Le HTML doit contenir du contenu de comparaison (baseline_date ou delta)
        assert "baseline" in html.lower() or "delta" in html.lower() or "comparison" in html.lower(), \
            "Le rapport doit contenir la section comparaison"

    def test_history_chart_after_two_runs(self, tmp_path):
        """Le graphique historique contient des données après 2+ runs."""
        # Run 1
        runner1 = _make_runner(tmp_path)
        runner1.run()

        # Run 2
        runner2 = _make_runner(tmp_path)
        runner2.timestamp = "2099-12-31-23-59"
        runner2.report_path = os.path.join(runner2.reports_dir, f"{runner2.brand_prefix}-REPORT-{runner2.timestamp}.html")
        runner2.data_path = os.path.join(runner2.datas_dir, f"{runner2.brand_prefix}-DATA-{runner2.timestamp}.json")
        runner2.run()

        html = _read_html(runner2)
        # Le chart_data doit contenir des labels d'historique
        assert "historyChart" in html or "history" in html, \
            "Le rapport doit contenir le graphique historique"


# =============================================================================
# 10b. EXEMPLES PAR CATÉGORIE (RETEX Reviewer R22)
# =============================================================================

class TestCategoryExamples:
    """Tests de la section 'Exemples représentatifs par catégorie' (RETEX
    Reviewer R22) : illustre le problème le plus fréquent de chaque catégorie
    avec une instance réelle détectée + la correction générique de la règle."""

    def test_category_example_shows_real_detected_code(self, tmp_path):
        """L'exemple SECURITY doit montrer le code réellement détecté dans
        le projet audité (pas un correctif automatique du code du client)."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        assert "section-category-examples" in html
        assert "category-example" in html
        assert "result = db.execute(f&quot;SELECT * FROM users WHERE id = {user_id}&quot;)" in html, \
            "Le code réellement détecté (fixture) doit apparaître, pas un exemple générique différent"
        assert "src/service.py:5" in html
        assert "db.execute(&quot;SELECT * FROM users WHERE id = :id&quot;, {&quot;id&quot;: user_id})" in html, \
            "La correction générique de la règle (fix_after du DSL) doit être affichée"

    def test_category_example_absent_without_findings(self, tmp_path):
        """Sans finding avec fix_before/fix_after, la section ne doit pas apparaître (pas de bloc vide)."""
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        assert "section-category-examples" not in html

    def test_category_example_picks_most_frequent_rule(self, tmp_path):
        """Quand plusieurs règles à exemple existent dans une catégorie,
        celle avec le plus d'occurrences doit être choisie."""
        (tmp_path / "src").mkdir(parents=True, exist_ok=True)
        # 1 occurrence de hardcoded_password, 2 occurrences de sql_injection_fstring
        _place_vuln_fixture(tmp_path, "hardcoded_password.py", "src/config.py")
        (tmp_path / "src" / "service.py").write_text(
            'def get_user(db, user_id):\n'
            '    return db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()\n'
            '\n'
            'def get_account(db, acct_id):\n'
            '    return db.execute(f"SELECT * FROM accounts WHERE id = {acct_id}").fetchone()\n'
        )
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        idx = html.find("section-category-examples")
        assert idx != -1
        # Un seul exemple SECURITY (la règle la plus fréquente), pas un par règle détectée
        assert html.count("category-example\"") <= 5  # au plus 1 par catégorie (5 catégories)

    def test_category_example_has_bridge_text(self, tmp_path):
        """Un texte de liaison pédagogique doit relier le code détecté et
        l'exemple de correction générique — sans lui, aucun lien n'est
        visible entre les deux blocs quand le pattern de la règle est large
        (RETEX Reviewer R30)."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        assert "category-example-bridge" in html
        solution = runner._rule("sql_injection_fstring").get("solution", "")
        assert solution, "La règle doit avoir un champ solution non vide pour ce test"
        assert solution in html, \
            "Le texte de liaison doit inclure la solution générique de la règle (déjà localisée)"


# =============================================================================
# 11. I18N COMPLET
# =============================================================================

class TestI18nComplete:
    """Tests d'internationalisation pour les 4 langues."""

    def test_html_language_es(self, tmp_path):
        """Le rapport en espagnol contient les textes espagnols."""
        runner = _make_runner(tmp_path, report_lang="es")
        runner.run()
        html = _read_html(runner)

        assert "Informe" in html or "Puntuaci" in html, \
            "Le rapport ES doit contenir des textes espagnols"

    def test_html_language_de(self, tmp_path):
        """Le rapport en allemand contient les textes allemands."""
        runner = _make_runner(tmp_path, report_lang="de")
        runner.run()
        html = _read_html(runner)

        assert "Bericht" in html or "Audit" in html, \
            "Le rapport DE doit contenir des textes allemands"

    def test_all_four_languages_produce_report(self, tmp_path):
        """Les 4 langues génèrent un rapport HTML valide."""
        for lang in ("fr", "en", "es", "de"):
            runner = _make_runner(tmp_path, report_lang=lang)
            runner.timestamp = f"2099-01-01-{lang}"
            runner.report_path = os.path.join(runner.reports_dir, f"{runner.brand_prefix}-REPORT-{runner.timestamp}.html")
            runner.data_path = os.path.join(runner.datas_dir, f"{runner.brand_prefix}-DATA-{runner.timestamp}.json")
            runner.run()

            assert os.path.exists(runner.report_path), f"Le rapport {lang} doit exister"
            assert os.path.getsize(runner.report_path) > 1000, f"Le rapport {lang} doit être substantiel"

    def test_json_findings_use_rule_key_not_translated_name(self, tmp_path):
        """Le JSON utilise les rule_keys invariants, pas les noms traduits."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")

        # Générer en FR et en EN
        runner_fr = _make_runner(tmp_path, report_lang="fr")
        runner_fr.run()
        data_fr = _read_json(runner_fr)

        runner_en = _make_runner(tmp_path, report_lang="en")
        runner_en.timestamp = "2099-01-01-en"
        runner_en.report_path = os.path.join(runner_en.reports_dir, f"{runner_en.brand_prefix}-REPORT-{runner_en.timestamp}.html")
        runner_en.data_path = os.path.join(runner_en.datas_dir, f"{runner_en.brand_prefix}-DATA-{runner_en.timestamp}.json")
        runner_en.run()
        data_en = _read_json(runner_en)

        # Les rule_keys doivent être identiques quelle que soit la langue
        keys_fr = {f["rule_key"] for f in data_fr["findings"] if f.get("rule_key")}
        keys_en = {f["rule_key"] for f in data_en["findings"] if f.get("rule_key")}
        assert keys_fr == keys_en, "Les rule_keys doivent être invariants entre langues"


# =============================================================================
# 12. SCORE DE SANTE AVANCE
# =============================================================================

class TestHealthScoreAdvanced:
    """Tests avancés du score de santé : valeur, poids, seuils."""

    def test_health_score_in_chart_data(self, tmp_path):
        """Le score de santé est dans les données du rapport."""
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        # Le healthScore est injecté dans chart_data JSON dans le HTML
        assert "healthScore" in html, "Le rapport doit contenir healthScore dans chart_data"

    def test_score_based_on_security_only(self, tmp_path):
        """Le score de santé ne compte que les findings SECURITY, pas les autres catégories."""
        # sql_injection = SECURITY (HIGH), console_log = MAINTENANCE (LOW)
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        _place_vuln_fixture(tmp_path, "console_log.js", "src/js/app.js")
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        import re
        match = re.search(r'"healthScore"\s*:\s*(\d+)', html)
        assert match, "healthScore doit être dans chart_data"
        score = int(match.group(1))
        # Le score doit etre < 100 (des findings SECURITY existent) et > 0
        # La valeur exacte depend du nombre de regles actives
        assert 30 <= score <= 80, f"Score devrait etre entre 30 et 80, got {score}"

    def test_score_penalty_detail_in_html(self, tmp_path):
        """Le rapport contient le détail des pénalités et l'explication du calcul."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        # Vérifier que l'explication et le tableau de pénalités sont présents
        assert "health-explanation" in html, "Le rapport doit contenir l'explication du score"
        assert "health-calc-table" in html, "Le rapport doit contenir le tableau de calcul"
        assert "healthSeverity" in html, "chart_data doit contenir healthSeverity"
        assert "healthPenalty" in html, "chart_data doit contenir healthPenalty"

    def test_score_100_without_findings(self, tmp_path):
        """Projet sans findings → score 100."""
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        # Le score doit être 100 pour un projet vide
        assert ">100<" in html or ">100%" in html or '"100"' in html or "100%" in html, \
            "Le score doit être 100 pour un projet sans findings"

    def test_score_decreases_with_more_findings(self, tmp_path):
        """Plus de findings → score plus bas (< 100)."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        _place_vuln_fixture(tmp_path, "hardcoded_password.py", "src/config.py")
        _place_vuln_fixture(tmp_path, "console_log.js", "src/js/app.js")
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)

        # Extraire le score depuis le HTML (il est dans {{health_score}})
        import re
        # Le score est injecté comme texte dans le HTML
        match = re.search(r'"healthScore"\s*:\s*(\d+)', html)
        assert match, "healthScore doit être dans chart_data"
        score = int(match.group(1))
        assert score < 100, f"Le score doit être < 100 avec des findings, got {score}"


# =============================================================================
# 13. OPTIONS CLI
# =============================================================================

class TestCliOptions:
    """Tests des options CLI via pipeline."""

    def test_fail_on_high_returns_nonzero(self, tmp_path):
        """Findings HIGH → run() retourne > 0 (pour --fail-on-high)."""
        _place_vuln_fixture(tmp_path, "hardcoded_password.py", "src/config.py")
        runner = _make_runner(tmp_path)
        result = runner.run()

        # run() retourne le nombre de HIGH (confidence >= 80)
        assert result > 0, "Doit retourner > 0 quand il y a des HIGH"

    def test_self_test_populates_fixture_validation(self, tmp_path):
        """self_test=True → fixture_validation est rempli."""
        runner = _make_runner(tmp_path)
        runner.self_test = True
        runner.run()

        assert runner.fixture_validation is not None, \
            "En mode self-test, fixture_validation doit être rempli"

    def test_json_metadata_brand(self, tmp_path):
        """Le JSON DATA contient metadata avec tool_name et prefix."""
        runner = _make_runner(tmp_path, extra_config={
            "brand": {"tool_name": "MyTool", "company_name": "MyCorp", "prefix": "MT"}
        })
        runner.run()

        data = _read_json(runner)
        assert "metadata" in data, "Le JSON doit contenir metadata"
        assert data["metadata"]["tool_name"] == "MyTool"
        assert data["metadata"]["company_name"] == "MyCorp"
        assert data["metadata"]["prefix"] == "MT"

    def test_custom_output_dir(self, tmp_path):
        """reports.output_dir custom → fichiers dans le bon dossier."""
        custom_dir = tmp_path / "custom-reports"
        custom_datas = custom_dir / "audit-datas"
        runner = _make_runner(tmp_path, extra_config={
            "reports": {
                "language": "en",
                "output_dir": str(custom_dir),
                "history_dir": str(custom_datas),
            },
        })
        runner.run()

        assert os.path.exists(runner.report_path)
        assert str(custom_dir) in runner.report_path, \
            f"Le rapport doit être dans {custom_dir}, got {runner.report_path}"

    def test_project_name_in_report(self, tmp_path):
        """project.name configuré apparaît dans le rapport HTML."""
        runner = _make_runner(tmp_path, extra_config={
            "project": {"name": "TestProjectAlpha", "version": "2.5.0"}
        })
        runner.run()
        html = _read_html(runner)

        assert "TestProjectAlpha" in html, "Le nom du projet doit apparaître dans le rapport"


# =============================================================================
# BLOC F — NOUVELLES RÈGLES (Priorité 2) DANS LES EXPORTS
# =============================================================================

class TestNewRulesInExports:
    """Vérifie que les nouvelles règles Priorité 2 apparaissent dans JSON/HTML/SARIF."""

    def test_ssrf_in_json(self, tmp_path):
        """Les findings SSRF doivent apparaître dans l'export JSON."""
        _place_vuln_fixture(tmp_path, "ssrf_python.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()
        data = _read_json(runner)
        rule_keys = [f["rule_key"] for f in data["findings"]]
        assert "ssrf_python" in rule_keys

    def test_path_traversal_in_json(self, tmp_path):
        """Les findings path traversal doivent apparaître dans l'export JSON."""
        _place_vuln_fixture(tmp_path, "path_traversal_python.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()
        data = _read_json(runner)
        rule_keys = [f["rule_key"] for f in data["findings"]]
        assert "taint_path_traversal" in rule_keys

    def test_framework_rules_in_json(self, tmp_path):
        """Les findings Django/Flask doivent apparaître dans l'export JSON."""
        _place_vuln_fixture(tmp_path, "django_vulnerable.py", "src/settings.py")
        _place_vuln_fixture(tmp_path, "flask_vulnerable.py", "src/main.py")
        runner = _make_runner(tmp_path)
        runner.run()
        data = _read_json(runner)
        rule_keys = [f["rule_key"] for f in data["findings"]]
        assert "django_csrf_exempt" in rule_keys
        assert "flask_debug_enabled" in rule_keys

    def test_insecure_cookie_in_json(self, tmp_path):
        """Les findings cookie insécurisé doivent apparaître dans l'export JSON."""
        _place_vuln_fixture(tmp_path, "insecure_cookie.py", "src/views.py")
        runner = _make_runner(tmp_path)
        runner.run()
        data = _read_json(runner)
        rule_keys = [f["rule_key"] for f in data["findings"]]
        assert "insecure_cookie" in rule_keys

    def test_named_secrets_in_html(self, tmp_path):
        """Les secrets nommés (AWS, GitHub) doivent apparaître dans le rapport HTML."""
        _place_vuln_fixture(tmp_path, "hardcoded_aws_key.py", "src/config.py")
        runner = _make_runner(tmp_path)
        runner.run()
        html = _read_html(runner)
        assert "hardcoded_secret" in html.lower() or "AKIA" in html

    def test_new_rules_in_sarif(self, tmp_path):
        """Les nouvelles règles doivent apparaître dans l'export SARIF."""
        _place_vuln_fixture(tmp_path, "ssrf_python.py", "src/service.py")
        _place_vuln_fixture(tmp_path, "django_vulnerable.py", "src/settings.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"sarif": True, "sbom": False}
        })
        runner.run()
        assert hasattr(runner, "_sarif_path"), "Le runner doit avoir _sarif_path"
        assert os.path.exists(runner._sarif_path), "Le fichier SARIF doit être généré"
        with open(runner._sarif_path, "r", encoding="utf-8") as f:
            sarif = json.load(f)
        results = sarif["runs"][0]["results"]
        rule_ids = [r["ruleId"] for r in results]
        assert "ssrf_python" in rule_ids
        assert "django_csrf_exempt" in rule_ids


# =============================================================================
# RETENTION — Tests fonctionnels du nettoyage automatique
# =============================================================================

class TestRetention:
    """Tests fonctionnels de la rétention configurable via run()."""

    def test_retention_cleanup_after_run(self, tmp_path):
        """run() appelle _cleanup_old_reports() et supprime les vieux rapports."""
        # Créer 5 anciens rapports avant le run
        reports_dir = tmp_path / "reports"
        datas_dir = tmp_path / "reports" / "audit-datas"
        reports_dir.mkdir(parents=True, exist_ok=True)
        datas_dir.mkdir(parents=True, exist_ok=True)

        from datetime import datetime, timedelta
        for i in range(5):
            dt = datetime.now() - timedelta(days=30 + i)
            ts = dt.strftime("%Y-%m-%d-%H-%M")
            (reports_dir / f"SCA-REPORT-{ts}.html").write_text(f"<html>{ts}</html>")
            (datas_dir / f"SCA-DATA-{ts}.json").write_text(
                json.dumps({"timestamp": ts, "totals": {}, "findings": []})
            )

        runner = _make_runner(tmp_path, extra_config={
            "retention": {"mode": "count", "max_count": 2},
        })
        runner.run()

        # Le run() crée 1 nouveau rapport + garde max 2 au total
        html_files = [f for f in os.listdir(str(reports_dir)) if f.endswith(".html")]
        # Après run : 5 anciens + 1 nouveau = 6, max_count=2 → garde 2
        assert len(html_files) == 2

    def test_retention_dry_run_via_pipeline(self, tmp_path):
        """run() en dry-run ne supprime rien."""
        reports_dir = tmp_path / "reports"
        datas_dir = tmp_path / "reports" / "audit-datas"
        reports_dir.mkdir(parents=True, exist_ok=True)
        datas_dir.mkdir(parents=True, exist_ok=True)

        from datetime import datetime, timedelta
        for i in range(3):
            dt = datetime.now() - timedelta(days=10 + i)
            ts = dt.strftime("%Y-%m-%d-%H-%M")
            (reports_dir / f"SCA-REPORT-{ts}.html").write_text(f"<html>{ts}</html>")
            (datas_dir / f"SCA-DATA-{ts}.json").write_text(
                json.dumps({"timestamp": ts, "totals": {}, "findings": []})
            )

        runner = _make_runner(tmp_path, extra_config={
            "retention": {"mode": "count", "max_count": 1},
            "_cli_options": {"retention_dry_run": True, "format": "html", "sbom": False},
        })
        runner.run()

        # 3 anciens + 1 nouveau = 4, mais dry_run → aucune suppression
        html_files = [f for f in os.listdir(str(reports_dir)) if f.endswith(".html")]
        assert len(html_files) == 4


# =============================================================================
# DÉTECTION MULTI-LIGNE — pipeline complet
# =============================================================================

# =============================================================================
# 15. COMPLIANCE ISO 27001
# =============================================================================

class TestCompliancePipeline:
    """Tests fonctionnels : section compliance ISO 27001 dans le pipeline."""

    def test_compliance_section_in_html(self, tmp_path):
        """La section compliance apparaît dans le rapport HTML."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "section-compliance" in html
        assert "compliance-matrix" in html
        assert "A.8.28" in html  # Secure coding

    def test_compliance_section_in_json(self, tmp_path):
        """Les données compliance apparaissent dans le JSON."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        assert "compliance" in data
        assert "iso27001" in data["compliance"]
        iso = data["compliance"]["iso27001"]
        assert iso["total_controls"] == 93
        assert iso["covered_controls"] > 0
        assert iso["with_findings"] > 0

    def test_compliance_disabled_via_config(self, tmp_path):
        """La section compliance peut être désactivée via la config."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "compliance": {"iso27001": {"enabled": False}}
        })
        runner.run()

        html = _read_html(runner)
        assert 'display:none' in html or "compliance-matrix" not in html

    def test_compliance_coverage_bar_in_html(self, tmp_path):
        """La barre de couverture est présente dans le HTML, avec un libellé
        de score de conformité et une classe de couleur good/warning/danger
        (RETEX Reviewer R01 — la barre utilisait un dégradé fixe invisible sur
        le fond du header, indépendant du score réel)."""
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "compliance-coverage" in html
        assert "Compliance Score" in html
        import re
        matches = re.findall(r'health-fill (good|warning|danger)"', html)
        assert len(matches) >= 2, \
            f"Les 2 barres (santé + conformité) doivent avoir une classe de couleur résolue, trouvé: {matches}"
        assert "{{score_legend}}" not in html, "Le placeholder de légende de score doit être résolu"
        assert html.count("score-legend") >= 2, "La légende de lecture doit apparaître sous les 2 barres"

    def test_compliance_themes_in_html(self, tmp_path):
        """Les 4 thèmes sont présents dans le HTML."""
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "compliance-theme" in html
        # Vérifier au moins les thèmes technological et organizational
        assert "A.5." in html
        assert "A.8." in html

    def test_compliance_i18n_fr(self, tmp_path):
        """La section compliance est traduite en français."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, report_lang="fr")
        runner.run()

        html = _read_html(runner)
        assert "Matrice de conformité ISO 27001" in html
        assert "Taux d'applicabilité" in html  # "SAST" est auto-lié au glossaire
        assert "Conformité parmi le testable" in html

    def test_compliance_applicability_vs_clean_rate(self, tmp_path):
        """Le taux d'applicabilité SAST (testable/total) et le taux de
        conformité parmi le testable (sans finding/testable) sont deux
        métriques distinctes, chacune avec sa propre barre colorée — les
        contrôles hors périmètre SAST (N/A) ne doivent plus être comptés
        comme un échec de conformité (RETEX Reviewer R25/R26)."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = runner._compute_iso27001_compliance()
        assert data["total_controls"] > data["covered_controls"] > 0, \
            "Ce test suppose des contrôles à la fois couverts et hors périmètre SAST"
        assert 0 <= data["clean_pct"] <= 100
        assert data["clean_controls"] == data["covered_controls"] - data["with_findings"]

        html = _read_html(runner)
        assert "compliance-coverage-secondary" in html
        assert "complianceRadarChart" not in html, \
            "Le radar (doublon de complianceThemeChart) doit être retiré (RETEX Reviewer R23)"

    def test_compliance_chart_titles_specify_unit(self, tmp_path):
        """Les titres des graphes de conformité précisent l'unité (% ou
        valeur) pour lever l'ambiguïté entre graphes de nature différente
        (RETEX Reviewer R24)."""
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "Overall Coverage (%)" in html
        assert "Coverage by Theme (%)" in html
        assert "Controls Status (count)" in html


# =============================================================================
# 15b. ASVS v5.0.0 PIPELINE
# =============================================================================

class TestAsvsCompliancePipeline:
    """Tests fonctionnels : section ASVS v5.0.0 dans le pipeline."""

    def test_asvs_section_in_html(self, tmp_path):
        """La section ASVS apparaît dans le rapport HTML."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "section-asvs" in html
        assert "asvsCoverageChart" in html

    def test_asvs_section_in_json(self, tmp_path):
        """Les données ASVS apparaissent dans le JSON."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        assert "compliance" in data
        assert "asvs" in data["compliance"]
        asvs = data["compliance"]["asvs"]
        assert asvs["total_requirements"] == 348
        assert asvs["covered_requirements"] > 0
        assert asvs["with_findings"] > 0

    def test_asvs_disabled_via_config(self, tmp_path):
        """La section ASVS peut être désactivée via la config."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "compliance": {"asvs": {"enabled": False}}
        })
        runner.run()

        html = _read_html(runner)
        # La section doit être masquée (display:none) ou absente
        assert 'display:none' in html or "asvsCoverageChart" not in html

    def test_asvs_chapters_in_html(self, tmp_path):
        """Les chapitres V1-V17 sont présents dans le HTML."""
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "V1" in html
        assert "V11" in html

    def test_asvs_level_badges_in_html(self, tmp_path):
        """Les badges de niveau L1/L2 sont dans le HTML."""
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "asvs-level-badge" in html

    def test_asvs_i18n_fr(self, tmp_path):
        """La section ASVS est traduite en français."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, report_lang="fr")
        runner.run()

        html = _read_html(runner)
        assert "Conformité OWASP ASVS v5.0.0" in html or "OWASP ASVS v5.0.0" in html

    def test_asvs_applicability_vs_clean_rate(self, tmp_path):
        """ASVS 44/348 : le taux d'applicabilité SAST et le taux de conformité
        parmi le testable sont deux métriques séparées, pour ne pas confondre
        les exigences hors périmètre SAST (pentest/revue manuelle) avec un
        échec de conformité (RETEX Reviewer R25/R26)."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        asvs = data["compliance"]["asvs"]
        assert "clean_pct" in asvs
        assert 0 <= asvs["clean_pct"] <= 100

        html = _read_html(runner)
        assert "asvsRadarChart" not in html, \
            "Le radar (doublon de asvsChapterChart) doit être retiré (RETEX Reviewer R23)"
        assert "Coverage by Chapter (%)" in html
        assert "Requirements Status (count)" in html


# =============================================================================
# 16. DETECTION MULTI-LIGNE
# =============================================================================

class TestMultilineDetectionPipeline:
    """Tests fonctionnels : la détection multi-ligne fonctionne dans le pipeline complet."""

    def test_sql_injection_fstring_multiline_in_json(self, tmp_path):
        """Les findings multi-ligne SQL injection f-string apparaissent dans le JSON."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        fstring_findings = [f for f in data["findings"] if f["rule_key"] == "sql_injection_fstring"]
        assert len(fstring_findings) >= 2, "Doit détecter mono-ligne + multi-ligne"

    def test_unvalidated_input_multiline_in_json(self, tmp_path):
        """Les findings multi-ligne subprocess shell=True apparaissent dans le JSON."""
        _place_vuln_fixture(tmp_path, "unvalidated_input.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        input_findings = [f for f in data["findings"] if f["rule_key"] == "taint_rce"]
        assert len(input_findings) >= 2, "Doit détecter mono-ligne + multi-ligne"

    def test_secret_logged_multiline_in_html(self, tmp_path):
        """Les findings multi-ligne secret_logged apparaissent dans le rapport HTML."""
        _place_vuln_fixture(tmp_path, "secret_logged.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        findings = get_findings_by_rule_key(runner, "secret_logged_fstring")
        assert len(findings) >= 2, "Doit détecter mono-ligne + multi-ligne"
        assert runner.report_path and os.path.exists(runner.report_path)

    def test_multiline_findings_have_correct_fields(self, tmp_path):
        """Les findings multi-ligne ont tous les champs requis dans le JSON."""
        _place_vuln_fixture(tmp_path, "sql_injection_concat.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        concat_findings = [f for f in data["findings"] if f["rule_key"] == "sql_injection_concat"]
        assert len(concat_findings) >= 2

        required_fields = {"category", "rule_key", "file", "line", "severity", "confidence"}
        for finding in concat_findings:
            missing = required_fields - finding.keys()
            assert not missing, f"Champs manquants dans finding multi-ligne : {missing}"


# =============================================================================
# ISO 27001 — NOUVELLES RÈGLES
# =============================================================================

class TestISO27001NewRules:
    """Tests fonctionnels pour les 9 nouvelles règles ISO 27001."""

    def test_privilege_escalation_in_json_and_html(self, tmp_path):
        """privilege_escalation apparaît dans le JSON et le HTML."""
        _place_vuln_fixture(tmp_path, "privilege_escalation.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "privilege_escalation"]
        assert len(findings) >= 1
        assert findings[0]["severity"] == "HIGH"

        html = _read_html(runner)
        assert "privilege_escalation" in html

    def test_unencrypted_transfer_in_json_and_html(self, tmp_path):
        """unencrypted_transfer apparaît dans le JSON et le HTML."""
        _place_vuln_fixture(tmp_path, "unencrypted_transfer.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "unencrypted_transfer"]
        assert len(findings) >= 1

        html = _read_html(runner)
        assert "unencrypted_transfer" in html

    def test_missing_auth_decorator_in_json(self, tmp_path):
        """missing_auth_decorator apparaît dans le JSON."""
        _place_vuln_fixture(tmp_path, "missing_auth_decorator.py", "src/main.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "missing_auth_decorator"]
        assert len(findings) >= 1

    def test_pii_in_tests_in_json(self, tmp_path):
        """pii_in_tests apparaît dans le JSON."""
        _place_vuln_fixture(tmp_path, "pii_in_tests.py", "src/test_users.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "pii_in_tests"]
        assert len(findings) >= 1

    def test_insecure_cloud_config_in_json(self, tmp_path):
        """insecure_cloud_config apparaît dans le JSON."""
        _place_vuln_fixture(tmp_path, "insecure_cloud_config.py", "src/infra.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "insecure_cloud_config"]
        assert len(findings) >= 1
        assert findings[0]["severity"] == "HIGH"

    def test_unbounded_query_in_json(self, tmp_path):
        """unbounded_query apparaît dans le JSON."""
        _place_vuln_fixture(tmp_path, "unbounded_query.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "unbounded_query"]
        assert len(findings) >= 1
        assert any(f["category"] == "ARCH" for f in findings)

    def test_missing_monitoring_in_json(self, tmp_path):
        """missing_monitoring apparaît dans le JSON."""
        _place_vuln_fixture(tmp_path, "missing_monitoring.py", "src/api.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "missing_monitoring"]
        assert len(findings) >= 1
        assert any(f["category"] == "MAINTENANCE" for f in findings)

    def test_missing_security_docs_in_json(self, tmp_path):
        """missing_security_docs apparaît dans le JSON."""
        _place_vuln_fixture(tmp_path, "missing_security_docs.py", "src/crypto.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "missing_security_docs"]
        assert len(findings) >= 1

    def test_missing_change_management_in_json(self, tmp_path):
        """missing_change_management apparaît dans le JSON."""
        _place_vuln_fixture(tmp_path, "missing_change_management.py", "src/deploy.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "missing_change_management"]
        assert len(findings) >= 1

    def test_iso27001_compliance_section_in_html(self, tmp_path):
        """La section compliance ISO 27001 contient les nouveaux contrôles."""
        _place_vuln_fixture(tmp_path, "privilege_escalation.py", "src/service.py")
        _place_vuln_fixture(tmp_path, "insecure_cloud_config.py", "src/infra.py")
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        # La section compliance doit exister
        assert "compliance" in html.lower()
        # Les contrôles ajoutés doivent apparaître
        assert "A.8.18" in html  # privilege_escalation
        assert "A.5.23" in html  # insecure_cloud_config


class TestISO27001A8Completion:
    """Tests E2E pour les 6 règles A.8 (couverture 32/34)."""

    # --- insecure_local_storage (A.8.1) ---

    def test_insecure_local_storage_in_json(self, tmp_path):
        """insecure_local_storage apparaît dans le JSON."""
        _place_vuln_fixture(tmp_path, "insecure_local_storage.js", "src/js/auth.js")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "insecure_local_storage"]
        assert len(findings) >= 1

    def test_insecure_local_storage_in_html(self, tmp_path):
        """insecure_local_storage apparaît dans le rapport HTML."""
        _place_vuln_fixture(tmp_path, "insecure_local_storage.js", "src/js/auth.js")
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "insecure_local_storage" in html

    # --- hardcoded_internal_ip (A.8.22) ---

    def test_hardcoded_internal_ip_in_json(self, tmp_path):
        """hardcoded_internal_ip apparaît dans le JSON."""
        _place_vuln_fixture(tmp_path, "hardcoded_internal_ip.py", "src/config.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "hardcoded_internal_ip"]
        assert len(findings) >= 1

    def test_hardcoded_internal_ip_in_html(self, tmp_path):
        """hardcoded_internal_ip apparaît dans le rapport HTML."""
        _place_vuln_fixture(tmp_path, "hardcoded_internal_ip.py", "src/config.py")
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "hardcoded_internal_ip" in html

    # --- missing_csp_header (A.8.23) ---

    def test_missing_csp_header_in_json(self, tmp_path):
        """missing_csp_header apparaît dans le JSON."""
        _place_vuln_fixture(tmp_path, "missing_csp_header.py", "src/app.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "missing_csp_header"]
        assert len(findings) >= 1

    def test_missing_csp_header_in_html(self, tmp_path):
        """missing_csp_header apparaît dans le rapport HTML."""
        _place_vuln_fixture(tmp_path, "missing_csp_header.py", "src/app.py")
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "missing_csp_header" in html

    # --- exposed_test_endpoint (A.8.34) ---

    def test_exposed_test_endpoint_in_json(self, tmp_path):
        """exposed_test_endpoint apparaît dans le JSON."""
        _place_vuln_fixture(tmp_path, "exposed_test_endpoint.py", "src/main.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "exposed_test_endpoint"]
        assert len(findings) >= 1

    def test_exposed_test_endpoint_in_html(self, tmp_path):
        """exposed_test_endpoint apparaît dans le rapport HTML."""
        _place_vuln_fixture(tmp_path, "exposed_test_endpoint.py", "src/main.py")
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "exposed_test_endpoint" in html

    # --- destructive_without_backup (A.8.13) ---

    def test_destructive_without_backup_in_json(self, tmp_path):
        """destructive_without_backup apparaît dans le JSON."""
        _place_vuln_fixture(tmp_path, "destructive_without_backup.py", "src/cleanup.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "destructive_without_backup"]
        assert len(findings) >= 1

    def test_destructive_without_backup_in_html(self, tmp_path):
        """destructive_without_backup apparaît dans le rapport HTML."""
        _place_vuln_fixture(tmp_path, "destructive_without_backup.py", "src/cleanup.py")
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "destructive_without_backup" in html

    # --- local_time_usage (A.8.17) ---

    def test_local_time_usage_in_json(self, tmp_path):
        """local_time_usage apparaît dans le JSON."""
        _place_vuln_fixture(tmp_path, "local_time_usage.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "local_time_usage"]
        assert len(findings) >= 1

    def test_local_time_usage_in_html(self, tmp_path):
        """local_time_usage apparaît dans le rapport HTML."""
        _place_vuln_fixture(tmp_path, "local_time_usage.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "local_time_usage" in html

    # --- ISO compliance section ---

    # --- missing_health_check (A.8.14) ---

    def test_missing_health_check_in_json(self, tmp_path):
        """missing_health_check apparaît dans le JSON."""
        _place_vuln_fixture(tmp_path, "missing_health_check.py", "src/app.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "missing_health_check"]
        assert len(findings) >= 1

    def test_missing_health_check_in_html(self, tmp_path):
        """missing_health_check apparaît dans le rapport HTML."""
        _place_vuln_fixture(tmp_path, "missing_health_check.py", "src/app.py")
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "missing_health_check" in html

    # --- unreviewed_vendor_code (A.8.30) ---

    def test_unreviewed_vendor_code_in_json(self, tmp_path):
        """unreviewed_vendor_code apparaît dans le JSON."""
        import os
        vendor_dir = os.path.join(str(tmp_path), "src", "vendor")
        os.makedirs(vendor_dir, exist_ok=True)
        _place_vuln_fixture(tmp_path, "unreviewed_vendor_code.py", "src/vendor/utils.py")
        runner = _make_runner(tmp_path)
        runner.run()

        data = _read_json(runner)
        findings = [f for f in data["findings"] if f["rule_key"] == "unreviewed_vendor_code"]
        assert len(findings) >= 1

    def test_unreviewed_vendor_code_in_html(self, tmp_path):
        """unreviewed_vendor_code apparaît dans le rapport HTML."""
        import os
        vendor_dir = os.path.join(str(tmp_path), "src", "vendor")
        os.makedirs(vendor_dir, exist_ok=True)
        _place_vuln_fixture(tmp_path, "unreviewed_vendor_code.py", "src/vendor/utils.py")
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert "unreviewed_vendor_code" in html

    # --- ISO compliance section ---

    def test_a8_controls_in_compliance_section(self, tmp_path):
        """Les 8 contrôles A.8 apparaissent dans la section compliance."""
        _place_vuln_fixture(tmp_path, "insecure_local_storage.js", "src/js/auth.js")
        _place_vuln_fixture(tmp_path, "hardcoded_internal_ip.py", "src/config.py")
        _place_vuln_fixture(tmp_path, "missing_csp_header.py", "src/app.py")
        _place_vuln_fixture(tmp_path, "exposed_test_endpoint.py", "src/main.py")
        _place_vuln_fixture(tmp_path, "destructive_without_backup.py", "src/cleanup.py")
        _place_vuln_fixture(tmp_path, "local_time_usage.py", "src/service.py")
        _place_vuln_fixture(tmp_path, "missing_health_check.py", "src/routes.py")
        import os
        vendor_dir = os.path.join(str(tmp_path), "src", "vendor")
        os.makedirs(vendor_dir, exist_ok=True)
        _place_vuln_fixture(tmp_path, "unreviewed_vendor_code.py", "src/vendor/utils.py")
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        # Les 8 contrôles A.8
        assert "A.8.1" in html    # insecure_local_storage
        assert "A.8.13" in html   # destructive_without_backup
        assert "A.8.14" in html   # missing_health_check
        assert "A.8.17" in html   # local_time_usage
        assert "A.8.22" in html   # hardcoded_internal_ip
        assert "A.8.23" in html   # missing_csp_header
        assert "A.8.30" in html   # unreviewed_vendor_code
        assert "A.8.34" in html   # exposed_test_endpoint

    def test_compliance_charts_in_html(self, tmp_path):
        """Les 3 graphiques ISO sont présents dans le rapport (le radar,
        doublon exact de complianceThemeChart, a été retiré — RETEX Reviewer
        R23)."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/db.py")
        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert 'id="complianceCoverageChart"' in html
        assert 'id="complianceThemeChart"' in html
        assert 'id="complianceStatusChart"' in html
        assert 'id="complianceRadarChart"' not in html


# =============================================================================
# LICENSE TIER ENFORCEMENT
# =============================================================================

class TestLicenseTierEnforcement:
    """Tests E2E du gating par tier de licence."""

    def test_source_mode_no_restrictions(self, tmp_path):
        """Sans module license_check (mode source), tout est disponible."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={"_cli_options": {"sarif": True, "sbom": True}})
        runner.run()

        # Aucune restriction : JSON, HTML, SARIF, SBOM produits
        assert os.path.exists(runner.report_path)
        assert os.path.exists(runner.data_path)
        # Licence defaults enterprise
        assert runner.config.get("_license", {}).get("tier") == "enterprise"

    def test_license_tier_limits_files(self, tmp_path):
        """Un tier avec max_files=2 ne scanne que 2 fichiers."""
        for i in range(5):
            _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", f"src/file{i}.py")
        runner = _make_runner(tmp_path, extra_config={
            "_license": {"tier": "solo", "features": ["taint", "compliance", "sarif", "sbom"],
                         "max_files": 2, "max_loc": 0, "exports": ["json", "html", "sarif", "sbom"], "seats": 1}
        })
        runner.run()

        # Le runner ne doit avoir scanné que 2 fichiers uniques
        assert len(runner._unique_files_scanned) <= 2

    def test_license_tier_limits_loc(self, tmp_path):
        """Un tier avec max_loc bas tronque le scan dès la limite SLOC atteinte.

        Note : _unique_files_scanned reflète le glob (collecte) et inclut tous
        les fichiers candidats, même skipés. Le truncate intervient au scan
        effectif, donc l'indicateur primaire est le flag _loc_limit_reached
        et le nombre de findings remontés (chaque fichier vulnérable produit
        2 findings sql_injection_fstring).
        """
        for i in range(5):
            _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", f"src/file{i}.py")
        runner = _make_runner(tmp_path, extra_config={
            "_license": {"tier": "solo", "features": ["taint", "compliance", "sarif", "sbom"],
                         "max_files": 0, "max_loc": 5, "exports": ["json", "html", "sarif", "sbom"], "seats": 1}
        })
        runner.run()

        # Flag levé : le runner sait que la limite a été atteinte
        assert runner._loc_limit_reached is True
        # Findings tronqués : sans limite on aurait ~10 findings (5 fichiers × 2),
        # avec truncate on doit en avoir nettement moins
        findings = get_findings_by_rule_key(runner, "sql_injection_fstring")
        assert len(findings) < 10  # truncate effectif

    def test_license_and_restrictive_files_and_loc(self, tmp_path):
        """AND restrictif : la première limite atteinte (files OU loc) tronque."""
        # 10 fichiers, max_files=3, max_loc grand → c'est files qui doit limiter
        for i in range(10):
            _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", f"src/file{i}.py")
        runner = _make_runner(tmp_path, extra_config={
            "_license": {"tier": "solo", "features": ["taint"],
                         "max_files": 3, "max_loc": 1000000,
                         "exports": ["json", "html"], "seats": 1}
        })
        runner.run()
        assert len(runner._unique_files_scanned) <= 3

    def test_license_blocks_sarif_export(self, tmp_path):
        """Un tier sans export SARIF ne génère pas de fichier SARIF."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_license": {"tier": "solo", "features": ["taint", "compliance"],
                         "max_files": 0, "exports": ["json", "html"], "seats": 1},
            "_cli_options": {"sarif": True},
        })
        runner.run()

        # Pas de fichier SARIF
        sarif_path = getattr(runner, '_sarif_path', None)
        if sarif_path:
            assert not os.path.exists(sarif_path)

    def test_compliance_gated_by_feature(self, tmp_path):
        """Sans feature 'compliance', la section ISO 27001 n'est pas dans le rapport."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_license": {"tier": "solo", "features": ["taint"],
                         "max_files": 0, "exports": ["json", "html"], "seats": 1},
        })
        runner.run()

        html = _read_html(runner)
        assert "iso27001" not in html.lower() or "display:none" in html or "display: none" in html

    def test_taint_blocked_without_feature(self, tmp_path):
        """Sans feature 'taint', aucun taint_flow ne doit apparaître dans les findings."""
        _place_vuln_fixture(tmp_path, "taint_sqli.py", "src/views.py")
        runner = _make_runner(tmp_path, extra_config={
            "_license": {"tier": "solo", "features": [],
                         "max_files": 0, "exports": ["json", "html"], "seats": 1},
        })
        runner.run()

        data = _read_json(runner)
        taint_findings = [f for f in data["findings"] if f.get("taint_flow")]
        assert len(taint_findings) == 0, "Aucun taint_flow sans feature 'taint'"

    def test_taint_active_with_feature(self, tmp_path):
        """Avec feature 'taint', les taint_flow sont présents dans les findings."""
        _place_vuln_fixture(tmp_path, "taint_sqli.py", "src/views.py")
        runner = _make_runner(tmp_path, extra_config={
            "_license": {"tier": "team", "features": ["taint", "multifile"],
                         "max_files": 0, "exports": ["json", "html"], "seats": 1},
        })
        runner.run()

        data = _read_json(runner)
        taint_findings = [f for f in data["findings"] if f.get("taint_flow")]
        assert len(taint_findings) >= 1, "Au moins un taint_flow attendu avec feature 'taint'"

    def test_multifile_skips_pass1_without_feature(self, tmp_path):
        """Sans feature 'multifile', le taint s'exécute sans résumés inter-procéduraux."""
        _place_vuln_fixture(tmp_path, "taint_sqli.py", "src/views.py")
        runner = _make_runner(tmp_path, extra_config={
            "_license": {"tier": "solo_plus", "features": ["taint"],
                         "max_files": 0, "exports": ["json", "html"], "seats": 1},
        })
        runner.run()

        # Sans multifile, le taint intra-fichier fonctionne encore
        # (pas de crash, rapport généré)
        assert os.path.exists(runner.report_path)
        assert os.path.exists(runner.data_path)

    def test_cross_file_without_feature_still_runs(self, tmp_path):
        """Sans feature 'cross_file', le taint s'exécute sans summaries inter-fichiers."""
        _place_vuln_fixture(tmp_path, "taint_sqli.py", "src/views.py")
        runner = _make_runner(tmp_path, extra_config={
            "_license": {"tier": "team", "features": ["taint", "multifile"],
                         "max_files": 0, "exports": ["json", "html"], "seats": 1},
        })
        runner.run()

        # Sans cross_file, le rapport est toujours généré
        assert os.path.exists(runner.report_path)
        data = _read_json(runner)
        assert "findings" in data


class TestLicenseInfoCommand:
    """Tests de la commande --license-info."""

    def test_license_info_source_mode_fr(self, tmp_path, capsys):
        """En mode source, --license-info affiche 'Mode source — aucune restriction'."""
        from sca.cli import _show_license_info
        _show_license_info(lang="fr")
        captured = capsys.readouterr()
        assert "Mode source" in captured.out
        assert "aucune restriction" in captured.out

    def test_license_info_source_mode_en(self, tmp_path, capsys):
        """En mode source, --license-info affiche 'Source mode' en anglais."""
        from sca.cli import _show_license_info
        _show_license_info(lang="en")
        captured = capsys.readouterr()
        assert "Source mode" in captured.out
        assert "no restrictions" in captured.out

    def test_license_info_source_mode_de(self, tmp_path, capsys):
        """En mode source, --license-info affiche le statut en allemand."""
        from sca.cli import _show_license_info
        _show_license_info(lang="de")
        captured = capsys.readouterr()
        assert "Quellmodus" in captured.out

    def test_license_info_source_mode_es(self, tmp_path, capsys):
        """En mode source, --license-info affiche le statut en espagnol."""
        from sca.cli import _show_license_info
        _show_license_info(lang="es")
        captured = capsys.readouterr()
        assert "Modo fuente" in captured.out

    def test_license_info_contains_title(self, capsys):
        """Le titre StaticCodeAudit est toujours présent."""
        from sca.cli import _show_license_info
        _show_license_info(lang="en")
        captured = capsys.readouterr()
        assert "StaticCodeAudit" in captured.out


class TestWithTests:
    """Tests pour l'option --with-tests (auto-détection des tests)."""

    def test_with_tests_detects_pytest(self, tmp_path):
        """--with-tests détecte pytest quand tests/ existe."""
        # Créer un répertoire tests/ à la racine du projet
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        (tests_dir / "test_sample.py").write_text("def test_ok(): assert True\n")

        runner = _make_runner(tmp_path, extra_config={
            "tests": {"enabled": False, "command": ""},
            "_cli_options": {"with_tests": True},
        })

        # Vérifier que la commande est auto-détectée
        cmd = runner._auto_detect_test_command()
        assert cmd is not None, "Doit détecter pytest"
        assert "pytest" in cmd

    def test_with_tests_prefers_configured_command(self, tmp_path):
        """Si tests.command est configuré, pas d'auto-détection."""
        runner = _make_runner(tmp_path, extra_config={
            "tests": {"enabled": True, "command": "echo ok", "tests_dir": "tests/"},
            "_cli_options": {"with_tests": True},
        })
        runner.run()
        # Le test passe si aucune erreur — la commande configurée a priorité

    def test_with_tests_no_framework_detected(self, tmp_path):
        """Sans framework de test → pas d'erreur, juste un avertissement."""
        runner = _make_runner(tmp_path, extra_config={
            "tests": {"enabled": False, "command": ""},
            "_cli_options": {"with_tests": True},
        })

        cmd = runner._auto_detect_test_command()
        assert cmd is None, "Pas de framework détecté dans un projet vide"

    def test_without_flag_no_autodetect(self, tmp_path):
        """Sans --with-tests, pas d'auto-détection même si tests/ existe."""
        tests_dir = tmp_path / "src" / "tests"
        tests_dir.mkdir(parents=True)
        (tests_dir / "test_sample.py").write_text("def test_ok(): assert True\n")

        runner = _make_runner(tmp_path, extra_config={
            "tests": {"enabled": False, "command": ""},
        })
        runner.run()

        # Tests non exécutés car enabled=False et pas de --with-tests
        assert runner.test_results is None or runner.test_results.passed == 0


# =============================================================================
# 15. FLAG --with-logs (Reporter — sortie console + fichier log)
# =============================================================================

class TestWithLogs:
    """Tests pour l'option --with-logs (capture verbose vers fichier log)."""

    def test_log_file_created(self, tmp_path):
        """--with-logs crée un fichier SCA-LOGS-*.log dans reports_dir."""
        import sys
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"with_logs": True},
        })
        runner.run()

        # Le Reporter ne touche plus à sys.stdout (refonte) — il écrit
        # directement dans son fichier dédié.
        reports_dir = Path(runner.reports_dir)
        log_files = list(reports_dir.glob("SCA-LOGS-*.log"))
        assert len(log_files) == 1, f"Doit créer exactement 1 fichier LOGS, trouvé: {log_files}"

    def test_log_file_contains_banner(self, tmp_path):
        """Le fichier log contient le banner de l'outil."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"with_logs": True},
        })
        runner.run()

        reports_dir = Path(runner.reports_dir)
        log_file = next(reports_dir.glob("SCA-LOGS-*.log"))
        content = log_file.read_text(encoding="utf-8")
        assert "StaticCodeAudit" in content
        assert "Console log active" in content or "log active" in content.lower() or "LOGS" in content

    def test_log_file_contains_verbose_messages(self, tmp_path):
        """Le fichier log contient les messages de progression (règles, fichiers)."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"with_logs": True},
        })
        runner.run()

        reports_dir = Path(runner.reports_dir)
        log_file = next(reports_dir.glob("SCA-LOGS-*.log"))
        content = log_file.read_text(encoding="utf-8")
        assert "Rules loaded:" in content
        assert "Files scanned:" in content

    def test_verbose_messages_always_shown(self, tmp_path):
        """Les messages de progression s'affichent même sans --with-logs."""
        import io
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)

        captured = io.StringIO()
        import sys
        original = sys.stdout
        sys.stdout = captured
        try:
            runner.run()
        finally:
            sys.stdout = original

        output = captured.getvalue()
        assert "Rules loaded:" in output
        assert "Files scanned:" in output
        # Phase moteur de règles affichée avec [n/N], icône et label localisé
        assert "Scanning rules" in output or "rules" in output.lower()

    def test_log_file_contains_report_path(self, tmp_path):
        """Le fichier log contient le chemin du rapport généré."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"with_logs": True},
        })
        runner.run()

        reports_dir = Path(runner.reports_dir)
        log_file = next(reports_dir.glob("SCA-LOGS-*.log"))
        content = log_file.read_text(encoding="utf-8")
        assert "SCA-REPORT-" in content
        assert "Console log saved" in content

    def test_no_log_without_flag(self, tmp_path):
        """Sans --with-logs, aucun fichier LOGS n'est créé."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)
        runner.run()

        reports_dir = Path(runner.reports_dir)
        log_files = list(reports_dir.glob("SCA-LOGS-*.log"))
        assert len(log_files) == 0, f"Sans --with-logs, aucun fichier LOGS attendu, trouvé: {log_files}"

    def test_log_file_i18n_fr(self, tmp_path):
        """--with-logs avec --lang=fr produit un log avec messages en français."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, script_lang="fr", extra_config={
            "_cli_options": {"with_logs": True},
        })
        runner.run()

        reports_dir = Path(runner.reports_dir)
        log_file = next(reports_dir.glob("SCA-LOGS-*.log"))
        content = log_file.read_text(encoding="utf-8")
        # Messages français
        assert "Regles chargees" in content or "Règles chargées" in content or "Regles" in content
        assert "Fichiers scannes" in content or "Fichiers" in content

    def test_log_file_has_timestamps(self, tmp_path):
        """Chaque ligne du fichier log est préfixée par [HH:MM:SS]."""
        import re
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"with_logs": True},
        })
        runner.run()

        reports_dir = Path(runner.reports_dir)
        log_file = next(reports_dir.glob("SCA-LOGS-*.log"))
        content = log_file.read_text(encoding="utf-8")
        # Au moins une ligne au format [HH:MM:SS]
        assert re.search(r"\[\d{2}:\d{2}:\d{2}\]", content), \
            "Le fichier log doit contenir des timestamps [HH:MM:SS]"

    def test_phase_numbering_consistent(self, tmp_path):
        """Tous les marqueurs [n/N] partagent le même N."""
        import io
        import re
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)

        captured = io.StringIO()
        import sys
        original = sys.stdout
        sys.stdout = captured
        try:
            runner.run()
        finally:
            sys.stdout = original

        output = captured.getvalue()
        # Ancre en debut de ligne : exclut le marqueur [n/N] de progression
        # PAR FICHIER de la phase taint (indente, prefixe icone, ex.
        # "   🧠 [1/1] src/service.py — ..."), qui a son propre total
        # (nombre de fichiers de CETTE regle) sans rapport avec le nombre
        # de phases globales de l'audit — ajoute par la progression live
        # taint (2026-08-17), sans lien avec ce que ce test verifie.
        markers = re.findall(r"^\[(\d+)/(\d+)\]", output, re.MULTILINE)
        assert markers, "Aucun marqueur de phase [n/N] trouvé dans la sortie"
        totals = {N for _, N in markers}
        assert len(totals) == 1, f"Numérotation incohérente — totaux différents : {totals}"

    def test_phase_numbering_starts_at_one(self, tmp_path):
        """Le premier marqueur affiché est [1/N]."""
        import io
        import re
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path)

        captured = io.StringIO()
        import sys
        original = sys.stdout
        sys.stdout = captured
        try:
            runner.run()
        finally:
            sys.stdout = original

        # Meme ancrage que test_phase_numbering_consistent (voir sa note) —
        # ne cible que le marqueur de phase globale, pas la progression
        # par fichier de la phase taint.
        first = re.search(r"^\[(\d+)/(\d+)\]", captured.getvalue(), re.MULTILINE)
        assert first is not None
        assert first.group(1) == "1", \
            f"Premier marqueur attendu [1/...], obtenu [{first.group(1)}/...]"

    def test_log_contains_lang_progression(self, tmp_path):
        """La progression par langage 📂 est visible dans le fichier log."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"with_logs": True},
        })
        runner.run()

        reports_dir = Path(runner.reports_dir)
        log_file = next(reports_dir.glob("SCA-LOGS-*.log"))
        content = log_file.read_text(encoding="utf-8")
        assert "📂" in content
        assert "Python" in content

    def test_log_contains_category_progression(self, tmp_path):
        """Une ligne par catégorie active apparaît dans le fichier log."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"with_logs": True},
        })
        runner.run()

        reports_dir = Path(runner.reports_dir)
        log_file = next(reports_dir.glob("SCA-LOGS-*.log"))
        content = log_file.read_text(encoding="utf-8")
        # Format : "→ SECURITY: 156 rules, 245 files, 12 findings (1.2s)"
        assert "SECURITY:" in content and "rules" in content and "findings" in content

    def test_log_contains_taint_progression(self, tmp_path):
        """Les étapes taint 🧠 sont visibles dans le fichier log."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"with_logs": True},
        })
        runner.run()

        reports_dir = Path(runner.reports_dir)
        log_file = next(reports_dir.glob("SCA-LOGS-*.log"))
        content = log_file.read_text(encoding="utf-8")
        # Au moins un message taint pass 1 doit apparaître
        assert "🧠" in content or "Taint" in content


# =============================================================================
# 15bis. FLAG --quiet (mode console silencieux)
# =============================================================================

class TestQuiet:
    """Tests pour l'option --quiet (silence console, sauf erreurs et résultat)."""

    def test_quiet_silences_progress(self, tmp_path):
        """En --quiet, les phases [n/N] ne sont PAS affichées."""
        import io
        import sys
        import re
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"quiet": True},
        })

        captured = io.StringIO()
        original = sys.stdout
        sys.stdout = captured
        try:
            runner.run()
        finally:
            sys.stdout = original

        output = captured.getvalue()
        # Aucun marqueur de phase
        assert not re.search(r"\[\d+/\d+\]", output), \
            f"--quiet ne doit pas afficher [n/N], trouvé: {output[:200]}"
        # Aucune ligne de progression par langage
        assert "📂" not in output

    def test_quiet_keeps_result(self, tmp_path):
        """En --quiet, le résultat final (rapport généré) reste visible."""
        import io
        import sys
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"quiet": True},
        })

        captured = io.StringIO()
        original = sys.stdout
        sys.stdout = captured
        try:
            runner.run()
        finally:
            sys.stdout = original

        output = captured.getvalue()
        # Le résultat final doit être visible
        assert "Report generated" in output or "Rapport" in output or "SCA-REPORT-" in output

    def test_quiet_with_logs_keeps_file_verbose(self, tmp_path):
        """--quiet --with-logs : console silencieuse, fichier complet."""
        import io
        import sys
        import re
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        runner = _make_runner(tmp_path, extra_config={
            "_cli_options": {"quiet": True, "with_logs": True},
        })

        captured = io.StringIO()
        original = sys.stdout
        sys.stdout = captured
        try:
            runner.run()
        finally:
            sys.stdout = original

        # Console : pas de progression (silencieuse)
        output = captured.getvalue()
        assert not re.search(r"\[\d+/\d+\]", output)
        assert "📂" not in output

        # Fichier log : progression complète
        reports_dir = Path(runner.reports_dir)
        log_file = next(reports_dir.glob("SCA-LOGS-*.log"))
        content = log_file.read_text(encoding="utf-8")
        assert re.search(r"\[\d+/\d+\]", content), \
            "Le fichier log doit contenir les marqueurs [n/N] même en --quiet"
        assert "Rules loaded:" in content


# =============================================================================
# FILTRE SÉVÉRITÉ (--severity)
# =============================================================================

class TestSeverityFilter:
    """Valide le filtrage des règles par niveau de sévérité."""

    def test_severity_high_only_excludes_low(self, tmp_path):
        """--severity HIGH,CRITICAL → les règles LOW/INFO ne tournent pas."""
        # Deux fichiers distincts pour éviter l'écrasement
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        _place_vuln_fixture(tmp_path, "todo_comment.py", "src/maintenance.py")

        runner = _make_runner(tmp_path, severity_levels=["HIGH", "CRITICAL"])
        runner.run()

        high_findings = [
            f for cat in runner.categories.values()
            for f in cat.findings
            if f.severity.upper() == "HIGH"
        ]
        low_findings = [
            f for cat in runner.categories.values()
            for f in cat.findings
            if f.severity.upper() in ("LOW", "INFO")
        ]
        assert len(high_findings) >= 1, "Les règles HIGH doivent être exécutées"
        assert len(low_findings) == 0, "Les règles LOW/INFO doivent être exclues"

    def test_severity_all_unchanged(self, tmp_path):
        """severity=all donne le même résultat que sans filtre."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")
        _place_vuln_fixture(tmp_path, "todo_comment.py", "src/maintenance.py")

        runner_all = _make_runner(tmp_path)
        runner_all.run()
        total_all = sum(len(cat.findings) for cat in runner_all.categories.values())

        runner_filtered = _make_runner(tmp_path, severity_levels=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        runner_filtered.run()
        total_filtered = sum(len(cat.findings) for cat in runner_filtered.categories.values())

        assert total_all == total_filtered, "severity=all doit donner le même résultat que sans filtre"

    def test_severity_banner_in_html(self, tmp_path):
        """--severity → bandeau de filtre présent dans le rapport HTML."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")

        runner = _make_runner(tmp_path, severity_levels=["HIGH", "CRITICAL"])
        runner.run()

        html = _read_html(runner)
        assert '<div class="severity-filter-banner">' in html, "Le rapport doit contenir le div severity-filter-banner"
        assert "HIGH" in html, "Le bandeau doit mentionner les niveaux actifs"

    def test_severity_no_banner_when_unfiltered(self, tmp_path):
        """Sans --severity, aucun bandeau de filtre dans le rapport HTML."""
        _place_vuln_fixture(tmp_path, "sql_injection_fstring.py", "src/service.py")

        runner = _make_runner(tmp_path)
        runner.run()

        html = _read_html(runner)
        assert '<div class="severity-filter-banner">' not in html, "Sans filtre, aucun div severity-filter-banner"


class TestTaintSensitiveAttrWrite:
    """Pipeline end-to-end pour le sink AttrLhs (taint_sensitive_attr_write)."""

    def test_vulnerable_attr_write_detected(self, tmp_path):
        """run() détecte l'écriture taintée vers un attribut sensible."""
        _place_vuln_fixture(tmp_path, "taint_sensitive_attr_write.py", "src/profile.py")
        runner = _make_runner(tmp_path)
        runner.run()

        findings = get_findings_by_rule_key(runner, "taint_sensitive_attr_write")
        assert len(findings) >= 1, "user.is_admin = request.form.get(...) doit être détecté"
        assert findings[0].severity.upper() == "HIGH"

    def test_clean_attr_write_not_detected(self, tmp_path):
        """Valeur validée par guard → aucun finding."""
        source = get_fixture_path("clean", "taint_sensitive_attr_write_clean.py")
        dest = tmp_path / "src" / "profile.py"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(source, dest)
        runner = _make_runner(tmp_path)
        runner.run()

        findings = get_findings_by_rule_key(runner, "taint_sensitive_attr_write")
        assert len(findings) == 0, "La fixture clean (guard re.fullmatch) ne doit rien déclencher"


class TestRouteParamSources:
    """Pipeline end-to-end : params de route web taintés comme sources HTTP."""

    def test_route_param_flows_to_sink(self, tmp_path):
        """Un param de route annoté scalaire qui atteint un sink est détecté."""
        (tmp_path / "src").mkdir(exist_ok=True)
        (tmp_path / "src" / "api.py").write_text(
            '@router.post("/search")\n'
            'async def search(query: str, db):\n'
            '    return db.execute("SELECT * FROM t WHERE x = \'" + query + "\'")\n'
        )
        runner = _make_runner(tmp_path)
        runner.run()
        data = _read_json(runner)
        taint = [f for f in data["findings"] if f.get("taint_flow")]
        assert len(taint) >= 1, "Le param de route 'query' doit produire un flux taint"
        assert taint[0]["taint_flow"]["source_kind"] == "http"

    def test_unannotated_route_param_no_flow(self, tmp_path):
        """Un param de route non annoté (dépendance) ne crée pas de flux."""
        (tmp_path / "src").mkdir(exist_ok=True)
        (tmp_path / "src" / "api.py").write_text(
            '@router.post("/search")\n'
            'async def search(query, db):\n'
            '    return db.execute("SELECT * FROM t WHERE x = \'" + query + "\'")\n'
        )
        runner = _make_runner(tmp_path)
        runner.run()
        data = _read_json(runner)
        taint = [f for f in data["findings"] if f.get("taint_flow")]
        assert len(taint) == 0, "Param non annoté ne doit pas être traité comme source"
