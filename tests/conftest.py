"""
Tests d'Audit - Fixtures communes
=================================
Fournit les fixtures pour tester les règles d'audit.
"""

import pytest
import shutil
import sys
from pathlib import Path

# Ajouter le répertoire racine au path pour importer le script d'audit
ROOT_DIR = Path(__file__).parent.parent
FIXTURES_BASE_DIR = Path(__file__).parent / "fixtures"
# Profil par défaut: generic
FIXTURES_DIR = FIXTURES_BASE_DIR / "generic"
sys.path.insert(0, str(ROOT_DIR))

from run_audit import AuditRunner, Finding


# =============================================================================
# FIXTURES PYTEST
# =============================================================================

@pytest.fixture
def temp_project(tmp_path):
    """Crée une structure de projet temporaire pour les tests."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "features").mkdir(parents=True)
    (tmp_path / "src" / "js").mkdir(parents=True)
    return tmp_path


@pytest.fixture
def audit_runner(temp_project):
    """Crée une instance d'AuditRunner pour le projet temporaire."""
    config = {
        "languages": ["python", "javascript", "html"],
        "paths": {
            "include": ["src/"]
        },
        "reports": {"language": "fr"}
    }
    return AuditRunner(config=config, root_dir=str(temp_project), quick_mode=False, script_lang="fr")


@pytest.fixture
def security_runner(temp_project):
    """Crée une instance d'AuditRunner en mode quick (sécurité uniquement)."""
    config = {
        "languages": ["python", "javascript", "html"],
        "paths": {
            "include": ["src/"]
        },
        "reports": {"language": "fr"}
    }
    return AuditRunner(config=config, root_dir=str(temp_project), quick_mode=True, script_lang="fr")


@pytest.fixture
def py_runner(tmp_path):
    """Crée un AuditRunner configuré pour auditer des fichiers Python uniquement."""
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    config = {
        "languages": ["python"],
        "paths": {"include": ["src/"]},
        "reports": {"language": "en"},
    }
    return AuditRunner(config=config, root_dir=str(tmp_path), quick_mode=False, script_lang="en")


@pytest.fixture
def js_runner(tmp_path):
    """Crée un AuditRunner configuré pour auditer des fichiers JavaScript."""
    (tmp_path / "src" / "js").mkdir(parents=True, exist_ok=True)
    config = {
        "languages": ["javascript"],
        "paths": {"include": ["src/"]},
        "reports": {"language": "en"},
    }
    return AuditRunner(config=config, root_dir=str(tmp_path), quick_mode=False, script_lang="en")


@pytest.fixture
def html_runner(tmp_path):
    """Crée un AuditRunner configuré pour auditer des fichiers HTML (.vue, .svelte)."""
    (tmp_path / "src" / "js").mkdir(parents=True, exist_ok=True)
    config = {
        "languages": ["html"],
        "paths": {"include": ["src/"]},
        "reports": {"language": "en"},
    }
    return AuditRunner(config=config, root_dir=str(tmp_path), quick_mode=False, script_lang="en")


@pytest.fixture
def java_runner(tmp_path):
    """Crée un AuditRunner configuré pour auditer des fichiers Java."""
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    config = {
        "languages": ["java"],
        "paths": {"include": ["src/"]},
        "reports": {"language": "en"},
    }
    return AuditRunner(config=config, root_dir=str(tmp_path), quick_mode=False, script_lang="en")


@pytest.fixture
def csharp_runner(tmp_path):
    """Crée un AuditRunner configuré pour auditer des fichiers C#."""
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    config = {
        "languages": ["csharp"],
        "paths": {"include": ["src/"]},
        "reports": {"language": "en"},
    }
    return AuditRunner(config=config, root_dir=str(tmp_path), quick_mode=False, script_lang="en")


@pytest.fixture
def php_runner(tmp_path):
    """Crée un AuditRunner configuré pour auditer des fichiers PHP."""
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    config = {
        "languages": ["php"],
        "paths": {"include": ["src/"]},
        "reports": {"language": "en"},
    }
    return AuditRunner(config=config, root_dir=str(tmp_path), quick_mode=False, script_lang="en")


# =============================================================================
# HELPERS - CRÉATION DE FICHIERS INLINE
# =============================================================================

def create_py_file(base_path: Path, relative_path: str, content: str) -> Path:
    """Helper pour créer un fichier Python dans le projet de test."""
    file_path = base_path / relative_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content)
    return file_path


def create_js_file(base_path: Path, relative_path: str, content: str) -> Path:
    """Helper pour créer un fichier JavaScript dans le projet de test."""
    file_path = base_path / relative_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content)
    return file_path


def create_html_file(base_path: Path, relative_path: str, content: str) -> Path:
    """Helper pour créer un fichier HTML dans le projet de test."""
    file_path = base_path / relative_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content)
    return file_path


# =============================================================================
# HELPERS - CHARGEMENT DE FIXTURES
# =============================================================================

def get_fixture_path(fixture_type: str, filename: str) -> Path:
    """
    Retourne le chemin vers un fichier fixture.

    Args:
        fixture_type: 'vulnerable' ou 'clean'
        filename: nom du fichier (ex: 'sql_injection_fstring.py')

    Returns:
        Path vers le fichier fixture
    """
    return FIXTURES_DIR / fixture_type / filename


def load_fixture(fixture_type: str, filename: str) -> str:
    """
    Charge le contenu d'un fichier fixture.

    Args:
        fixture_type: 'vulnerable' ou 'clean'
        filename: nom du fichier

    Returns:
        Contenu du fichier
    """
    fixture_path = get_fixture_path(fixture_type, filename)
    if not fixture_path.exists():
        raise FileNotFoundError(f"Fixture not found: {fixture_path}")
    return fixture_path.read_text()


def copy_fixture_to_project(
    temp_project: Path,
    fixture_type: str,
    fixture_name: str,
    target_path: str
) -> Path:
    """
    Copie un fichier fixture vers le projet de test.

    Args:
        temp_project: chemin du projet temporaire
        fixture_type: 'vulnerable' ou 'clean'
        fixture_name: nom du fichier fixture
        target_path: chemin relatif dans le projet (ex: 'src/service.py')

    Returns:
        Path vers le fichier copié
    """
    source = get_fixture_path(fixture_type, fixture_name)
    dest = temp_project / target_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(source, dest)
    return dest


def use_vulnerable_fixture(temp_project: Path, fixture_name: str, target_path: str) -> Path:
    """Raccourci pour copier une fixture vulnérable."""
    return copy_fixture_to_project(temp_project, "vulnerable", fixture_name, target_path)


def use_clean_fixture(temp_project: Path, fixture_name: str, target_path: str) -> Path:
    """Raccourci pour copier une fixture saine."""
    return copy_fixture_to_project(temp_project, "clean", fixture_name, target_path)


# =============================================================================
# HELPERS - ANALYSE DES RÉSULTATS
# =============================================================================

def get_findings_by_rule(runner: AuditRunner, rule_name: str) -> list:
    """Retourne les findings correspondant à une règle spécifique (nom traduit, legacy)."""
    findings = []
    for cat in runner.categories.values():
        for f in cat.findings:
            if rule_name.lower() in f.rule.lower():
                findings.append(f)
    return findings


def get_findings_by_rule_key(runner: AuditRunner, rule_key: str) -> list:
    """Retourne les findings correspondant à une rule_key (invariant i18n)."""
    findings = []
    for cat in runner.categories.values():
        for f in cat.findings:
            if f.rule_key == rule_key:
                findings.append(f)
    return findings


def get_findings_by_category(runner: AuditRunner, category: str) -> list:
    """Retourne tous les findings d'une catégorie."""
    if category in runner.categories:
        return runner.categories[category].findings
    return []


def get_all_findings(runner: AuditRunner) -> list:
    """Retourne tous les findings de toutes les catégories."""
    findings = []
    for cat in runner.categories.values():
        findings.extend(cat.findings)
    return findings



from tests.registry import VULNERABLE_FIXTURES, CLEAN_FIXTURES  # noqa: F401
