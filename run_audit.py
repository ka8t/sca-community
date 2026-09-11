#!/usr/bin/env python3
"""
StaticCodeAudit — Script d'Audit de Conformité
================================================
Analyse le codebase et génère un rapport HTML groupé par priorité.
Compare automatiquement avec le dernier audit (si disponible).
Configuration via <projet_cible>/audit.config.json ou variables d'environnement.

Usage:
    python ../StaticCodeAudit/run_audit.py
    python ../StaticCodeAudit/run_audit.py --quick                    # Sécurité uniquement
    python ../StaticCodeAudit/run_audit.py --fail-on-high             # Exit 1 si HIGH trouvé
    python ../StaticCodeAudit/run_audit.py --self-test                # Exit 2 si fixtures invalides
    python ../StaticCodeAudit/run_audit.py --config=custom.json       # Config personnalisée
    python ../StaticCodeAudit/run_audit.py --project="Mon Projet"     # Nom du projet
    python ../StaticCodeAudit/run_audit.py --output=./reports         # Dossier de sortie
    python ../StaticCodeAudit/run_audit.py --skip-deps               # Sans scan dépendances
    python ../StaticCodeAudit/run_audit.py --skip-tests              # Sans tests unitaires
    python ../StaticCodeAudit/run_audit.py --debug                   # Debug info (INFO)
    python ../StaticCodeAudit/run_audit.py --debug=detail            # Debug detail (DETAIL)
    python ../StaticCodeAudit/run_audit.py --debug=trace             # Debug trace (TRACE)
    python ../StaticCodeAudit/run_audit.py --list-categories          # Lister les catégories
    python ../StaticCodeAudit/run_audit.py --list-rules               # Lister les règles par catégorie

Environment Variables:
    SCA_CONFIG   - Chemin vers le fichier de configuration (défaut: <projet>/audit.config.json)
    SCA_OUTPUT   - Dossier de sortie des rapports
    SCA_VERBOSE  - Mode verbose (0/1)
    SCA_DEBUG    - Debug level (info/detail/trace)

Output:
    {output_dir}/SCA-REPORT-YYYY-MM-DD-HH-MM.html
    {output_dir}/audit-datas/SCA-DATA-YYYY-MM-DD-HH-MM.json
"""

import sys
from pathlib import Path

# Ajouter le .venv local au path pour les dépendances optionnelles (ex: psycopg2)
_venv_site = Path(__file__).parent / ".venv" / "lib"
if _venv_site.exists():
    for p in sorted(_venv_site.glob("python*/site-packages")):
        if str(p) not in sys.path:
            sys.path.append(str(p))

# ============================================================================
# RÉ-EXPORTS — Rétrocompatibilité avec les imports existants
# ============================================================================
# Tous les symboles sont ré-exportés pour que
# `from run_audit import AuditRunner, Finding` continue de fonctionner.

from sca import (
    AuditRunner, Finding, Category, ComparisonResult,
    TestResults, FixtureValidation, ProgressDisplay,
)
from sca.config import load_config, validate_config, DEFAULT_CONFIG
from sca.projects import (
    _auto_detect_project, _generate_config_from_detection,
    _init_project_config, _register_project, _get_project_dir,
)
from sca.i18n import _load_script_locale, _t, get_verbose
from sca.cli import (
    parse_args, list_rules, list_fixtures, match_rules_fixtures, main,
)


if __name__ == "__main__":
    main()
