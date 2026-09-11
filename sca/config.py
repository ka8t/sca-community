"""
Configuration — chargement, validation, fusion et valeurs par défaut.
"""
import os
import re
import sys
import json
import logging
from pathlib import Path

from sca import SCRIPT_DIR
from sca.i18n import _t

logger = logging.getLogger("sca.config")


DEFAULT_CONFIG = {
    "brand": {
        "tool_name": "StaticCodeAudit",
        "company_name": "CodeFixture",
        "prefix": "SCA",
        "logo": None,
        "primary_color": "#1e3a5f",
        "accent_color": "#2c5282",
        "website_url": None
    },
    "project": {
        "id": None,  # UUID generated at --init, required
        "name": "StaticCodeAudit",
        "version": "1.0",
        "description": ""
    },
    "paths": {
        # IMPORTANT: paths.include is REQUIRED - must be defined in audit.config.json
        "include": None,  # Validated after loading
        "exclude": ["node_modules/", "vendor/", ".venv/", "__pycache__/", "*.min.js", "audit-reports/", "audit-datas/"]
    },
    "reports": {
        "output_dir": "../StaticCodeAudit/reports/audit-reports",
        "history_dir": "../StaticCodeAudit/reports/audit-reports/audit-datas",
        "max_history": 10,
        "language": "en"
    },
    "categories": {
        "security": {"enabled": True, "weight": 3},
        "architecture": {"enabled": True, "weight": 2},
        "ui": {"enabled": True, "weight": 1},
        "ux": {"enabled": True, "weight": 1},
        "maintenance": {"enabled": True, "weight": 1}
    },
    "rules": {
        "disabled": [],
        "custom_patterns": {}
    },
    "tests": {
        "enabled": True,
        "tests_dir": "tests/",
        "command": "python -m pytest {tests_dir} -v --tb=short"
    },
    "fixtures": {
        "profile": "generic",
        "include_generic": True
    },
    "thresholds": {
        "max_high": 0,
        "max_medium": 10,
        "min_health": 80
    },
    "retention": {
        "mode": None,       # "count" | "days" | "both" | null (no cleanup)
        "max_count": 10,
        "max_days": 90
    },
    "database": {
        "enabled": False,
        "host": "localhost",
        "port": "5432",
        "database": "",
        "user": "",
        "password_env_file": ".env",
        "password_env_var": "DB_PASSWORD",
        "track": {
            "tables": True,
            "columns": True,
            "constraints": True,
            "indexes": True,
            "enums": True
        },
        "severity": {
            "column_dropped": "HIGH",
            "table_dropped": "HIGH",
            "type_changed": "MEDIUM",
            "column_added": "LOW",
            "index_added": "INFO"
        },
        "code_analysis": {
            "enabled": True,
            "escalate_severity": True
        }
    }
}


def load_config(config_path: str = None, project_path: Path = None, silent: bool = False, lang: str = "en") -> dict:
    """Load configuration with the following priority:
    1. CLI options (passed via overrides)
    2. Environment variables
    3. Project configuration file
    4. Default values

    Args:
        config_path: Path to the configuration file (default: <project>/audit.config.json)
        project_path: Absolute path to the project being audited
        silent: If True, suppress printed messages (for internal calls)
    """
    # Determine the config file path
    if config_path is None and project_path:
        config_path = str(project_path / "audit.config.json")
    elif config_path is None:
        config_path = os.environ.get("SCA_CONFIG", "audit.config.json")

    # Load the default config
    config = json.loads(json.dumps(DEFAULT_CONFIG))  # Deep copy

    # Load from the file if it exists
    config_file = Path(config_path)  # sca-ignore:taint_pathtraver — config_path comes from env var SCA_CONFIG or local CLI, not remote input
    if config_file.exists():
        try:
            with open(config_file, 'r', encoding='utf-8') as f:  # sca-ignore:taint_pathtraver — same string (local env var)
                file_config = json.load(f)
            # Strip _comment fields from the template
            file_config = _remove_comments(file_config)
            # Recursive merge
            config = _merge_config(config, file_config)
            log_path = os.path.relpath(config_path, project_path) if project_path else config_path
            logger.info(_t("log_config_file", lang).format(path=log_path))  # sca-ignore:taint_loginjection — local env var, internal logger
            logger.detail(_t("log_config_sections", lang).format(sections=", ".join(file_config.keys())))
            if not silent:
                print(f"📄 {_t('config_loaded', lang)}: {config_path}")
        except json.JSONDecodeError as e:
            print(f"⚠️  {_t('config_syntax_error', lang).format(path=config_path)}: {e}")
        except Exception as e:
            print(f"⚠️  {_t('config_load_error', lang).format(path=config_path)}: {e}")

    # Resolve paths relative to the project
    if project_path:
        # Set the output directory within the project
        if "reports" not in config:
            config["reports"] = {}
        if not config["reports"].get("output_dir"):
            config["reports"]["output_dir"] = str(project_path / "docs" / "audit-reports")
        if not config["reports"].get("history_dir"):
            config["reports"]["history_dir"] = str(project_path / "docs" / "audit-reports" / "audit-datas")

        # Store the project and config paths in the config
        config["_project_path"] = str(project_path)
        config["_config_path"] = os.path.relpath(config_path, project_path) if config_path else "audit.config.json"

    # Override with environment variables
    if os.environ.get("SCA_OUTPUT"):
        config["reports"]["output_dir"] = os.environ["SCA_OUTPUT"]
        config["reports"]["history_dir"] = os.path.join(os.environ["SCA_OUTPUT"], "audit-datas")

    # --- License check (distributed binary only) ---
    # In source mode _IS_SOURCE_MODE=True → no restriction.
    # In binary mode _IS_SOURCE_MODE=False → check the license.
    _skip_license = any(a in sys.argv for a in ("--version", "--help", "-h", "--list-rules", "--list-categories"))
    if not _skip_license:
        try:
            import sca.license_check as _lc
            from sca.license_check import verify_license, DEMO_MAX_FILES, DEMO_CATEGORIES
            # Read _IS_SOURCE_MODE via the module (not a local copy) so that
            # --simulate-binary can patch it dynamically from cli.py.
            if getattr(_lc, "_IS_SOURCE_MODE", True):
                config["_demo_mode"] = False
            else:
                _license = verify_license()
                if _license is None:
                    config["_demo_mode"] = True
                    config["_demo_max_files"] = DEMO_MAX_FILES
                    # For the LOC lever: import from license_check (already imported via _lc)
                    config["_demo_max_loc"] = getattr(_lc, "DEMO_MAX_LOC", 1000)
                    config["_demo_categories"] = DEMO_CATEGORIES
                else:
                    config["_demo_mode"] = False
                    config["_license_data"] = _license
        except ImportError:
            config["_demo_mode"] = False
        except Exception:
            config["_demo_mode"] = False

    # --- Extended license information (facade) ---
    # Centralizes tier, features, max_files, exports, seats in config["_license"].
    # In source mode (no license_check), enterprise defaults (no restriction).
    from sca.license_facade import get_license_info
    config["_license"] = get_license_info()

    return config


def _merge_config(base: dict, override: dict) -> dict:
    """Recursively merge two configuration dictionaries."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_config(result[key], value)
        else:
            result[key] = value
    return result


def _remove_comments(config: dict) -> dict:
    """Strip _comment* fields from the configuration dictionary."""
    result = {}
    for key, value in config.items():
        if key.startswith("_comment"):
            continue
        if isinstance(value, dict):
            result[key] = _remove_comments(value)
        else:
            result[key] = value
    return result


def validate_config(config: dict, project_path: Path, lang: str = "en") -> bool:
    """Validate that the configuration contains the required fields.

    Args:
        config: Loaded configuration
        project_path: Project path, used in error messages

    Returns:
        True if valid, False otherwise (with an error message printed)
    """
    # Check languages
    supported_languages = {"python", "javascript", "html", "java", "csharp", "php", "yaml"}
    languages = config.get("languages")
    if not languages:
        print(f"❌ {_t('config_languages_required', lang)}")
        print()
        print(f"   {_t('config_languages_hint', lang)}")
        print(f"   {_t('config_supported_values', lang)}: python, javascript, html, java, csharp, php, yaml")
        print(f"   {_t('config_example_languages', lang)}")
        print()
        print(f"   {_t('config_or_use_init', lang)}: python3 run_audit.py --init {project_path}")
        return False

    invalid_langs = set(languages) - supported_languages
    if invalid_langs:
        print(f"❌ {_t('config_unsupported_languages', lang)}: {', '.join(sorted(invalid_langs))}")
        print(f"   {_t('config_supported_values', lang)}: {', '.join(sorted(supported_languages))}")
        return False

    # Validate the optional versions key (dict of strings)
    versions = config.get("versions")
    if versions is not None:
        if not isinstance(versions, dict):
            print(f"❌ {_t('config_versions_invalid', lang)}")
            return False

    # Check paths.include
    paths_include = config.get("paths", {}).get("include")
    if not paths_include:
        print(f"❌ {_t('config_paths_required', lang)}")
        print()
        print(f"   {_t('config_paths_hint', lang)}")
        print(f"   {_t('config_example_paths', lang)}")
        print()
        print(f"   {_t('config_auto_generate', lang)}")
        print(f"   {_t('config_delete_file', lang).format(path=project_path / 'audit.config.json')}")
        print(f"   {_t('config_rerun_detection', lang)}")
        print()
        print(f"   {_t('config_or_use_init', lang)}: python3 run_audit.py --init {project_path}")
        return False

    # Validate brand (optional, but checked if present)
    brand = config.get("brand", {})
    prefix = brand.get("prefix", "SCA")
    if not prefix or not re.match(r'^[A-Za-z0-9_-]{1,10}$', prefix):
        print(f"❌ {_t('config_brand_prefix_invalid', lang).format(prefix=prefix)}")
        return False

    _HEX_RE = re.compile(r'^#[0-9a-fA-F]{6}$')
    for key in ("primary_color", "accent_color"):
        value = brand.get(key)
        if value and not _HEX_RE.match(value):
            print(f"❌ {_t('config_brand_color_invalid', lang).format(key=key, value=value)}")
            return False

    logo = brand.get("logo")
    if logo:
        logo_path = Path(logo) if os.path.isabs(logo) else project_path / logo
        if not logo_path.exists():
            print(f"⚠️  {_t('config_brand_logo_not_found', lang).format(path=logo_path)}")
        elif logo_path.suffix.lower() not in (".svg", ".png", ".jpg", ".jpeg"):
            print(f"⚠️  {_t('config_brand_logo_bad_format', lang).format(ext=logo_path.suffix)}")

    return True


def _create_config_from_template(config_path: str, lang: str = "en") -> None:
    """Copy the configuration template to the given path and exit the script.

    In binary mode, filters out the database section (a feature not
    exposed to clients).
    """
    template_path = SCRIPT_DIR / "templates" / "audit.config.template.json"

    if template_path.exists():
        from sca.cli import _check_is_binary
        if _check_is_binary():
            with open(template_path, "r", encoding="utf-8") as f:
                tpl = json.load(f)
            tpl.pop("database", None)
            if isinstance(tpl.get("categories"), dict):
                tpl["categories"].pop("database", None)
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(tpl, f, indent=2, ensure_ascii=False)
        else:
            import shutil
            shutil.copy(template_path, config_path)
        print(f"📄 {_t('config_file_created', lang)}: {config_path}")
        print(f"   {_t('config_edit_and_rerun', lang)}")
        print(f"   {_t('config_comment_hint', lang)}\n")
        sys.exit(0)
    else:
        print(f"❌ {_t('template_not_found', lang)}: {template_path}")
        print(f"   {_t('config_create_manually', lang)}")
        sys.exit(1)
