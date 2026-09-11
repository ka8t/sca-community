"""
Project management — standalone functions for registration and detection.
"""
import os
import re
import sys
import json
import uuid
import logging
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Optional

from sca import SCRIPT_DIR
from sca.config import _remove_comments, DEFAULT_CONFIG
from sca.i18n import _t

logger = logging.getLogger("sca.projects")

# Extension → language mapping (single source of truth, consistent with runner.py)
EXT_TO_LANG = {}
for _lang, _exts in {
    "python": [".py"],
    "javascript": [".js", ".jsx", ".ts", ".tsx", ".mjs"],
    "html": [
        ".html", ".htm", ".xhtml", ".shtml",
        ".vue", ".svelte",
        ".ejs", ".hbs", ".njk",
        ".jinja", ".jinja2", ".twig", ".liquid", ".mustache",
        ".phtml", ".erb", ".jsp", ".asp", ".aspx", ".cshtml",
    ],
    "java": [".java"],
    "csharp": [".cs"],
    "php": [".php", ".inc"],
    "yaml": [".yml", ".yaml"],
}.items():
    for _ext in _exts:
        EXT_TO_LANG[_ext] = _lang

# Directories excluded from the extension scan
_EXCLUDED_DIRS = {"node_modules", "__pycache__", ".venv", "venv", "vendor",
                  ".git", "dist", "build", ".tox", ".mypy_cache", ".pytest_cache"}


def _auto_detect_project(project_path: Path) -> dict:
    """Auto-detect project information to generate the configuration.

    Returns:
        dict with the detected information (name, version, type, paths, etc.)
    """
    info = {
        "name": project_path.name,
        "version": "1.0.0",
        "type": [],
        "include_paths": [],
        "exclude_patterns": [
            "**/node_modules/**",
            "**/__pycache__/**",
            "**/.venv/**",
            "**/venv/**",
            "**/vendor/**",
            "**/.git/**",
            "**/dist/**",
            "**/build/**",
        ]
    }

    # Detect the version from package.json
    package_json = project_path / "package.json"
    if package_json.exists():
        try:
            with open(package_json, 'r', encoding='utf-8') as f:
                pkg = json.load(f)
                if "version" in pkg:
                    info["version"] = pkg["version"]
                if "name" in pkg:
                    info["name"] = pkg["name"]
        except (json.JSONDecodeError, IOError):
            pass

    # Detect the version from pyproject.toml
    pyproject = project_path / "pyproject.toml"
    if pyproject.exists():
        try:
            with open(pyproject, 'r', encoding='utf-8') as f:
                content = f.read()
                # Simple parsing for the version
                match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                if match:
                    info["version"] = match.group(1)
        except IOError:
            pass

    # Detect languages by scanning file extensions
    detected_langs = set()
    top_level_dirs = set()
    has_root_level_files = False

    for root, dirs, files in os.walk(project_path):
        # Exclude irrelevant directories + hidden directories (.git,
        # .github, .vscode, .circleci, etc.): never a source of code to
        # audit, and their presence must not mask the project root's
        # files (cf. bug 2026-07-19 — see below).
        dirs[:] = [d for d in dirs if d not in _EXCLUDED_DIRS and not d.startswith(".")]

        rel_root = Path(root).relative_to(project_path)
        for f in files:
            ext = Path(f).suffix.lower()
            lang = EXT_TO_LANG.get(ext)
            if lang:
                detected_langs.add(lang)
                # Remember the top-level directory
                parts = rel_root.parts
                if parts:
                    top_level_dirs.add(parts[0])
                else:
                    # File directly at the project root: nothing to
                    # remember in top_level_dirs, but "." must be
                    # explicitly included (see below), otherwise this
                    # file is silently excluded from the scan as soon as
                    # another subdirectory is detected elsewhere.
                    has_root_level_files = True

    # Build include_paths from the detected top-level directories
    for d in sorted(top_level_dirs):
        info["include_paths"].append(f"{d}/")

    # Files recognized directly at the root: always include "." even if
    # subdirectories were also detected — otherwise these files are
    # silently excluded from the scan (bug 2026-07-19: a project with
    # code at the root plus a detected subdirectory never scanned the
    # root, reporting "everything is OK" while nothing was scanned).
    if has_root_level_files:
        info["include_paths"].insert(0, ".")

    # Complement: config files indicate a language even without source code
    config_hints = {
        "requirements.txt": "python", "pyproject.toml": "python",
        "package.json": "javascript", "tsconfig.json": "javascript",
        "pom.xml": "java", "build.gradle": "java",
        "composer.json": "php", "composer.lock": "php",
        "artisan": "php", "symfony.lock": "php",
    }
    for config_file, lang in config_hints.items():
        if (project_path / config_file).exists():
            detected_langs.add(lang)

    # If no specific path was found, use the root
    if not info["include_paths"]:
        info["include_paths"] = ["."]

    # Deduplicate and clean up
    info["include_paths"] = list(dict.fromkeys(info["include_paths"]))

    # Build type[] and languages[] from the detected languages
    lang_to_type = {
        "python": "Python", "javascript": "JavaScript", "html": "HTML",
        "java": "Java", "csharp": "CSharp", "php": "PHP", "yaml": "YAML",
    }
    info["type"] = [lang_to_type[l] for l in sorted(detected_langs) if l in lang_to_type] or ["Unknown"]
    info["languages"] = sorted(detected_langs) if detected_langs else []

    return info


def _generate_config_from_detection(project_path: Path, info: dict) -> dict:
    """Load the audit.config.template.json template and customize it
    with the detected project information.
    """
    # Load the template
    template_path = SCRIPT_DIR / "templates" / "audit.config.template.json"

    if template_path.exists():
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"⚠️  {_t('template_load_error', 'en')}: {e}")
            config = {}
    else:
        print(f"⚠️  {_t('template_not_found', 'en')}: {template_path}")
        config = {}

    # Remove _comment fields from the template
    config = _remove_comments(config)

    # In binary mode: remove the database section (feature not exposed to clients)
    from sca.cli import _check_is_binary
    if _check_is_binary():
        config.pop("database", None)
        # Database category also removed from the enable-able categories dict
        if isinstance(config.get("categories"), dict):
            config["categories"].pop("database", None)

    # Customize with the detected information
    if "project" not in config:
        config["project"] = {}

    # Generate a unique UUID for this project
    project_uuid = str(uuid.uuid4())
    config["project"]["id"] = project_uuid
    config["project"]["name"] = info["name"]
    config["project"]["version"] = info["version"]
    config["project"]["description"] = ""

    # Detected languages
    config["languages"] = info.get("languages", [])

    if "paths" not in config:
        config["paths"] = {}
    config["paths"]["include"] = info["include_paths"]
    config["paths"]["exclude"] = info["exclude_patterns"]
    # Remove the python/js/html keys if present (leftover from the template)
    for key in ("python", "js", "html"):
        config["paths"].pop(key, None)

    # Make sure the required sections exist
    if "reports" not in config:
        config["reports"] = {
            "output_dir": "docs/audit-reports",
            "history_dir": "docs/audit-reports/audit-datas",
            "max_history": 10
        }

    if "categories" not in config:
        config["categories"] = {
            "security": {"enabled": True, "weight": 3},
            "architecture": {"enabled": True, "weight": 2},
            "ui": {"enabled": True, "weight": 1},
            "ux": {"enabled": True, "weight": 1},
            "maintenance": {"enabled": True, "weight": 1},
            "dependencies": {"enabled": False, "weight": 2}
        }

    if "thresholds" not in config:
        config["thresholds"] = {
            "max_high": 0,
            "min_health": 70
        }

    if "rules" not in config:
        config["rules"] = {"disabled": []}

    return config


def _init_project_config(project_path: Path, force_init: bool = False, lang: str = "fr") -> None:
    """Auto-detect project information and create audit.config.json.
    Also registers the project in the projects/{uuid}/ directory.

    Args:
        project_path: Path to the project being audited
        force_init: If True, called via --init (shows a different message)
        lang: Language for console messages
    """
    dest_path = project_path / "audit.config.json"

    if dest_path.exists():
        if force_init:
            print(f"⚠️  File already exists: {dest_path}")
            print(f"   Delete it manually to recreate.")
        return

    # Auto-detection
    print(f"🔍 {_t('auto_detection', lang)} \"{project_path.name}\"...")
    info = _auto_detect_project(project_path)
    logger.detail(_t("log_auto_detection", lang).format(info=info))

    # Display the detected information
    type_str = " + ".join(info["type"]) if info["type"] else "Unknown"
    print(f"   Type: {type_str}")
    print(f"   Paths: {', '.join(info['include_paths'])}")
    print(f"   Excludes: {', '.join(p.replace('**/', '') for p in info['exclude_patterns'][:4])}...")
    print()

    # Generate the configuration (includes UUID generation)
    config = _generate_config_from_detection(project_path, info)
    project_uuid = config["project"]["id"]
    project_uuid_short = project_uuid[:8]

    print(f"🔑 {_t('unique_id_generated', lang)}: {project_uuid_short}")

    # Write the audit.config.json file into the target project
    with open(dest_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    # Create the reports output directory
    output_dir = project_path / "docs" / "audit-reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Register the project on the audit script side
    _register_project(project_path, config)

    # Generate the CI/CD template files
    _generate_cicd_templates(project_path, config, lang)

    # Determine the real directory label (slug or uuid8 fallback) for the prints
    project_dir_path = _get_project_dir(project_uuid)
    project_dir_label = project_dir_path.name if project_dir_path else project_uuid_short

    print(f"✅ {_t('config_generated', lang)}: {dest_path}")
    print(f"✅ {_t('project_registered', lang)}: projects/{project_dir_label}/")
    print()
    print(f"   {_t('add_specific_fixtures', lang)}:")
    print(f"   {SCRIPT_DIR}/projects/{project_dir_label}/fixtures/vulnerable/")
    print(f"   {SCRIPT_DIR}/projects/{project_dir_label}/fixtures/clean/")
    print()
    print(f"   {_t('rerun_audit', lang)}:")
    audit_script = SCRIPT_DIR / "run_audit.py"
    print(f"   python3 {audit_script} {project_path}")

    # Exit the script
    sys.exit(0)


def _generate_cicd_templates(project_path: Path, config: dict, lang: str = "fr") -> None:
    """Generate CI/CD template files for GitHub Actions and GitLab CI.
    Files are only created if they don't already exist.
    """
    audit_script = SCRIPT_DIR / "run_audit.py"
    brand = config.get("brand", {})
    tool_name = brand.get("tool_name", DEFAULT_CONFIG["brand"]["tool_name"])
    prefix = brand.get("prefix", DEFAULT_CONFIG["brand"]["prefix"])

    # GitHub Actions
    gh_dir = project_path / ".github" / "workflows"
    gh_file = gh_dir / "audit.yml"
    if not gh_file.exists():
        gh_dir.mkdir(parents=True, exist_ok=True)
        gh_content = f"""name: {tool_name}

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am UTC

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Run {tool_name}
        run: |
          python3 {audit_script} . --skip-tests --fail-on-high

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: audit-report
          path: docs/audit-reports/{prefix}-REPORT-*.html
"""
        gh_file.write_text(gh_content)
        print(f"✅ {_t('cicd_generated', lang)}: {gh_file}")

    # GitLab CI
    gl_file = project_path / ".gitlab-ci-audit.yml"
    if not gl_file.exists():
        gl_content = f"""audit:
  stage: test
  image: python:3.12-slim
  script:
    - python3 {audit_script} . --skip-tests --fail-on-high
  artifacts:
    when: always
    paths:
      - docs/audit-reports/{prefix}-REPORT-*.html
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_PIPELINE_SOURCE == "schedule"
"""
        gl_file.write_text(gl_content)
        print(f"✅ {_t('cicd_generated', lang)}: {gl_file}")


def _slugify_name(name: str) -> str:
    """Convert a project name into a directory-name-safe slug.

    - Lowercase, no accents, [a-z0-9-] only
    - Spaces and underscores → hyphens
    - Consecutive hyphens collapsed to one
    - Max length 50 characters
    - Returns an empty string if nothing usable (caller must fall back to uuid)
    """
    if not name:
        return ""
    n = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    n = n.lower()
    n = re.sub(r"[^a-z0-9]+", "-", n)
    n = re.sub(r"-+", "-", n).strip("-")
    return n[:50]


def _resolve_project_dir_name(project_uuid: str, project_name: str) -> str:
    """Determine the `projects/<dir>/` directory name for a given project.

    Strategy:
    - Slugify ``project_name``; if empty, fall back to the first 8 chars of the UUID.
    - If the slug directory already exists AND belongs to a different UUID
      (collision) → suffix `-<uuid8>` to disambiguate deterministically.
    """
    uuid_short = (project_uuid or "")[:8]
    slug = _slugify_name(project_name) or uuid_short or "project"
    candidate_dir = SCRIPT_DIR / "projects" / slug
    if candidate_dir.exists():
        existing_id = _read_project_id_from_dir(candidate_dir)
        if existing_id and existing_id != project_uuid:
            return f"{slug}-{uuid_short}"
    return slug


def _read_project_id_from_dir(dir_path: Path) -> Optional[str]:
    """Read a project directory's UUID from its project.json. Returns None if missing/unreadable."""
    pj = dir_path / "project.json"
    if not pj.exists():
        return None
    try:
        return json.loads(pj.read_text(encoding="utf-8")).get("id")
    except (json.JSONDecodeError, IOError):
        return None


# Cache uuid → directory name (lazy, populated on the 1st call to _get_project_dir).
_PROJECT_DIR_CACHE: dict[str, str] = {}


def _scan_projects_index() -> dict[str, str]:
    """Build a `{uuid → dir_name}` index by scanning projects/."""
    index: dict[str, str] = {}
    projects_root = SCRIPT_DIR / "projects"
    if not projects_root.is_dir():
        return index
    for entry in projects_root.iterdir():
        if not entry.is_dir():
            continue
        pid = _read_project_id_from_dir(entry)
        if pid:
            index[pid] = entry.name
    return index


def _register_project(project_path: Path, config: dict) -> None:
    """Register a project in the projects/{uuid}/ directory.
    Creates the directory and the project.json file.

    Args:
        project_path: Path to the project
        config: Project configuration (contains project.id)
    """
    project_uuid = config["project"]["id"]
    project_name = config["project"].get("name", "")
    project_uuid_short = project_uuid[:8]

    # Create the projects/<slug>/ directory (readable) — uuid8 fallback if the name is empty
    dir_name = _resolve_project_dir_name(project_uuid, project_name)
    project_dir = SCRIPT_DIR / "projects" / dir_name
    project_dir.mkdir(parents=True, exist_ok=True)

    # Create the fixtures directories
    (project_dir / "fixtures" / "vulnerable").mkdir(parents=True, exist_ok=True)
    (project_dir / "fixtures" / "clean").mkdir(parents=True, exist_ok=True)

    # Create project.json
    project_json = {
        "id": project_uuid,
        "name": project_name,
        "description": config["project"].get("description", ""),
        "path": str(project_path.resolve()),
        "config_path": str((project_path / "audit.config.json").resolve()),
        "registered_at": datetime.now().isoformat(),
    }

    project_json_path = project_dir / "project.json"
    with open(project_json_path, 'w', encoding='utf-8') as f:
        json.dump(project_json, f, indent=2, ensure_ascii=False)

    # Update the uuid→dir cache for subsequent lookups in this process
    _PROJECT_DIR_CACHE[project_uuid] = dir_name

    logger.detail(_t("log_project_registered").format(uuid=project_uuid_short, dir=project_dir))


def _get_project_dir(project_uuid: str) -> Optional[Path]:
    """Return the path to the project's directory under projects/.

    First looks up the uuid→dir cache (populated by scanning each
    subdirectory's project.json), then falls back to the legacy uuid8 format.
    """
    if not project_uuid:
        return None

    if not _PROJECT_DIR_CACHE:
        _PROJECT_DIR_CACHE.update(_scan_projects_index())

    dir_name = _PROJECT_DIR_CACHE.get(project_uuid)
    if dir_name:
        candidate = SCRIPT_DIR / "projects" / dir_name
        if candidate.exists():
            return candidate

    # Backward-compat fallback: legacy projects/<uuid8>/ format
    project_uuid_short = project_uuid[:8]
    legacy = SCRIPT_DIR / "projects" / project_uuid_short
    if legacy.exists():
        return legacy
    return None
