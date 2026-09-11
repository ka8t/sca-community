"""
Chargeur de profils de framework pour l'analyse taint.

Détecte automatiquement le framework utilisé par le projet (Flask, Django,
FastAPI, Express, Spring...) et charge les sources/sinks/sanitizers adaptés.

Les profils sont dans sca/profiles/<langage>/<framework>.profile.
Le profil stdlib est chargé comme base si un fichier
`sca/profiles/<langage>/stdlib.profile` existe pour ce langage.
"""
import logging
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

from sca import SCRIPT_DIR

logger = logging.getLogger("sca.profile_loader")

# Profiles directory
PROFILES_DIR = SCRIPT_DIR / "sca" / "profiles"


def detect_frameworks(project_path: str, language: str,
                       file_contents: Dict[str, str] = None) -> List[str]:
    """Detect the frameworks used in the project.

    Analyzes imports and dependency files to identify frameworks. Returns
    a list of profile names to load.

    Args:
        project_path: project root path
        language: language to analyze (python, javascript, java)
        file_contents: dict filepath → content (avoids re-reading if already loaded)

    Returns:
        List of profile names (e.g. ["stdlib", "flask"])
    """
    # `stdlib` loaded as a base only if the file exists for this
    # language. Avoids a "Profile not found" warning for languages
    # that don't (yet) have a stdlib profile defined (javascript, java,
    # php...). Sources/sinks/sanitizers for these languages are defined
    # directly in the `.sca` rules.
    profiles: List[str] = []
    if (PROFILES_DIR / language / "stdlib.profile").exists():
        profiles.append("stdlib")
    project = Path(project_path)

    if language == "python":
        profiles.extend(_detect_python_frameworks(project, file_contents))
    elif language == "javascript":
        profiles.extend(_detect_js_frameworks(project, file_contents))
    elif language == "java":
        profiles.extend(_detect_java_frameworks(project, file_contents))

    return profiles


def _detect_python_frameworks(project: Path, file_contents: Dict[str, str] = None) -> List[str]:
    """Detect Python frameworks (Flask, Django, FastAPI)."""
    found = set()

    # 1. Check requirements.txt / pyproject.toml
    for dep_file in ["requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"]:
        dep_path = project / dep_file
        if dep_path.exists():
            try:
                content = dep_path.read_text(encoding="utf-8").lower()
                if "flask" in content:
                    found.add("flask")
                if "django" in content:
                    found.add("django")
                if "fastapi" in content:
                    found.add("fastapi")
            except Exception:
                pass

    # 2. Check imports in the source code
    if file_contents:
        for filepath, content in file_contents.items():
            if not filepath.endswith(".py"):
                continue
            if "from flask " in content or "import flask" in content:
                found.add("flask")
            if "from django" in content or "import django" in content:
                found.add("django")
            if "from fastapi" in content or "import fastapi" in content:
                found.add("fastapi")

    if found:
        logger.info("[profile] Frameworks Python détectés : %s", ', '.join(sorted(found)))
    else:
        logger.info("[profile] Aucun framework Python détecté — profil stdlib uniquement")

    return sorted(found)


def _detect_js_frameworks(project: Path, file_contents: Dict[str, str] = None) -> List[str]:
    """Detect JavaScript frameworks (Express, Next.js, NestJS)."""
    found = set()
    package_json = project / "package.json"
    if package_json.exists():
        try:
            content = package_json.read_text(encoding="utf-8").lower()
            if "express" in content:
                found.add("express")
            if "next" in content:
                found.add("nextjs")
            if "@nestjs" in content:
                found.add("nestjs")
        except Exception:
            pass
    return sorted(found)


def _detect_java_frameworks(project: Path, file_contents: Dict[str, str] = None) -> List[str]:
    """Detect Java frameworks (Spring, Servlet)."""
    found = set()
    for build_file in ["pom.xml", "build.gradle", "build.gradle.kts"]:
        path = project / build_file
        if path.exists():
            try:
                content = path.read_text(encoding="utf-8").lower()
                if "spring" in content:
                    found.add("spring")
            except Exception:
                pass
    return sorted(found)


def load_profile(language: str, framework: str) -> Dict:
    """Load a framework profile from a .profile file.

    Returns:
        Dict with keys: sources, sinks, sanitizers
        Each source is (pattern_text, kind)
        Each sink is (pattern_text, category)
        Each sanitizer is pattern_text
    """
    profile_path = PROFILES_DIR / language / f"{framework}.profile"
    if not profile_path.exists():
        logger.warning("[profile] Profil introuvable : %s", profile_path)
        return {"sources": [], "sinks": [], "sanitizers": []}

    sources = []
    sinks = []
    sanitizers = []
    current_section = None

    try:
        for line in profile_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].lower()
                continue

            if current_section == "detect":
                continue  # Used by detect_frameworks, not here

            if current_section == "sources":
                parts = line.rsplit(None, 1)  # "request.args.get(    http" → ["request.args.get(", "http"]
                if len(parts) == 2:
                    sources.append((parts[0].strip(), parts[1].strip()))
                else:
                    sources.append((line, "http"))

            elif current_section == "sinks":
                parts = line.rsplit(None, 1)
                if len(parts) == 2:
                    sinks.append((parts[0].strip(), parts[1].strip()))
                else:
                    sinks.append((line, "unknown"))

            elif current_section == "sanitizers":
                sanitizers.append(line)

    except Exception as e:
        logger.warning("[profile] Erreur lecture %s: %s", profile_path, e)

    return {"sources": sources, "sinks": sinks, "sanitizers": sanitizers}


def load_merged_profile(language: str, frameworks: List[str]) -> Dict:
    """Load and merge multiple profiles (stdlib + detected frameworks).

    Profiles are merged in order: stdlib first, then the detected
    frameworks. Duplicates are removed.

    Returns:
        Dict with merged and deduplicated sources, sinks, sanitizers.
    """
    all_sources = []
    all_sinks = []
    all_sanitizers = []
    seen_sources = set()
    seen_sinks = set()
    seen_sanitizers = set()

    for fw in frameworks:
        profile = load_profile(language, fw)
        for src in profile["sources"]:
            key = src[0]
            if key not in seen_sources:
                seen_sources.add(key)
                all_sources.append(src)
        for sink in profile["sinks"]:
            key = sink[0]
            if key not in seen_sinks:
                seen_sinks.add(key)
                all_sinks.append(sink)
        for san in profile["sanitizers"]:
            if san not in seen_sanitizers:
                seen_sanitizers.add(san)
                all_sanitizers.append(san)

    logger.info("[profile] Profil fusionné (%s): %d sources, %d sinks, %d sanitizers",  # sca-ignore:taint_log_injection — frameworks contains only fixed internal constants ("flask","django","fastapi",...), never the raw content of the audited project despite the source flagged by the taint engine
                '+'.join(frameworks), len(all_sources), len(all_sinks), len(all_sanitizers))

    return {"sources": all_sources, "sinks": all_sinks, "sanitizers": all_sanitizers}


def profile_to_compiled_rules(profile: Dict) -> Tuple[List, List, List]:
    """Convert a profile into compiled (regex) lists — legacy function.

    Kept for backward compatibility. The dataflow engine now consumes
    profiles via `sca/rule_engine.py:_extend_rules_with_profile`, which
    returns extended JSON rules rather than compiled tuples.

    Returns:
        (sources, sinks, sanitizers) with compiled regexes.
    """
    from sca.cli import _text_to_regex

    compiled_sources = []
    for pattern_text, kind in profile["sources"]:
        regex = _text_to_regex(pattern_text)
        try:
            compiled = re.compile(regex)
            compiled_sources.append((compiled, kind, {"id": f"profile_{kind}"}))
        except re.error:
            pass

    compiled_sinks = []
    for pattern_text, category in profile["sinks"]:
        regex = _text_to_regex(pattern_text)
        try:
            compiled = re.compile(regex)
            compiled_sinks.append((compiled, 0, {"id": f"taint_{category}"}))
        except re.error:
            pass

    compiled_sanitizers = []
    for pattern_text in profile["sanitizers"]:
        regex = _text_to_regex(pattern_text)
        try:
            compiled_sanitizers.append(re.compile(regex))
        except re.error:
            pass

    return compiled_sources, compiled_sinks, compiled_sanitizers
