"""
StaticCodeAudit (sca) — Multi-language static code analysis package.
"""
import sys
from pathlib import Path

# Tool version (source of truth for the script and the distribution)
VERSION = "2.0.0"

# Compiled-mode detection (Nuitka/PyInstaller)
_exe_name = Path(sys.executable).name.lower()
_is_compiled = not any(_exe_name.startswith(p) for p in ("python", "pypy"))

# SCRIPT_DIR — externalized resources (templates, locales, assets, vendor, config).
# Compiled mode: next to the binary. Source mode: repo root.
if _is_compiled:
    SCRIPT_DIR = Path(sys.executable).parent
else:
    SCRIPT_DIR = Path(__file__).parent.parent

# SCA_PACKAGE_DIR — resources bundled into the binary (builtin rules,
# ISO/ASVS mappings). Always relative to the sca/ package (bundled by Nuitka).
SCA_PACKAGE_DIR = Path(__file__).parent

from sca.models import Finding, TaintFlow, Category, ComparisonResult, TestResults, FixtureValidation, ProgressDisplay
from sca.debug import setup_debug, get_debug_level, DETAIL, TRACE
from sca.runner import AuditRunner
