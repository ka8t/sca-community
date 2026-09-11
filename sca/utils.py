"""
Utilities — standalone, stateless functions.
"""
import os
import logging
from typing import List, Tuple

from sca.debug import TRACE
from sca.i18n import _t

logger = logging.getLogger("sca.utils")


def read_file(filepath: str) -> List[tuple]:
    """Read a file and return its lines paired with 1-based line numbers."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = list(enumerate(f.readlines(), 1))
            if logger.isEnabledFor(TRACE):
                logger.trace(_t("log_file_read").format(file=os.path.basename(filepath), lines=len(lines)))
            return lines
    except Exception:
        if logger.isEnabledFor(TRACE):
            logger.trace(_t("log_file_unreadable").format(file=os.path.basename(filepath)))
        return []


def get_file_type(filepath: str) -> str:
    """Classify a file path as migration, test, vendor, config, or production."""
    path_lower = filepath.lower()
    if '/alembic/' in path_lower or '/migrations/' in path_lower:
        return "migration"
    if '/test' in path_lower or 'test_' in os.path.basename(path_lower) or '_test.py' in path_lower:
        return "test"
    if '/vendor/' in path_lower or '/lib/' in path_lower or '/node_modules/' in path_lower:
        file_type = "vendor"
    elif 'config' in os.path.basename(path_lower) or '/config/' in path_lower:
        file_type = "config"
    else:
        file_type = "production"

    if logger.isEnabledFor(TRACE):
        logger.trace(_t("log_file_type").format(file=os.path.basename(filepath), type=file_type))
    return file_type


def get_context(filepath: str, line: int, context_size: int = 2) -> Tuple[str, str]:
    """Return the lines of context surrounding a given line as (before, after)."""
    try:
        lines = read_file(filepath)
        before_lines = []
        after_lines = []
        for ln, content in lines:
            if line - context_size <= ln < line:
                before_lines.append(content.rstrip())
            elif line < ln <= line + context_size:
                after_lines.append(content.rstrip())
        return "\n".join(before_lines), "\n".join(after_lines)
    except Exception:
        return "", ""


def is_dependency(filepath: str) -> bool:
    """Return True if the file path belongs to external dependencies/vendor code."""
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


def get_file_group(filepath: str) -> str:
    """Return the file's group: 'deps' or 'business'."""
    return "deps" if is_dependency(filepath) else "business"
