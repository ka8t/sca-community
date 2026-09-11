"""
Internationalization — standalone functions for console messages.
"""
import os
import json
from pathlib import Path

from sca import SCRIPT_DIR

# Global cache for script translations
_i18n_cache: dict = {}

# Current script language (default: "en", updated by cli.py via _set_script_lang)
_script_lang: str = "en"


def _load_script_locale(lang: str = "fr") -> dict:
    """Load and cache the console message translation file for the given language."""
    if lang in _i18n_cache:
        return _i18n_cache[lang]

    locales_dir = SCRIPT_DIR / "locales" / "script"
    locale_file = locales_dir / f"{lang}.json"

    # Fallback to "en" if the file doesn't exist
    if not locale_file.exists():
        locale_file = locales_dir / "en.json"

    if locale_file.exists():
        with open(locale_file, "r", encoding="utf-8") as f:
            _i18n_cache[lang] = json.load(f)
            return _i18n_cache[lang]
    return {}


def _set_script_lang(lang: str):
    """Set the current script language (called by cli.py at startup)."""
    global _script_lang
    _script_lang = lang


def _get_script_lang() -> str:
    """Return the current script language."""
    return _script_lang


def _t(key: str, lang: str = None) -> str:
    """Translate a key for use outside of class contexts.

    If lang is not specified, uses the current language (_script_lang).
    """
    i18n = _load_script_locale(lang or _script_lang)
    return i18n.get(key, key)


def get_verbose() -> bool:
    """Return True if verbose mode is enabled."""
    return os.environ.get("SCA_VERBOSE", "0") == "1"
