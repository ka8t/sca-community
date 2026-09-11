"""
Compiled rules cache (D.2.1 — see docs/plans/PLAN-AUDIT-CONFORMITE.html §20.1).

Serializes the parsed rules and their compiled regexes to `.sca-cache/rules.pkl`
to speed up loading on successive runs.

Automatic invalidation:
- SCA version changes → different key → cache rejected
- Any .sca file changes → mtime changes → hash changes → cache rejected

Disabling:
- Environment variable: SCA_NO_CACHE=1
- CLI option (handled in cli.py): --no-cache

Security: pickle is used to serialize the compiled regexes (re.Pattern).
The cache is written inside the audited project's directory ({project}/.sca-cache/),
treated as a trust zone equivalent to the source code.
"""
import hashlib
import logging
import os
import pickle
import tempfile
import threading
from pathlib import Path
from typing import Dict, List, Optional

from sca import VERSION

logger = logging.getLogger("sca.rule_cache")

ENV_NO_CACHE = "SCA_NO_CACHE"
CACHE_FILENAME = "rules.pkl"
CACHE_VERSION = 1  # Bump if the pickle structure changes

# In-process memory cache (Perf — fixture validation instantiates a fresh
# AuditRunner per fixture, ~1600 times in one process; re-unpickling the same
# rule set from disk every time cost ~0.25-0.29s/fixture, measured via
# cProfile). Keyed on (cache file path, expected_key) rather than just
# expected_key: two different cache directories could otherwise collide if a
# caller ever reused the same content-derived key across them (tests do
# exactly this, with literal keys like "key1" against distinct tmp_path
# cache dirs) — the path makes collision impossible, no new invalidation
# logic needed beyond what expected_key already encodes.
_memory_cache: Dict[tuple, List[dict]] = {}
_memory_cache_lock = threading.Lock()


def is_disabled() -> bool:
    """Check whether the cache is disabled via the environment variable."""
    return os.environ.get(ENV_NO_CACHE, "").lower() in {"1", "true", "yes", "on"}


def _hash_rules_directory(rules_dir: Path) -> str:
    """Compute a hash representing the state of a rules directory.

    Concatenates the relative paths and mtimes of all .sca files, sorted,
    then SHA-256.
    """
    if not rules_dir.exists() or not rules_dir.is_dir():
        return ""

    entries = []
    for sca_file in sorted(rules_dir.rglob("*.sca")):
        try:
            rel = sca_file.relative_to(rules_dir)
            mtime = sca_file.stat().st_mtime
            entries.append(f"{rel}:{mtime}")
        except OSError:
            continue
    return hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest()


def compute_cache_key(rules_dirs: List[Path]) -> str:
    """Compose the cache key from the given rules directories.

    Format: v{SCA_VERSION}:c{CACHE_VERSION}:{hash_dir1}:{hash_dir2}:...
    """
    hashes = [_hash_rules_directory(d) for d in rules_dirs]
    payload = ":".join(hashes)
    return f"v{VERSION}:c{CACHE_VERSION}:{payload}"


def load_rules_cache(cache_dir: Path, expected_key: str, name: str = CACHE_FILENAME) -> Optional[List[dict]]:
    """Load rules from the cache if the key matches.

    Args:
        cache_dir: Directory containing the cache (e.g. {project}/.sca-cache/).
        expected_key: Expected key (computed via compute_cache_key).

    Returns:
        List of rules if the cache is valid, None otherwise (missing cache,
        key mismatch, corrupt file, or disabled via env var).
    """
    if is_disabled():
        logger.debug("Cache des règles désactivé via SCA_NO_CACHE")
        return None

    cache_file = cache_dir / name
    memory_key = (str(cache_file), expected_key)
    with _memory_cache_lock:
        cached = _memory_cache.get(memory_key)
    if cached is not None:
        return cached

    if not cache_file.exists():
        return None

    try:
        with open(cache_file, "rb") as f:
            data = pickle.load(f)
    except (pickle.UnpicklingError, EOFError, OSError, AttributeError) as e:
        logger.warning("Cache des règles corrompu, ignoré : %s", e)
        return None

    if not isinstance(data, dict) or data.get("key") != expected_key:
        logger.info("Cache des règles invalidé (clé différente, version SCA ou règles modifiées)")
        return None

    rules = data.get("rules", [])
    if not isinstance(rules, list):
        logger.warning("Cache des règles invalide (format inattendu)")
        return None

    logger.info("Cache des règles chargé : %d règles", len(rules))
    with _memory_cache_lock:
        _memory_cache[memory_key] = rules
    return rules


def save_rules_cache(cache_dir: Path, key: str, rules: List[dict], name: str = CACHE_FILENAME) -> bool:
    """Save compiled rules to the cache (atomic write).

    Args:
        cache_dir: Target directory (created if it doesn't exist).
        key: Cache key (computed via compute_cache_key).
        rules: List of compiled rules to serialize.

    Returns:
        True on success, False otherwise (silent, logs a warning).
    """
    if is_disabled():
        return False

    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning("Impossible de créer le répertoire cache : %s", e)
        return False

    cache_file = cache_dir / name

    # Unique tmp filename per writer (mkstemp): several mini-audits (fixture
    # validation's pool workers) can share the same cache_dir and race to
    # save concurrently. A fixed "<name>.tmp" path let one worker's
    # replace() consume the file out from under another worker's — the
    # second replace() then raised FileNotFoundError (source already moved).
    try:
        fd, tmp_path = tempfile.mkstemp(dir=str(cache_dir), prefix=f".{name}.", suffix=".tmp")
    except OSError as e:
        logger.warning("Impossible de créer le fichier temporaire du cache : %s", e)
        return False
    tmp_file = Path(tmp_path)

    try:
        with os.fdopen(fd, "wb") as f:
            pickle.dump(
                {"key": key, "rules": rules},
                f,
                protocol=pickle.HIGHEST_PROTOCOL,
            )
        # Atomic rename (POSIX): replaces cache_file indivisibly
        tmp_file.replace(cache_file)
        logger.info("Cache des règles sauvegardé : %d règles dans %s", len(rules), cache_file)
        with _memory_cache_lock:
            _memory_cache[(str(cache_file), key)] = rules
        return True
    except (OSError, pickle.PicklingError) as e:
        logger.warning("Impossible de sauvegarder le cache des règles : %s", e)
        try:
            tmp_file.unlink(missing_ok=True)
        except OSError:
            pass
        return False
