"""
Cache des findings par fichier (D.2.2 — voir docs/plans/PLAN-AUDIT-CONFORMITE.html §20.2).

Maintient une base SHA-256 → findings dans `.sca-cache/file-hashes.json`.
Permet de skipper les fichiers inchangés entre deux runs successifs.

Invalidation automatique :
- Version SCA change → cache rejeté
- Hash des règles change (un .sca modifié) → cache rejeté
- Hash du fichier change → entrée individuelle invalidée

Sécurité :
- HMAC-SHA256 du payload anti-falsification (defense in depth, §20.6)
- Écriture atomique (temp + rename, §20.6)
- Purge automatique des entrées orphelines (fichiers supprimés) à chaque save

Désactivation :
- Variable d'environnement : SCA_NO_INCREMENTAL=1
- Option CLI (gérée dans cli.py) : --no-incremental
"""
import gzip
import hashlib
import hmac
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from sca import VERSION

logger = logging.getLogger("sca.file_cache")

ENV_NO_INCREMENTAL = "SCA_NO_INCREMENTAL"
CACHE_FILENAME = "file-hashes.json"
CACHE_VERSION = 3  # v3: added per-entry taint_flows (incremental taint engine cache)
CACHE_GZIP_THRESHOLD = 5 * 1024 * 1024  # 5 MB → auto gzip compression
GZIP_MAGIC = b"\x1f\x8b"
HASH_BUFFER_SIZE = 65536  # 64 KB chunks for SHA-256


def is_disabled() -> bool:
    """Check whether the cache is disabled via the environment variable."""
    return os.environ.get(ENV_NO_INCREMENTAL, "").lower() in {"1", "true", "yes", "on"}


def _hmac_key() -> bytes:
    """Derive the HMAC key from the SCA version (defense in depth)."""
    return hashlib.sha256(f"sca-cache-key-v{VERSION}-c{CACHE_VERSION}".encode()).digest()


def _compute_hmac(payload_bytes: bytes) -> str:
    """Compute the HMAC-SHA256 hex digest of the payload."""
    return hmac.new(_hmac_key(), payload_bytes, hashlib.sha256).hexdigest()


def compute_file_hash(file_path: Path) -> Optional[str]:
    """Compute a file's SHA-256 by streaming it (efficient for large files)."""
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(HASH_BUFFER_SIZE), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


class FileCache:
    """Per-file findings cache with hash- and HMAC-based invalidation."""

    def __init__(self, cache_dir: Path, rules_hash: str):
        """Initialize the cache with its storage directory and rules hash.

        Args:
            cache_dir: Cache directory (e.g. {project}/.sca-cache/).
            rules_hash: Current hash of the SCA rules (global invalidation
                key). If it differs from the stored hash, the whole cache
                is rejected.
        """
        self.cache_dir = cache_dir
        self.rules_hash = rules_hash
        # path → {sha256, mtime, findings, code_lines, taint_flows?}
        self.entries: Dict[str, dict] = {}
        self.stats = {
            "hits": 0,
            "misses": 0,
            "orphans_removed": 0,
            "loaded_entries": 0,
            # Taint stats (same invalidations as scan: file hash + rules_hash).
            "taint_hits": 0,
            "taint_misses": 0,
        }
        self._loaded = False

    def load(self) -> None:
        """Load the cache from disk. Marks _loaded even if empty/invalid."""
        self._loaded = True

        if is_disabled():
            logger.debug("Cache fichiers désactivé via SCA_NO_INCREMENTAL")
            return

        cache_file = self.cache_dir / CACHE_FILENAME
        if not cache_file.exists():
            return

        try:
            raw = cache_file.read_bytes()
            # Auto-detect gzip
            if raw[:2] == GZIP_MAGIC:
                raw = gzip.decompress(raw)
            wrapper = json.loads(raw.decode("utf-8"))
        except (OSError, json.JSONDecodeError, ValueError, gzip.BadGzipFile) as e:
            logger.warning("Cache fichiers corrompu, ignoré : %s", e)
            return

        # Check the wrapper structure
        if not isinstance(wrapper, dict) or "hmac" not in wrapper or "data" not in wrapper:
            logger.warning("Cache fichiers : structure invalide (manque hmac ou data)")
            return

        # Check version / rules-hash mismatches first: these invalidations are
        # legitimate (dev bump, rules update, SCA version upgrade) and must
        # NOT be reported as "tampering" when no malicious attempt occurred.
        # The HMAC is checked last, to catch genuine tampering at identical
        # versions.
        data = wrapper["data"]
        if data.get("cache_version") != CACHE_VERSION:
            logger.info("Cache fichiers invalidé (CACHE_VERSION différente)")
            return
        if data.get("sca_version") != VERSION:
            logger.info("Cache fichiers invalidé (version SCA différente)")
            return
        if data.get("rules_hash") != self.rules_hash:
            logger.info("Cache fichiers invalidé (règles modifiées)")
            return

        # Verify the anti-tampering HMAC (identical versions only)
        try:
            payload_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
        except (TypeError, ValueError):
            logger.warning("Cache fichiers : payload non sérialisable")
            return

        expected_hmac = _compute_hmac(payload_bytes)
        if not hmac.compare_digest(wrapper["hmac"], expected_hmac):
            logger.warning("Cache fichiers : HMAC invalide (falsification détectée), rejeté")
            return

        # OK, load the entries
        files = data.get("files", {})
        if not isinstance(files, dict):
            return

        self.entries = files
        self.stats["loaded_entries"] = len(files)
        logger.info("Cache fichiers chargé : %d entrées", len(files))

    def get(self, file_path: str) -> Optional[List[dict]]:
        """Return the cached findings if the file hasn't changed, None otherwise.

        To also retrieve metadata (e.g. code_lines), use get_meta().
        """
        meta = self.get_meta(file_path)
        return meta["findings"] if meta is not None else None

    def get_meta(self, file_path: str) -> Optional[dict]:
        """Return the full cache entry if the file hasn't changed, None otherwise.

        The entry contains at least 'findings' (List[dict]) and
        'code_lines' (int). Used to restore the global LOC counter even on
        a cache hit (otherwise the health score becomes non-deterministic).
        """
        if is_disabled() or not self._loaded:
            self.stats["misses"] += 1
            return None

        entry = self.entries.get(file_path)
        if entry is None:
            self.stats["misses"] += 1
            return None

        current_hash = compute_file_hash(Path(file_path))
        if current_hash is None or current_hash != entry.get("sha256"):
            self.stats["misses"] += 1
            return None

        self.stats["hits"] += 1
        return {
            "findings": entry.get("findings", []),
            "code_lines": entry.get("code_lines", 0),
        }

    def set(self, file_path: str, findings: List[dict], code_lines: int = 0) -> None:
        """Update the cache entry for this file.

        Args:
            file_path: path of the scanned file
            findings: list of findings produced by the scan
            code_lines: number of code lines (excluding comments/blanks) —
                used to restore the global counter on a cache hit
                (deterministic score).
        """
        if is_disabled():
            return

        path = Path(file_path)
        sha = compute_file_hash(path)
        if sha is None:
            return  # file inaccessible, don't cache it

        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = 0.0

        self.entries[file_path] = {
            "sha256": sha,
            "mtime": mtime,
            "findings": findings,
            "code_lines": code_lines,
        }

    # ------------------------------------------------------------------ taint
    # v3 extension — incremental cache for the taint engine.
    # Serialized TaintFlow dicts are stored alongside the findings.
    # Invalidation: identical to the scan cache (file hash + global rules_hash).

    def get_taint_flows(self, file_path: str) -> Optional[List[dict]]:
        """Return the cached TaintFlow dicts (JSON-serialized) if the file
        hasn't changed. None on a miss (no entry, hash changed, or no
        flows cached yet for this file).
        """
        if is_disabled() or not self._loaded:
            self.stats["taint_misses"] += 1
            return None
        entry = self.entries.get(file_path)
        if entry is None:
            self.stats["taint_misses"] += 1
            return None
        current_hash = compute_file_hash(Path(file_path))
        if current_hash is None or current_hash != entry.get("sha256"):
            self.stats["taint_misses"] += 1
            return None
        flows = entry.get("taint_flows")
        if flows is None:
            # Entry exists (scan already done) but taint not cached yet.
            self.stats["taint_misses"] += 1
            return None
        self.stats["taint_hits"] += 1
        return flows

    def set_taint_flows(self, file_path: str, flows: List[dict]) -> None:
        """Store the serialized TaintFlow dicts for the file.

        If the entry didn't exist yet (first audit, or scan disabled), it
        is initialized. An empty list is accepted: it means "this file was
        analyzed and no flow was found" — avoiding re-analysis on the next
        audit.
        """
        if is_disabled():
            return
        sha = compute_file_hash(Path(file_path))
        if sha is None:
            return
        entry = self.entries.get(file_path)
        if entry is None:
            try:
                mtime = Path(file_path).stat().st_mtime
            except OSError:
                mtime = 0.0
            entry = {
                "sha256": sha,
                "mtime": mtime,
                "findings": [],
                "code_lines": 0,
            }
        else:
            # Make sure sha256 reflects the current content (the file
            # could have been modified between the scan and taint analysis).
            entry["sha256"] = sha
        entry["taint_flows"] = list(flows)
        self.entries[file_path] = entry

    def save(self) -> bool:
        """Save the cache (purge orphans → HMAC → gzip if large → atomic write)."""
        if is_disabled():
            return False

        # Purge orphaned entries (deleted files)
        before = len(self.entries)
        self.entries = {p: e for p, e in self.entries.items() if Path(p).exists()}
        self.stats["orphans_removed"] = before - len(self.entries)

        # Build the signed payload. cache_version is included so that
        # structure bumps (dev-side) are detected BEFORE the HMAC, avoiding
        # a false "tampering" alarm on a legitimate change.
        data = {
            "cache_version": CACHE_VERSION,
            "sca_version": VERSION,
            "rules_hash": self.rules_hash,
            "files": self.entries,
        }
        try:
            payload_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
        except (TypeError, ValueError) as e:
            logger.warning("Cache fichiers : impossible de sérialiser (%s)", e)
            return False

        wrapper = {
            "hmac": _compute_hmac(payload_bytes),
            "data": data,
        }
        wrapper_bytes = json.dumps(wrapper).encode("utf-8")

        # Auto-compress above the threshold
        if len(wrapper_bytes) > CACHE_GZIP_THRESHOLD:
            wrapper_bytes = gzip.compress(wrapper_bytes)
            logger.info("Cache fichiers compressé (seuil %d dépassé)", CACHE_GZIP_THRESHOLD)

        # Atomic write (temp + rename). Unique tmp filename per writer
        # (mkstemp): a fixed "<name>.tmp" path would let two concurrent
        # writers race on the same file, one's replace() consuming it out
        # from under the other's (FileNotFoundError on the second replace).
        tmp_file = None
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(
                dir=str(self.cache_dir), prefix=f".{CACHE_FILENAME}.", suffix=".tmp"
            )
            tmp_file = Path(tmp_path)
            with os.fdopen(fd, "wb") as f:
                f.write(wrapper_bytes)
            tmp_file.replace(self.cache_dir / CACHE_FILENAME)
            logger.info("Cache fichiers sauvegardé : %d entrées", len(self.entries))
            return True
        except OSError as e:
            logger.warning("Impossible de sauvegarder le cache fichiers : %s", e)
            if tmp_file is not None:
                try:
                    tmp_file.unlink(missing_ok=True)
                except OSError:
                    pass
            return False
