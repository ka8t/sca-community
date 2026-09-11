"""
Rule Engine mixin — orchestrates loading and execution of rules.

Loads the builtin rules (encrypted or in clear) and the custom rules,
then dispatches to the specialized executors (sca/executors/).

The execution mode is automatically inferred from the rule's structure
(patterns → regex, file_contains → file_check, hook → hook,
ast_patterns → ast, sources/sinks → taint).
"""
import os
import re
import fnmatch
import logging
from pathlib import Path
from typing import List, Dict, Optional


def _matches_any_exclude(rel_path: str, excludes: list) -> bool:
    """Return True if rel_path matches at least one exclude pattern (fnmatch + folder).

    Supports these pattern forms:
      - direct fnmatch (e.g. "*.min.js")
      - recursive glob "**/foo/**" (matched via presence of "/foo/" in the path)
      - simple folder "vendor/" (matched by prefix or /vendor/ in the path)
    Aligned with the logic of AuditRunner._is_excluded (runner.py).
    """
    norm = rel_path.replace(os.sep, "/")
    for pattern in excludes:
        if fnmatch.fnmatch(norm, pattern):
            return True
        # For "**/X/**": extract X and look for /X/ in the path
        if pattern.startswith("**/") and pattern.endswith("/**"):
            middle = pattern[3:-3]
            if middle and (f"/{middle}/" in f"/{norm}/" or norm == middle or norm.startswith(f"{middle}/")):
                return True
        # Simple folder "foo/"
        clean = pattern.rstrip("/")
        if clean and ("/" not in clean) and (f"/{clean}/" in f"/{norm}/" or norm.startswith(f"{clean}/")):
            return True
    return False

from dataclasses import asdict

from sca import SCA_PACKAGE_DIR
from sca.rule_loader import (
    load_rules_from_directory, index_rules_by_language,
    filter_rules_by_tier, filter_demo_fallback_rules,
)
from sca.rule_cache import (
    compute_cache_key, load_rules_cache, save_rules_cache,
    is_disabled as _cache_env_disabled,
)
from sca.file_cache import FileCache, is_disabled as _file_cache_env_disabled
from sca.models import Finding

logger = logging.getLogger("sca.rule_engine")


class AuditRuleEngineMixin:
    """Mixin for executing declarative .sca and JSON rules."""

    def _audit_rule_engine(self):
        """Entry point — executes all .sca and JSON rules.

        Idempotent: runs only once per audit.
        """
        if getattr(self, "_rule_engine_executed", False):
            return
        self._rule_engine_executed = True

        if self.config.get("_cli_options", {}).get("skip_rule_engine", False):
            return

        silent = self.config.get("_silent", False)

        if not silent:
            self.reporter.step(self.t_console("progress_rules_loading"))

        all_rules = self._load_all_json_rules()
        if not all_rules:
            logger.info("Aucune regle chargee — moteur de regles inactif")
            return

        all_rules, rejected = self._apply_license_gating(all_rules)
        self._cached_json_rules = {r["id"]: r for r in all_rules}

        # Counters per source (builtin / packs / custom)
        pack_counts = {}
        for r in all_rules:
            src = r.get("_source", "")
            if src.startswith("json_pack:"):
                pid = src.split(":", 1)[1]
                pack_counts[pid] = pack_counts.get(pid, 0) + 1
        self._rule_engine_stats = {
            "builtin_loaded": sum(1 for r in all_rules if r.get("_source") == "json_builtin"),
            "custom_loaded": sum(1 for r in all_rules if r.get("_source") == "json_custom"),
            "packs_loaded": sum(pack_counts.values()),
            "packs_detail": pack_counts,
            "custom_rejected": len([r for r in rejected if r.get("_source") == "json_custom"]),
            "rejected_details": [
                {"id": r["id"], "reason": r.get("_rejection_reason", "")}
                for r in rejected
            ],
        }

        # Filter by severity (--severity CRITICAL,HIGH,...)
        severity_levels = self.config.get("_cli_options", {}).get("severity_levels")
        if severity_levels:
            severity_set = {s.upper() for s in severity_levels}
            all_rules = [r for r in all_rules if r.get("severity", "").upper() in severity_set]

        # Filter by quick mode / only_category / categories config
        if self.quick_mode:
            all_rules = [r for r in all_rules if r["category"] == "security"]
        if self.only_category:
            target_cat = self.only_category.lower()
            all_rules = [r for r in all_rules if r["category"] == target_cat]

        cat_aliases = {"architecture": "arch"}
        categories_config = self.config.get("categories", {})
        if categories_config:
            enabled_cats = set()
            for cat_key, cat_conf in categories_config.items():
                if cat_conf.get("enabled", True):
                    norm = cat_aliases.get(cat_key.lower(), cat_key.lower())
                    enabled_cats.add(norm)
            enabled_cats.add("security")
            all_rules = [r for r in all_rules if r["category"].lower() in enabled_cats]

        if not all_rules:
            return

        # Index by language
        rules_by_lang = index_rules_by_language(all_rules)
        configured_languages = self.config.get("languages", [])
        all_rule_languages = set(configured_languages)
        if "dockerfile" in rules_by_lang:
            all_rule_languages.add("dockerfile")

        # Pre-cache the files (avoids double-discovery, needed to compute the total phase count)
        import time as _time
        _files_per_lang = {l: self._get_files_for_language(l) for l in sorted(all_rule_languages)}

        # Active taint languages (those with both taint rules AND files)
        _TAINT_MODES = {"taint", "regex+taint"}
        skip_taint = self.config.get("_cli_options", {}).get("skip_taint", False)
        _taint_active = [] if skip_taint else [
            l for l in sorted(all_rule_languages)
            if _files_per_lang.get(l) and any(
                r.get("mode", "") in _TAINT_MODES for r in rules_by_lang.get(l, [])
            )
        ]

        if not silent:
            self.reporter.rules_loaded(
                builtin=self._rule_engine_stats["builtin_loaded"],
                custom=self._rule_engine_stats["custom_loaded"],
                total=len(all_rules),
                langs=", ".join(sorted(all_rule_languages)),
            )
            if severity_levels:
                _all_sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                _excluded = [s for s in _all_sevs if s not in {sv.upper() for sv in severity_levels}]
                self.reporter.step(
                    self.t_console("severity_filter_active").format(
                        levels=", ".join(severity_levels),
                        excluded=len(_excluded),
                    ),
                    icon="🔍",
                )
            # Total phase count = scan per language + taint per language + optional phases
            _active_langs = [l for l in sorted(all_rule_languages) if _files_per_lang.get(l)]
            _n_optional = self._compute_phase_total()
            self.reporter.init_phases(len(_active_langs) + len(_taint_active) + _n_optional)
            self.reporter._phase_index = 0

        # Fill in missing i18n from the locales
        for rule in all_rules:
            self._fill_i18n(rule)

        # Dispatch to the executors
        from sca.executors import regex as regex_executor
        from sca.executors import file_check as file_check_executor
        from sca.executors import hook as hook_executor
        from sca.executors import ast as ast_executor

        # Track findings per category for category_done reporting
        cat_findings_before = {
            cat_key: len(self.categories[cat_key].findings)
            for cat_key in self.categories
        }
        # Cumulative counters per language and per category for the reporter
        per_lang_files = {}
        per_lang_duration = {}
        per_cat_files = {cat: 0 for cat in self.categories}
        per_cat_duration = {cat: 0.0 for cat in self.categories}

        # Incremental cache: initialized once for all languages
        file_cache = self._get_file_cache()

        for lang in sorted(all_rule_languages):
            lang_rules = rules_by_lang.get(lang, [])
            files = _files_per_lang.get(lang, [])
            if not silent and files:
                self.reporter.phase_custom(
                    self.t_console("progress_lang_scan_start").format(
                        lang=lang.title(), count=len(files)
                    ),
                    icon="🔍",
                )
            t_lang = _time.perf_counter()

            # Choose between sequential and parallel scan (D.2.3 — see PLAN §20.3)
            if self._should_use_parallel(len(files)):
                self._scan_files_parallel(
                    files, lang_rules, file_cache,
                    regex_executor, file_check_executor, hook_executor,
                )
            else:
                for filepath in files:
                    self._scan_single_file(
                        filepath, lang_rules, file_cache,
                        regex_executor, file_check_executor, hook_executor,
                    )

            # AST rules (need the full tree, not line by line)
            ast_rules = [r for r in lang_rules if r.get("mode") == "ast" or r.get("ast_patterns")]
            if ast_rules:
                ast_executor.execute_rules(self, ast_rules, lang)

            duration = round(_time.perf_counter() - t_lang, 2)
            per_lang_files[lang] = len(files)
            per_lang_duration[lang] = duration
            if files and not silent:
                self.reporter.lang_scan(lang, count=len(files), duration=duration)

        # Save the file cache (before taint, which stays in full-scan mode)
        if file_cache is not None:
            file_cache.save()
            if not silent:
                hits = file_cache.stats.get("hits", 0)
                misses = file_cache.stats.get("misses", 0)
                if hits or misses:
                    self.reporter.step(
                        self.t_console("cache_files_summary").format(
                            hits=hits,
                            misses=misses,
                            orphans=file_cache.stats.get("orphans_removed", 0),
                        ),
                        icon="💾",
                    )
            # Stats for the JSON report (consumed by §20.7)
            self._rule_engine_stats["file_cache"] = dict(file_cache.stats)

        # Taint (cross-files, separate mode) — one numbered phase per taint language
        if not skip_taint and not self._check_feature("taint"):
            if not silent and _taint_active:
                _tier = self.config.get("_license", {}).get("tier", "?")
                self.reporter.warn(
                    self.t_console("feature_unavailable_tier").format(feature="taint", tier=_tier)
                )
        elif not skip_taint:
            for lang in _taint_active:
                lang_rules = rules_by_lang.get(lang, [])
                taint_rules = [r for r in lang_rules if r["mode"] in _TAINT_MODES]
                if taint_rules:
                    if not silent:
                        self.reporter.phase_custom(
                            self.t_console("progress_taint_start").format(language=lang.title()),
                            icon="🧠",
                        )
                    self._execute_taint_rules(taint_rules, lang)

        # Recap per category: rule count, cumulative files, findings, duration
        if not silent:
            total_files_scanned = sum(per_lang_files.values())
            for cat_key in ("SECURITY", "ARCH", "UI", "UX", "MAINTENANCE",
                             "DEPENDENCIES", "CICD"):
                if cat_key not in self.categories:
                    continue
                cat_lower = cat_key.lower()
                aliases = {"arch": "architecture"}
                cat_alias = aliases.get(cat_lower, cat_lower)
                rules_in_cat = sum(
                    1 for r in all_rules
                    if r.get("category", "").lower() in (cat_lower, cat_alias)
                )
                if rules_in_cat == 0:
                    continue
                findings_in_cat = (
                    len(self.categories[cat_key].findings)
                    - cat_findings_before.get(cat_key, 0)
                )
                self.reporter.category_done(
                    category=cat_key,
                    rules=rules_in_cat,
                    files=total_files_scanned,
                    findings=findings_in_cat,
                    duration=0.0,
                )

    def _dispatch_rule(self, rule, filepath, all_lines, content,
                       regex_executor, file_check_executor, hook_executor):
        """Dispatch a rule to the right executor. Mode is inferred automatically."""
        mode = rule.get("mode", "")
        has_patterns = bool(rule.get("patterns"))
        has_fc = bool(rule.get("file_contains"))
        has_hook = bool(rule.get("hook"))
        has_ast = bool(rule.get("ast_patterns"))

        # AST is handled separately (needs the tree, not line by line)
        if has_ast or mode == "ast":
            return

        # Taint is handled separately (cross-files)
        if mode in ("taint", "regex+taint") and not has_patterns:
            return

        # Hook: direct execution
        if has_hook:
            hook_executor.execute(self, rule, filepath, all_lines)
            return

        # Combo match + requires: regex filtered by file conditions
        if has_patterns and has_fc:
            if not file_check_executor.matches(rule["file_contains"], content,
                                               filepath=filepath, line_count=len(all_lines)):
                return
            regex_executor.execute(self, rule, filepath, all_lines)
            return

        # Regex only
        if has_patterns:
            regex_executor.execute(self, rule, filepath, all_lines)
            return

        # file_contains only (file-level finding)
        if has_fc:
            file_check_executor.execute(self, rule, filepath, content, all_lines)
            return

    # =========================================================================
    # RULE LOADING
    # =========================================================================

    def _load_all_json_rules(self) -> List[dict]:
        """Load builtin rules + update packs + custom rules."""
        rules = []
        rules.extend(self._load_builtin_rules())
        rules.extend(self._load_update_packs())
        skip_rule_engine = self.config.get("_cli_options", {}).get("skip_rule_engine", False)
        if not skip_rule_engine:
            rules.extend(self._load_custom_rules())
        return rules

    def _load_update_packs(self) -> List[dict]:
        """Load out-of-band rule update packs (CVE feeds, etc.).

        Convention: `{SCRIPT_DIR}/rules-updates/{pack_id}/` with:
          - manifest.json: metadata + SHA-256 hash per rule
          - rules/{lang}/{cat}/{rule_id}.sca: rules in DSL format
        Format frozen in `docs/RULES-PACK-FORMAT.md`.

        Verifies the SHA-256 integrity of each rule against the manifest.
        A rule whose hash diverges is skipped (and logged). If a pack has
        no valid manifest.json, the whole pack is skipped.
        """
        from sca import SCRIPT_DIR
        import hashlib
        import json as _json

        updates_root = SCRIPT_DIR / "rules-updates"
        if not updates_root.exists() or not updates_root.is_dir():
            return []

        all_rules = []
        for pack_dir in sorted(updates_root.iterdir()):
            if not pack_dir.is_dir():
                continue
            manifest_path = pack_dir / "manifest.json"
            rules_dir = pack_dir / "rules"
            if not manifest_path.exists() or not rules_dir.exists():
                logger.warning(
                    "Pack ignoré (manifest.json ou rules/ manquant) : %s", pack_dir.name
                )
                continue

            try:
                manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
            except Exception as e:
                logger.warning(
                    "Pack ignoré (manifest.json invalide) : %s — %s", pack_dir.name, e
                )
                continue

            pack_id = manifest.get("pack_id") or pack_dir.name
            expected = {entry["path"]: entry["sha256"] for entry in manifest.get("rules", [])}

            pack_rules = load_rules_from_directory(rules_dir, source=f"json_pack:{pack_id}")

            kept = 0
            for r in pack_rules:
                rel = r.get("_file_path", "")
                full = rules_dir / rel
                if not full.exists():
                    continue
                actual_hash = hashlib.sha256(full.read_bytes()).hexdigest()
                exp_hash = expected.get(rel)
                if exp_hash and exp_hash != actual_hash:
                    logger.warning(
                        "Règle exclue du pack %s (hash SHA-256 divergent) : %s",
                        pack_id, rel,
                    )
                    continue
                all_rules.append(r)
                kept += 1
            logger.info("Pack %s chargé : %d règles", pack_id, kept)

        return all_rules

    # =========================================================================
    # COMPILED RULES CACHE (D.2.1 — see PLAN §20.1)
    # =========================================================================

    def _is_rule_cache_disabled(self) -> bool:
        """Return True if the rule cache is disabled via SCA_NO_CACHE or --no-cache."""
        if _cache_env_disabled():
            return True
        return bool(self.config.get("_cli_options", {}).get("no_cache", False))

    def _get_rule_cache_dir(self) -> Optional[Path]:
        """Return the cache directory for this project, or None if disabled/unavailable.

        Honors `_rule_cache_dir_override` when set (used by fixture validation's
        mini-audits, whose `root_dir` is a throwaway per-fixture temp directory —
        without the override, every mini-audit would resolve to a fresh, never-reused
        cache location and reload/recompile the full rule set from scratch).
        """
        if self._is_rule_cache_disabled():
            return None
        override = getattr(self, "_rule_cache_dir_override", None)
        if override is not None:
            return override
        try:
            project_path = Path(self.root_dir)
        except (TypeError, ValueError):
            return None
        if not project_path.exists():
            return None
        return project_path / ".sca-cache"

    def _load_with_cache(self, rules_dir: Path, source: str, cache_name: str) -> List[dict]:
        """Load rules with caching (compute_key → load → fallback → save)."""
        cache_dir = self._get_rule_cache_dir()
        if cache_dir is None:
            return load_rules_from_directory(rules_dir, source=source)

        cache_key = compute_cache_key([rules_dir])
        cached = load_rules_cache(cache_dir, cache_key, name=cache_name)
        if cached is not None:
            # Re-annotate in case the source is missing (safety net)
            for r in cached:
                r.setdefault("_source", source)
            return cached

        rules = load_rules_from_directory(rules_dir, source=source)
        if rules:
            save_rules_cache(cache_dir, cache_key, rules, name=cache_name)
        return rules

    # =========================================================================
    # PER-FILE INCREMENTAL FINDINGS CACHE (D.2.2 — see PLAN §20.2)
    # =========================================================================

    def _is_file_cache_disabled(self) -> bool:
        """Return True if the file cache is disabled via SCA_NO_INCREMENTAL or --no-incremental."""
        if _file_cache_env_disabled():
            return True
        return bool(self.config.get("_cli_options", {}).get("no_incremental", False))

    def _get_file_cache(self) -> Optional["FileCache"]:
        """Instantiate and load the file cache, or return None if disabled.

        `rules_hash` now covers both `builtin/` and `profiles/`: the taint
        cache (CACHE_VERSION >= 3) must be invalidated when a framework
        profile changes, since that alters the effective sources/sinks via
        `_extend_rules_with_profile`.
        """
        if self._is_file_cache_disabled():
            return None
        cache_dir = self._get_rule_cache_dir()
        if cache_dir is None:
            return None
        builtin_dir = SCA_PACKAGE_DIR / "rules" / "builtin"
        profiles_dir = SCA_PACKAGE_DIR / "profiles"
        hash_inputs = [builtin_dir]
        if profiles_dir.exists():
            hash_inputs.append(profiles_dir)
        rules_hash = compute_cache_key(hash_inputs)
        cache = FileCache(cache_dir, rules_hash=rules_hash)
        cache.load()
        return cache

    def _restore_findings_from_cache(self, cached_findings: List[dict]) -> int:
        """Re-inject cached findings into their categories. Returns the count restored.

        Applies the same filters as `_add_finding` (disabled_rules + suppressions)
        so cached findings stay consistent with the current config, even if
        .sca-suppress.json or audit.config.json changed since caching.
        """
        restored = 0
        for fdict in cached_findings:
            cat_key = fdict.get("category")
            if not cat_key or cat_key not in self.categories:
                continue

            # Filter 1: disabled rule (rules.disabled)
            rule_key = fdict.get("rule_key", "")
            if rule_key and rule_key in self.disabled_rules:
                continue

            # Filter 2: targeted suppression (.sca-suppress.json / rules.suppress)
            # The `file` stored in the cache is already relative (cf. _add_finding).
            if rule_key and self._is_suppressed(rule_key, fdict.get("file", ""), fdict.get("code", "")):
                self._suppressed_count += 1
                continue

            try:
                # Remove the taint_flow field (not serializable in a simple cache)
                clean = {k: v for k, v in fdict.items() if k != "taint_flow"}
                clean.setdefault("taint_flow", None)
                self.categories[cat_key].findings.append(Finding(**clean))
                restored += 1
            except (TypeError, KeyError):
                continue
        return restored

    def _capture_new_findings(self, snapshot: Dict[str, int]) -> List[dict]:
        """Capture findings added since the snapshot, excluding those with a taint_flow."""
        new = []
        for cat_key, cat in self.categories.items():
            before = snapshot.get(cat_key, 0)
            for f in cat.findings[before:]:
                if getattr(f, "taint_flow", None) is None:
                    new.append(asdict(f))
        return new

    # =========================================================================
    # SINGLE-FILE SCAN (D.2.3 — extraction preparing for parallelization)
    # =========================================================================

    def _scan_single_file(self, filepath, lang_rules, file_cache,
                           regex_executor, file_check_executor, hook_executor) -> None:
        """Scan a single file, with cache handling.

        - On cache hit: restore the cached findings and return
        - Otherwise: read the file, apply the rules, capture new findings into the cache
        - If the license LOC limit is reached: skip the file (restrictive truncate)
        """
        # License LOC lever: if the limit is already reached, skip (truncate)
        if hasattr(self, "_check_loc_limit_reached") and self._check_loc_limit_reached():
            return

        # Snapshots before the scan (to compute the findings delta + LOC delta)
        snapshot = {cn: len(c.findings) for cn, c in self.categories.items()}
        loc_snapshot = getattr(self, "_total_lines_code", 0)

        # Try a cache hit
        if file_cache is not None:
            cached_meta = file_cache.get_meta(filepath)
            if cached_meta is not None:
                self._restore_findings_from_cache(cached_meta["findings"])
                # Restore the global LOC counter (otherwise the score is non-deterministic:
                # it would drop on every cache hit even though the code is unchanged).
                code_lines = cached_meta.get("code_lines", 0)
                if code_lines and hasattr(self, "_total_lines_code"):
                    self._total_lines_code += code_lines
                    if hasattr(self, "_counted_files"):
                        self._counted_files.add(filepath)
                return  # skip the scan, findings + LOC restored

        # Cache miss: normal scan
        all_lines = self._read_file(filepath)
        if not all_lines:
            return

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            content = ""

        for rule in lang_rules:
            self._dispatch_rule(
                rule, filepath, all_lines, content,
                regex_executor, file_check_executor, hook_executor,
            )

        # Capture the added findings and cache them
        if file_cache is not None:
            new_findings = self._capture_new_findings(snapshot)
            # LOC delta added by this file (exact, since _read_file increments
            # _total_lines_code only once per unique file).
            code_lines_added = getattr(self, "_total_lines_code", 0) - loc_snapshot
            file_cache.set(filepath, new_findings, code_lines=code_lines_added)

    # =========================================================================
    # PER-FILE PARALLELIZATION (D.2.3 — see PLAN §20.3)
    # =========================================================================

    def _is_parallel_disabled(self) -> bool:
        """Return True if parallelization is disabled via SCA_NO_PARALLEL or --no-parallel."""
        import os
        if os.environ.get("SCA_NO_PARALLEL", "").lower() in {"1", "true", "yes", "on"}:
            return True
        return bool(self.config.get("_cli_options", {}).get("no_parallel", False))

    def _get_parallel_threshold(self) -> int:
        """Return the file-count threshold below which scanning stays sequential."""
        perf = self.config.get("performance", {})
        return int(perf.get("parallel_threshold", 100))

    def _get_max_workers(self) -> int:
        """Return the max number of workers (0 = auto via cpu_count)."""
        import os
        perf = self.config.get("performance", {})
        configured = int(perf.get("max_workers", 0))
        if configured > 0:
            return configured
        return min(os.cpu_count() or 4, 8)

    def _should_use_parallel(self, file_count: int) -> bool:
        """Decide whether to enable parallelization for this group of files.

        Disabled by default until the executors are refactored to be
        thread-safe (see PLAN §20.3). Can be enabled manually via
        audit.config.json {"performance": {"parallel": true}}.
        """
        if self._is_parallel_disabled():
            return False
        perf = self.config.get("performance", {})
        if not perf.get("parallel", False):  # disabled by default
            return False
        if file_count < self._get_parallel_threshold():
            return False
        return True

    def _scan_files_parallel(self, files, lang_rules, file_cache,
                              regex_executor, file_check_executor, hook_executor) -> None:
        """Scan files in parallel via ThreadPoolExecutor, with a lock serializing appends."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading

        max_workers = self._get_max_workers()
        # Global lock protecting concurrent appends into self.categories
        # (CPython guarantees list.append atomicity, but the snapshot in
        # _scan_single_file reads + writes, so a lock is required for consistency)
        lock = threading.Lock()

        def _worker(filepath):
            """Scan a single file while holding the shared append lock."""
            with lock:
                self._scan_single_file(
                    filepath, lang_rules, file_cache,
                    regex_executor, file_check_executor, hook_executor,
                )

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(_worker, fp) for fp in files]
            for fut in as_completed(futures):
                # Propagate any worker exception
                exc = fut.exception()
                if exc is not None:
                    logger.warning("Erreur worker scan : %s", exc)

    def _load_builtin_rules(self) -> List[dict]:
        """Load the builtin rules (encrypted blob or plain files)."""
        try:
            from sca._rules_blob import _BUILTIN_RULES_BLOB
            from sca.encryption import decrypt_blob, derive_key
            from sca.license_check import get_license_signature, is_valid

            if not is_valid():
                logger.info("Licence invalide — builtin chiffrees non disponibles")
                return self._load_demo_fallback()

            key = derive_key(get_license_signature().encode())
            decrypted = decrypt_blob(_BUILTIN_RULES_BLOB, key)
            if decrypted is None:
                logger.warning("Dechiffrement echoue — fallback mode demo")
                return self._load_demo_fallback()

            rules = []
            for rule_id, rule_dict in decrypted.items():
                if rule_id.startswith("__"):
                    continue
                rule_dict["_source"] = "json_builtin"
                from sca.rule_loader import _compile_rule_patterns
                _compile_rule_patterns(rule_dict, rule_id)
                rules.append(rule_dict)
            logger.info("Regles builtin chiffrees chargees : %d", len(rules))
            return rules

        except ImportError:
            pass

        builtin_dir = SCA_PACKAGE_DIR / "rules" / "builtin"
        rules = self._load_with_cache(builtin_dir, source="json_builtin", cache_name="rules-builtin.pkl")
        if rules:
            logger.info("Regles builtin en clair chargees : %d (mode developpement)", len(rules))
        return rules

    def _load_custom_rules(self) -> List[dict]:
        """Load the client's custom rules from audit-rules/."""
        custom_dir = self._find_custom_rules_dir()
        if custom_dir is None:
            return []
        rules = self._load_with_cache(custom_dir, source="json_custom", cache_name="rules-custom.pkl")
        if rules:
            logger.info("Regles custom chargees : %d depuis %s", len(rules), custom_dir)
        return rules

    def _find_custom_rules_dir(self) -> Optional[Path]:
        """Find the client's custom rules directory.

        Looks in {SCRIPT_DIR}/custom-rules/ (created by the wizard).
        """
        from sca import SCRIPT_DIR
        custom = SCRIPT_DIR / "custom-rules"
        return custom if custom.exists() else None

    # =========================================================================
    # LICENSE GATING — 3 levers: files, custom rules, exports
    # =========================================================================

    def _apply_license_gating(self, rules: List[dict]):
        """Apply license gating: limit the number of custom rules per project.

        Only 3 levers:
        - Files: handled in runner._find_files() (already in place)
        - Custom rules: limited here (0/5/50/200/unlimited per tier)
        - Exports: handled in _export_sarif() and _export_sbom()

        Builtin rules are outside the quota, except for tier=demo which is
        further restricted to the curated demo_fallback subset (cf.
        ``filter_demo_fallback_rules``). Taint is always active.
        """
        from sca.license_facade import get_max_custom_rules, get_tier
        max_custom = get_max_custom_rules()
        current_tier = get_tier()

        # Separate builtin (outside the quota) from custom (subject to the quota)
        builtin = [r for r in rules if r.get("_source") != "json_custom"]
        custom = [r for r in rules if r.get("_source") == "json_custom"]

        builtin = filter_demo_fallback_rules(builtin, current_tier)

        accepted = list(builtin)
        rejected = []

        # The first N custom rules are accepted, the rest is ignored
        for r in custom[:max_custom]:
            accepted.append(r)
        for r in custom[max_custom:]:
            r["_rejection_reason"] = f"custom rules limit ({max_custom}) exceeded for tier '{current_tier}'"
            rejected.append(r)

        return accepted, rejected

    def _load_demo_fallback(self) -> List[dict]:
        """Return the full builtin catalog, decrypted via the universal
        (license-independent) key, for the zero-license runtime path.

        No rule content lives here in clear text nor as a pre-cut subset:
        AuditDistrib/pipeline/encrypt_rules.py::encrypt_builtin_rules()
        encrypts the SAME full plaintext a second time with a key derived
        from the root secret (not a client license signature, which is
        unavailable here by definition). Restriction to the curated
        ~10 rules/language ("demo_fallback" flag) happens uniformly in
        _apply_license_gating via filter_demo_fallback_rules — the same
        step also used for a real, licensed tier=demo client — not here.
        """
        try:
            from sca._rules_blob import _BUILTIN_RULES_BLOB_UNIVERSAL
            from sca.encryption import decrypt_blob, derive_key
            from sca.license_check import _SECRET

            key = derive_key(_SECRET, salt=b"sca_demo_universal_v1", info=b"aes-256-gcm")
            decrypted = decrypt_blob(_BUILTIN_RULES_BLOB_UNIVERSAL, key)
            if decrypted is None:
                logger.warning("Dechiffrement demo (cle universelle) echoue — aucune regle")
                return []

            rules = []
            for rule_id, rule_dict in decrypted.items():
                if rule_id.startswith("__"):
                    continue
                rule_dict["_source"] = "json_builtin"
                from sca.rule_loader import _compile_rule_patterns
                _compile_rule_patterns(rule_dict, rule_id)
                rules.append(rule_dict)
            logger.info("Regles demo (cle universelle) chargees : %d", len(rules))
            return rules

        except ImportError:
            pass

        # Mode source/developpement : pas de blob compile, catalogue en
        # clair (le filtre demo_fallback s'applique ensuite dans
        # _apply_license_gating, comme pour le chemin licence normale).
        builtin_dir = SCA_PACKAGE_DIR / "rules" / "builtin"
        rules = self._load_with_cache(builtin_dir, source="json_builtin", cache_name="rules-builtin.pkl")
        if rules:
            logger.info("Regles builtin en clair chargees : %d (mode demo/developpement)", len(rules))
        return rules

    # =========================================================================
    # TAINT (cross-files, stays in the mixin for file access)
    # =========================================================================

    _DATAFLOW_LANGUAGES = ("python", "javascript", "java", "csharp", "php")

    def _execute_taint_rules(self, rules: List[dict], language: str):
        """Dispatch taint rules to the dataflow engine (Phase 7/8).

        Since the legacy taint_engine.py / taint_treesitter.py was removed,
        all supported languages go through the same dataflow pipeline.
        """
        if language in self._DATAFLOW_LANGUAGES:
            self._execute_taint_dataflow(rules, language)
        else:
            logger.info("[taint] Pas de backend taint pour '%s'", language)

    def _execute_taint_dataflow(self, rules: List[dict], language: str) -> None:
        """Taint pipeline via the dataflow engine (Phase 7-8).

        Loads the files, extends each taint rule with the sources/sinks/
        sanitizers of the detected framework profile, runs `run_taint_rule`
        and integrates the resulting TaintFlow like the historical pipeline.

        Spec §10 + the internal rule-generation contract doc §3.1.
        """
        from dataclasses import asdict
        from sca.executors.dataflow_adapter import (
            MIN_PARALLEL_TAINT_FILES,
            run_dataflow_taint_for_files,
            run_dataflow_taint_for_files_parallel,
        )
        from sca.models import TaintFlow

        silent = self.config.get("_silent", False)
        lang_exts = {
            "python": getattr(self, "_py_exts", [".py"]),
            "javascript": getattr(self, "_js_exts", [".js", ".jsx", ".ts", ".tsx", ".mjs"]),
            "java": [".java"],
            "csharp": [".cs"],
            "php": [".php", ".inc"],
        }
        exts = lang_exts.get(language, [".py"])
        files = self._find_files(exts, self.config.get("paths", {}).get("include", []))

        file_contents = {}
        for filepath in files:
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                    file_contents[filepath] = fh.read()
            except Exception:
                continue

        # Load the framework profile (Flask/Django/Express/Spring/etc.) and
        # extend the taint rules with its sources/sinks/sanitizers. This way
        # the dataflow engine gets the same contextual knowledge as the
        # legacy PythonTaintAnalyzer.
        extended_rules = self._extend_rules_with_profile(rules, language, silent)

        # Live per-file progress: one line per file, printed as it completes
        # (not a single self-overwriting counter — on a small project the
        # whole phase can finish in well under a second, too fast for a
        # live-refreshing line to be perceptible; a scrolling log is visible
        # regardless of total duration). Covers cache hits too — otherwise a
        # warm-cache re-run (the common case once a project's been audited
        # once) would silently skip the log for every unchanged file.
        # Skipped when silent (mini-audits — fixture validation itself spawns
        # hundreds of these; each printing its own log would flood stdout).
        _progress_total = len(file_contents)
        _progress_index = [0]

        def _log_taint_progress(key, filepath, flows, duration=None):
            _progress_index[0] += 1
            kwargs = dict(index=_progress_index[0], total=_progress_total,
                          file=self._rel(filepath), flows=flows)
            if duration is not None:
                kwargs["duration"] = round(duration, 2)
            self.reporter.step(self.t_console(key).format(**kwargs), icon="🧠")

        # ─── Incremental taint cache (Perf) ─────────────────────────────
        # `_get_file_cache` is shared with the line-by-line scan. TaintFlow
        # objects are stored per file (`set_taint_flows`); invalidation is
        # keyed on file hash + rules_hash (which covers builtin/ and
        # profiles/). First audit: everything misses. Re-audit with no
        # changes: everything hits, huge speedup.
        file_cache = self._get_file_cache()
        cached_flow_count = 0
        to_analyze: dict = {}
        if file_cache is not None:
            for filepath, content in file_contents.items():
                cached_flows = file_cache.get_taint_flows(filepath)
                if cached_flows is None:
                    to_analyze[filepath] = content
                    continue
                # Hit: replay the flows directly into the findings.
                for flow_dict in cached_flows:
                    self._integrate_taint_flow(TaintFlow(**flow_dict))
                    cached_flow_count += 1
                if not silent:
                    _log_taint_progress("taint_file_cached", filepath, len(cached_flows))
        else:
            to_analyze = file_contents

        # Parallelization (Perf) — above the threshold, uses one worker
        # per file via ProcessPoolExecutor. Below it, sequential.
        # The user can force sequential mode via --no-parallel-taint.
        no_parallel = self.config.get("_cli_options", {}).get("no_parallel_taint", False)
        call_graph_cache_dir = self._get_rule_cache_dir()
        new_flows_by_file: dict = {p: [] for p in to_analyze}
        if to_analyze:
            def _on_file_done(filepath, duration, flow_count):
                _log_taint_progress("taint_file_progress", filepath, flow_count, duration)

            # Phase 1 (call graph summary resolution) runs entirely before
            # phase 2's first _on_file_done can fire — a purely sequential
            # loop over every taint rule (~10s/rule on the sca/ self-audit,
            # independent of rule content) that stayed completely silent
            # until this callback existed. Confirmed live on a cold run:
            # 216s of silence right after "Taint {language}..." is printed,
            # even with per-file progress already wired up.
            def _on_rule_summary_done(rule_id, index, total, duration):
                self.reporter.step(
                    self.t_console("taint_rule_summary_progress").format(
                        index=index, total=total, rule=rule_id, duration=round(duration, 2),
                    ),
                    icon="🧠",
                )

            on_file_done = _on_file_done if not silent else None
            on_rule_summary_done = _on_rule_summary_done if not silent else None
            if not no_parallel and len(to_analyze) >= MIN_PARALLEL_TAINT_FILES:
                flow_iter = run_dataflow_taint_for_files_parallel(
                    extended_rules, to_analyze, language,
                    cache_dir=call_graph_cache_dir, on_file_done=on_file_done,
                    on_rule_summary_done=on_rule_summary_done,
                )
            else:
                flow_iter = run_dataflow_taint_for_files(
                    extended_rules, to_analyze, language,
                    cache_dir=call_graph_cache_dir, on_file_done=on_file_done,
                    on_rule_summary_done=on_rule_summary_done,
                )
            for flow in flow_iter:
                self._integrate_taint_flow(flow)
                new_flows_by_file.setdefault(flow.source_file, []).append(flow)

        # Store into the cache for the next run (empty list accepted).
        # Re-save() after taint to persist the new taint_flows (the scan
        # already saved once earlier, but the cache was reloaded to
        # retrieve the findings — must re-save here to avoid losing the
        # taint additions).
        if file_cache is not None and to_analyze:
            for filepath in to_analyze:
                flows = new_flows_by_file.get(filepath, [])
                file_cache.set_taint_flows(filepath, [asdict(f) for f in flows])
            file_cache.save()
            if not silent:
                t_hits = file_cache.stats.get("taint_hits", 0)
                t_misses = file_cache.stats.get("taint_misses", 0)
                if t_hits or t_misses:
                    self.reporter.step(
                        f"💾 Cache taint {language}: {t_hits} hits / {t_misses} analysés",
                        icon="🧠",
                    )

        total_flows = cached_flow_count + sum(len(v) for v in new_flows_by_file.values())

        if total_flows > 0 and not silent:
            self.reporter.taint_flows(language, total_flows)
        if not hasattr(self, "_rule_engine_stats"):
            self._rule_engine_stats = {}
        self._rule_engine_stats[f"taint_flows_{language}"] = total_flows

    @staticmethod
    def _sink_category_matches_rule(rule_id: str, category: str) -> bool:
        """Check whether a profile sink with category X should feed rule_id.

        The matching tolerates variants: `sqli` <-> `sql_injection`,
        `loginjection` <-> `log_injection`, `pathtraver` <-> `path_traversal`.
        If either form (with or without underscores) of the category name
        appears as a substring of rule_id, they are considered semantically
        related.
        """
        if not rule_id or not category:
            return False
        rid = rule_id.lower()
        cat = category.lower()
        if cat == "unknown":
            return False
        return cat in rid or cat.replace("_", "") in rid.replace("_", "")

    def _extend_rules_with_profile(self, rules: List[dict], language: str, silent: bool) -> List[dict]:
        """Extend each taint rule with sources/sinks/sanitizers from the detected profile.

        Returns a new list of rules (shallow copies) — the original rules
        are never mutated. A non-taint rule is returned unchanged.

        Profile sinks are injected per category: a sink declared as
        `cursor.execute    sqli` in `flask.profile` is only added to rules
        whose id contains "sqli" (taint_sqli, sql_injection_*, etc.) — not
        to `taint_xss` or `llm_output_to_sink`. This filter avoids the FP
        cascade observed without categorization (logger.* becoming a sink
        for SSRF, LLM, path_traversal, etc.).
        """
        try:
            from sca.profile_loader import detect_frameworks, load_merged_profile
            from sca.cli import _text_to_regex
        except Exception:
            return rules

        try:
            frameworks = detect_frameworks(self.root_dir, language)
            profile = load_merged_profile(language, frameworks)
        except Exception:
            return rules

        profile_sources = [
            {"pattern": _text_to_regex(p), "kind": k}
            for p, k in profile.get("sources", [])
        ]
        profile_sanitizers = [
            {"pattern": _text_to_regex(p)}
            for p in profile.get("sanitizers", [])
        ]
        # Sinks kept in their (pattern_text, category) form to match
        # on the fly against the rule_id (cf. _sink_category_matches_rule).
        raw_profile_sinks = [(p, cat) for p, cat in profile.get("sinks", [])]

        if not silent and (profile_sources or profile_sanitizers or raw_profile_sinks):
            try:
                self.reporter.detail(self.t_console("progress_taint_profile").format(
                    frameworks="+".join(frameworks) or "none",
                    sources=len(profile_sources),
                    sinks=len(raw_profile_sinks),
                    sanitizers=len(profile_sanitizers),
                ))
            except Exception:
                pass

        extended = []
        for r in rules:  # sca-ignore:n_plus_1_query — false positive: "cursor.execute(sql, (param,))" at line 969 is an example inside a comment, not code executed in this loop (which only iterates over a list of Python dicts)
            if r.get("mode") not in ("taint", "regex+taint"):
                extended.append(r)
                continue
            r2 = dict(r)
            r2["sources"] = list(r.get("sources", [])) + profile_sources
            r2["sanitizers"] = list(r.get("sanitizers", [])) + profile_sanitizers
            rule_id = r.get("id") or r.get("rule_id") or ""
            # Profile sinks: restrict to the 1st argument (arg_index=0) by
            # default. E.g. `cursor.execute(sql, (param,))` stays safe since
            # the parameter is in position 1, outside the SQL query. The
            # profile lists calls "whose 1st arg is the attack vector".
            matched_sinks = [
                {"pattern": _text_to_regex(p), "arg_index": 0}
                for p, cat in raw_profile_sinks
                if self._sink_category_matches_rule(rule_id, cat)
            ]
            r2["sinks"] = list(r.get("sinks", [])) + matched_sinks
            extended.append(r2)
        return extended

    def _integrate_taint_flow(self, flow):
        """Attach a taint flow to its matching finding, or create a new finding for it."""
        from sca.models import TaintFlow

        # Helper to attach a flow to a finding without overwriting flows already
        # attached. Each finding accumulates the list of all taint rules that
        # qualified it (e.g. file_get_contents → ssrf + path_traversal).
        # f.taint_flow (singular) remains a backward-compat alias = first flow.
        def _attach(finding, fl):
            """Attach flow fl to finding, without overwriting flows already attached."""
            if any(existing.rule_key == fl.rule_key for existing in finding.taint_flows):
                return  # already attached for this rule_id
            finding.taint_flows.append(fl)
            if finding.taint_flow is None:
                finding.taint_flow = fl
            finding.confidence = max(finding.confidence, 95)

        sink_rel = self._rel(flow.sink_file)
        cat_key = flow.category.upper()
        if cat_key in self.categories:
            # Pass 1: look for a finding with a compatible rule_key (same family)
            best = None
            for f in self.categories[cat_key].findings:
                if f.file == sink_rel and f.line == flow.sink_line:
                    # Exact match or common prefix (ssrf ↔ ssrf_python)
                    fk = f.rule_key or ""
                    tk = flow.rule_key or ""
                    if fk == tk or fk.startswith(tk) or tk.startswith(fk):
                        _attach(f, flow)
                        return
                    if best is None:
                        best = f
            # Pass 2: merge with the first finding on the same line
            if best is not None:
                _attach(best, flow)
                return

        rule_data = getattr(self, "_cached_json_rules", {}).get(flow.rule_key)
        if rule_data:
            msg = self._resolve_i18n(rule_data.get("message", {}))
            risk = self._resolve_i18n(rule_data.get("risk", {}))
            solution = self._resolve_i18n(rule_data.get("solution", {}))
            benefit = self._resolve_i18n(rule_data.get("benefit", {}))
        else:
            msg = f"Taint flow detected: {flow.rule_key}"
            risk = solution = benefit = ""

        self._add_finding(
            cat_key, msg, flow.sink_file, flow.sink_line,
            self._get_line_content(flow.sink_file, flow.sink_line),
            rule_data.get("severity", "HIGH") if rule_data else "HIGH",
            risk, solution, benefit,
            confidence=90, rule_key=flow.rule_key,
        )

        if cat_key in self.categories:
            for f in reversed(self.categories[cat_key].findings):
                if f.file == sink_rel and f.line == flow.sink_line and f.rule_key == flow.rule_key:
                    _attach(f, flow)
                    f.rule_source = "json_builtin"
                    break

    # =========================================================================
    # BACKWARD COMPAT — wrappers for direct calls from tests
    # =========================================================================

    def _execute_regex_rules(self, rules: List[dict], language: str):
        """Backward-compat wrapper: run regex-mode rules directly for a language."""
        from sca.executors import regex as regex_executor
        files = self._get_files_for_language(language)
        for filepath in files:
            all_lines = self._read_file(filepath)
            if not all_lines:
                continue
            for rule in rules:
                regex_executor.execute(self, rule, filepath, all_lines)

    def _execute_file_contains_rules(self, rules: List[dict], language: str):
        """Backward-compat wrapper: run file_contains-mode rules directly for a language."""
        from sca.executors import file_check as fc_executor
        files = self._get_files_for_language(language)
        for filepath in files:
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except Exception:
                continue
            all_lines = self._read_file(filepath)
            for rule in rules:
                fc_executor.execute(self, rule, filepath, content, all_lines)

    def _execute_hook_rules(self, rules: List[dict], language: str):
        """Backward-compat wrapper: run hook-mode rules directly for a language."""
        from sca.executors import hook as hook_executor
        files = self._get_files_for_language(language)
        for filepath in files:
            all_lines = self._read_file(filepath)
            if not all_lines:
                continue
            for rule in rules:
                hook_executor.execute(self, rule, filepath, all_lines)

    def _execute_ast_rules(self, rules: List[dict], language: str):
        """Backward-compat wrapper: run AST-mode rules directly for a language."""
        from sca.executors import ast as ast_executor
        ast_executor.execute_rules(self, rules, language)

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _fill_i18n(self, rule: dict):
        """Fill in missing i18n fields on a rule from the locale files."""
        rule_id = rule.get("id", "")
        if not rule_id:
            return

        # If the message is missing or empty, look it up in the locales
        if not rule.get("message"):
            locale_data = self._rule(rule_id)
            rule["message"] = {self.report_lang: locale_data.get("name", rule_id)}

        for field in ("risk", "solution", "benefit"):
            if not rule.get(field):
                locale_data = self._rule(rule_id)
                val = locale_data.get(field, "")
                if val:
                    rule[field] = {self.report_lang: val}

        # Default category
        if not rule.get("category"):
            rule["category"] = "security"

    def _finding_exists(self, filepath: str, line: int, rule_key: str) -> bool:
        """Check whether a finding already exists for (file, line, rule_key)."""
        rel = self._rel(filepath)
        for cat in self.categories.values():
            for f in cat.findings:
                if f.file == rel and f.line == line and f.rule_key == rule_key:
                    return True
        return False

    def _get_line_content(self, filepath: str, lineno: int) -> str:
        """Read a specific line from a file."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    if i == lineno:
                        return line.rstrip()
        except Exception:
            pass
        return ""

    def _resolve_i18n(self, i18n_obj) -> str:
        """Resolve a multilingual i18n object to the report language."""
        if not isinstance(i18n_obj, dict):
            return str(i18n_obj) if i18n_obj else ""
        lang = getattr(self, "report_lang", "en")
        return i18n_obj.get(lang, i18n_obj.get("en", ""))

    def _get_files_for_language(self, language: str) -> list:
        """Return the list of files for a given language."""
        if language == "dockerfile":
            return self._find_dockerfile_files()

        lang_ext_map = {
            "python": getattr(self, "_py_exts", [".py"]),
            "javascript": getattr(self, "_js_exts", [".js", ".jsx", ".ts", ".tsx", ".mjs"]),
            "java": [".java"],
            "csharp": [".cs"],
            "php": [".php", ".inc"],
            "yaml": [".yml", ".yaml"],
            "html": getattr(self, "_html_exts", [".html", ".htm"]),
        }
        exts = lang_ext_map.get(language, [])
        if not exts:
            return []

        paths = getattr(self, "include_paths", self.config.get("paths", {}).get("include", []))
        return self._find_files(exts, paths)

    def _find_dockerfile_files(self) -> list:
        """Find Dockerfile files in the project, honoring paths.exclude.

        Scans paths.include plus the project root (Dockerfiles are usually
        at the root, outside src/ or sca/). paths.exclude is applied to
        avoid scanning fixtures/benchmarks.
        """
        dockerfile_files = []
        paths = getattr(self, "include_paths", self.config.get("paths", {}).get("include", []))
        search_dirs = list(paths) + ["."]
        excludes = self.config.get("paths", {}).get("exclude", [])
        seen = set()
        for path in search_dirs:
            full_path = os.path.join(self.root_dir, path)
            if not os.path.exists(full_path):
                continue
            for root, dirs, filenames in os.walk(full_path):
                rel_root = os.path.relpath(root, self.root_dir)
                # Filter out subdirectories matching an exclude pattern (in-place mod)
                dirs[:] = [
                    d for d in dirs
                    if not _matches_any_exclude(os.path.join(rel_root, d), excludes)
                ]
                if _matches_any_exclude(rel_root, excludes):
                    continue
                for filename in filenames:
                    if filename.lower() in ("dockerfile", "dockerfile.dev", "dockerfile.prod"):
                        filepath = os.path.join(root, filename)
                        if filepath not in seen:
                            seen.add(filepath)
                            dockerfile_files.append(filepath)
        return dockerfile_files
