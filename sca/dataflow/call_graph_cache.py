"""Persistance incrémentale du graphe d'appels (Volet graphe d'appels, D.2-like).

Cache la **structure** du graphe (arêtes : quel appel local vise quel nœud
cible) dans `.sca-cache/call-graph.db` (sqlite3, stdlib), indexée par hash
SHA-256 du fichier — même patron d'invalidation que `sca/file_cache.py`
(réutilise `compute_file_hash`/`is_disabled` telles quelles, aucune
réimplémentation).

Ce qui N'EST PAS caché : les `FunctionInfo` (portent un nœud AST vivant,
`ast_def`, non sérialisable) — reconstruits à chaque run depuis les arbres
déjà parsés par l'appelant (`_parse_trees`, coût déjà payé indépendamment de
ce cache). Seule la résolution des arêtes (suffix-matching des imports +
walk des sites d'appel) est évitée pour les fichiers inchangés — c'est la
partie la plus coûteuse à O(imports × fichiers connus).

Dégradation sûre : si un fichier B est modifié (renommage d'une fonction
ciblée par un import d'un fichier A inchangé), les arêtes en cache de A
pointent temporairement vers un nœud qui n'existe plus dans le graphe
reconstruit — `resolve_summaries` l'ignore simplement (`target in resolved`
échoue), aucun flux inventé. La prochaine modification de A invalide ses
propres arêtes et les recalcule correctement. Compromis identique à celui
déjà accepté par `extra_summaries`/`ModuleRegistry` aujourd'hui (invalidation
par hash du fichier lui-même, pas de ses dépendances transitives).
"""
from __future__ import annotations

import ast
import logging
import sqlite3
from pathlib import Path
from typing import Dict, Optional, Tuple

from sca import VERSION
from sca.dataflow.call_graph import CallGraph, _outgoing_edges, _resolve_import_bindings
from sca.dataflow.summary import collect_functions, collect_imports
from sca.file_cache import compute_file_hash, is_disabled

logger = logging.getLogger("sca.dataflow.call_graph_cache")

CACHE_FILENAME = "call-graph.db"
CACHE_VERSION = 1


class CallGraphCache:
    """Load/rebuild a `CallGraph`, reusing edges already resolved for
    files unchanged since the last run."""

    def __init__(self, cache_dir: Path):
        """Store the cache directory; the sqlite3 connection is opened lazily."""
        self.cache_dir = cache_dir
        self._conn: Optional[sqlite3.Connection] = None

    def _connect(self) -> Optional[sqlite3.Connection]:
        """Open (or return the cached) sqlite3 connection, creating/migrating
        the schema as needed. Returns None if the cache is unusable."""
        if self._conn is not None:
            return self._conn
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.cache_dir / CACHE_FILENAME))
            conn.execute(
                "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS file_hashes "
                "(filepath TEXT PRIMARY KEY, sha256 TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS edges "
                "(filepath TEXT NOT NULL, function_name TEXT NOT NULL, "
                " local_call_name TEXT NOT NULL, "
                " target_file TEXT NOT NULL, target_name TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_edges_file ON edges(filepath)"
            )
            stored = dict(conn.execute("SELECT key, value FROM meta"))
            if stored.get("cache_version") != str(CACHE_VERSION) or stored.get("sca_version") != VERSION:
                logger.info("Cache graphe d'appels invalidé (version)")
                conn.execute("DELETE FROM meta")
                conn.execute("DELETE FROM file_hashes")
                conn.execute("DELETE FROM edges")
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES ('cache_version', ?), "
                    "('sca_version', ?)",
                    (str(CACHE_VERSION), VERSION),
                )
                conn.commit()
            self._conn = conn
            return conn
        except sqlite3.Error as e:
            logger.warning("Cache graphe d'appels inaccessible, ignoré : %s", e)
            return None

    def load_or_build(self, trees: Dict[str, Optional[ast.Module]]) -> CallGraph:
        """Build the current run's `CallGraph`, reusing already-resolved
        edges (sqlite3 cache) for files whose hash has not changed.
        Updates the cache along the way (changed/new files upserted,
        vanished files purged).
        """
        graph = CallGraph()
        file_function_names: Dict[str, set] = {}
        file_functions: Dict[str, list] = {}
        imports_by_file: Dict[str, list] = {}

        for filepath, tree in trees.items():  # sca-ignore:n_plus_1_query — false positive: this loop executes no query, `conn.execute` (line 119) is outside this block, matched at a distance by the rule's indentation-only pattern
            if tree is None:
                continue
            functions = collect_functions(tree)
            file_functions[filepath] = functions
            file_function_names[filepath] = {fn.name for fn in functions}
            for fn in functions:
                graph.nodes[(filepath, fn.name)] = fn
            imports_by_file[filepath] = collect_imports(tree)

        conn = None if is_disabled() else self._connect()
        current_hashes: Dict[str, Optional[str]] = {
            fp: compute_file_hash(Path(fp)) for fp in file_functions
        }
        cached_hashes: Dict[str, str] = {}
        if conn is not None:
            cached_hashes = dict(conn.execute("SELECT filepath, sha256 FROM file_hashes"))

        known_files = list(file_function_names.keys())

        # Import bindings (suffix-matching) are recomputed on every run
        # for all files -- low cost (O(imports) per file) compared
        # to the call-site walk (the real cost cached
        # below), and necessary even for an unchanged file if a
        # target imported elsewhere has moved.
        for filepath in file_functions:  # sca-ignore:n_plus_1_query — false positive: no query here, `conn.execute` (line 185) is in `_persist`, a separate method much further down, matched at a distance by the rule's indentation-only pattern
            graph.import_bindings[filepath] = _resolve_import_bindings(
                filepath, imports_by_file.get(filepath, []),
                known_files, file_function_names,
            )

        unchanged = [
            fp for fp in file_functions
            if conn is not None and current_hashes.get(fp) is not None
            and cached_hashes.get(fp) == current_hashes[fp]
        ]
        to_recompute = [fp for fp in file_functions if fp not in unchanged]

        if unchanged:
            self._load_cached_edges(conn, graph, unchanged, file_functions)
        for filepath in to_recompute:
            local_names = file_function_names[filepath]
            for fn in file_functions[filepath]:
                graph.edges[(filepath, fn.name)] = _outgoing_edges(
                    fn, filepath, local_names, graph.import_bindings[filepath],
                )

        if conn is not None:
            orphans = [fp for fp in cached_hashes if fp not in file_function_names]
            self._persist(conn, graph, to_recompute, current_hashes,
                          file_functions, orphans)

        return graph

    @staticmethod
    def _load_cached_edges(conn: sqlite3.Connection, graph: CallGraph,
                           filepaths: list, file_functions: Dict[str, list]) -> None:
        """Load, in a single query, the already-cached edges for all
        unchanged files (avoids one query per file)."""
        placeholders = ",".join("?" * len(filepaths))
        rows = conn.execute(
            f"SELECT filepath, function_name, local_call_name, target_file, target_name "
            f"FROM edges WHERE filepath IN ({placeholders})", filepaths,
        ).fetchall()
        by_file_fn: Dict[Tuple[str, str], Dict[str, tuple]] = {}
        for filepath, fn_name, local_name, target_file, target_name in rows:
            by_file_fn.setdefault((filepath, fn_name), {})[local_name] = (target_file, target_name)
        for filepath in filepaths:
            for fn in file_functions[filepath]:
                graph.edges[(filepath, fn.name)] = by_file_fn.get((filepath, fn.name), {})

    @staticmethod
    def _persist(conn: sqlite3.Connection, graph: CallGraph, to_recompute: list,
                current_hashes: Dict[str, Optional[str]],
                file_functions: Dict[str, list], orphans: list) -> None:
        """Write the recomputed files (edges + hash) to the database and
        purge vanished files — batched queries (`executemany`), not one
        per file."""
        changed = [fp for fp in to_recompute if current_hashes.get(fp) is not None]
        try:
            if changed:
                placeholders = ",".join("?" * len(changed))
                conn.execute(f"DELETE FROM edges WHERE filepath IN ({placeholders})", changed)
                conn.executemany(
                    "INSERT OR REPLACE INTO file_hashes (filepath, sha256) VALUES (?, ?)",
                    [(fp, current_hashes[fp]) for fp in changed],
                )
                edge_rows = [
                    (filepath, fn.name, local_name, target[0], target[1])
                    for filepath in changed
                    for fn in file_functions[filepath]
                    for local_name, target in graph.edges[(filepath, fn.name)].items()
                ]
                if edge_rows:
                    conn.executemany(
                        "INSERT INTO edges (filepath, function_name, local_call_name, "
                        "target_file, target_name) VALUES (?, ?, ?, ?, ?)",
                        edge_rows,
                    )
            if orphans:
                placeholders = ",".join("?" * len(orphans))
                conn.execute(f"DELETE FROM edges WHERE filepath IN ({placeholders})", orphans)
                conn.execute(f"DELETE FROM file_hashes WHERE filepath IN ({placeholders})", orphans)
            conn.commit()
        except sqlite3.Error as e:
            logger.warning("Écriture du cache graphe d'appels échouée : %s", e)

    def close(self) -> None:
        """Close the sqlite3 connection, if one is open."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None
