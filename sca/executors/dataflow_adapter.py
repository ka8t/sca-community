"""Adapter between the SCA runtime and the Phase 7-8 dataflow engine.

Converts Finding objects (contract §3.2) into TaintFlow (SCA internal format).
Since the removal of the legacy taint_engine.py, dataflow is the only taint
backend and this adapter is always active.

Spec §10 and the internal rule-generation contract doc §3.
"""
from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

from sca.dataflow.call_graph import CallGraph
from sca.dataflow.call_graph_cache import CallGraphCache
from sca.executors.dataflow_taint import (
    UnsupportedLanguage,
    rule_json_to_specs,
    run_taint_rule,
)
from sca.models import TaintFlow


logger = logging.getLogger("sca.dataflow.adapter")


def _rule_id_of(rule: dict) -> str:
    """Return the rule's id, falling back to "unknown" if unset."""
    return rule.get("id") or rule.get("rule_id") or "unknown"


def _extract_source_expr(flow) -> str:
    """Return the text of the flow's source step, or "" if there is none."""
    if not flow:
        return ""
    return next((step.text for step in flow if step.kind == "source"), "")


def _build_chain(flow):
    """Build the (line, var_name, code_snippet) chain for a TaintFlow from raw flow steps."""
    # chain = [(line, var_name, code_snippet)]. The middle field carries the
    # label of propagation steps (e.g. interprocedural hop `callee(...) → sink`),
    # and stays empty for source/sink steps (rendering unchanged).
    out = []
    for step in (flow or ()):
        var = step.text if step.kind == "propagation" else ""
        out.append((step.line, var, step.text))
    return out


def _finding_to_taint_flow(f, rule_id: str, language: str, filepath: str, category: str) -> TaintFlow:
    """Convert a taint Finding into the SCA-internal TaintFlow representation."""
    return TaintFlow(
        category=category,
        rule_key=f.rule_id or rule_id,
        language=language,
        source_file=filepath,
        source_line=f.source_line or f.line,
        source_expr=_extract_source_expr(f.flow),
        source_kind=getattr(f, "source_kind", "unknown") or "unknown",
        sink_file=filepath,
        sink_line=f.line,
        sink_expr=f.sink_text or "",
        chain=_build_chain(f.flow),
    )


def _analyze_file(rule: dict, rule_id: str, filepath: str, content: str,
                  language: str, precomputed_summaries=None, extra_summaries=None):
    """Run a single taint rule against one file's content, returning findings (or [] on error)."""
    try:
        return list(run_taint_rule(
            rule, content, filename=filepath, language=language,
            precomputed_summaries=precomputed_summaries,
            extra_summaries=extra_summaries,
        ))
    except UnsupportedLanguage:
        logger.debug("dataflow_adapter: language %s not supported", language)
        raise
    except Exception as exc:
        logger.debug(
            "dataflow_adapter: error analyzing %s with rule %s: %s",
            filepath, rule_id, exc,
        )
        return []


# ============================================================================
# Persistent call graph — multi-hop interprocedural resolution
# (replaces the old Volet 3 / 1-hop ModuleRegistry, cf. docs/ROADMAP.md
#  § Persistent call graph, 2026-07-26)
# ============================================================================

def _parse_trees(file_contents: dict) -> Dict[str, Optional[ast.Module]]:
    """Parse each Python file once, caching None on SyntaxError, so the pre-pass
    doesn't re-parse per rule."""
    trees: Dict[str, Optional[ast.Module]] = {}
    for filepath, content in file_contents.items():
        try:
            trees[filepath] = ast.parse(content)
        except SyntaxError:
            trees[filepath] = None
    return trees


def _load_call_graph(
    trees: Dict[str, Optional[ast.Module]], cache_dir: Optional[Path],
) -> CallGraph:
    """Build the current run's Python call graph once, for reuse across all rules
    (the graph structure doesn't depend on a rule's specs, unlike the summaries
    derived from it).

    `cache_dir`: project `.sca-cache/` directory for incremental persistence;
    `None` rebuilds the graph in memory with no persistence (e.g. evaluation
    scripts that have no project cache).
    """
    if cache_dir is None:
        return CallGraph.build(trees)
    cache = CallGraphCache(cache_dir)
    graph = cache.load_or_build(trees)
    cache.close()
    return graph


def _resolve_rule_summaries(graph: CallGraph, rule: dict, file_contents: dict):
    """Resolve a rule's (own, extra) summaries in topological order, or ({}, {})
    if the rule can't be converted to specs."""
    specs = rule_json_to_specs(rule)
    if specs is None:
        return {}, {}
    source_lines_by_file = {fp: c.splitlines() for fp, c in file_contents.items()}
    return graph.resolve_summaries(specs, source_lines_by_file=source_lines_by_file)


def run_dataflow_taint_for_files(
    rules: List[dict],
    file_contents: dict,
    language: str,
    category: str = "security",
    cache_dir: Optional[Path] = None,
    on_file_done: Optional[Callable[[str, float, int], None]] = None,
    on_rule_summary_done: Optional[Callable[[str, int, int, float], None]] = None,
) -> Iterable[TaintFlow]:
    """Run the Phase 7-8 dataflow engine over each (rule, file) pair.

    Args:
        rules: list of compiled taint rules (SCA internal format).
        file_contents: dict {filepath: content}.
        language: "python", "javascript", "java", "csharp", "php".
        category: SCA category (security, etc.).
        cache_dir: project `.sca-cache/` directory, for incremental
            persistence of the call graph. `None` disables persistence
            (the graph is rebuilt in memory, still multi-hop).
        on_file_done: optional callback invoked once per file, after every
            rule has been run against it, as (filepath, duration_seconds,
            flow_count) — live per-file progress reporting (Perf).
        on_rule_summary_done: optional callback invoked once per rule after
            phase 1's `_resolve_rule_summaries`, as (rule_id, index, total,
            duration_seconds) — this phase is a purely sequential loop over
            all taint rules (~10s/rule on the sca/ self-audit, independent
            of graph size — the worklist fixed-point in `analyze()`
            dominates, not CFG construction) that runs entirely before the
            first per-file `on_file_done` can fire; without this, a cold
            run stays silent for minutes right after "Taint {language}..."
            is printed (confirmed live: 216s of silence on sca/'s own 23
            Python taint rules) even though per-file progress is wired up.

    Yields:
        TaintFlow in SCA internal format (compatible with _integrate_taint_flow).
    """
    import time as _time
    # Call graph: Python (always) or Java (prototype, only if
    # SCA_JAVA_DATAFLOW_ENGINE is enabled — cf. `dataflow_taint.py`). Other
    # languages go through the lexical engine (`run_taint_rule`), with no
    # notion of summary/graph.
    if language == "python":
        trees = _parse_trees(file_contents)
        graph = _load_call_graph(trees, cache_dir)
    else:
        graph = None

    taint_rules = [r for r in rules if r.get("mode") in ("taint", "regex+taint")]

    # Phase 1: resolve each rule's summaries once, upfront (mirrors the
    # parallel variant's phase 1). Lets phase 2 iterate file-outer /
    # rule-inner below, so on_file_done can fire once a file has been run
    # against every rule — the reordering doesn't change what's yielded,
    # only the order (callers only ever check flow membership/count).
    per_rule_ctx: Dict[str, tuple] = {}
    if graph is not None:
        _n_rules = len(taint_rules)
        for _rule_idx, rule in enumerate(taint_rules, start=1):
            _rt0 = _time.perf_counter()
            own, extra = _resolve_rule_summaries(graph, rule, file_contents)
            if own or extra:
                per_rule_ctx[_rule_id_of(rule)] = (own, extra)
            if on_rule_summary_done is not None:
                on_rule_summary_done(
                    _rule_id_of(rule), _rule_idx, _n_rules, _time.perf_counter() - _rt0,
                )

    for filepath, content in file_contents.items():
        _t0 = _time.perf_counter()
        _flow_count = 0
        for rule in taint_rules:
            rule_id = _rule_id_of(rule)
            own, extra = per_rule_ctx.get(rule_id, ({}, {}))
            pre = own.get(filepath)
            ex = extra.get(filepath)
            try:
                findings = _analyze_file(
                    rule, rule_id, filepath, content, language, pre, ex,
                )
            except UnsupportedLanguage:
                if on_file_done is not None:
                    on_file_done(filepath, _time.perf_counter() - _t0, _flow_count)
                return
            for f in findings:
                _flow_count += 1
                yield _finding_to_taint_flow(f, rule_id, language, filepath, category)
        if on_file_done is not None:
            on_file_done(filepath, _time.perf_counter() - _t0, _flow_count)


# ============================================================================
# Parallelization (Perf — one worker per file)
# ============================================================================

# Minimum threshold to trigger parallelization. Below it, the pool spawn
# overhead outweighs the gain. Measured empirically on ProcessPoolExecutor /
# Python 3.14 / Mac M1: ~0.3s overhead per pool.
MIN_PARALLEL_TAINT_FILES = 20


def _analyze_one_file_worker(args):
    """Phase 2 worker (module-level, picklable) — analyzes one file with all
    taint rules and returns `(flows, worker_duration_seconds)`.

    `file_context` = {rule_id: (precomputed_summaries, extra_summaries)} supplies
    the intra-file (reused) and cross-file (call graph) summaries already
    resolved from the global graph. Empty for non-Python languages.

    The worker rebuilds specs from JSON on every call (the cost is negligible
    next to the analysis itself) — this avoids sharing compiled re.Pattern
    objects across processes.

    The duration is measured *inside* the worker (start to end of its own
    analysis), not by the caller around submission-to-completion — the pool
    can queue files behind busier workers, so a caller-side measurement
    would report elapsed-since-submission (rises through the whole batch,
    dominated by queueing) rather than this file's actual processing cost.
    """
    import time as _time

    filepath, content, rules, language, category, file_context = args
    file_context = file_context or {}
    _t0 = _time.perf_counter()
    flows: List[TaintFlow] = []
    for rule in rules:
        if rule.get("mode") not in ("taint", "regex+taint"):
            continue
        rule_id = _rule_id_of(rule)
        pre, extra = file_context.get(rule_id, (None, None))
        try:
            findings = _analyze_file(
                rule, rule_id, filepath, content, language, pre, extra,
            )
        except UnsupportedLanguage:
            return flows, _time.perf_counter() - _t0
        for f in findings:
            flows.append(_finding_to_taint_flow(f, rule_id, language, filepath, category))
    return flows, _time.perf_counter() - _t0


def run_dataflow_taint_for_files_parallel(
    rules: List[dict],
    file_contents: dict,
    language: str,
    category: str = "security",
    max_workers: int = None,
    cache_dir: Optional[Path] = None,
    on_file_done: Optional[Callable[[str, float, int], None]] = None,
    on_rule_summary_done: Optional[Callable[[str, int, int, float], None]] = None,
) -> Iterable[TaintFlow]:
    """Parallel variant of `run_dataflow_taint_for_files`.

    Uses a `ProcessPoolExecutor` with one worker per file for the analysis
    phase (phase 2). Only activates when
    `len(file_contents) >= MIN_PARALLEL_TAINT_FILES`; otherwise falls back to
    the sequential version (pool overhead would exceed the gain).

    The call graph construction and summary resolution (phase 1) stay
    sequential in the main process: the multi-hop topological order is
    inherently a global dependency across files, unlike the old Volet 3
    (1-hop resolution, independent by construction) which could be
    parallelized per file. The bulk of the work — the taint analysis itself —
    remains parallelized in phase 2.

    Args:
        max_workers: defaults to `os.cpu_count()` (Python standard).
        cache_dir: see `run_dataflow_taint_for_files`.
        on_rule_summary_done: see `run_dataflow_taint_for_files` — phase 1
            progress, fired once per rule before phase 2 starts.

    Yields:
        TaintFlow in worker-completion order (non-deterministic). Callers
        that care about order must already deduplicate by
        (rule, source_line, sink_line).
    """
    if len(file_contents) < MIN_PARALLEL_TAINT_FILES:
        yield from run_dataflow_taint_for_files(
            rules, file_contents, language, category, cache_dir,
            on_file_done=on_file_done, on_rule_summary_done=on_rule_summary_done,
        )
        return

    from concurrent.futures import ProcessPoolExecutor, as_completed
    import time as _time

    # Pre-filter taint rules so we don't pickle noise
    taint_rules = [r for r in rules if r.get("mode") in ("taint", "regex+taint")]
    if not taint_rules:
        return

    # Phase 1 (sequential, main process): call graph + per-rule summaries —
    # cf. docstring above for why this isn't parallelized.
    per_rule_ctx: Dict[str, tuple] = {}  # rule_id -> (own, extra)
    graph = None
    if language == "python":
        trees = _parse_trees(file_contents)
        graph = _load_call_graph(trees, cache_dir)
    if graph is not None:
        _n_rules = len(taint_rules)
        for _rule_idx, rule in enumerate(taint_rules, start=1):
            _rt0 = _time.perf_counter()
            own, extra = _resolve_rule_summaries(graph, rule, file_contents)
            if own or extra:
                per_rule_ctx[_rule_id_of(rule)] = (own, extra)
            if on_rule_summary_done is not None:
                on_rule_summary_done(
                    _rule_id_of(rule), _rule_idx, _n_rules, _time.perf_counter() - _rt0,
                )

    with ProcessPoolExecutor(max_workers=max_workers) as pool:
        # Per-file cross-file context: {rule_id: (precomputed, extra)}.
        def _ctx_for(filepath):
            """Build the per-rule (precomputed, extra) summary context for one file."""
            ctx = {}
            for rule_id, (own, extra) in per_rule_ctx.items():
                pre = own.get(filepath)
                ex = extra.get(filepath)
                if pre or ex:
                    ctx[rule_id] = (pre, ex)
            return ctx

        # Phase 2 (parallel): analysis with summary injection.
        p2_items = [
            (filepath, content, taint_rules, language, category, _ctx_for(filepath))
            for filepath, content in file_contents.items()
        ]
        # Duration comes back from the worker itself (see
        # _analyze_one_file_worker) rather than being measured here around
        # submission-to-completion: with more files than workers, several
        # sit queued behind busier ones, so a caller-side measurement would
        # report elapsed-since-submission (rising through the whole batch)
        # instead of this file's actual processing cost.
        future_to_filepath = {}
        p2_futures = []
        for it in p2_items:
            future = pool.submit(_analyze_one_file_worker, it)
            future_to_filepath[future] = it[0]
            p2_futures.append(future)
        for future in as_completed(p2_futures):
            filepath = future_to_filepath[future]
            try:
                flows, worker_duration = future.result()
            except Exception as exc:
                logger.debug("parallel taint worker failed: %s", exc)
                if on_file_done is not None:
                    on_file_done(filepath, 0.0, 0)
                continue
            if on_file_done is not None:
                on_file_done(filepath, worker_duration, len(flows))
            yield from flows
