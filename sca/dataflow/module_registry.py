"""Module registry for cross-file taint propagation (Part 3).

Clean-room implementation. No third-party code was read.

Overview:
    The taint engine analyzes one file at a time (`run_taint_rule`). To
    link a source in module A to a sink in module B reached via an import
    (`from b import helper`), we compute, in a pre-pass, a summary record
    for each file and its imports, then resolve — for each importing file —
    the calls to functions defined elsewhere.

    Scope of the first increment: **intra-package** resolution only.
    An import only resolves to a file present in the analyzed set (the
    stdlib / third-party packages are naturally excluded).

    Anti-FP guard: an ambiguous absolute import (several candidate files)
    is not resolved — better to miss a flow than to invent a false one.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from sca.dataflow.summary import FunctionSummary, ImportInfo


def _path_parts(path: str) -> List[str]:
    """Split a path into components, independent of the OS separator."""
    return [p for p in path.replace("\\", "/").split("/") if p and p != "."]


def resolve_target_file(importer: str, imp: ImportInfo,
                        known_files: Iterable[str]) -> Optional[str]:
    """Return the path of the analyzed file targeted by an import, or None.

    Free-standing (instance-less) version of the resolution used by both
    `ModuleRegistry` and `CallGraph` (call-graph component) — shared
    suffix-matching logic to avoid divergence between the two resolvers.

    Relative (`level ≥ 1`): anchored to the importer's directory (climbs
    `level - 1` levels up), then follows the module path.
    Absolute (`level == 0`): suffix `mod/parts.py`; resolved only if it
    matches **exactly one** file in the set (ambiguity ⇒ give up, anti-FP).
    """
    mod_parts = imp.module.split(".") if imp.module else []
    known = list(known_files)

    if imp.level >= 1:
        dir_parts = _path_parts(importer)[:-1]  # strip the file name
        ascend = imp.level - 1
        if ascend > len(dir_parts):
            return None
        base = dir_parts[: len(dir_parts) - ascend] if ascend else dir_parts
        target_parts = base + mod_parts
        if not target_parts:
            return None
        target_suffix = "/".join(target_parts) + ".py"
        return match_unique_suffix(target_suffix, anchored=True,
                                   importer=importer, known_files=known)

    if not mod_parts:
        return None
    target_suffix = "/".join(mod_parts) + ".py"
    return match_unique_suffix(target_suffix, anchored=False,
                               importer=importer, known_files=known)


def match_unique_suffix(suffix: str, anchored: bool, importer: str,
                        known_files: Iterable[str]) -> Optional[str]:
    """Return the file in `known_files` whose path ends with `suffix`.

    `anchored` (relative import) requires an exact tail match; unanchored
    (absolute import), a directory prefix is tolerated but only a
    **single** candidate is accepted (otherwise ambiguous → None).
    """
    suffix_parts = _path_parts(suffix)
    candidates = []
    for fp in known_files:
        if fp == importer:
            continue
        fp_parts = _path_parts(fp)
        if fp_parts[-len(suffix_parts):] == suffix_parts:
            candidates.append(fp)
    if len(candidates) == 1:
        return candidates[0]
    if anchored and candidates:
        imp_parts = _path_parts(importer)
        candidates.sort(
            key=lambda c: _common_prefix_len(_path_parts(c), imp_parts),
            reverse=True,
        )
        return candidates[0]
    return None


@dataclass
class FileEntry:
    """Record of a file in the registry: its summaries + its imports."""
    filepath: str
    summaries: Dict[str, FunctionSummary] = field(default_factory=dict)
    imports: List[ImportInfo] = field(default_factory=list)


class ModuleRegistry:
    """Aggregates, for a set of files, the summary records and the
    imports, and resolves intra-package cross-file calls.

    Built in a pre-pass (once per rule), then consulted during the
    analysis pass to inject the cross-file records into the specs.
    """

    def __init__(self) -> None:
        """Initialize an empty registry with no files."""
        self.files: Dict[str, FileEntry] = {}

    def add_file(self, filepath: str, summaries: Dict[str, FunctionSummary],
                 imports: List[ImportInfo]) -> None:
        """Register `filepath`'s function summaries and imports in the registry."""
        self.files[filepath] = FileEntry(filepath, summaries, imports)

    # ------------------------------------------------------------------
    # Import -> analyzed file resolution
    # ------------------------------------------------------------------

    def _resolve_target_file(self, importer: str, imp: ImportInfo) -> Optional[str]:
        """Return the path of the analyzed file targeted by an import, or None.

        Delegates to `resolve_target_file` (logic shared with `CallGraph`).
        """
        return resolve_target_file(importer, imp, self.files.keys())

    # ------------------------------------------------------------------
    # API consulted by the analysis pass
    # ------------------------------------------------------------------

    def resolve_imported_summaries(self, filepath: str) -> Dict[str, FunctionSummary]:
        """Return the summaries of functions imported by `filepath`, indexed by
        the **local call name** (as it appears in that file's code).

        - `from mod import func [as h]`  → key `h`/`func`
        - `import mod [as m]` / `from . import mod` → keys `m.func` for each
          top-level function of `mod` (the call is written `m.func(...)`).
        """
        entry = self.files.get(filepath)
        if entry is None:
            return {}
        out: Dict[str, FunctionSummary] = {}
        star_imports = []
        for imp in entry.imports:
            if imp.orig_name == "*":
                star_imports.append(imp)  # handled afterwards (collisions, Part 5C)
            else:
                self._resolve_one_import(filepath, imp, out)
        if star_imports:
            self._apply_star_imports(filepath, star_imports, out)
        return out

    def _apply_star_imports(self, filepath: str, star_imports: List[ImportInfo],
                            out: Dict[str, FunctionSummary]) -> None:
        """Component 5C — `from mod import *`: expose the target module's
        top-level functions under their bare name. Anti-FP: a name brought
        in by two distinct `*` imports (with different summaries) is
        ambiguous → ignored; an already-resolved explicit import takes
        precedence over the wildcard.
        """
        seen: Dict[str, FunctionSummary] = {}
        collided = set()
        for imp in star_imports:
            target = self._resolve_target_file(filepath, imp)
            if target is None:
                continue
            for fname, summary in self.files[target].summaries.items():
                if "." in fname:
                    continue  # methods / nested functions: out of scope
                if fname in seen and seen[fname] is not summary:
                    collided.add(fname)
                else:
                    seen[fname] = summary
        for name, summary in seen.items():
            if name not in collided and name not in out:
                out[name] = summary

    def _resolve_one_import(self, filepath: str, imp: ImportInfo,
                            out: Dict[str, FunctionSummary]) -> None:
        """Add to `out` the summaries brought in by a single import."""
        if not imp.orig_name:
            # `import mod [as m]` -> calls of the form `m.func(...)`.
            target = self._resolve_target_file(filepath, imp)
            if target is not None:
                _expose_module_funcs(out, imp.local_name, self.files[target])
            return
        # `from mod import X`: X is either a function or a submodule.
        target = self._resolve_target_file(filepath, imp)
        summary = self._summary_in(target, imp.orig_name)
        if summary is not None:
            out[imp.local_name] = summary  # direct binding of a function
            return
        submod = self._resolve_target_file(filepath, _as_submodule(imp))
        if submod is not None:  # `from pkg import submod` -> calls submod.func(...)
            _expose_module_funcs(out, imp.local_name, self.files[submod])

    def _summary_in(self, target: Optional[str], name: str) -> Optional[FunctionSummary]:
        """Return the summary for `name` in file `target`, or None if either is missing."""
        if target is None:
            return None
        return self.files[target].summaries.get(name)


def _as_submodule(imp: ImportInfo) -> ImportInfo:
    """View a `from pkg import submod` as an import of module `pkg.submod`
    (so `from . import utils` resolves to the file `utils.py`)."""
    module = f"{imp.module}.{imp.orig_name}".lstrip(".") if imp.module else imp.orig_name
    return ImportInfo(local_name=imp.local_name, module=module,
                      orig_name="", level=imp.level)


def _expose_module_funcs(out: Dict[str, FunctionSummary], local: str,
                         tgt: FileEntry) -> None:
    """Expose an imported module's top-level functions under `local.func`."""
    for fname, summary in tgt.summaries.items():
        if "." in fname:
            continue  # methods / nested functions: out of scope
        out[f"{local}.{fname}"] = summary


def _common_prefix_len(a: List[str], b: List[str]) -> int:
    """Return the length of the common leading segment prefix of `a` and `b`."""
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n
