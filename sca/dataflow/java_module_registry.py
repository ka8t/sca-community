"""Registre de modules pour la propagation taint inter-fichiers — Java.

3e et dernière pièce du front-end Java (voir `docs/ARCHITECTURE.md`
§ Extension multi-langage du moteur dataflow). Même rôle que
`sca/dataflow/module_registry.py` (Python) — résoudre, pour un fichier
donné, les fiches résumé (`FunctionSummary`, langage-neutre, réutilisé
tel quel) des méthodes atteintes via ses imports — mais **pas un
portage** : l'algorithme de résolution est entièrement réécrit, la
sémantique d'import Java n'ayant rien de commun avec celle de Python.

Différences sémantiques avec `module_registry.py` :
  - Résolution par **FQCN** (package + nom de classe), pas par suffixe de
    chemin de fichier : deux fichiers au même chemin relatif dans des
    packages différents ne sont jamais confondus (contrairement au
    matching par suffixe de `_match_unique_suffix`, qui n'a pas
    d'équivalent ici — la correspondance FQCN est exacte, pas
    approximative).
  - Une classe du **même package** est visible sans import explicite —
    aucun équivalent côté Python (qui exige toujours un import, même
    pour un module du même package).
  - `import pkg.Class;` importe une **classe** (espace de noms de
    méthodes) — jamais une fonction unique directement appelable (Java
    n'a pas de fonctions top-level). Équivalent le plus proche côté
    Python : `import mod as m` (objet module, pas `from mod import
    func`).
  - `import static pkg.Class.member;` est le **seul** cas Java qui
    expose un nom directement appelable sans préfixe — équivalent exact
    de `from mod import func` côté Python.
  - `import pkg.*;` importe toutes les classes du package (pas des
    fonctions individuelles) ; `import static pkg.Class.*;` importe tous
    les membres statiques d'**une** classe sous leur nom nu — équivalent
    exact de `from mod import *` côté Python (`_apply_star_imports`).

Garde-fou anti-FP identique à Python : un FQCN porté par plusieurs
fichiers analysés (théoriquement invalide en Java réel, mais un jeu de
fichiers audité peut être incohérent) n'est pas résolu — mieux vaut
rater un flux que d'en inventer un faux.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple

from sca.dataflow.summary import FunctionSummary

if TYPE_CHECKING:
    from tree_sitter import Node as TSNode

NodeKey = Tuple[str, str]  # (filepath, "ClassName.methodName")


# ============================================================================
# Extraction — package / imports / top-level classes of a Java file
# ============================================================================

@dataclass(frozen=True)
class JavaImportInfo:
    """A Java import.

    Attributes:
        path: dotted path as written in the source code.
            - `import pkg.Class;`               -> "pkg.Class"
            - `import pkg.*;`                    -> "pkg" (wildcard=True)
            - `import static pkg.Class.member;`  -> "pkg.Class.member" (is_static=True)
            - `import static pkg.Class.*;`       -> "pkg.Class" (is_static=True, wildcard=True)
        is_static: `import static ...`.
        wildcard: import ending with `.*`.
    """
    path: str
    is_static: bool = False
    wildcard: bool = False


_TOP_LEVEL_TYPE_DECLS = (
    "class_declaration", "interface_declaration",
    "enum_declaration", "record_declaration",
)


def collect_package(root: TSNode) -> str:
    """Return the declared package name (`""` = default package)."""
    for child in root.named_children:
        if child.type == "package_declaration":
            name_node = next((c for c in child.named_children), None)
            if name_node is not None:
                return name_node.text.decode("utf-8", errors="replace")
    return ""


def collect_java_imports(root: TSNode) -> List[JavaImportInfo]:
    """List the imports of a Java file (tree-sitter `compilation_unit`)."""
    imports: List[JavaImportInfo] = []
    for child in root.named_children:
        if child.type != "import_declaration":
            continue
        is_static = any(c.type == "static" for c in child.children)
        wildcard = any(c.type == "asterisk" for c in child.children)
        scoped = next((c for c in child.named_children if c.type in ("scoped_identifier", "identifier")), None)
        if scoped is None:
            continue
        path = scoped.text.decode("utf-8", errors="replace")
        imports.append(JavaImportInfo(path=path, is_static=is_static, wildcard=wildcard))
    return imports


def collect_java_class_names(root: TSNode) -> List[str]:
    """Return the names of classes/interfaces/enums/records declared at the
    top level of the file (nested classes out of scope — a call
    `Outer.Inner.method()` from another file will not be resolved)."""
    names: List[str] = []
    for child in root.named_children:
        if child.type in _TOP_LEVEL_TYPE_DECLS:
            name_node = child.child_by_field_name("name")
            if name_node is not None:
                names.append(name_node.text.decode("utf-8", errors="replace"))
    return names


def collect_java_superclass(root: TSNode) -> Dict[str, Optional[str]]:
    """Return `{simple_class_name: simple_superclass_name_or_None}` for each
    top-level class declaration in the file (interfaces/enums/records
    have no superclass in the Java sense — absent from the dict, not
    `None`). Required to resolve `super.foo()` (`JavaCallGraph`) — no
    prior equivalent. Nested classes out of scope, same limitation as
    `collect_java_class_names`."""
    out: Dict[str, Optional[str]] = {}
    for child in root.named_children:
        if child.type != "class_declaration":
            continue
        name_node = child.child_by_field_name("name")
        if name_node is None:
            continue
        cname = name_node.text.decode("utf-8", errors="replace")
        superclass_node = child.child_by_field_name("superclass")
        simple_super: Optional[str] = None
        if superclass_node is not None:
            type_node = next(
                (c for c in superclass_node.named_children
                 if c.type in ("type_identifier", "scoped_type_identifier", "generic_type")),
                None,
            )
            if type_node is not None:
                text = type_node.text.decode("utf-8", errors="replace")
                simple_super = text.split("<", 1)[0].rsplit(".", 1)[-1] or None
        out[cname] = simple_super
    return out


# ============================================================================
# Free functions — resolution without depending on `JavaModuleRegistry`
# (needed by `JavaCallGraph.build`, which builds its edges BEFORE the
# summaries exist — same causality chain as Python, where `call_graph.py`
# only reuses `resolve_target_file`, never `ModuleRegistry` itself).
# ============================================================================

def build_fqcn_index(
    class_names_by_file: Dict[str, Tuple[str, List[str]]],
) -> Dict[str, Optional[str]]:
    """Return fqcn -> filepath, or None if carried by several files
    (ambiguous, anti-FP — better to miss a flow than invent a false one).
    `class_names_by_file` = `{filepath: (package, [class_names])}`."""
    index: Dict[str, Optional[str]] = {}
    owner: Dict[str, str] = {}
    for fp, (package, class_names) in class_names_by_file.items():
        for cname in class_names:
            fqcn = f"{package}.{cname}" if package else cname
            if fqcn in owner and owner[fqcn] != fp:
                index[fqcn] = None
            else:
                owner[fqcn] = fp
                index[fqcn] = fp
    return index


def resolve_visible_classes(
    filepath: str,
    package: str,
    imports: List["JavaImportInfo"],
    class_names_by_file: Dict[str, Tuple[str, List[str]]],
    fqcn_index: Dict[str, Optional[str]],
) -> Dict[str, str]:
    """Return `{simple_class_name: defining_file}` visible from `filepath`:
    same-package classes (auto-visible, Java specificity) + explicit
    non-static imports (`import pkg.Class`/`import pkg.*`). An ambiguous
    FQCN (`fqcn_index[...] is None`) is excluded, same caution as
    elsewhere in this file. Static imports are NOT handled here (see
    `build_static_import_bindings` — different semantics: they expose a
    bare member, not a class)."""
    out: Dict[str, str] = {}
    for other_fp, (other_package, other_classes) in class_names_by_file.items():
        if other_fp == filepath or other_package != package:
            continue
        for cname in other_classes:
            out[cname] = other_fp
    for imp in imports:
        if imp.is_static:
            continue
        if imp.wildcard:
            for other_fp, (other_package, other_classes) in class_names_by_file.items():
                if other_fp == filepath or other_package != imp.path:
                    continue
                for cname in other_classes:
                    out[cname] = other_fp
            continue
        target_fp = fqcn_index.get(imp.path)
        if not target_fp:
            continue
        cname = imp.path.rsplit(".", 1)[-1]
        out[cname] = target_fp
    return out


def build_static_import_bindings(
    filepath: str,
    imports: List["JavaImportInfo"],
    class_names_by_file: Dict[str, Tuple[str, List[str]]],
    fqcn_index: Dict[str, Optional[str]],
    file_function_names: Dict[str, Set[str]],
) -> Dict[str, NodeKey]:
    """`import static pkg.Class.member;` / `import static pkg.Class.*;` ->
    `{bare_name: (target_file, "Class.member")}`. Mirrors the `is_static`
    branches of `_resolve_one_import`, but resolves to `NodeKey`s (the
    graph has no `FunctionSummary` yet when its edges are built) instead
    of looking directly into `file_entry.summaries`. `file_function_names`
    = `{filepath: {dotted "Class.member" names known in that file}}`,
    required to produce an edge ONLY if the static member actually
    exists (same anti-FP guard as the rest of this file)."""
    out: Dict[str, NodeKey] = {}
    for imp in imports:
        if not imp.is_static:
            continue
        if imp.wildcard:
            target_fp = fqcn_index.get(imp.path)
            if not target_fp:
                continue
            cname = imp.path.rsplit(".", 1)[-1]
            prefix = f"{cname}."
            for dotted in file_function_names.get(target_fp, ()):
                if dotted.startswith(prefix):
                    out.setdefault(dotted[len(prefix):], (target_fp, dotted))
            continue
        class_fqcn, _, member = imp.path.rpartition(".")
        target_fp = fqcn_index.get(class_fqcn)
        if not target_fp:
            continue
        cname = class_fqcn.rsplit(".", 1)[-1]
        dotted = f"{cname}.{member}"
        if dotted in file_function_names.get(target_fp, ()):
            out[member] = (target_fp, dotted)
    return out


# ============================================================================
# Registry — aggregation + cross-file resolution
# ============================================================================

@dataclass
class JavaFileEntry:
    """Record of a Java file in the registry."""
    filepath: str
    package: str
    class_names: List[str] = field(default_factory=list)
    summaries: Dict[str, FunctionSummary] = field(default_factory=dict)
    imports: List[JavaImportInfo] = field(default_factory=list)


class JavaModuleRegistry:
    """Aggregates, for a set of Java files, the summary records and the
    imports, and resolves cross-file calls.

    `FunctionSummary` (dotted key `"ClassName.methodName"`, consistent
    with the convention already used on the Python side for methods) is
    reused as-is — language-neutral, no Python-specific field.
    """

    def __init__(self) -> None:
        """Initialize an empty registry with no files and no FQCN index cache."""
        self.files: Dict[str, JavaFileEntry] = {}
        self._fqcn_index: Optional[Dict[str, Optional[str]]] = None

    def add_file(
        self, filepath: str, package: str, class_names: List[str],
        summaries: Dict[str, FunctionSummary], imports: List[JavaImportInfo],
    ) -> None:
        """Register a Java file's package, classes, summaries and imports,
        invalidating the cached FQCN index."""
        self.files[filepath] = JavaFileEntry(
            filepath=filepath, package=package,
            class_names=list(class_names), summaries=summaries, imports=list(imports),
        )
        self._fqcn_index = None  # invalidate the cache

    # ------------------------------------------------------------------
    # FQCN → file index
    # ------------------------------------------------------------------

    def _ensure_index(self) -> Dict[str, Optional[str]]:
        """Return the FQCN index, building and caching it on first use."""
        if self._fqcn_index is None:
            self._fqcn_index = self._build_fqcn_index()
        return self._fqcn_index

    def _build_fqcn_index(self) -> Dict[str, Optional[str]]:
        """Return fqcn -> filepath, or None if carried by several files (ambiguous)."""
        return build_fqcn_index({fp: (e.package, e.class_names) for fp, e in self.files.items()})

    # ------------------------------------------------------------------
    # API consulted by the analysis pass
    # ------------------------------------------------------------------

    def resolve_imported_summaries(self, filepath: str) -> Dict[str, FunctionSummary]:
        """Return the summaries of methods reachable from `filepath`, indexed
        by the **local call name** (as it appears in the code):
        `"ClassName.methodName"` for a qualified call, or just
        `"methodName"` for a static import."""
        entry = self.files.get(filepath)
        if entry is None:
            return {}
        index = self._ensure_index()
        out: Dict[str, FunctionSummary] = {}

        # 1. Same package: visible without an explicit import (Java specificity).
        for other_fp, other in self.files.items():
            if other_fp == filepath or other.package != entry.package:
                continue
            for cname in other.class_names:
                self._expose_class_methods(out, cname, other)

        # 2. Explicit imports (can either add to — static imports — or
        #    override the same-package resolution for an identical name).
        for imp in entry.imports:
            self._resolve_one_import(filepath, imp, index, out)

        return out

    def _expose_class_methods(self, out: Dict[str, FunctionSummary],
                              class_name: str, file_entry: JavaFileEntry) -> None:
        """Expose the methods of `class_name` under `"ClassName.method"` —
        already the key used in `file_entry.summaries` (dotted convention
        shared with Python methods)."""
        prefix = f"{class_name}."
        for mname, summary in file_entry.summaries.items():
            if mname.startswith(prefix):
                out[mname] = summary

    def _resolve_one_import(self, filepath: str, imp: JavaImportInfo,
                            index: Dict[str, Optional[str]],
                            out: Dict[str, FunctionSummary]) -> None:
        """Add to `out` the summaries brought in by a single Java import,
        dispatching on wildcard/static combinations."""
        if imp.wildcard and not imp.is_static:
            # `import pkg.*;` — all classes of the package present in the
            # analyzed file set.
            for fp, file_entry in self.files.items():
                if fp == filepath or file_entry.package != imp.path:
                    continue
                for cname in file_entry.class_names:
                    self._expose_class_methods(out, cname, file_entry)
            return

        if imp.is_static and imp.wildcard:
            # `import static pkg.Class.*;` — all static members of Class,
            # exposed WITHOUT a prefix (bare name).
            target_fp = index.get(imp.path)
            if not target_fp:
                return
            target = self.files[target_fp]
            cname = imp.path.rsplit(".", 1)[-1]
            prefix = f"{cname}."
            for mname, summary in target.summaries.items():
                if mname.startswith(prefix):
                    out.setdefault(mname[len(prefix):], summary)
            return

        if imp.is_static:
            # `import static pkg.Class.member;` — member exposed bare.
            class_fqcn, _, member = imp.path.rpartition(".")
            target_fp = index.get(class_fqcn)
            if not target_fp:
                return
            target = self.files[target_fp]
            cname = class_fqcn.rsplit(".", 1)[-1]
            summary = target.summaries.get(f"{cname}.{member}")
            if summary is not None:
                out[member] = summary
            return

        # `import pkg.Class;` — Class.method exposed (key already dotted).
        target_fp = index.get(imp.path)
        if not target_fp:
            return
        target = self.files[target_fp]
        cname = imp.path.rsplit(".", 1)[-1]
        self._expose_class_methods(out, cname, target)
