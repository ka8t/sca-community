"""
AST parsing engine via tree-sitter.

Unified parsing for 7 languages with parser caching and S-expression
query execution. Conditional import — tree-sitter is optional
(the script's zero-dependency philosophy).
"""
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("sca.treesitter_engine")

# Mapping of SCA language → tree-sitter grammar module
_GRAMMAR_MODULES = {
    "python": "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
    "java": "tree_sitter_java",
    "csharp": "tree_sitter_c_sharp",
    "php": "tree_sitter_php",
    "html": "tree_sitter_html",
    "yaml": "tree_sitter_yaml",
}

# Name of the language() function in the grammar module (special cases)
_GRAMMAR_LANG_FUNC = {
    "php": "language_php",
}


def has_treesitter() -> bool:
    """Check whether tree-sitter is installed."""
    try:
        import tree_sitter
        return True
    except ImportError:
        return False


class TreeSitterManager:
    """Cache-backed manager for tree-sitter parsers.

    Instantiates parsers on demand and caches them for reuse. Handles the
    7 languages supported by SCA.
    """

    def __init__(self):
        """Initialize empty parser/language caches and check tree-sitter availability."""
        self._parsers: Dict[str, object] = {}
        self._languages: Dict[str, object] = {}
        self._ts_available = has_treesitter()

    def has_language(self, sca_lang: str) -> bool:
        """Check whether a tree-sitter grammar is available for this language."""
        if not self._ts_available:
            return False
        if sca_lang in self._languages:
            return True
        return self._try_load_language(sca_lang)

    def get_language(self, sca_lang: str):
        """Return the tree-sitter Language object for an SCA language."""
        if sca_lang in self._languages:
            return self._languages[sca_lang]
        if self._try_load_language(sca_lang):
            return self._languages[sca_lang]
        return None

    def get_parser(self, sca_lang: str):
        """Return a configured Parser for the given language, using the cache."""
        if sca_lang in self._parsers:
            return self._parsers[sca_lang]

        lang = self.get_language(sca_lang)
        if lang is None:
            return None

        import tree_sitter
        parser = tree_sitter.Parser(lang)
        self._parsers[sca_lang] = parser
        return parser

    def parse_file(self, filepath: str, sca_lang: str):
        """Parse a file and return its syntax tree."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            return None
        return self.parse_source(source.encode("utf-8"), sca_lang)

    def parse_source(self, source: bytes, sca_lang: str):
        """Parse source code (bytes) and return its syntax tree."""
        parser = self.get_parser(sca_lang)
        if parser is None:
            return None
        try:
            return parser.parse(source)
        except Exception as e:
            logger.warning("[tree-sitter] Erreur parsing %s : %s", sca_lang, e)
            return None

    def query(self, tree, sca_lang: str, pattern: str) -> List[dict]:
        """Run an S-expression query against a parsed tree.

        Returns a list of dicts with named captures. Each dict contains at
        least 'node' (the primary node).
        """
        lang = self.get_language(sca_lang)
        if lang is None:
            return []

        import tree_sitter
        try:
            query_obj = tree_sitter.Query(lang, pattern)
        except Exception as e:
            raise ValueError(f"Query S-expression invalide : {e}")

        cursor = tree_sitter.QueryCursor(query_obj)
        matches = cursor.matches(tree.root_node)
        results = []
        for _, captures in matches:
            result = {}
            for name, nodes in captures.items():
                if isinstance(nodes, list):
                    for node in nodes:
                        result[name] = node
                        if "node" not in result:
                            result["node"] = node
                else:
                    result[name] = nodes
                    if "node" not in result:
                        result["node"] = nodes
            if result:
                results.append(result)
        return results

    def get_node_text(self, node, source: bytes) -> str:
        """Return the source text corresponding to a node."""
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def get_node_line(self, node) -> int:
        """Return a node's line number (1-indexed)."""
        return node.start_point[0] + 1

    def walk_tree(self, node, node_type: str) -> list:
        """Walk the tree and return all nodes of the given type."""
        results = []
        if node.type == node_type:
            results.append(node)
        for child in node.children:
            results.extend(self.walk_tree(child, node_type))
        return results

    def _try_load_language(self, sca_lang: str) -> bool:
        """Try to load the tree-sitter grammar for a language."""
        if not self._ts_available:
            return False

        module_name = _GRAMMAR_MODULES.get(sca_lang)
        if module_name is None:
            return False

        try:
            import importlib
            import tree_sitter

            grammar_module = importlib.import_module(module_name)

            # tree-sitter >= 0.23: Language(grammar_module.language())
            # Special case: tree_sitter_php exposes language_php() instead of language()
            lang_func_name = _GRAMMAR_LANG_FUNC.get(sca_lang, "language")
            if hasattr(grammar_module, lang_func_name):
                lang_func = getattr(grammar_module, lang_func_name)()
                lang = tree_sitter.Language(lang_func)
            elif hasattr(grammar_module, "language"):
                lang_func = grammar_module.language()
                lang = tree_sitter.Language(lang_func)
            else:
                logger.warning("[tree-sitter] Module %s sans function language()", module_name)
                return False

            self._languages[sca_lang] = lang
            return True

        except ImportError:
            logger.info("[tree-sitter] Module %s non installé", module_name)
            return False
        except Exception as e:
            logger.warning("[tree-sitter] Erreur chargement %s : %s", module_name, e)
            return False
