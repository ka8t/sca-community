"""
Parser for the .sca DSL — builds the AST tree from tokens.

Recursive-descent, line-oriented parser. Each line starts with a
keyword that determines the instruction type. Blocks are delimited
by opening keywords and the 'end' keyword.

For lines containing raw content (regex, tree-sitter S-expressions),
the parser uses raw_content instead of tokens to avoid tokenization
issues with quotes inside patterns.
"""
import re
from typing import Dict, List, Tuple

from sca.dsl.lexer import DSLSyntaxError, Line, Token, TokenType

# Import the KV pattern for extraction from raw text
from sca.dsl.lexer import _KV_PATTERN

from sca.dsl.nodes import (
    FileConditionBlock,
    I18nBlock,
    LicenseBlock,
    MatchAstBlock,
    MatchFileContainsBlock,
    MatchRegexBlock,
    MetadataBlock,
    RuleNode,
    SanitizerSpec,
    SinkSpec,
    SourceSpec,
)

# Keywords that open an i18n block
_I18N_KEYWORDS = {"message", "risk", "solution", "benefit"}

# Keywords that open a raw text block (code, no i18n)
_PLAINTEXT_KEYWORDS = {"fix_before", "fix_after"}


class DSLParser:
    """Parser for the .sca DSL — produces a list of RuleNode."""

    def __init__(self, lines: List[Line], filename: str = "<string>"):
        """Store the tokenized lines and filename to parse from."""
        self.lines = lines
        self.filename = filename
        self.pos = 0

    def parse(self) -> List[RuleNode]:
        """Parse the line stream and return the list of rules."""
        rules = []
        while self.pos < len(self.lines):
            kw = self._keyword()
            if kw == "rule":
                rules.append(self._parse_rule())
            else:
                self._error(f"Mot-clé 'rule' attendu, trouvé : '{kw}'")
        return rules

    # --- Utility methods ---

    def _keyword(self) -> str:
        """Return the first word of the current line."""
        return self.lines[self.pos].tokens[0].value

    def _line(self) -> Line:
        """Return the current line."""
        return self.lines[self.pos]

    def _advance(self):
        """Move to the next line."""
        self.pos += 1

    def _at_end(self) -> bool:
        """Check whether the end of the line stream has been reached."""
        return self.pos >= len(self.lines)

    def _error(self, msg: str):
        """Raise a syntax error at the current position."""
        line = self.lines[self.pos] if self.pos < len(self.lines) else None
        num = line.number if line else 0
        raise DSLSyntaxError(msg, num, filename=self.filename)

    def _parse_value(self) -> str:
        """Read all text after the keyword (via tokens) and advance.

        Used for structured values (language, category, severity,
        scope, i18n text). For raw content (regex, patterns),
        use _parse_raw_after_keyword() instead.
        """
        line = self._line()
        tokens = line.tokens[1:]
        if not tokens:
            self._error(f"Valeur manquante après '{line.tokens[0].value}'")
        result = ' '.join(t.value for t in tokens)
        self._advance()
        return result

    def _parse_raw_after_keyword(self) -> str:
        """Extract the raw text after the keyword from raw_content.

        Used for regexes, AST patterns, source/sink — preserves
        quotes, backslashes and special characters as-is.
        """
        line = self._line()
        raw = line.raw_content
        kw = line.tokens[0].value
        # Find the keyword in the raw content and extract the rest
        idx = raw.find(kw)
        if idx >= 0:
            rest = raw[idx + len(kw):].strip()
        else:
            rest = raw.strip()
        self._advance()
        if not rest:
            raise DSLSyntaxError(
                f"Valeur manquante après '{kw}'",
                line.number, filename=self.filename,
            )
        return rest

    def _parse_raw_with_kvs(self) -> Tuple[str, Dict[str, str]]:
        """Extract raw text plus key=value pairs from raw_content.

        Used for source and sink: the text is the regex pattern,
        the key=value pairs are options (kind=http, arg_index=0).
        """
        line = self._line()
        raw = line.raw_content
        kw = line.tokens[0].value
        idx = raw.find(kw)
        rest = raw[idx + len(kw):].strip() if idx >= 0 else raw.strip()

        # Split into words and identify key=value pairs
        parts = rest.split()
        kvs = {}
        text_parts = []
        for part in parts:
            m = _KV_PATTERN.match(part)
            if m:
                kvs[m.group(1)] = m.group(2)
            else:
                text_parts.append(part)

        self._advance()
        return ' '.join(text_parts), kvs

    # --- Rule parsing ---

    def _parse_rule(self) -> RuleNode:
        """Parse one complete rule...end block."""
        line = self._line()
        tokens = line.tokens
        if len(tokens) < 2:
            self._error("Identifiant de règle manquant après 'rule'")
        rule_id = tokens[1].value
        node = RuleNode(id=rule_id, line_number=line.number)
        self._advance()

        while not self._at_end():
            kw = self._keyword()

            if kw == "end":
                self._advance()
                return node
            elif kw == "language":
                node.language = self._parse_value()
            elif kw == "category":
                node.category = self._parse_value()
            elif kw == "severity":
                node.severity = self._parse_value()
            elif kw == "confidence":
                try:
                    node.confidence = int(self._parse_value())
                except ValueError:
                    self._error("'confidence' doit être un entier")
            elif kw == "mode":
                node.mode = self._parse_value()
            elif kw == "match":
                node.match_blocks.append(self._parse_match_block())
            elif kw == "source":
                node.sources.append(self._parse_source())
            elif kw == "sink":
                node.sinks.append(self._parse_sink())
            elif kw == "sanitizer":
                node.sanitizers.append(self._parse_sanitizer())
            elif kw == "passthrough":
                node.passthroughs.append(self._parse_passthrough())
            elif kw in _I18N_KEYWORDS:
                block = self._parse_i18n_block()
                setattr(node, kw, block)
            elif kw in _PLAINTEXT_KEYWORDS:
                setattr(node, kw, self._parse_plaintext_block())
            elif kw == "metadata":
                node.metadata = self._parse_metadata_block()
            elif kw == "requires":
                # Distinguish file requires (has/not_has) from license requires
                # (min_tier/features) by looking at the block's first keyword.
                req = self._parse_requires_block_unified(node)
                # req is either a LicenseBlock or a FileConditionBlock
                if isinstance(req, LicenseBlock):
                    node.license = req
                elif isinstance(req, FileConditionBlock):
                    node.file_conditions.append(req)
            elif kw == "hook":
                node.hook = self._parse_value()
            else:
                self._error(f"Mot-clé inconnu dans une règle : '{kw}'")

        self._error("Bloc 'rule' non fermé (manque 'end')")

    # --- Match block parsing ---

    def _parse_match_block(self):
        """Parse a match block.

        Supported formats:
          - `match regex` → MatchRegexBlock (backward compat)
          - `match ast` → MatchAstBlock (backward compat)
          - `match file_contains` → MatchFileContainsBlock (backward compat)
          - `match` (no suffix) → MatchRegexBlock (new unified format)
        """
        line = self._line()
        tokens = line.tokens
        ln = line.number

        if len(tokens) >= 2:
            match_type = tokens[1].value
            self._advance()
            if match_type == "regex":
                return self._parse_match_regex(ln)
            elif match_type == "ast":
                return self._parse_match_ast(ln)
            elif match_type == "file_contains":
                return self._parse_match_file_contains(ln)
            else:
                raise DSLSyntaxError(
                    f"Type de match inconnu : '{match_type}'",
                    ln, filename=self.filename,
                )
        else:
            # `match` with no suffix → regex by default
            self._advance()
            return self._parse_match_regex(ln)

    def _parse_match_regex(self, start_line: int) -> MatchRegexBlock:
        """Parse a match...end block.

        Supports two pattern types:
          - `pattern`: regex (for advanced users)
          - `text`: plain text, auto-escaped (* = wildcard)
        And for conditions:
          - `with` / `with-text`: positive condition
          - `pattern-not` / `text-not`: negative condition
        """
        block = MatchRegexBlock(line_number=start_line)
        while not self._at_end():
            kw = self._keyword()
            if kw == "end":
                self._advance()
                return block
            elif kw == "pattern":
                block.pattern = self._parse_raw_after_keyword()
                block.is_text = False
            elif kw == "text":
                block.pattern = self._parse_raw_after_keyword()
                block.is_text = True
            elif kw == "scope":
                block.scope = self._parse_value()
            elif kw == "with":
                block.with_pattern = self._parse_raw_after_keyword()
                block.with_is_text = False
            elif kw == "with-text":
                block.with_pattern = self._parse_raw_after_keyword()
                block.with_is_text = True
            elif kw == "pattern-not":
                block.pattern_not = self._parse_raw_after_keyword()
                block.pattern_not_is_text = False
            elif kw == "text-not":
                block.pattern_not = self._parse_raw_after_keyword()
                block.pattern_not_is_text = True
            elif kw == "pattern-inside":
                block.pattern_inside = self._parse_raw_after_keyword()
            elif kw == "pattern-not-inside":
                block.pattern_not_inside = self._parse_raw_after_keyword()
            else:
                self._error(f"Mot-cle inconnu dans match : '{kw}'")
        self._error("Bloc 'match' non ferme (manque 'end')")

    def _parse_match_ast(self, start_line: int) -> MatchAstBlock:
        """Parse a match ast...end block (supports multi-line patterns).

        Uses raw_content to preserve quotes inside tree-sitter
        S-expressions (e.g. #match? @name "regex").
        """
        block = MatchAstBlock(line_number=start_line)
        pattern_parts = []
        in_pattern = False

        while not self._at_end():
            line = self._line()
            kw = line.tokens[0].value

            if kw == "end" and not in_pattern:
                if pattern_parts:
                    block.pattern = ' '.join(pattern_parts).strip()
                self._advance()
                return block

            if kw == "end" and in_pattern:
                # Check whether the parentheses are balanced
                joined = ' '.join(pattern_parts)
                if joined.count('(') <= joined.count(')'):
                    block.pattern = joined.strip()
                    self._advance()
                    return block
                # Unlikely: 'end' is actually part of the pattern
                pattern_parts.append(line.raw_content.strip())
                self._advance()
                continue

            if kw == "pattern" and not in_pattern:
                # Extract the raw text after 'pattern'
                raw = line.raw_content
                idx = raw.find('pattern')
                rest = raw[idx + len('pattern'):].strip() if idx >= 0 else ""
                if rest:
                    pattern_parts.append(rest)
                in_pattern = True
                self._advance()
                # Check whether the pattern is complete on a single line
                joined = ' '.join(pattern_parts)
                if joined and joined.count('(') <= joined.count(')'):
                    block.pattern = joined.strip()
                    in_pattern = False
            elif in_pattern:
                # Continuation of the multi-line pattern (raw text)
                pattern_parts.append(line.raw_content.strip())
                self._advance()
                joined = ' '.join(pattern_parts)
                if joined.count('(') <= joined.count(')'):
                    block.pattern = joined.strip()
                    in_pattern = False
            else:
                self._error(f"Mot-clé 'pattern' attendu dans match ast, "
                            f"trouvé : '{kw}'")

        self._error("Bloc 'match ast' non fermé (manque 'end')")

    def _parse_match_file_contains(self, start_line: int) -> MatchFileContainsBlock:
        """Parse a match file_contains...end block."""
        block = MatchFileContainsBlock(line_number=start_line)
        while not self._at_end():
            kw = self._keyword()
            if kw == "end":
                self._advance()
                return block
            elif kw == "has":
                block.has_patterns.append(self._parse_raw_after_keyword())
            elif kw == "not_has":
                block.not_has_patterns.append(self._parse_raw_after_keyword())
            elif kw == "scope":
                block.scope = self._parse_value()
            else:
                self._error(f"Mot-clé inconnu dans match file_contains : '{kw}'")
        self._error("Bloc 'match file_contains' non fermé (manque 'end')")

    # --- Taint element parsing ---

    def _parse_source(self) -> SourceSpec:
        """Parse a source line (pattern + key=value)."""
        ln = self._line().number
        text, kvs = self._parse_raw_with_kvs()
        return SourceSpec(
            pattern=text,
            kind=kvs.get("kind", "http"),
            line_number=ln,
        )

    def _parse_sink(self) -> SinkSpec:
        """Parse a sink line (pattern + key=value)."""
        ln = self._line().number
        text, kvs = self._parse_raw_with_kvs()
        try:
            arg_index = int(kvs.get("arg_index", "0"))
        except ValueError:
            arg_index = 0
        return SinkSpec(
            pattern=text,
            arg_index=arg_index,
            line_number=ln,
        )

    def _parse_sanitizer(self) -> SanitizerSpec:
        """Parse a sanitizer line."""
        ln = self._line().number
        text = self._parse_raw_after_keyword()
        return SanitizerSpec(pattern=text, line_number=ln)

    def _parse_passthrough(self):
        """Parse a passthrough line (a function that preserves taint)."""
        from sca.dsl.nodes import PassthroughSpec
        ln = self._line().number
        text = self._parse_raw_after_keyword()
        return PassthroughSpec(pattern=text, line_number=ln)

    # --- Structured block parsing ---

    def _parse_i18n_block(self) -> I18nBlock:
        """Parse an i18n block (message, risk, solution, benefit)...end."""
        line = self._line()
        ln = line.number
        self._advance()
        block = I18nBlock(line_number=ln)

        while not self._at_end():
            kw = self._keyword()
            if kw == "end":
                self._advance()
                return block

            # The first token is the language code, the rest is the text
            tokens = self._line().tokens
            lang_code = tokens[0].value.rstrip(":")
            if len(tokens) < 2:
                self._error(f"Texte manquant après le code langue '{lang_code}'")
            text_tokens = tokens[1:]
            text = ' '.join(t.value for t in text_tokens)
            block.texts[lang_code] = text
            self._advance()

        self._error("Bloc i18n non fermé (manque 'end')")

    def _parse_plaintext_block(self) -> str:
        """Parse a raw text block (fix_before, fix_after)...end.

        Uses raw_content (like patterns/AST blocks) instead of rebuilding the
        line from tokens: token values drop quote characters around string
        literals and collapse inter-token spacing, which corrupted any
        example containing a quoted string.
        Leading whitespace is reconstructed from Line.indent (the lexer
        strips it out of raw_content itself, tracking it separately): some
        rules key off indentation depth, so losing it would make their own
        fix_before/fix_after example inconsistent with the rule again, just
        for a different reason. Only the indentation *relative* to the
        block's own least-indented line is kept (dedented): the absolute
        indent also includes the .sca source's own structural indent for
        being inside `fix_before ... end`, which a `^`-anchored pattern
        would otherwise see as leading whitespace that was never really
        part of the illustrated code.
        """
        self._advance()
        raw_lines = []
        while not self._at_end():
            kw = self._keyword()
            if kw == "end":
                self._advance()
                if not raw_lines:
                    return ""
                base = min(indent for indent, _ in raw_lines)
                return "\n".join(" " * (indent - base) + content for indent, content in raw_lines)
            line = self._line()
            raw_lines.append((line.indent, line.raw_content))
            self._advance()
        self._error("Bloc texte non fermé (manque 'end')")

    def _parse_metadata_block(self) -> MetadataBlock:
        """Parse a metadata...end block."""
        line = self._line()
        ln = line.number
        self._advance()
        block = MetadataBlock(line_number=ln)

        while not self._at_end():
            kw = self._keyword()
            if kw == "end":
                self._advance()
                return block
            elif kw == "cwe":
                # Multiple CWEs are possible: several tokens on the same
                # line OR repeated `cwe X` lines (cumulative extend).
                tokens = self._line().tokens[1:]
                block.cwe.extend([t.value for t in tokens])
                self._advance()
            elif kw == "cve":
                tokens = self._line().tokens[1:]
                block.cve.extend([t.value for t in tokens])
                self._advance()
            elif kw == "owasp":
                block.owasp = self._parse_value()
            elif kw == "iso27001":
                tokens = self._line().tokens[1:]
                block.iso27001 = [t.value for t in tokens]
                self._advance()
            elif kw == "asvs":
                tokens = self._line().tokens[1:]
                block.asvs = [t.value for t in tokens]
                self._advance()
            elif kw == "wcag":
                tokens = self._line().tokens[1:]
                block.wcag.extend([t.value for t in tokens])
                self._advance()
            elif kw == "generated_by":
                block.generated_by = self._parse_value()
            elif kw == "generated_at":
                block.generated_at = self._parse_value()
            elif kw == "generator_version":
                block.generator_version = self._parse_value()
            elif kw == "manifest_hash":
                block.manifest_hash = self._parse_value()
            elif kw == "org_id":
                block.org_id = self._parse_value()
            elif kw == "signature":
                block.signature = self._parse_value()
            else:
                self._error(f"Clé metadata inconnue : '{kw}'")

        self._error("Bloc 'metadata' non fermé (manque 'end')")

    def _parse_requires_block(self) -> LicenseBlock:
        """Parse a requires license...end block (backward compat)."""
        line = self._line()
        ln = line.number
        self._advance()
        block = LicenseBlock(line_number=ln)

        while not self._at_end():
            kw = self._keyword()
            if kw == "end":
                self._advance()
                return block
            elif kw == "min_tier":
                block.min_tier = self._parse_value()
            elif kw == "features":
                tokens = self._line().tokens[1:]
                block.features = [t.value for t in tokens]
                self._advance()
            elif kw == "demo_fallback":
                block.demo_fallback = self._parse_value().strip().lower() == "true"
            else:
                self._error(f"Clé requires inconnue : '{kw}'")

        self._error("Bloc 'requires' non fermé (manque 'end')")

    def _parse_requires_block_unified(self, node: RuleNode):
        """Parse a requires block — auto-detects license vs file kind.

        License: contains min_tier or features.
        File: contains has or not_has.
        """
        line = self._line()
        ln = line.number
        # Peek: look at the block's keywords to determine its kind
        saved_pos = self.pos
        self._advance()

        # Scan the block's keywords without consuming them
        keys_found = set()
        scan_pos = self.pos
        while scan_pos < len(self.lines):
            scan_line = self.lines[scan_pos]
            if scan_line.tokens and scan_line.tokens[0].value == "end":
                break
            if scan_line.tokens:
                keys_found.add(scan_line.tokens[0].value)
            scan_pos += 1

        # Restore the position and parse according to the detected kind
        self.pos = saved_pos

        file_keys = {"has", "not_has", "scope", "min_lines", "path_contains", "not_path_has_file"}
        license_keys = {"min_tier", "features", "demo_fallback"}

        if keys_found & file_keys:
            return self._parse_file_condition_block()
        elif keys_found & license_keys:
            return self._parse_requires_block()
        else:
            # Empty or unknown block → treat as license (backward compat)
            return self._parse_requires_block()

    def _parse_file_condition_block(self) -> FileConditionBlock:
        """Parse a requires file (has/not_has)...end block."""
        line = self._line()
        ln = line.number
        self._advance()
        block = FileConditionBlock(line_number=ln)

        while not self._at_end():
            line = self._line()
            kw = self._keyword()

            if kw == "end":
                self._advance()
                return block
            elif kw == "has":
                raw = line.raw_content.strip()
                pattern = raw.split(None, 1)[1] if len(raw.split(None, 1)) > 1 else ""
                block.has_patterns.append(pattern)
                self._advance()
            elif kw == "not_has":
                raw = line.raw_content.strip()
                pattern = raw.split(None, 1)[1] if len(raw.split(None, 1)) > 1 else ""
                block.not_has_patterns.append(pattern)
                self._advance()
            elif kw == "scope":
                block.scope = self._parse_value()
            elif kw == "min_lines":
                raw = line.raw_content.strip()
                val = raw.split(None, 1)[1] if len(raw.split(None, 1)) > 1 else "0"
                block.min_lines = int(val)
                self._advance()
            elif kw == "path_contains":
                raw = line.raw_content.strip()
                pattern = raw.split(None, 1)[1] if len(raw.split(None, 1)) > 1 else ""
                block.path_contains.append(pattern)
                self._advance()
            elif kw == "not_path_has_file":
                raw = line.raw_content.strip()
                pattern = raw.split(None, 1)[1] if len(raw.split(None, 1)) > 1 else ""
                block.not_path_has_file.append(pattern)
                self._advance()
            else:
                self._error(f"Clé requires fichier inconnue : '{kw}'")

        self._error("Bloc 'requires' non fermé (manque 'end')")
