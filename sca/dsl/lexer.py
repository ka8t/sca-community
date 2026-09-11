"""
Lexer for the .sca DSL — line-by-line tokenization.

Produces lines of tokens from the DSL source code.
Handles comments (#), quoted strings, key=value pairs
and raw words (regex, identifiers, numbers).

Tokenization strategy:
- Words are read up to the next whitespace (quotes do not stop a word)
- Strings ("...") are only recognized at the start of a token (after whitespace)
- On a tokenization error (unclosed quote), falls back to a whitespace split
- Each line's raw text is kept (raw_content) for direct extraction
- '#' is only treated as a comment at the start of a line or when preceded by
  whitespace (preserves `(#match?` inside tree-sitter S-expressions)
"""
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Tuple


class TokenType(Enum):
    """Token kinds produced by the .sca DSL lexer."""

    WORD = "word"
    STRING = "string"
    NUMBER = "number"
    KV = "kv"


@dataclass
class Token:
    """A single token produced by the lexer."""

    type: TokenType
    value: str
    line: int
    col: int = 0
    kv_key: str = ""
    kv_val: str = ""


@dataclass
class Line:
    """A tokenized line with its number, indentation and raw content."""

    number: int
    indent: int
    tokens: List[Token]
    raw_content: str = ""


class DSLSyntaxError(Exception):
    """Syntax error raised while parsing a .sca file."""

    def __init__(self, message: str, line: int = 0, col: int = 0,
                 filename: str = ""):
        """Build the error, prefixing the message with file:line:col when known."""
        self.dsl_line = line
        self.col = col
        self.dsl_filename = filename
        loc = f"{filename}:" if filename else ""
        loc += f"{line}" if line else ""
        if col:
            loc += f":{col}"
        super().__init__(f"{loc}: {message}" if loc else message)


# Pattern to identify key=value pairs (simple words around the =)
_KV_PATTERN = re.compile(r'^([a-z_][a-z0-9_]*)=(\S+)$')


class DSLLexer:
    """Lexer for the .sca DSL — tokenizes the source into lines of tokens."""

    def __init__(self, source: str, filename: str = "<string>"):
        """Store the source text and its filename for error reporting."""
        self.source = source
        self.filename = filename
        self.raw_lines = source.splitlines()

    def tokenize(self) -> List[Line]:
        """Tokenize the whole source and return the non-empty lines.

        If tokenization fails on a line (unclosed quote in a regex/AST
        pattern), falls back to a whitespace split for that line.

        fix_before/fix_after...end blocks hold arbitrary illustrative code
        (Python, YAML...), not DSL syntax: while inside one, '#' is real
        code content, not a DSL comment, so it must not go through
        _strip_comment like every other line does.
        """
        result = []
        in_plaintext = False
        for i, raw in enumerate(self.raw_lines, 1):
            if in_plaintext:
                stripped = raw.rstrip()
                content = stripped.lstrip()
                if not content:
                    continue
                if content == "end":
                    in_plaintext = False
                    result.append(Line(
                        number=i, indent=len(stripped) - len(content),
                        tokens=[Token(TokenType.WORD, "end", i)],
                        raw_content="end",
                    ))
                    continue
                indent = len(stripped) - len(content)
                first_word = content.split(None, 1)[0]
                result.append(Line(
                    number=i, indent=indent,
                    tokens=[Token(TokenType.WORD, first_word, i)],
                    raw_content=content,
                ))
                continue

            text = _strip_comment(raw)
            stripped = text.rstrip()
            content = stripped.lstrip()
            if not content:
                continue

            indent = len(stripped) - len(content)
            try:
                tokens = _tokenize_content(content, i)
            except DSLSyntaxError:
                # Fallback: split by whitespace (lines with quotes inside
                # regexes or tree-sitter S-expressions)
                tokens = [
                    Token(TokenType.WORD, w, i)
                    for w in content.split()
                ]
            if tokens:
                result.append(Line(
                    number=i, indent=indent,
                    tokens=tokens, raw_content=content,
                ))
                if len(tokens) == 1 and tokens[0].value in ("fix_before", "fix_after"):
                    in_plaintext = True

        return result

    def get_raw_line(self, line_num: int) -> str:
        """Return the raw source line (1-indexed)."""
        if 1 <= line_num <= len(self.raw_lines):
            return self.raw_lines[line_num - 1]
        return ""


def _strip_comment(line: str) -> str:
    """Strip a trailing '#' comment while respecting strings and S-expressions.

    '#' is only treated as a comment when it is at the start of the line
    or preceded by whitespace (not inside `(#match?` tree-sitter S-expressions).
    """
    in_string = None
    escape = False
    for i, ch in enumerate(line):
        if escape:
            escape = False
            continue
        if ch == '\\':
            escape = True
            continue
        if ch in ('"', "'") and in_string is None:
            in_string = ch
        elif ch == in_string:
            in_string = None
        elif ch == '#' and in_string is None:
            if i == 0 or line[i - 1].isspace():
                return line[:i]
    return line


def _tokenize_content(text: str, line_num: int) -> List[Token]:
    """Tokenize a line's content (comment and indentation already stripped)."""
    tokens = []
    pos = 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        if text[pos] in ('"', "'"):
            tok, pos = _read_string(text, pos, line_num)
            tokens.append(tok)
        else:
            tok, pos = _read_word(text, pos, line_num)
            tokens.append(tok)
    return tokens


def _read_string(text: str, pos: int, line_num: int) -> Tuple[Token, int]:
    """Read a quoted string, handling \\\\ and \\quote escape sequences."""
    quote = text[pos]
    start = pos
    pos += 1
    value = []
    while pos < len(text):
        ch = text[pos]
        if ch == '\\' and pos + 1 < len(text):
            next_ch = text[pos + 1]
            if next_ch in (quote, '\\'):
                value.append(next_ch)
                pos += 2
                continue
            # Keep other escape sequences as-is (\\s, \\d, etc.)
            value.append(ch)
            value.append(next_ch)
            pos += 2
            continue
        if ch == quote:
            pos += 1
            return Token(TokenType.STRING, ''.join(value), line_num, start), pos
        value.append(ch)
        pos += 1
    raise DSLSyntaxError("Chaîne non fermée", line_num, start)


def _read_word(text: str, pos: int, line_num: int) -> Tuple[Token, int]:
    """Read a word (a non-whitespace sequence).

    Quotes are NOT delimiters — a word like ["'] or \\s*=\\s*["'] is read
    whole. Only whitespace separates tokens.
    """
    start = pos
    while pos < len(text) and not text[pos].isspace():
        pos += 1
    word = text[start:pos]

    # key=value pair?
    m = _KV_PATTERN.match(word)
    if m:
        return Token(TokenType.KV, word, line_num, start,
                     kv_key=m.group(1), kv_val=m.group(2)), pos

    # Number?
    if word.isdigit():
        return Token(TokenType.NUMBER, word, line_num, start), pos

    return Token(TokenType.WORD, word, line_num, start), pos
