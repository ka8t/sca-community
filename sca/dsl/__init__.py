"""
DSL package for the .sca format — parses, compiles and validates declarative rules.

Main entry points: parse_sca_file() and compile_sca_to_json().
The .sca DSL is a declarative format that compiles to the internal JSON
format consumed by rule_loader.py and rule_engine.py.
"""
from sca.dsl.compiler import compile_to_json
from sca.dsl.lexer import DSLSyntaxError
from sca.dsl.nodes import RuleNode
from sca.dsl.validator import validate_rule


def parse_sca_file(source: str, filename: str = "<string>"):
    """Parse a .sca file and return the list of RuleNode.

    Args:
        source: Contents of the .sca file.
        filename: File name (used in error messages).

    Returns:
        List of RuleNode (one per rule...end block).
    """
    from sca.dsl.lexer import DSLLexer
    from sca.dsl.parser import DSLParser

    lexer = DSLLexer(source, filename)
    lines = lexer.tokenize()
    if not lines:
        return []
    parser = DSLParser(lines, filename)
    return parser.parse()


def compile_sca_to_json(source: str, filename: str = "<string>"):
    """Parse, validate and compile a .sca file into a list of JSON dicts.

    Args:
        source: Contents of the .sca file.
        filename: File name (used in error messages).

    Returns:
        List of JSON dicts compatible with rule_loader.py.

    Raises:
        DSLSyntaxError: If parsing fails or validation detects an error.
    """
    rules = parse_sca_file(source, filename)
    results = []
    for rule in rules:
        errors = validate_rule(rule)
        if errors:
            raise DSLSyntaxError(
                f"Règle '{rule.id}' invalide : {'; '.join(errors)}",
                rule.line_number, filename=filename,
            )
        results.append(compile_to_json(rule))
    return results
