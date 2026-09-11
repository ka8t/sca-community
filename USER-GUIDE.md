# User Guide

For the high-level pipeline, see [ARCHITECTURE.md](ARCHITECTURE.md). This
document goes deeper into the rule format and the public API for anyone
integrating the scanner or writing a new rule.

## Rule modes

- **Pattern** (`match ... end`) — a regex against a line, a file, or a
  block. No dataflow tracking. Used by every rule in this edition except
  the 10 Python taint rules.
- **Taint** (`source`/`sink`/`sanitizer` blocks) — tracks how a value
  flows from a source (e.g. `request.args.get(...)`) through the
  program to a sink (e.g. `cursor.execute(...)`), and whether it passes
  through a sanitizer on the way. Python only in this edition.
- **file_contains** — gates a rule on the presence/absence of a pattern
  anywhere in the file, cheaper than a full match when the rule only
  needs a yes/no signal.

## `.sca` format — full grammar

Reference grammar: `sca/dsl/parser.py`. Minimal schema, checked at load
time:

```sca
rule <id>                            # [a-z0-9_]+, must match the filename
  language  <python|java|javascript|csharp|php|html|dockerfile|yaml>
  category  <security|maintenance|ui|ux|arch|cicd>
  severity  <CRITICAL|HIGH|MEDIUM|LOW|INFO>
  confidence <0-100>                 # optional, default 100

  # ─── exactly one mode ↓ ───
  match … end                        # pattern mode
  source / sink / sanitizer / passthrough   # taint mode (>=1 source, >=1 sink)
  file_contains … end                # file_contains mode

  requires                           # optional gating
    has  <regex>
    not_has  <regex>
  end

  message  en: …  fr: …  end          # i18n required (English minimum)
  risk     en: …  end
  solution en: …  end
  benefit  en: …  end
  fix_before  …  end                 # vulnerable code example
  fix_after   …  end                 # fixed code example
  metadata
    cwe   CWE-N
  end
end
```

The file path constrains `language`/`category`:
`sca/rules/builtin/<lang>/<cat>/<id>.sca`. A mismatch means the rule is
silently skipped (with a warning) at load time.

## Naming & fixture conventions

| Element | Pattern | Constraint |
|---|---|---|
| `rule_id` | `[a-z][a-z0-9_]*` | unique across the whole rule set |
| Rule path | `sca/rules/builtin/<lang>/<cat>/<rule_id>.sca` | `<lang>`/`<cat>` must match the file's own declared values |
| Vulnerable fixture | `tests/fixtures/generic/vulnerable/<rule_id>.<ext>` | `<ext>` matches the language |
| Clean fixture | `tests/fixtures/generic/clean/<rule_id>_clean.<ext>` | same |

For fixtures that don't follow this convention, an explicit mapping in
`tests/registry.py` is required:

```python
VULNERABLE_FIXTURES = {
    "key": ("filename.ext", "target_path", "rule_key"),
}
```

Verification:

```bash
./run_audit.py . --rules-match       # rule <-> fixture coverage
./run_audit.py . --check-integrity   # duplicate hashes, orphan fixtures, pattern collisions
```

## Public API

To embed the scanner in another tool.

### Load a rule

```python
from pathlib import Path
from sca.rule_loader import _load_sca_rules

rule = _load_sca_rules(
    Path("sca/rules/builtin/python/security/taint_sqli.sca"),
    Path("sca/rules"),
    "json_builtin",
)[0]  # a list, since a .sca file can define more than one rule
```

### Run a rule against source code

```python
from sca.executors.dataflow_taint import run_taint_rule

findings = list(run_taint_rule(
    rule_json=rule,
    content=source_code,      # str
    filename="user_input.py", # str (informational only)
    language="python",        # this edition supports "python" only for taint rules
))
```

`run_taint_rule` is the taint engine's **only** public entry point. It
converts the DSL to internal `RuleSpecs`, applies `file_contains` gating,
and deduplicates findings within a single rule.

### `Finding` structure

```python
@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str             # CRITICAL|HIGH|MEDIUM|LOW|INFO
    line: int
    column: int
    sink_text: str             # sink's source text
    source_line: Optional[int]
    message: str
    cwe: Optional[str]         # e.g. "CWE-89"
    flow: Tuple[FlowStep, ...]  # FlowStep(line, kind, text), kind in {source, prop, sink}
    source_kind: str           # http|stdin|cli|env|network
```

### API stability

| Surface | Status |
|---|---|
| `sca/rules/builtin/<lang>/<cat>/<id>.sca` paths | stable |
| `.sca` grammar (DSL parser) | stable |
| `run_taint_rule`, `Finding`, `FlowStep` | stable |
| Anything prefixed `_` | private, may break |
| `sca/dataflow/` internals | private, refactorable |

## Adding a rule — worked example

Say you want a new Python pattern rule flagging `eval()` on anything
that isn't a string literal (a lightweight signal, not the full taint
`taint_codeinj` rule already shipped):

1. `sca/rules/builtin/python/security/eval_non_literal.sca`:
   ```sca
   rule eval_non_literal
     language python
     category security
     severity MEDIUM
     match
       pattern  eval\s*\(\s*(?!['"])
       scope    line
     end
     message  en: "eval() called with a non-literal argument" end
     risk     en: "Arbitrary code execution if the argument is influenced by user input." end
     solution en: "Avoid eval(); use ast.literal_eval() for data, or a dedicated parser." end
     benefit  en: "Removes a common code-injection vector." end
     metadata
       cwe CWE-95
     end
   end
   ```
2. Add the same 4 keys (`en`/`fr`/`es`/`de`) to
   `locales/report/*.json` under `rules.eval_non_literal`.
3. `tests/fixtures/generic/vulnerable/eval_non_literal.py` (a call
   matching the pattern) and
   `tests/fixtures/generic/clean/eval_non_literal_clean.py` (a call that
   doesn't, e.g. `eval("2+2")`).
4. A test in a new `tests/test_*.py` file, using the helpers and
   `audit_runner`/`temp_project` fixtures from `tests/conftest.py`:
   ```python
   from tests.conftest import use_vulnerable_fixture, get_findings_by_rule_key

   def test_eval_non_literal(temp_project, audit_runner):
       use_vulnerable_fixture(temp_project, "eval_non_literal.py", "src/service.py")
       audit_runner.run()
       assert get_findings_by_rule_key(audit_runner, "eval_non_literal")
   ```
