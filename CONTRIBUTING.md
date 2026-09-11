# Contributing

## Who maintains this

SCA Community Edition is maintained by CodeFixture. For licensing
questions, see [LICENSE](LICENSE) or contact contact@codefixture.com.

## Reporting a bug

Open an issue with: the command you ran, the language/rule involved, and
a minimal code snippet that reproduces the finding (or the missed
detection). If the snippet is from a private codebase, reduce it to the
smallest synthetic example that still reproduces the issue — don't paste
proprietary code into a public issue.

## Adding a rule

See [USER-GUIDE.md](USER-GUIDE.md#adding-a-rule--worked-example) for
the exact steps, worked through end to end. In short: a `.sca` file, a
vulnerable + a clean fixture, a test, and a `metadata` block with at
least one CWE id. Every rule needs both fixtures — a rule without a
demonstrated false-positive-free clean case won't be merged.

## Code style

- Code, comments, and docstrings: English.
- `snake_case` for variables/functions, `CamelCase` for classes,
  `UPPERCASE` for constants.
- No hardcoded values — configuration goes through `audit.config.json`.

## Tests

```bash
python -m pytest tests/ -v
```

`tests/conftest.py` provides the fixture-loading helpers
(`use_vulnerable_fixture`, `get_findings_by_rule_key`, per-language
`AuditRunner` fixtures) and `tests/registry.py` the fixture ↔ rule
mapping — see
[USER-GUIDE.md](USER-GUIDE.md#adding-a-rule--worked-example) for a
worked example. Add a `tests/test_*.py` file alongside any new rule.

## Pull requests

Keep the scope tight — one rule, one bug fix, one feature per PR. Include
the fixtures and tests in the same PR as the rule/fix itself, not as a
follow-up.
