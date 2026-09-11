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

See [ARCHITECTURE.md](ARCHITECTURE.md#adding-a-rule) for the exact
steps. In short: a `.sca` file, a vulnerable + a clean fixture, a test,
and a `metadata` block with at least one CWE id. Every rule needs both
fixtures — a rule without a demonstrated false-positive-free clean case
won't be merged.

## Code style

- Code, comments, and docstrings: English.
- `snake_case` for variables/functions, `CamelCase` for classes,
  `UPPERCASE` for constants.
- No hardcoded values — configuration goes through `audit.config.json`.

## Tests

```bash
python -m pytest tests/ -v
```

Functional (end-to-end) tests live in `tests/test_functional.py`. A
change to rule-loading, report generation, or the CLI should come with a
functional test, not just a unit test.

## Pull requests

Keep the scope tight — one rule, one bug fix, one feature per PR. Include
the fixtures and tests in the same PR as the rule/fix itself, not as a
follow-up.
