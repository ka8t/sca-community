# Roadmap

This file describes what's **deliberately not** in this repository, and
why — not a promise of future features.

## Why a Community Edition

SCA Community Edition exists to let anyone try the real engine — not a
watered-down demo — on their own Python codebase, for free, forever (see
the [license](LICENSE)). It's also how we show our work: the dataflow
engine here is the same architecture (CFG, worklist fixed-point,
function summaries, persistent call graph) used in the commercial
product, just scoped to Python.

## What's commercial-only, and why

- **Multi-language taint engine** (Java, C#, PHP, JavaScript source→sink
  tracking, framework-aware detection such as Spring). Building and
  calibrating this took a large, sustained engineering effort — it's the
  main differentiator of the paid product.
- **~650 additional rules** beyond the 52 shipped here — broader
  coverage across CWE categories, CI/CD supply-chain attacks, and
  framework-specific patterns.
- **Compliance mapping** (ISO 27001, ASVS, NIST CSF) and the historical
  comparison / SBOM / SARIF export pipeline used in enterprise
  workflows.

None of this is artificially disabled in the code you're reading — it
simply isn't present. There's no license check to work around.

## What could be added to this edition over time

Not committed, but plausible if there's interest:

- A few more pattern-only rules per language (the current 52 are a
  deliberately small, representative slice).
- Community-contributed rules, reviewed against the same fixture
  convention as the builtin ones (a vulnerable + a clean example, a
  CWE mapping).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
