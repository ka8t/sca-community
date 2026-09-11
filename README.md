# SCA Community Edition

A multi-language static code scanner combining a **taint engine**
(source → sink dataflow tracking) with pattern-based rules for
structural anti-patterns.

**Languages**: Python (full taint engine), Java, C#, PHP, JavaScript
(pattern rules), YAML/GitHub Actions, Dockerfile, HTML.

No external dependencies beyond the Python standard library. Runs
entirely offline — your code never leaves your machine.

---

## About

SCA Community Edition is maintained by [CodeFixture](https://codefixture.com),
the team behind **StaticCodeAudit**, a commercial SAST tool. This
repository is the free, source-available edition of that engine — see
[Community Edition vs. full engine](#community-edition-vs-full-engine)
below for exactly what's included and what isn't, and why.

Licensed under the [Business Source License 1.1](LICENSE) — free for any
use, including production, except offering it as a competing hosted
service. Converts to Apache 2.0 four years after each release.

## Quickstart

```bash
git clone https://github.com/ka8t/sca-community.git
cd sca-community

# Try it on the included demo app (a small, intentionally vulnerable Flask app)
./run_audit.py examples/demo-app

# Or on your own project
./run_audit.py /path/to/your/project --init
./run_audit.py /path/to/your/project
```

The HTML report and JSON data are written to
`<project>/docs/audit-reports/` by default.

## Community Edition vs. full engine

This repository ships **52 rules** (10 Python taint rules + 42
pattern-based rules across Java/C#/PHP/JavaScript/YAML/Dockerfile/HTML) —
a deliberately small, representative slice. The commercial engine adds:

- A **multi-language taint engine** (Java, C#, PHP, JavaScript
  source→sink tracking, framework-aware detection). This edition's
  taint engine is Python-only; other languages get pattern rules only
  (no dataflow tracking — SQLi/XSS-style rules that need it aren't
  included for those languages, since they wouldn't work reliably
  without the tracking).
- **~650 additional rules** across all languages and categories
  (security, CI/CD supply-chain, architecture, accessibility).
- **Full** compliance mapping (ISO 27001, ASVS, NIST CSF) across all
  ~650 rules. This edition ships compliance data only for the subset of
  its 52 rules that have a mapped control (`sca/*_mapping.json`) —
  partial by construction, not a bug.

There is no license or feature-gating system in this edition (see
[ARCHITECTURE.md](ARCHITECTURE.md)) — SARIF/SBOM export, the HTML
report, and historical comparison against a previous run all work
exactly as in the commercial product. The only differences are the
rule catalog and language coverage above.

**Measured results, two different things — read the attribution
carefully:**

- The **full commercial engine** detects 17/18 real vulnerabilities in a
  WebGoat-based corpus (94.4%), against 9/18 (50%) for Semgrep on the
  same corpus, and reaches F1 98.8% on OWASP BenchmarkJava (2,740 cases).
  *This reflects the paid product, not what ships in this repository.*
- **This repository's Python taint engine** reaches **F1 macro 0.938**
  on OWASP BenchmarkPython (1,230 cases, averaged across the 10
  categories the 10 included taint rules cover), using only the rules
  shipped here — reproduce it yourself:
  ```bash
  python scripts/eval_owasp_benchmark_python.py --benchmark /path/to/BenchmarkPython
  ```

## Adding a rule

See [ARCHITECTURE.md](ARCHITECTURE.md#adding-a-rule) and
[USER-GUIDE.md](USER-GUIDE.md#adding-a-rule--worked-example).

## Known limitations (read before relying on this for security review)

- Java, C#, PHP, and JavaScript rules here are pattern-only — no
  dataflow tracking. A SQLi/XSS pattern that depends on tracing a
  variable across lines will not be caught for these languages in this
  edition.
- The dataflow architecture itself (CFG construction, the worklist
  fixed-point algorithm, function summaries, the persistent call graph)
  is fully readable in this repository — what's not included is the
  ~650 additional rules and the multi-language engine built on the same
  architecture.
- This tool is an aid, not a substitute for professional security
  review or penetration testing.

## CI/CD

```yaml
# .github/workflows/audit.yml
- run: ./run_audit.py . --sarif --fail-on-high
- uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: docs/audit-reports/*.sarif
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — pipeline, taint engine internals.
- [USER-GUIDE.md](USER-GUIDE.md) — `.sca` rule format, public API.
- [ROADMAP.md](ROADMAP.md) — what's commercial-only, and why.
- [CONTRIBUTING.md](CONTRIBUTING.md) — reporting bugs, adding rules.

## License

[Business Source License 1.1](LICENSE) — see the file for the exact
terms (production use is free for your own purposes; the one
restriction is offering this as a competing hosted service).
