#!/usr/bin/env python3
"""Generate RULES.md — a catalog of every rule shipped in this edition.

Reads the .sca source files directly (not a cache, not the encrypted
builtin blob used by the commercial binary — this edition ships plain
.sca files only), so the catalog can never drift from what's actually
in sca/rules/builtin/.

Regenerate after adding, removing, or editing a rule:
    python3 scripts/generate_rules_catalog.py
"""
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sca.rule_loader import _load_sca_rules  # noqa: E402

RULES_DIR = ROOT / "sca" / "rules" / "builtin"


def load_all_rules() -> list[dict]:
    rules = []
    for sca_file in sorted(RULES_DIR.rglob("*.sca")):
        rules.extend(_load_sca_rules(sca_file, ROOT / "sca" / "rules", "json_builtin"))
    return rules


def _description(rule: dict) -> str:
    """Prefer risk (why it matters) over message (short label) — falls
    back to empty if a rule carries neither (message is optional, see
    USER-GUIDE.md)."""
    for block_name in ("risk", "message"):
        block = rule.get(block_name) or {}
        text = block.get("en")
        if text:
            return text.strip().replace("|", "\\|")
    return "—"


def _standards(rule: dict) -> str:
    meta = rule.get("metadata") or {}
    cwe = meta.get("cwe") or []
    wcag = meta.get("wcag") or []
    tags = list(cwe) + list(wcag)
    return ", ".join(tags) if tags else "—"


def main() -> int:
    rules = load_all_rules()
    by_category: dict[str, list[dict]] = defaultdict(list)
    for r in rules:
        by_category[r.get("category", "?")].append(r)

    lines = [
        "# Rule catalog",
        "",
        f"{len(rules)} rules across {len(by_category)} categories — auto-generated "
        "from the `.sca` files in `sca/rules/builtin/`. **Do not edit by hand**, "
        "regenerate with:",
        "",
        "```bash",
        "python3 scripts/generate_rules_catalog.py",
        "```",
        "",
    ]

    for category in sorted(by_category):
        cat_rules = sorted(by_category[category], key=lambda r: r["id"])
        lines.append(f"## {category} ({len(cat_rules)})")
        lines.append("")
        lines.append("| Rule | Language | Severity | CWE / WCAG | Description |")
        lines.append("|---|---|---|---|---|")
        for r in cat_rules:
            lines.append(
                f"| `{r['id']}` | {r.get('language', '?')} | {r.get('severity', '?')} "
                f"| {_standards(r)} | {_description(r)} |"
            )
        lines.append("")

    out_path = ROOT / "RULES.md"
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out_path} ({len(rules)} rules, {len(by_category)} categories)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
