"""
Génère les fixtures (vulnerable + clean) pour toutes les règles .sca sans fixture.
Lit fix_before → vulnerable, fix_after → clean.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
RULES_DIR = ROOT / "sca" / "rules" / "builtin"
VULN_DIR  = ROOT / "tests" / "fixtures" / "generic" / "vulnerable"
CLEAN_DIR = ROOT / "tests" / "fixtures" / "generic" / "clean"

EXT = {"python": ".py", "javascript": ".js", "java": ".java", "csharp": ".cs", "php": ".php"}
COMMENT = {"python": "#", "javascript": "//", "java": "//", "csharp": "//", "php": "//"}

def parse_sca(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    def extract(tag):
        m = re.search(rf"^\s*{tag}\n(.*?)^\s*end\b", text, re.MULTILINE | re.DOTALL)
        if not m:
            return ""
        return m.group(1).rstrip()
    lang = (re.search(r"language\s+(\w+)", text) or ["", ""])[1]
    return {
        "rule_id": path.stem,
        "language": lang,
        "fix_before": extract("fix_before"),
        "fix_after":  extract("fix_after"),
    }

def write_fixture(dest: Path, comment_char: str, header_lines: list[str], code: str):
    lines = [f"{comment_char} {l}" for l in header_lines] + ["", code, ""]
    dest.write_text("\n".join(lines), encoding="utf-8")

def main():
    created = 0
    skipped = 0
    for sca_path in sorted(RULES_DIR.rglob("*.sca")):
        info = parse_sca(sca_path)
        lang = info["language"]
        rid  = info["rule_id"]
        ext  = EXT.get(lang, ".txt")
        cc   = COMMENT.get(lang, "#")

        vuln_file  = VULN_DIR  / f"{rid}{ext}"
        clean_file = CLEAN_DIR / f"{rid}_clean{ext}"

        if vuln_file.exists() and clean_file.exists():
            skipped += 1
            continue

        if not info["fix_before"].strip() or not info["fix_after"].strip():
            print(f"  ⚠ pas de fix_before/fix_after : {rid}")
            continue

        if not vuln_file.exists():
            write_fixture(vuln_file, cc, [
                f"VULNERABLE: {rid}",
                f"Expected  : Should trigger {rid} ({lang})",
            ], info["fix_before"])

        if not clean_file.exists():
            write_fixture(clean_file, cc, [
                f"@audit-fixture",
                f"@rule: {rid}",
                f"@category: security",
                f"@expected: clean",
            ], info["fix_after"])

        created += 1
        print(f"  ✓ {rid} ({lang})")

    print(f"\n{created} paires créées, {skipped} déjà présentes.")

if __name__ == "__main__":
    main()
