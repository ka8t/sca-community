"""
Ajoute dans conftest.py les entrées VULNERABLE_FIXTURES et CLEAN_FIXTURES
pour chaque règle .sca sans entrée existante.
"""
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
CONFTEST = ROOT / "tests" / "conftest.py"
RULES_DIR = ROOT / "sca" / "rules" / "builtin"

EXT = {"python": ".py", "javascript": ".js", "java": ".java", "csharp": ".cs", "php": ".php"}
TARGET = {
    "python": "src/service.py", "javascript": "src/js/app.js",
    "java": "src/Main.java", "csharp": "src/Program.cs", "php": "src/service.php",
}

def get_language(sca_path):
    m = re.search(r"language\s+(\w+)", sca_path.read_text(encoding="utf-8"))
    return m.group(1) if m else ""

def get_existing_keys(text):
    return set(re.findall(r'"(\w+)":\s*\("[^"]+",', text))

def build_vuln_entry(rule_id, lang):
    ext = EXT.get(lang, ".py")
    tgt = TARGET.get(lang, "src/service.py")
    return f'    "{rule_id}": ("{rule_id}{ext}", "{tgt}", "{rule_id}"),\n'

def build_clean_entry(rule_id, lang):
    ext = EXT.get(lang, ".py")
    tgt = TARGET.get(lang, "src/service.py")
    key = f"{rule_id}_clean"
    return f'    "{key}": ("{rule_id}_clean{ext}", "{tgt}", "{rule_id}"),\n'

def main():
    text = CONFTEST.read_text(encoding="utf-8")
    existing = get_existing_keys(text)

    vuln_lines = []
    clean_lines = []

    for sca in sorted(RULES_DIR.rglob("*.sca")):
        rule_id = sca.stem
        if rule_id in existing:
            continue
        lang = get_language(sca)
        if not lang:
            continue
        vuln_lines.append(build_vuln_entry(rule_id, lang))
        clean_key = f"{rule_id}_clean"
        if clean_key not in existing:
            clean_lines.append(build_clean_entry(rule_id, lang))

    if not vuln_lines:
        print("Rien à ajouter.")
        return

    # Insérer avant la fermeture de VULNERABLE_FIXTURES
    vuln_block = "".join(vuln_lines)
    text = text.replace(
        "CLEAN_FIXTURES = {",
        vuln_block + "\nCLEAN_FIXTURES = {",
        1
    )

    # Insérer à la fin de CLEAN_FIXTURES (avant la ligne vide suivante ou EOF)
    clean_block = "".join(clean_lines)
    # Trouver la dernière entrée de CLEAN_FIXTURES et insérer après
    m = list(re.finditer(r'(\}\s*\n)(?!.*FIXTURES)', text, re.DOTALL))
    if m and clean_lines:
        pos = m[-1].start()
        text = text[:pos] + clean_block + text[pos:]

    CONFTEST.write_text(text, encoding="utf-8")
    print(f"{len(vuln_lines)} entrées VULNERABLE + {len(clean_lines)} entrées CLEAN ajoutées.")

if __name__ == "__main__":
    main()
