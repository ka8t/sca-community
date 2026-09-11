#!/usr/bin/env python3
"""Migration : projects/<uuid8>/ → projects/<slug>/

Renomme chaque dossier `projects/<uuid8>/` en `projects/<slug>/` (lisible).

Stratégie :
- Lit le `project.json` de chaque dossier pour récupérer le nom du projet.
- Calcule un slug via `_slugify_name()` (cohérent avec sca/projects.py).
- En cas de collision (slug déjà pris par un autre uuid) : suffixe `-<uuid8>`.
- Si le dossier n'a pas de project.json ou nom vide : laissé tel quel.
- Si le dossier porte déjà un nom de slug valide (pas un hex8) : laissé tel quel.

Mode dry-run par défaut. Passer `--apply` pour exécuter le renommage.
"""
import argparse
import json
import re
import shutil
import sys
import unicodedata
from pathlib import Path

PROJECTS_DIR = Path(__file__).resolve().parent.parent / "projects"


def slugify(name: str) -> str:
    if not name:
        return ""
    n = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    n = n.lower()
    n = re.sub(r"[^a-z0-9]+", "-", n)
    n = re.sub(r"-+", "-", n).strip("-")
    return n[:50]


def is_uuid8_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[a-f0-9]{8}", s))


def main() -> int:
    parser = argparse.ArgumentParser(description="Migre projects/<uuid8>/ → projects/<slug>/")
    parser.add_argument("--apply", action="store_true",
                        help="Exécute réellement les renommages (sinon dry-run).")
    args = parser.parse_args()

    if not PROJECTS_DIR.is_dir():
        print(f"❌ {PROJECTS_DIR} introuvable")
        return 1

    # Index : uuid → ancien dir actuellement présent
    existing: dict[str, str] = {}
    nameless: list[str] = []
    for entry in sorted(PROJECTS_DIR.iterdir()):
        if not entry.is_dir():
            continue
        pj = entry / "project.json"
        if not pj.exists():
            continue
        try:
            data = json.loads(pj.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, IOError):
            print(f"  ⚠ {entry.name} : project.json illisible")
            continue
        pid = data.get("id", "")
        name = data.get("name", "")
        if not pid:
            continue
        if not name:
            nameless.append(entry.name)
            continue
        existing[pid] = entry.name

    # Pré-réserve les noms slugs déjà utilisés (dossiers ayant déjà un nom non-hex)
    reserved: dict[str, str] = {}  # slug → uuid
    for pid, dirname in existing.items():
        if not is_uuid8_hex(dirname):
            reserved[dirname] = pid

    # Calcule le plan de renommage
    operations = []  # (src_path, dst_path, raison)
    skipped_existing = []
    skipped_nameless = list(nameless)
    seen_slugs: dict[str, str] = dict(reserved)  # slug déjà réservé → uuid propriétaire

    for pid, dirname in sorted(existing.items()):
        # Déjà au format slug : on saute
        if not is_uuid8_hex(dirname):
            skipped_existing.append(dirname)
            seen_slugs[dirname] = pid
            continue
        # Lit le nom à nouveau pour le slug
        pj = (PROJECTS_DIR / dirname / "project.json")
        try:
            data = json.loads(pj.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, IOError):
            continue
        slug = slugify(data.get("name", ""))
        uuid_short = pid[:8]
        if not slug:
            slug = uuid_short  # fallback : laisse tel quel
        # Collision ?
        if slug in seen_slugs and seen_slugs[slug] != pid:
            slug = f"{slug}-{uuid_short}"
        seen_slugs[slug] = pid
        if slug == dirname:
            skipped_existing.append(dirname)
            continue
        src = PROJECTS_DIR / dirname
        dst = PROJECTS_DIR / slug
        if dst.exists():
            print(f"  ⚠ collision physique pour {dirname} → {slug} (existe déjà)")
            continue
        operations.append((src, dst, f"{dirname} ({pid[:8]})"))

    # Affiche le plan
    print(f"\n📊 Plan de migration")
    print(f"  Dossiers totaux scannés : {len(existing) + len(nameless)}")
    print(f"  Déjà au bon format (slug)  : {len(skipped_existing)}")
    print(f"  Sans nom (laissés)         : {len(skipped_nameless)}")
    print(f"  À renommer                 : {len(operations)}")
    print()
    for src, dst, label in operations:
        print(f"  {src.name:14s} → {dst.name}")

    if not args.apply:
        print(f"\n💡 Dry-run. Relancez avec --apply pour exécuter.")
        return 0

    # Exécute
    print(f"\n🚀 Application…")
    ok = ko = 0
    for src, dst, label in operations:
        try:
            shutil.move(str(src), str(dst))
            print(f"  ✓ {src.name} → {dst.name}")
            ok += 1
        except OSError as exc:
            print(f"  ✗ {src.name} → {dst.name} : {exc}")
            ko += 1
    print(f"\n✅ {ok} renommé(s), {ko} échec(s).")
    return 0 if ko == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
