# -*- coding: utf-8 -*-
"""
build_release_manifest.py

Genera manifest.json para una release conjunta de:
  - las reglas Semgrep propias (rules/semgrep/custom/<lenguaje>/),
  - las reglas Semgrep integradas de terceros (rules/semgrep/third-party/<vendor>/<carpeta>/),
  - las reglas YARA ya puntuadas y publicadas (dist/yara_scored/<categoria>/).

Alcance deliberado (ver .claude/ImplementacionFlujoCICD.md):
  - YARA: SOLO dist/yara_scored/, el artefacto final ya publicado con la
    puntuacion de riesgo inyectada. Nunca yara_scores_output/*.json ni el
    submodulo yara_rules/Yara-Rules-Repo: eso es entrada del pipeline (el
    submodulo es el repo upstream COMPLETO y sin curar; solo un subconjunto
    elegido por yara_rule_scores.json llega a publicarse), no lo que el
    consumidor descarga y ejecuta.
  - Semgrep: TANTO custom/ como third-party/. A diferencia del submodulo
    YARA, third-party/ no es "upstream en bruto pendiente de curar": son
    reglas ya seleccionadas e integradas, commiteadas en el repo y usadas
    directamente (ver README, seccion "Escanear con reglas de terceros").
    Para varios lenguajes son ademas la inmensa mayoria del ruleset real
    (p.ej. Python: 10 reglas propias frente a 144 de terceros segun
    rules/semgrep/RULES-BY-LANGUAGE.md) -- excluirlas del manifest haria que
    "languages_changed" y sus hashes no reflejasen el ruleset que el
    consumidor realmente ejecuta.

    custom/ y third-party/ NO se fusionan en una sola clave por lenguaje:
    third-party esta organizado primero por vendor y luego por carpeta
    (rules/semgrep/third-party/<vendor>/<carpeta>/), y esa carpeta no
    siempre es un nombre de lenguaje reconocible (hay "generic",
    "problem-based-packs", "noisy") ni usa la misma convencion de nombres
    que custom/ (p.ej. third-party/trailofbits/rs/ frente a custom/rust/).
    Inventar un mapeo de normalizacion (rs -> rust, etc.) introduciria
    juicios de valor no verificables por el consumidor. En su lugar,
    "hashes.semgrep.third_party" refleja la estructura real de carpetas
    tal cual, sin traducir nombres: <vendor>/<carpeta>. Es la opcion sin
    perdida de informacion y sin inventar equivalencias.

--------------------------------------------------------------------------
METODO DE HASH (debe poder reproducirse de forma independiente en el repo
consumidor, que solo hace sparse-checkout de una o varias claves):
--------------------------------------------------------------------------
Para cada clave (un lenguaje dentro de "semgrep.custom", un "<vendor>/<carpeta>"
dentro de "semgrep.third_party", una categoria dentro de "yara"):
  1. Listar todos los ficheros de esa subcarpeta de forma recursiva.
  2. Ordenarlos alfabeticamente por su ruta relativa a esa subcarpeta
     (orden de bytes de la cadena, el mismo que produce `sort` de Unix
     sobre una lista de rutas UTF-8).
  3. Concatenar el contenido BINARIO de esos ficheros, en ese orden, sin
     separadores ni cabeceras (ni nombre de fichero ni longitud).
  4. sha256 sobre esa concatenacion. El manifest guarda "sha256:<hexdigest>".

Equivalente en shell puro (para que el consumidor lo pueda verificar sin
Python), asumiendo que esta en la carpeta correspondiente a la clave:
    find . -type f | sort | xargs cat | sha256sum

Por que un hash POR CLAVE y no uno global de toda la carpeta: (1) aisla
fallos -- si una clave no cuadra, se sabe EXACTAMENTE que lenguaje,
vendor/carpeta o categoria fallo, en vez de "algo en semgrep/ no cuadra";
(2) el consumidor hace descargas parciales (solo lo que necesita), asi que
necesita poder verificar la integridad de esa descarga parcial sin
traerse el repo completo.

Nota sobre el metodo (concatenacion simple, sin separadores): es
deliberadamente el metodo mas simple posible de reproducir con
herramientas de linea de comandos estandar. Tiene una colision teorica
conocida (mover un byte final de un fichero al principio del siguiente
produce la misma concatenacion), aceptable aqui porque el objetivo es
detectar corrupcion/discrepancias en la descarga parcial, no defenderse
de un adversario que ya tiene push access al propio repo de reglas.

Uso:
    python scripts/build_release_manifest.py --version vX.Y.Z \
        [--base-ref <tag-o-commit-anterior>] [--out manifest.json]

    --base-ref se usa para calcular languages_changed / third_party_changed /
    yara_categories_changed (git diff --base-ref..HEAD). Si se omite o esta
    vacio, se compara contra el arbol vacio de git (equivale a "todo es
    nuevo": primera release).

--------------------------------------------------------------------------
finding_type_summary / finding_type_notes:
--------------------------------------------------------------------------
Ademas de hashes y rule_count, el manifest incluye, con el mismo anidado
por clave (lenguaje bajo semgrep.custom, vendor/carpeta bajo
semgrep.third_party, categoria bajo yara), un desglose de cuantas reglas
puntuadas de esa clave son finding_type malicious vs vulnerability, cuantas
llevan needs_review: true, y cuantas reglas puntuadas todavia no tienen
finding_type ("unclassified" -- deberia ser 0; ver
.claude/criterioPuntuacionReglas.md para el esquema de clasificacion).
finding_type_notes es una frase generada a partir de los totales globales,
pensada para ir directamente en las notas de la release / el payload de
repository_dispatch sin que el consumidor tenga que sumar los conteos el
mismo.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from collections import Counter

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SEMGREP_CUSTOM_ROOT = REPO_ROOT / "rules" / "semgrep" / "custom"
SEMGREP_THIRD_PARTY_ROOT = REPO_ROOT / "rules" / "semgrep" / "third-party"
YARA_ROOT = REPO_ROOT / "dist" / "yara_scored"

# Un fichero de reglas Semgrep contiene una lista `rules:` cuyos elementos
# empiezan por "- id:"; contar esas lineas equivale a contar reglas.
SEMGREP_RULE_PATTERN = re.compile(r"^\s*-\s*id:\s*\S", re.MULTILINE)
# Una regla YARA (publica o privada, esta ultima incluida como dependencia
# estructural por generate_scored_yara.py) empieza por "rule <nombre>" o
# "private rule <nombre>".
YARA_RULE_PATTERN = re.compile(r"^\s*(private\s+)?rule\s+\w+", re.MULTILINE)

# finding_type (malicious|vulnerability) + needs_review: clasificacion
# anadida por scripts/classify_semgrep_finding_type.py (metadata: de cada
# regla Semgrep, sintaxis YAML) y scripts/backfill_finding_type_yara.py +
# generate_scored_yara.py (meta: de cada regla YARA, sintaxis "clave =
# valor"). Ver .claude/criterioPuntuacionReglas.md para el esquema.
SEMGREP_RISK_SCORE_PATTERN = re.compile(r"^\s*risk_score\s*:", re.MULTILINE)
SEMGREP_FINDING_TYPE_PATTERN = re.compile(r"^\s*finding_type\s*:\s*(malicious|vulnerability)\s*$", re.MULTILINE)
SEMGREP_NEEDS_REVIEW_PATTERN = re.compile(r"^\s*needs_review\s*:\s*true\s*$", re.MULTILINE)
YARA_RISK_SCORE_PATTERN = re.compile(r"^\s*risk_score\s*=", re.MULTILINE)
YARA_FINDING_TYPE_PATTERN = re.compile(r'^\s*finding_type\s*=\s*"(malicious|vulnerability)"\s*$', re.MULTILINE)
YARA_NEEDS_REVIEW_PATTERN = re.compile(r"^\s*needs_review\s*=\s*true\s*$", re.MULTILINE)


def run_git(args):
    result = subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} fallo: {result.stderr.strip()}")
    return result.stdout


def list_subdirs(root: pathlib.Path):
    """Subcarpetas directas de root, ordenadas alfabeticamente por nombre."""
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir())


def hash_directory(dir_path: pathlib.Path) -> str:
    files = sorted(
        (p for p in dir_path.rglob("*") if p.is_file()),
        key=lambda p: p.relative_to(dir_path).as_posix(),
    )
    digest = hashlib.sha256()
    for f in files:
        digest.update(f.read_bytes())
    return f"sha256:{digest.hexdigest()}"


def count_rules(root: pathlib.Path, extensions, pattern) -> int:
    total = 0
    for ext in extensions:
        for f in root.rglob(f"*{ext}"):
            total += len(pattern.findall(f.read_text(encoding="utf-8", errors="replace")))
    return total


def count_finding_types(root: pathlib.Path, extensions, risk_score_pattern,
                         finding_type_pattern, needs_review_pattern) -> dict:
    """
    Para los ficheros de regla directamente bajo `root` (recursivo): cuantas
    reglas puntuadas (risk_score presente) son finding_type malicious vs
    vulnerability, cuantas de esas llevan needs_review: true, y cuantas
    reglas puntuadas todavia no tienen finding_type ("unclassified" --
    deberia quedarse en 0 para todo lo que ya paso por
    scripts/classify_semgrep_finding_type.py o
    scripts/backfill_finding_type_yara.py; un valor distinto de cero es la
    senal de que se anadieron reglas nuevas sin clasificar).
    """
    scored_total = 0
    values = []
    needs_review = 0
    for ext in extensions:
        for f in root.rglob(f"*{ext}"):
            text = f.read_text(encoding="utf-8", errors="replace")
            scored_total += len(risk_score_pattern.findall(text))
            values.extend(finding_type_pattern.findall(text))
            needs_review += len(needs_review_pattern.findall(text))
    counts = Counter(values)
    return {
        "malicious": counts.get("malicious", 0),
        "vulnerability": counts.get("vulnerability", 0),
        "needs_review": needs_review,
        "unclassified": scored_total - len(values),
    }


def finding_types_by_subdir(root: pathlib.Path, extensions, risk_score_pattern,
                             finding_type_pattern, needs_review_pattern) -> dict:
    return {
        name: count_finding_types(root / name, extensions, risk_score_pattern,
                                   finding_type_pattern, needs_review_pattern)
        for name in list_subdirs(root)
    }


def finding_types_two_level(root: pathlib.Path, extensions, risk_score_pattern,
                             finding_type_pattern, needs_review_pattern) -> dict:
    """Mismo criterio de agrupacion vendor/carpeta que hash_two_level()."""
    result = {}
    for vendor in list_subdirs(root):
        vendor_counts = {
            folder: count_finding_types(root / vendor / folder, extensions, risk_score_pattern,
                                         finding_type_pattern, needs_review_pattern)
            for folder in list_subdirs(root / vendor)
        }
        if vendor_counts:
            result[vendor] = vendor_counts
    return result


def _iter_leaf_finding_type_counts(node):
    """Recorre finding_type_summary (mismo anidado que hashes/rule_count) y
    devuelve cada dict hoja {malicious, vulnerability, needs_review, unclassified}."""
    if isinstance(node, dict) and "malicious" in node and "vulnerability" in node:
        yield node
        return
    if isinstance(node, dict):
        for v in node.values():
            yield from _iter_leaf_finding_type_counts(v)


def total_finding_types(finding_type_summary: dict) -> dict:
    totals = {"malicious": 0, "vulnerability": 0, "needs_review": 0, "unclassified": 0}
    for leaf in _iter_leaf_finding_type_counts(finding_type_summary):
        for key in totals:
            totals[key] += leaf[key]
    return totals


def build_finding_type_notes(totals: dict) -> str:
    scored = totals["malicious"] + totals["vulnerability"]
    notes = (
        f"De {scored} regla(s) puntuada(s) y clasificada(s): {totals['malicious']} "
        f"apuntan a codigo ya malicioso (webshells, backdoors, tecnicas sin uso "
        f"legitimo razonable -- respuesta esperada: contencion/aislamiento), "
        f"{totals['vulnerability']} a vulnerabilidades explotables en codigo "
        f"legitimo (respuesta esperada: ciclo normal de remediacion); "
        f"{totals['needs_review']} de ellas estan marcadas needs_review para "
        f"confirmacion humana."
    )
    if totals["unclassified"]:
        notes += (
            f" Aviso: {totals['unclassified']} regla(s) puntuada(s) todavia no "
            f"tienen finding_type asignado."
        )
    return notes


def hash_two_level(root: pathlib.Path) -> dict:
    """
    Hash por <vendor>/<carpeta>, para arboles de dos niveles como
    rules/semgrep/third-party/<vendor>/<carpeta>/. Ficheros sueltos en la
    raiz del vendor (p.ej. LICENSE) quedan fuera deliberadamente: no son
    contenido de reglas y no tienen una "carpeta" a la que asignarse.
    """
    hashes = {}
    for vendor in list_subdirs(root):
        vendor_hashes = {
            folder: hash_directory(root / vendor / folder)
            for folder in list_subdirs(root / vendor)
        }
        if vendor_hashes:
            hashes[vendor] = vendor_hashes
    return hashes


# SHA fijo y bien conocido del "arbol vacio" en git (el mismo en cualquier
# repositorio: no depende de /dev/null ni de la plataforma). Se usa como
# base de comparacion cuando no existe ningun tag previo, de forma que
# `git diff <empty-tree>..HEAD` liste todos los ficheros actuales como
# "nuevos" -- exactamente lo que queremos para una primera release.
EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _changed_paths(root_relative: str, base_ref: str):
    base = base_ref if base_ref else EMPTY_TREE_SHA
    diff_output = run_git(["diff", "--name-only", base, "HEAD", "--", root_relative])
    prefix_depth = len(pathlib.PurePosixPath(root_relative).parts)
    for line in diff_output.splitlines():
        parts = pathlib.PurePosixPath(line).parts
        if len(parts) > prefix_depth:
            yield parts, prefix_depth


def changed_top_level_dirs(root_relative: str, base_ref: str) -> list:
    """
    Nombres de subcarpetas directas bajo root_relative que tienen algun
    fichero anadido/modificado/borrado entre base_ref y HEAD.
    """
    changed = {parts[depth] for parts, depth in _changed_paths(root_relative, base_ref)}
    return sorted(changed)


def changed_two_level_dirs(root_relative: str, base_ref: str) -> list:
    """
    Rutas "<vendor>/<carpeta>" bajo root_relative con algun fichero
    anadido/modificado/borrado entre base_ref y HEAD. Devuelve solo las
    entradas con vendor Y carpeta (ignora ficheros sueltos en la raiz del
    vendor, p.ej. LICENSE, que tampoco se hashean en hash_two_level).
    """
    changed = set()
    for parts, depth in _changed_paths(root_relative, base_ref):
        # Se exige que, ademas de vendor y carpeta, quede al menos un
        # componente mas (el nombre de fichero); si no, lo que cambio es
        # un fichero suelto en la raiz del vendor (p.ej. LICENSE), que
        # tampoco se hashea en hash_two_level y por tanto no cuenta aqui.
        if len(parts) > depth + 2:
            changed.add(f"{parts[depth]}/{parts[depth + 1]}")
    return sorted(changed)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True, help="Version calculada, formato vX.Y.Z")
    parser.add_argument(
        "--base-ref", default="",
        help="Tag/commit anterior para detectar cambios (vacio = primera release)",
    )
    parser.add_argument("--out", default="manifest.json")
    args = parser.parse_args()

    custom_hashes = {
        lang: hash_directory(SEMGREP_CUSTOM_ROOT / lang) for lang in list_subdirs(SEMGREP_CUSTOM_ROOT)
    }
    third_party_hashes = hash_two_level(SEMGREP_THIRD_PARTY_ROOT)
    yara_hashes = {cat: hash_directory(YARA_ROOT / cat) for cat in list_subdirs(YARA_ROOT)}

    finding_type_summary = {
        "semgrep": {
            "custom": finding_types_by_subdir(
                SEMGREP_CUSTOM_ROOT, (".yml", ".yaml"), SEMGREP_RISK_SCORE_PATTERN,
                SEMGREP_FINDING_TYPE_PATTERN, SEMGREP_NEEDS_REVIEW_PATTERN),
            "third_party": finding_types_two_level(
                SEMGREP_THIRD_PARTY_ROOT, (".yml", ".yaml"), SEMGREP_RISK_SCORE_PATTERN,
                SEMGREP_FINDING_TYPE_PATTERN, SEMGREP_NEEDS_REVIEW_PATTERN),
        },
        "yara": finding_types_by_subdir(
            YARA_ROOT, (".yar", ".yara"), YARA_RISK_SCORE_PATTERN,
            YARA_FINDING_TYPE_PATTERN, YARA_NEEDS_REVIEW_PATTERN),
    }
    finding_type_notes = build_finding_type_notes(total_finding_types(finding_type_summary))

    manifest = {
        "version": args.version,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hashes": {
            "semgrep": {
                "custom": custom_hashes,
                "third_party": third_party_hashes,
            },
            "yara": yara_hashes,
        },
        "languages_changed": changed_top_level_dirs("rules/semgrep/custom", args.base_ref),
        "third_party_changed": changed_two_level_dirs("rules/semgrep/third-party", args.base_ref),
        "yara_categories_changed": changed_top_level_dirs("dist/yara_scored", args.base_ref),
        "rule_count": {
            "semgrep": {
                "custom": count_rules(SEMGREP_CUSTOM_ROOT, (".yml", ".yaml"), SEMGREP_RULE_PATTERN),
                "third_party": count_rules(SEMGREP_THIRD_PARTY_ROOT, (".yml", ".yaml"), SEMGREP_RULE_PATTERN),
            },
            "yara": count_rules(YARA_ROOT, (".yar", ".yara"), YARA_RULE_PATTERN),
        },
        "finding_type_summary": finding_type_summary,
        "finding_type_notes": finding_type_notes,
    }

    out_path = pathlib.Path(args.out)
    out_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"manifest.json escrito en {out_path} (version {manifest['version']})")
    print(f"  languages_changed: {manifest['languages_changed']}")
    print(f"  third_party_changed: {manifest['third_party_changed']}")
    print(f"  yara_categories_changed: {manifest['yara_categories_changed']}")
    print(f"  rule_count: {manifest['rule_count']}")
    print(f"  finding_type_notes: {manifest['finding_type_notes']}")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
