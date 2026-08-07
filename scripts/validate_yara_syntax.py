# -*- coding: utf-8 -*-
"""
validate_yara_syntax.py

Valida que cada regla YARA en dist/yara_scored/ (el artefacto YA PUBLICADO,
con la puntuacion de riesgo inyectada por scripts/generate_scored_yara.py)
compila correctamente con el motor YARA real.

Por que solo dist/yara_scored/ y no el submodulo:
El submodulo yara_rules/Yara-Rules-Repo nunca se modifica directamente y no
es lo que el repo consumidor va a descargar y ejecutar; lo unico cuyo
compilado importa verificar end-to-end es el artefacto final tal y como se
va a distribuir. Revalidar el submodulo completo aqui seria redundante
(no ha cambiado por accion nuestra) y mas lento sin aportar garantia extra.

Por que yara-python y no el binario `yara` CLI:
Compilar via libreria no requiere un fichero "objetivo" ficticio sobre el
que escanear (el CLI de yara siempre exige uno para poder ejecutarse) y
da errores de compilacion mas precisos (fichero:linea) que parsear stdout.

Cada fichero de dist/yara_scored/<categoria>/<archivo>.yar debe ser
autocontenido: generate_scored_yara.py ya se encarga de incluir, dentro del
propio fichero, cualquier `private rule` de la que dependa la condicion.
Por eso aqui compilamos fichero a fichero, sin necesitar imports cruzados
entre categorias ni construir un namespace compartido.

Exit code 0 si todo compila; 1 si cualquier fichero falla (se listan TODOS
los fallos encontrados, no solo el primero, para poder corregirlos de una
sola vez).

Uso:
    python scripts/validate_yara_syntax.py
"""
import pathlib
import sys

try:
    import yara
except ImportError:
    print("ERROR: falta el paquete 'yara-python' (pip install yara-python)", file=sys.stderr)
    sys.exit(1)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCORED_DIR = REPO_ROOT / "dist" / "yara_scored"


def main():
    rule_files = sorted(SCORED_DIR.rglob("*.yar")) + sorted(SCORED_DIR.rglob("*.yara"))
    if not rule_files:
        print(f"ERROR: no se encontraron reglas .yar/.yara bajo {SCORED_DIR}", file=sys.stderr)
        sys.exit(1)

    failures = []
    for path in rule_files:
        try:
            yara.compile(filepath=str(path))
        except yara.Error as exc:
            failures.append((path, exc))

    print(f"Validadas {len(rule_files)} reglas YARA en {SCORED_DIR}")

    if failures:
        print(f"\n{len(failures)} regla(s) con errores de sintaxis:", file=sys.stderr)
        for path, exc in failures:
            print(f"  - {path.relative_to(REPO_ROOT)}: {exc}", file=sys.stderr)
        sys.exit(1)

    print("Todas las reglas YARA compilan correctamente.")


if __name__ == "__main__":
    main()
