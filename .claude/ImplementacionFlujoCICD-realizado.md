# Cómo quedó implementado realmente el flujo de release

Este documento describe la implementación final de `.github/workflows/release-rules.yml`
y los scripts que lo acompañan, tal y como quedaron después de construirlo y depurarlo
contra el repo real. El encargo original está en [`ImplementacionFlujoCICD.md`](ImplementacionFlujoCICD.md);
este fichero recoge dónde la implementación se desvía de ese encargo (y por qué), y los
bugs reales que aparecieron por el camino — útil para poder explicarlo en el TFG.

Verificado en producción: el workflow ha corrido de punta a punta con éxito, generando
las releases [`v0.0.1`](https://github.com/pablojimz/Repo-reglas-SEMGREP-y-YARA/releases/tag/v0.0.1)
y [`v0.0.2`](https://github.com/pablojimz/Repo-reglas-SEMGREP-y-YARA/releases/tag/v0.0.2),
con notificación real a `pablojimz/watch_gate` incluida.

---

## 1. Diferencias de estructura respecto al encargo original

El encargo asumía una carpeta plana `SEMGREP/<lenguaje>/`. La estructura real del repo es
distinta y con más matices:

- **`rules/semgrep/custom/<lenguaje>/`** — reglas propias (17 lenguajes: python, javascript,
  dockerfile, etc.).
- **`rules/semgrep/third-party/<vendor>/<carpeta>/`** — reglas integradas de terceros
  (trailofbits, opengrep, elttam, 0xdea), organizadas por vendor y luego por carpeta, no
  siempre un nombre de lenguaje (`generic`, `problem-based-packs`, `noisy` existen) y con
  nombres que no siempre coinciden con los de `custom/` (`trailofbits/rs` vs `custom/rust`).
- **`rules/semgrep/config.yaml`** — config de LiteLLM que vive en la raíz de `rules/semgrep/`,
  sin relación con reglas Semgrep (importante para el punto 3.2).
- Todo `rules/semgrep/**/*.yaml` está gestionado con **Git LFS** (`.gitattributes`), algo
  que el encargo original no mencionaba y que rompió el workflow la primera vez que corrió
  (ver 4.4).

### Decisión de alcance para Semgrep

Se decidió incluir **tanto `custom/` como `third-party/`** en el versionado, no solo
`custom/` como se planteó al principio. Motivo: `third-party/` no es upstream sin curar —
son reglas ya elegidas e integradas, commiteadas y usadas directamente — y para varios
lenguajes es la inmensa mayoría del ruleset real (Python: 10 reglas propias frente a 144
de terceros). Dejarlo fuera habría hecho que `languages_changed` y sus hashes no
reflejaran el ruleset que el consumidor realmente ejecuta.

`custom/` y `third-party/` se mantienen como **namespaces separados** en el manifest (no
se fusionan en una sola clave por lenguaje), precisamente por los desajustes de nombres y
carpetas no-lenguaje mencionados arriba. Ver el docstring de
`scripts/build_release_manifest.py` para el detalle completo del razonamiento.

---

## 2. Estructura real de `manifest.json`

Difiere del ejemplo del encargo original (que solo preveía `semgrep.<lenguaje>` plano):

```json
{
  "version": "v0.0.2",
  "generated_at": "2026-08-07T12:47:00Z",
  "hashes": {
    "semgrep": {
      "custom": {
        "python": "sha256:...",
        "dockerfile": "sha256:...",
        "...": "una entrada por cada carpeta de rules/semgrep/custom/ (17 en total)"
      },
      "third_party": {
        "opengrep": { "python": "sha256:...", "generic": "sha256:...", "...": "..." },
        "trailofbits": { "python": "sha256:...", "rs": "sha256:...", "...": "..." },
        "elttam": { "go": "sha256:...", "yaml": "sha256:..." },
        "0xdea": { "c": "sha256:...", "noisy": "sha256:..." }
      }
    },
    "yara": {
      "antidebug_antivm": "sha256:...",
      "webshells": "sha256:..."
    }
  },
  "languages_changed": [],
  "third_party_changed": [],
  "yara_categories_changed": [],
  "rule_count": {
    "semgrep": { "custom": 64, "third_party": 717 },
    "yara": 695
  }
}
```

Cambios respecto al encargo:
- `hashes.semgrep` tiene dos sub-claves (`custom`, `third_party`) en vez de una lista
  plana por lenguaje; `third_party` está a su vez anidado por `<vendor>/<carpeta>`.
- Nuevo campo `third_party_changed` (lista de strings `"<vendor>/<carpeta>"`), análogo a
  `languages_changed` pero para el árbol de terceros.
- `rule_count.semgrep` es un objeto `{custom, third_party}` en vez de un único número.

**Método de hash** (sin cambios respecto al encargo): por cada clave, se listan
recursivamente los ficheros de esa subcarpeta, se ordenan alfabéticamente por ruta
relativa, se concatena su contenido binario sin separadores, y se calcula sha256 sobre esa
concatenación. Documentado con más detalle (incluido el equivalente en shell puro para que
el consumidor lo recalcule) en el docstring de `scripts/build_release_manifest.py`.

**Detección de cambios**: en vez de diferenciar contra el commit padre inmediato (como
pedía el encargo), se diferencia contra **el último tag** (`git describe --tags --abbrev=0`,
o el árbol vacío de git si no existe ningún tag todavía). Motivo: con el pipeline YARA en
dos fases (ver 3), "el commit anterior" a veces es solo el commit del bot de
`publish-scored-yara.yml` (que solo trae `dist/yara_scored/`) y a veces solo el commit
humano original — ninguno de los dos por sí solo refleja "todo lo que cambió desde la
última versión publicada", que es lo que un manifest de release necesita.

---

## 3. Por qué dos triggers (`push` y `workflow_run`), no solo `push`

El encargo sugería "dispararse también con push a main una vez el commit de
`dist/yara_scored/` ya está aplicado" como una opción entre varias. En la práctica hizo
falta, no fue opcional, por este motivo:

`publish-scored-yara.yml` (el workflow ya existente que regenera `dist/yara_scored/`)
commitea sus cambios con el mensaje `chore: regenerate scored YARA ruleset [skip ci]`.
GitHub Actions **no dispara ningún workflow** vía `push`/`pull_request` para un commit que
contenga `[skip ci]` en el mensaje — es un comportamiento global de la plataforma. Un
workflow que solo escuchara `push` nunca vería ese commit, que es justo el que actualiza
`dist/yara_scored/`.

Solución implementada: dos disparadores complementarios —

- **`push`** a `main`, filtrado a `rules/semgrep/custom/**`, `rules/semgrep/third-party/**`
  y `dist/yara_scored/**`. Cubre cambios que no disparan `publish-scored-yara.yml`.
- **`workflow_run`**, cuando `Publish scored YARA rules` termina con éxito. Cubre el caso
  en que sí hubo regeneración, leyendo `main` ya con el commit del bot aplicado.
- **`workflow_dispatch`**, añadido para poder relanzar manualmente durante las pruebas
  (no estaba en el encargo original, se añadió por necesidad práctica de depuración).

**Guard anti-carrera** (tampoco estaba en el encargo, hizo falta para el caso mixto): si un
mismo push toca a la vez `rules/semgrep/custom/**` y algo que también dispara
`publish-scored-yara.yml` (p. ej. `yara_scores_output/yara_rule_scores.json`), el trigger
`push` se dispararía de inmediato, pero en ese momento `dist/yara_scored/` todavía no se ha
regenerado → el hash de YARA sería el viejo. El primer step del job (`decide`) detecta esta
situación comparando los ficheros tocados por el push contra las rutas que disparan
`publish-scored-yara.yml`, y si coinciden, se autocancela (`proceed=false`), delegando la
creación del release al trigger `workflow_run` posterior, que llega después con
`dist/yara_scored/` ya actualizado.

Verificado en producción: en la ejecución real que generó `v0.0.1`/`v0.0.2` se vio
exactamente este patrón — un `push` y un `workflow_run` separados por 14 segundos, sin
generar releases duplicadas ni inconsistentes.

---

## 4. Bugs reales encontrados y arreglados durante la implementación

Ninguno de estos afecta a la lógica de negocio del workflow en sí — todos aparecieron al
ejecutarlo contra el repo real, y quedan documentados aquí porque el proceso de
encontrarlos y depurarlos es tan relevante para el TFG como el propio workflow.

### 4.1 — `${{ }}` literal dentro de comentarios bash rompía el parser de Actions

Dos comentarios explicativos dentro de bloques `run:` contenían, como prosa, la sintaxis
`${{ }}` vacía para referirse a ella misma. El pre-procesador de expresiones de GitHub
Actions escanea el texto completo de cada `run:` buscando `${{ ... }}` **antes** de que
bash vea nada — no distingue un comentario — y al encontrar una expresión vacía, la
workflow entera queda invalidada (`Invalid workflow file ... An expression was expected`,
0 jobs ejecutados). Arreglado reescribiendo esos comentarios en prosa, sin el literal.

### 4.2 — `semgrep --validate` sobre `rules/semgrep/` entero

Apuntar `semgrep --validate` a la carpeta raíz `rules/semgrep/` hacía que semgrep
intentara cargar también `rules/semgrep/config.yaml` (la config de LiteLLM) como si fuera
un fichero de reglas, y fallaba por no tener la clave `rules:`. Arreglado apuntando el
validador a `rules/semgrep/custom/` y `rules/semgrep/third-party/` explícitamente (dos
`--config`), nunca a la carpeta raíz.

### 4.3 — Bug de semgrep con valores YAML `float` en la metadata (upstream, confirmado)

`semgrep --validate` (y de hecho `semgrep scan` normal, no es exclusivo de `--validate`)
**crashea** con cualquier valor YAML de tipo `float` en cualquier punto de un fichero de
reglas — excepción sin capturar en `rule_lang.py`, método `unroll()`, que no reconoce el
tipo `ScalarFloat` que produce su propio parser YAML. Confirmado con una reproducción
mínima de 8 líneas, y reproducido igual en semgrep `1.172.0` (la última disponible en PyPI)
y en `1.130.0` (bastante más antigua) — no es una regresión reciente.

30 ficheros de `rules/semgrep/third-party/` (`0xdea`, `opengrep`, `trailofbits`) tenían un
`severity_score` con decimales (`87.5`/`62.5`/`37.5` — probablemente interpolaciones entre
los niveles discretos que documenta el README: 100/75/50/25). Arreglado poniendo esos 30
valores entre comillas (`"87.5"`): mismo número, mismo contenido informativo, solo cambia
de tipo YAML de `float` a `str`, lo cual esquiva el bug sin alterar ningún criterio de
puntuación de riesgo real. **Nota pendiente, no resuelta a propósito**: esos 30 valores no
encajan en la escala discreta documentada; decidir si les corresponde 75 o 100 es un
juicio de seguridad que se dejó fuera del alcance de este arreglo.

### 4.4 — Checkout sin `lfs: true`

`rules/semgrep/**/*.yaml` está gestionado con Git LFS (`.gitattributes`, configurado en un
commit anterior y no mencionado en el encargo original). `actions/checkout` no descarga el
contenido real de los objetos LFS por defecto — sin `lfs: true`, cada fichero de reglas
queda como el puntero LFS de 3 líneas (`version`/`oid`/`size`), no el YAML real. Esto rompía
`semgrep --validate` (`was not a mapping`, el puntero no es un mapping YAML válido) y
además habría corrompido en silencio los hashes y `rule_count` de
`build_release_manifest.py` (habría hasheado punteros, no reglas) si hubiera llegado a
ejecutarse. Arreglado añadiendo `lfs: true` al step de `Checkout`.

### 4.5 — Bugs reales en `scripts/generate_scored_yara.py` (detectados por la propia validación)

El step de validación YARA hizo exactamente su trabajo: encontró que el artefacto ya
publicado en `dist/yara_scored/` no compilaba, por dos bugs preexistentes en el generador
(no en el workflow nuevo):

- **Imports de módulo perdidos**: el generador solo extraía bloques `rule { ... }` del
  fichero fuente; cualquier `import "modulo"` (p. ej. `import "pe"`, necesario porque
  `antidebug_antivm.yar` usa `pe.imports(...)`) se perdía por completo. Arreglado con
  `extract_imports()`, que recoge todos los imports del fichero fuente y los escribe en la
  cabecera del fichero generado (un import de más es inocuo en YARA; uno de menos no
  compila).
- **Regex truncada**: `strip_comments()` no sabía distinguir un literal de regex de YARA
  (`/patrón/`) de un comentario. Un regex legítimo en `WShell_Drupalgeddon2_icos.yar` que
  termina en `...\*\//` se interpretaba mal (el `//` final parecía "inicio de comentario
  de línea") y se comía el cierre de la regex, dejándola sin terminar
  (`yara-python`: "unexpected end of file, expecting text string"). Arreglado dando a
  `strip_comments()` un modo dedicado para literales de regex, activado cuando un `/`
  aparece justo después de un `=` (así se introducen todas las regex de este ruleset:
  `$id = /regex/`), que consume hasta el siguiente `/` sin escapar sin tratar nada de en
  medio como comentario.

Tras el arreglo, se regeneró `dist/yara_scored/` con el script corregido y se revalidaron
las 694 reglas publicadas (incluida `WShell_THOR_Webshells.yar`, con 613 reglas) — todas
compilan limpio.

---

## 5. Scripts nuevos (no estaban en el encargo, hicieron falta para implementarlo)

- **`scripts/build_release_manifest.py`** — calcula los hashes por clave, `rule_count` y las
  listas de cambios, y escribe `manifest.json`. CLI: `--version`, `--base-ref` (tag/commit
  anterior; vacío = primera release), `--out`.
- **`scripts/validate_yara_syntax.py`** — compila cada regla de `dist/yara_scored/` con
  `yara-python` (no con el CLI `yara`, que exige un fichero objetivo ficticio para poder
  ejecutarse; compilar vía librería da errores más precisos de fichero:línea).

---

## 6. Configuración manual pendiente (fuera del alcance de lo que un workflow puede hacer)

- **Secret `DISPATCH_TOKEN`**: fine-grained PAT sobre `pablojimz/watch_gate` únicamente,
  permiso `Contents: Read and write` (el único que exige el endpoint de
  `repository_dispatch`), guardado como secret en este repo. **Ya configurado y verificado
  funcionando** — la notificación a `watch_gate` respondió con éxito en las releases
  `v0.0.1`/`v0.0.2`.
- **Repo consumidor confirmado**: `pablojimz/watch_gate` (dato que el encargo original
  pedía explícitamente confirmar antes de hardcodearlo).

---

## 7. Cómo probarlo de nuevo

```
Actions → "Release rules (SemVer + notify consumer)" → Run workflow → rama main → Run
```

Para forzar un bump concreto, incluir `[major]`, `[minor]` o `[patch]` en el mensaje del
commit/PR que dispara el push; sin etiqueta, se aplica `[patch]` por defecto y queda
constancia explícita en el log del workflow.
