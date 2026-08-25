# Análisis: uso de `semgrep/semgrep-rules` (registro oficial) bajo Semgrep Rules License v1.0

Contexto: `semgrep/semgrep-rules` (el registro oficial de Semgrep, Inc.) se descartó como fuente de `third-party/` en este repo (ver [`NOTICE.md`](../rules/semgrep/NOTICE.md), sección "Qué NO está aquí, y por qué") porque su licencia prohíbe la redistribución. Este documento recoge el análisis de si existe alguna vía legítima de aprovechar esa fuente sin violar su licencia, y qué se decidió.

## Texto relevante de la licencia (Semgrep Rules License v1.0)

Fuente: https://semgrep.dev/legal/rules-license

- **Uso permitido**: *"You may use the rules only for your own internal business purposes."*
- **Prohibición explícita de redistribución**: *"This license does not allow you to distribute the rules, or to make them available to others as a service."*
- Si se modifican las reglas, hay que indicarlo explícitamente en las copias modificadas.
- No se pueden eliminar/ocultar avisos de copyright o licencia de Semgrep, Inc.
- Licencia de patente para uso interno, que se anula automáticamente si se demanda a Semgrep por infracción de patente.
- Incumplimiento → terminación automática de todas las licencias otorgadas.
- "Your company" (a efectos de "uso interno") son las entidades bajo control común con el usuario — no cubre a terceros externos aunque el uso sea gratuito o no comercial.

## Opción descartada: incluir la fuente oficial en `third-party/` de este repo

El workflow `.github/workflows/release-rules.yml` empaqueta `rules/semgrep/third-party/` (comiteado en el repo), genera un `manifest.json`, crea un GitHub Release versionado y notifica a un repo consumidor privado vía `repository_dispatch`. Esto es, por diseño, un mecanismo de **distribución**: aunque el consumidor sea privado y controlado por el mismo equipo, el propio acto de empaquetar + publicar + notificar excede "uso interno" y encaja en "distribuir" / "poner a disposición". Por tanto, la fuente oficial **no puede entrar en este repo** mientras el pipeline funcione así. Esta conclusión reafirma la decisión original documentada en `NOTICE.md`.

## Opción viable: herramienta-wrapper separada, ejecutada por el usuario final

Se evaluó construir una herramienta distinta (no este repo de reglas curadas) que invoque el registro oficial de Semgrep en tiempo de ejecución, en vez de vendorizar su contenido. Conclusión: **es viable**, bajo las siguientes condiciones, y solo si se cumplen todas:

1. **El escaneo lo ejecuta el usuario final, en su propio entorno** (su máquina o su propio runner de CI) — nunca infraestructura controlada por nosotros actuando de intermediario entre el registro oficial y un tercero. Esta es la condición determinante: si un proceso nuestro hace el *fetch* y el *scan* y luego entrega el resultado (o las reglas) a otro, eso sigue encajando en *"make them available to others as a service"* aunque no sea un SaaS con suscripción — la cláusula no exige un negocio, exige que un tercero reciba el beneficio de las reglas a través de nosotros en vez de usarlas él mismo bajo su propia aceptación de la licencia.
2. **La herramienta no empaqueta ni vendoriza contenido de `semgrep/semgrep-rules`.** El repo de la herramienta contiene solo código de orquestación (parseo de resultados, interfaz propia, etc.), nunca el texto/patrón/metadata de una regla copiado literalmente.
3. **El fetch al registro oficial ocurre en la ejecución del propio usuario** (p. ej. `semgrep --config=p/...` o `--config=r/...`, o clonar el repo oficial en caliente dentro del job del usuario) — nunca en un build/release nuestro que después se publique como artefacto con las reglas ya incluidas.
4. **Sin caché compartida entre usuarios.** Cualquier caché para acelerar ejecuciones debe vivir en el entorno local de cada usuario, nunca en un almacenamiento nuestro que sirva a más de un usuario.
5. **La herramienta solo escanea código del propio usuario que la invoca** — no terceros.

Cumpliendo esto, quien "usa" las reglas (a efectos de la licencia) es cada usuario final con su propia instalación de Semgrep contactando directamente al registro oficial — el mismo patrón que ya usan públicamente miles de GitHub Actions (`semgrep/semgrep-action` con `config: p/ci`, por ejemplo).

## Decisión

- `semgrep/semgrep-rules` (fuente oficial) sigue sin poder incorporarse a `rules/semgrep/third-party/` de este repo, por las razones ya documentadas en `NOTICE.md` y reafirmadas aquí.
- Se procede a implementar la herramienta-wrapper descrita arriba como **proyecto separado** de este repo de reglas curadas, cumpliendo las 5 condiciones listadas. Ver diseño e implementación en [ubicación pendiente de completar tras el diseño].
