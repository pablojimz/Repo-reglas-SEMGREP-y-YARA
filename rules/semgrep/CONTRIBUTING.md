# Contribuir a rules/semgrep/

## Estructura

- `third-party/<fuente>/<lenguaje>/` — reglas importadas de un proyecto externo, sin
  modificar su lógica de negocio (solo ajustes de formato/paths si es imprescindible).
  Cada fuente tiene su propio `LICENSE` en la raíz de su carpeta.
- `custom/<lenguaje>/` — reglas escritas o adaptadas sustancialmente por este
  repositorio.
- `registry.json` — índice de todas las reglas con metadatos, incluida la licencia.
- `RULES-BY-LANGUAGE.md` — vista de navegación rápida por lenguaje.

## Checklist antes de añadir una nueva fuente externa (third-party/)

1. **Identificar la licencia original** del repositorio/proyecto fuente (revisar su
   `LICENSE`, `README`, y cabeceras de fichero — pueden diferir del `LICENSE` raíz).
2. **Comprobar compatibilidad** con el resto del repositorio:
   - ¿Es una licencia copyleft fuerte (p. ej. AGPL-3.0)? Si es así, documentarlo
     claramente en `NOTICE.md` y evaluar el impacto si este repo se distribuye o se
     ofrece como servicio.
   - ¿Incluye cláusulas adicionales no estándar (p. ej. Commons Clause)? Documentarlas
     explícitamente — pueden restringir la venta o el uso comercial de las reglas.
   - ¿Es compatible con MIT/Apache-2.0 si el resto del repo usa licencias permisivas?
3. **Copiar el texto completo de la licencia** a
   `third-party/<fuente>/LICENSE` (no enlazar, no resumir).
4. **Actualizar `NOTICE.md`** añadiendo la fuente a la tabla de licencias.
5. **Actualizar `registry.json`** añadiendo cada regla nueva con su campo
   `"license"` explícito (no heredar implícitamente del directorio).
6. **Actualizar `RULES-BY-LANGUAGE.md`** con los enlaces a las nuevas rutas.
7. **Solicitar revisión** de alguien listado en `CODEOWNERS` para `third-party/`.
8. **No modificar la lógica** de detección de una regla third-party sin dejar constancia
   (comentario + entrada en el registry) de que ha sido adaptada localmente; si el
   cambio es sustancial, considerar moverla a `custom/` citando la fuente original.

## Añadir una regla en custom/

1. Ubicarla en `custom/<lenguaje>/` según corresponda.
2. Incluir metadata estándar de Semgrep (`id`, `message`, `severity`, `languages`,
   `metadata.references`, etc.).
3. Añadir un test (`.yaml`/código de ejemplo con `ruleid:`/`ok:`) si el flujo de CI del
   repo lo requiere.
4. Registrar la regla en `registry.json`.

## Formato de registry.json

Cada entrada debe incluir, como mínimo:

```json
{
  "id": "namespace.rule-id",
  "path": "third-party/trailofbits/python/example.yaml",
  "language": "python",
  "source": "trailofbits",
  "license": "AGPL-3.0",
  "severity": "WARNING"
}
```
