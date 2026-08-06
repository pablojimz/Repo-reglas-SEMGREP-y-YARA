# Repo Reglas SEMGREP y YARA

Repositorio para la gestión, desarrollo y evaluación de reglas de Análisis Estático de Código (SAST) orientadas a la detección de vulnerabilidades, malas prácticas de seguridad y amenazas en código fuente, configuraciones de infraestructura (IaC) y contenedores.

---

## 📁 Estructura del Repositorio

* **`rules/semgrep/`**:
  * **`custom/`**: Reglas personalizadas organizadas por lenguaje (`c`, `csharp`, `dockerfile`, `html`, `java`, `javascript`, `json`, `ocaml`, `php`, `powershell`, `python`, `regex`, `ruby`, `rust`, `swift`). Incluye casos de prueba asociados (`.c`, `.py`, `.rs`, etc.).
  * **`third-party/`**: Reglas integradas de terceros (*Trail of Bits*, *0xdea*) para GitHub Actions, Ansible, Docker Compose y herramientas genéricas.
* **`.archivos/`**:
  * Reglas consolidadas para Dockerfile (`common_dockerfile_vulnerabilities.yaml`, `malicious_dockerfile_rules.yaml`) y OCaml (`ocaml_vulnerabilities.yaml`).
  * Casos de prueba e imágenes/scripts de validación (`test_cases/`).
* **`reports/`**: Informes de consultas e inteligencia de amenazas extraídos de VirusTotal (`search_results*.json`).
* **`.claude/`**: Criterios de puntuación y guías para asistentes IA / evaluadores de seguridad (`criterioPuntuacionReglas.md`).

---

## 📊 Sistema de Puntuación de Riesgo (`risk_score`)

Cada regla Semgrep incluye en sus Metadatos un cálculo cuantitativo de riesgo basado en la fórmula:

$$\text{Riesgo} = (0.45 \times S) + (0.30 \times C) + (0.25 \times E)$$

* **Severidad ($S$ - 45%):** Impacto en caso de explotación (100 = RCE/robo de datos, 75 = inyección/secretos, 50 = TLS/cifrado débil, 25 = código deficiente).
* **Confianza ($C$ - 30%):** Certeza del patrón AST/Regex para evitar falsos positivos (100 = patrón exacto, 60 = posible trampa, 30 = regex genérico).
* **Explotabilidad ($E$ - 25%):** Facilidad de desencadenar la falla (100 = automático en build/despliegue, 80 = flujo normal, 40 = requiere flag/debug, 10 = código muerto).

Ejemplo de metadatos en una regla YAML:
```yaml
metadata:
  severity_score: 75
  confidence_score: 100
  exploitability_score: 80
  risk_score: 84
  risk_justification: "Falta de validación permite RCE bajo flujo de ejecución normal."
```

---

## 🚀 Uso y Ejecución de Semgrep

### Requisitos
Tener [Semgrep](https://semgrep.dev/) instalado:
```bash
pip install semgrep
# O mediante brew/apt según el sistema operativo
```

### 1. Escanear código con reglas personalizadas
Para analizar un proyecto o archivo usando las reglas personalizadas:
```bash
semgrep --config rules/semgrep/custom/ /ruta/a/tu/codigo
```

Para aplicar solo un lenguaje específico (por ejemplo, Python):
```bash
semgrep --config rules/semgrep/custom/python/ /ruta/a/tu/codigo
```

### 2. Escanear con reglas de terceros
```bash
semgrep --config rules/semgrep/third-party/ /ruta/a/tu/codigo
```

### 3. Ejecutar pruebas unitarias de las reglas
Semgrep permite validar automáticamente las reglas contra sus archivos de prueba (casos vulnerables y seguros):
```bash
semgrep --test rules/semgrep/custom/
```

---

## 🤝 Contribuciones

Al agregar una nueva regla:
1. Ubica la regla en `rules/semgrep/custom/<lenguaje>/`.
2. Incluye un archivo de prueba correspondiente (ej. `mi-regla.yaml` y `mi-regla.py`).
3. Completa el bloque `metadata` calculando los valores de `severity_score`, `confidence_score`, `exploitability_score` y `risk_score` siguiendo las pautas de `.claude/criterioPuntuacionReglas.md`.
