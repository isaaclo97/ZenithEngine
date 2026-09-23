# Carpeta educativa: fallos comunes en workflows de GitHub Actions

Este directorio acompaña a **Zenith Engine** con material didáctico sobre los fallos de seguridad más habituales detectados al analizar workflows reales de GitHub Actions (más de 21.000 alertas al escanear un corpus de workflows reales de repositorios públicos).

Cada carpeta es una **lección autocontenida** sobre una de las "debilidades comunes" (*common weaknesses*) descritas en el paper *"Unpacking Security Scanners for GitHub Actions Workflows"* (Fares, Gamage & Baudry), la misma taxonomía que usa Zenith Engine para clasificar sus 26 reglas (ver tabla `Rule → common weakness mapping` en el `README.md` raíz del proyecto).

Además hay dos lecciones que no corresponden a una debilidad concreta: la **00**, con los fundamentos de GitHub Actions que el resto da por sabidos, y la **12**, con consejos contra el typosquatting y buenas prácticas de cadena de suministro.

## Por dónde empezar

- **Si nunca has escrito un workflow:** empieza por la [00](00-fundamentos-github-actions/) y sigue en orden.
- **Si ya conoces GitHub Actions:** ve directamente a la 01. El orden va de lo más frecuente (higiene básica) a lo más grave (inyección, secretos, triggers privilegiados).
- **Para terminar:** la [12](12-consejos-typosquatting-buenas-practicas/) resume qué hacer siempre, más allá de lo que detecte cualquier herramienta.

Cada lección termina con un ejercicio **"Tu turno"** que se corrige solo.

## Cómo está organizada cada lección

Dentro de cada carpeta encontrarás siempre:

- **`README.md`**: qué es el fallo, por qué ocurre, qué riesgo real implica (con incidentes conocidos cuando aplica), qué reglas de Zenith Engine lo detectan y cómo solucionarlo.
- **`vulnerable.yml`**: un workflow realista con el fallo presente.
- **`fixed.yml`**: el mismo workflow ya corregido. (La lección 00 usa en su lugar un único `ejemplo.yml` comentado línea a línea.)
- **`simulate.py`**: un script en Python que importa y ejecuta **las funciones reales de `engine/rules/*.py`** (las mismas que usa la aplicación Flask, con `engine/parser.py` incluido para el parseo) sobre `vulnerable.yml`, y cuando es posible **simula el efecto real del ataque** (qué comando acabaría ejecutándose, qué dato se filtraría, qué permisos heredaría el token...). Al final se ejecuta también contra `fixed.yml` para que se vea el contraste antes/después. La única excepción es `R1008` (lección 04), que en producción llama a la API de GitHub; aquí se sustituye por un mock local explícito para no depender de red.
- **`ejercicio.yml`**: el ejercicio "Tu turno", un workflow distinto con el mismo tipo de fallo para que lo corrijas tú.
- **`docker/`** *(solo en las lecciones donde aporta algo)*: un entorno aislado con `docker compose up` para observar el impacto sin tocar GitHub real (por ejemplo, ejecutar localmente el comando inyectado, o levantar un "receptor" que capture una exfiltración simulada).

## Cómo usar cada lección

```bash
cd educational/es/<carpeta>
python3 -m venv .venv && source .venv/bin/activate   # opcional
pip install pyyaml requests
python3 simulate.py
```

`simulate.py` no requiere las dependencias completas del proyecto (no hace falta Flask); solo `pyyaml` y `requests`, ambas ya en `requirements.txt` del repo raíz. Si ya has instalado ese fichero (`pip install -r requirements.txt` desde la raíz), no necesitas instalar nada más.

### Ejercicios "Tu turno"

```bash
cp ejercicio.yml mi_solucion.yml     # trabaja siempre sobre una copia
python3 ../comprobar.py              # comprueba mi_solucion.yml
python3 ../comprobar.py --todas      # reto extra: todas las reglas del motor, no solo las de la lección
python3 ../comprobar.py --online     # además comprueba en GitHub que tus hashes existen (necesita red)
```

[`comprobar.py`](comprobar.py) ejecuta sobre tu solución las mismas reglas reales de la lección y verifica además que no la hayas "resuelto" borrando el step que fallaba, la condición o el dato. Las soluciones están en [`soluciones/`](soluciones/): mira la tuya solo cuando la hayas intentado.

## Índice de lecciones

| # | Carpeta | Debilidad común | Reglas Zenith | Severidad típica |
|---|---------|------------------|----------------|-------------------|
| 00 | [`fundamentos-github-actions`](00-fundamentos-github-actions/) | Conceptos básicos y modelo de confianza | (estructura del workflow, R1003) | |
| 01 | [`dependencias-sin-fijar`](01-dependencias-sin-fijar/) | UDW: Unpinned Dependency Weakness | R1002, R1012, R1017 | MEDIUM a CRITICAL |
| 02 | [`permisos-excesivos-github-token`](02-permisos-excesivos-github-token/) | EPW: Excessive Permission Weakness | R1003, R1011 | MEDIUM a HIGH |
| 03 | [`hardening-runner-egress`](03-hardening-runner-egress/) | HGW: Hardening Gap Weakness | R1004 | LOW a MEDIUM |
| 04 | [`integridad-acciones-artefactos`](04-integridad-acciones-artefactos/) | AIW: Artifact Integrity Weakness | R1007, R1008, R1010 | LOW a MEDIUM |
| 05 | [`runtime-obsoleto-runner-desconocido`](05-runtime-obsoleto-runner-desconocido/) | GRCW: GitHub Runner Compatibility Weakness | R1023, R1024 | LOW a MEDIUM |
| 06 | [`triggers-privilegiados-pull-request-target`](06-triggers-privilegiados-pull-request-target/) | PTW: Privileged Trigger Weakness | R1000, R1001, R1021 | HIGH a CRITICAL |
| 07 | [`inyeccion-de-expresiones`](07-inyeccion-de-expresiones/) | IW: Injection Weakness | R1016 | CRITICAL |
| 08 | [`exposicion-de-secretos`](08-exposicion-de-secretos/) | SEW: Secrets Exposure Weakness | R1014, R1019 | CRITICAL |
| 09 | [`condiciones-if-siempre-true`](09-condiciones-if-siempre-true/) | CFW: Control Flow Weakness | R1022 | HIGH |
| 10 | [`componentes-con-cve-conocido`](10-componentes-con-cve-conocido/) | KVCW: Known Vulnerable Component Weakness | R1025 | CRITICAL |
| 11 | [`exfiltracion-red-y-superficie-ataque`](11-exfiltracion-red-y-superficie-ataque/) | Reglas específicas de Zenith (fuera de la taxonomía) | R1005, R1006, R1009, R1013, R1015, R1018, R1020 | LOW a CRITICAL |
| 12 | [`consejos-typosquatting-buenas-practicas`](12-consejos-typosquatting-buenas-practicas/) | Consejos: typosquatting y cadena de suministro | Detector educativo propio + R1002 | |

## Frecuencia real observada

Los porcentajes provienen de escanear con Zenith Engine el corpus de 2.722 workflows reales de repositorios públicos del estudio de referencia (Fares, Gamage & Baudry, *"Unpacking Security Scanners for GitHub Actions Workflows"*). De ellos, 2.720 tuvieron al menos una alerta, 21.886 en total. Los workflows escaneados no se incluyen aquí: pertenecen a ese estudio. La distribución por debilidad fue:

| Debilidad | Nº de alertas | % del total |
|---|---:|---:|
| UDW | 10.345 | 47,3% |
| HGW | 5.197 | 23,7% |
| EPW | 2.183 | 10,0% |
| AIW | 2.134 | 9,8% |
| GRCW | 876 | 4,0% |
| Específicas de Zenith (OTRO) | 587 | 2,7% |
| IW | 362 | 1,7% |
| PTW | 131 | 0,6% |
| SEW | 63 | 0,3% |
| CFW | 6 | <0,1% |
| KVCW | 2 | <0,1% |

Es decir: la inmensa mayoría de los problemas reales son **higiene básica** (dependencias sin fijar y falta de hardening del runner), mientras que los fallos más graves en impacto (inyección, secretos expuestos, triggers privilegiados) son mucho más raros pero muchísimo más peligrosos cuando aparecen. Por eso cada lección indica severidad además de frecuencia.

## Aviso

Todo el material de esta carpeta es **educativo**. Los workflows `vulnerable.yml` son ejemplos sintéticos (no pertenecen a ningún repositorio real) pensados para ilustrar el patrón; los scripts `simulate.py` no ejecutan nada contra GitHub ni contra servicios externos reales: todo ocurre localmente, en el propio proceso Python o en el contenedor Docker aislado de la lección. La única excepción es opcional: `simulate.py --online` en la lección 12 consulta a GitHub (`git ls-remote`, solo lectura) a qué commit apunta cada versión.
