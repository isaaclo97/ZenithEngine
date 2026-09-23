# 04. Integridad de acciones y artefactos (AIW: Artifact Integrity Weakness)

**CWE:** CWE-353 (Missing Support for Integrity Check) / CWE-494 (Download of Code Without Integrity Check)
**Categoría OWASP CI/CD:** CICD-SEC-8 / CICD-SEC-9 (Ungoverned Usage of 3rd Party Services / Improper Artifact Integrity Validation)
**Reglas Zenith Engine:** `R1007` (acción de organización no verificada), `R1008` (acción no encontrada en el Marketplace), `R1010` (artefacto publicado sin verificación de integridad)
**Frecuencia real observada:** 2.134 alertas (9,8% del total).

## Qué es

Tres formas distintas de la misma pregunta: *"¿lo que se ejecuta/publica es realmente lo que crees que es?"*

- **`R1007`**: la acción pertenece a una organización que no está en `engine/verified_organizations.txt` (organizaciones con buena reputación y mantenimiento activo conocido: `actions`, `github`, `docker`, `aws-actions`...). No significa que la acción sea maliciosa, pero sí que **nadie ha verificado su procedencia** por ti.
- **`R1008`**: la referencia `uses:` no corresponde a ningún repositorio con `action.yml`/`action.yaml` accesible vía la API de GitHub. Puede ser un typo, una acción borrada, o (en el peor caso) un intento de **typosquatting**: un atacante registra `actions/checkuot` esperando que alguien la use por error.
- **`R1010`**: el job publica un artefacto (imagen Docker, paquete PyPI, release de GitHub, binario con `goreleaser`...) sin firmarlo ni verificarlo con una herramienta de integridad como **cosign** (Sigstore). Sin firma, cualquiera que comprometa el paso de build puede alterar el artefacto entre que se construye y que se publica, sin dejar ninguna evidencia verificable.

## Por qué importa

`R1007`/`R1008` son la puerta de entrada del **supply-chain de acciones**: si confías ciegamente en cualquier `owner/accion@tag` sin comprobar quién lo mantiene, estás delegando la seguridad de tu pipeline en la higiene de seguridad de un tercero desconocido con acceso potencial a tus secretos (ver lección [`02`](../02-permisos-excesivos-github-token/)).

`R1010` protege el otro extremo de la cadena: aunque tu pipeline sea perfecto, si publicas un artefacto sin firma, **nada impide que alguien lo sustituya después** (en un registry comprometido, en tránsito, o directamente en el propio job si hay un paso intermedio comprometido) y que tus usuarios finales instalen ese artefacto alterado confiando en que viene de ti.

## Cómo solucionarlo

**Para `R1007`/`R1008`:**
1. Antes de adoptar una acción de un autor individual o de una organización desconocida, revisa: número de estrellas, actividad reciente, si tiene badge de verificación de GitHub, si aparece en el Marketplace oficial.
2. Prioriza forks/mirrors mantenidos por organizaciones que sí controlas, o vendoriza la acción como composite action local (`./local-actions/...`) tras revisar su código.
3. Si decides usarla igualmente, fíjala siempre por hash (lección [`01`](../01-dependencias-sin-fijar/)) para que un futuro compromiso de esa cuenta no te afecte automáticamente.

**Para `R1010`:**
```yaml
- uses: docker/build-push-action@<hash> # v7.4.0
  id: build
  with:
    push: true
    tags: myorg/myimage:${{ github.sha }}

- uses: sigstore/cosign-installer@<hash> # v3.5.0

- env:
    DIGEST: ${{ steps.build.outputs.digest }}
  run: cosign sign --yes "myorg/myimage@${DIGEST}"
```
Esto firma la imagen con **Sigstore keyless signing** usando la propia identidad OIDC del workflow de GitHub Actions, de modo que quien consuma la imagen puede verificar con `cosign verify` que salió exactamente de este repositorio y este workflow.

> **Por qué `fixed.yml` sigue dando un R1007:** `sigstore` no está en `engine/verified_organizations.txt`, así que R1007 marca `sigstore/cosign-installer` aunque sea la herramienta oficial de firma. La lista de organizaciones verificadas es una heurística corta, no un registro de todo lo fiable. La alerta sigue siendo útil: obliga a decidir conscientemente que confías en esa organización. Si prefieres no depender de ninguna acción de terceros, la solución del ejercicio "Tu turno" descarga cosign de su release oficial y comprueba su SHA-256.

## Ejecuta la simulación

```bash
cd educational/es/04-integridad-acciones-artefactos
pip install pyyaml requests
python3 simulate.py
```

El script reproduce `R1007`/`R1008`(offline, sin llamar a la API real de GitHub)/`R1010`, y simula el escenario de integridad: genera un "hash" ficticio del artefacto en el momento del build y otro tras una manipulación simulada en el registry, mostrando cómo `cosign verify` lo detectaría mientras que un `docker pull` normal no lo haría.

## Tu turno

[`ejercicio.yml`](ejercicio.yml) construye y publica una imagen Docker. Usa una acción con un nombre sospechoso, otra de un autor desconocido, y publica la imagen sin firmar. Arréglalo sin quitar ningún step (puedes añadir los que necesites).

```bash
cp ejercicio.yml mi_solucion.yml     # trabaja sobre la copia
python3 ../comprobar.py              # repite hasta ver "SUPERADO"
python3 ../comprobar.py --todas      # reto extra: todas las reglas del motor
```

El comprobador ejecuta las mismas reglas reales de esta lección y además verifica que no hayas "resuelto" el ejercicio borrando lo que fallaba.

<details>
<summary>Pistas</summary>

- Lee con atención el nombre de la primera acción, letra a letra.
- Analizar un Dockerfile no requiere una acción de terceros: la imagen oficial `hadolint/hadolint` se puede ejecutar con un `run:`.
- Para firmar con cosign sin depender de una acción de terceros, descarga el binario de su release oficial y comprueba su SHA-256 con `sha256sum -c` antes de usarlo. La firma keyless necesita `id-token: write`.

</details>

La solución está en [`../soluciones/04.yml`](../soluciones/04.yml). Inténtalo antes de mirarla.
