# 02. Permisos excesivos del `GITHUB_TOKEN` (EPW: Excessive Permission Weakness)

**CWE:** CWE-250 (Execution with Unnecessary Privileges) / CWE-732 (Incorrect Permission Assignment)
**Categoría OWASP CI/CD:** CICD-SEC-5 (Insufficient PBAC: Pipeline-Based Access Controls)
**Reglas Zenith Engine:** `R1003` (sin bloque `permissions`), `R1011` (acción de tercero con acceso al `GITHUB_TOKEN`)
**Frecuencia real observada:** 2.183 alertas (10% del total), la tercera debilidad más común.

## Qué es

Cada ejecución de un workflow recibe automáticamente un `GITHUB_TOKEN` de corta duración. Si el workflow **no declara explícitamente** un bloque `permissions:` (ni a nivel de workflow ni de job), ese token hereda los **permisos por defecto del repositorio**, que en muchas organizaciones siguen siendo `read/write` sobre casi todo: contenidos, issues, pull requests, packages, etc. (Los repositorios y organizaciones creados desde 2023 empiezan en solo lectura, pero el ajuste se hereda y se cambia a mano, así que no conviene suponerlo.)

`R1003` avisa de esto: ningún `permissions:` definido = superficie de ataque máxima por defecto.

`R1011` es más específico: si una **acción de terceros no verificada** tiene acceso a ese token (bien porque lo recibe explícitamente en un `with:`/`env:`, bien porque hereda los permisos del job), y esa acción se ve comprometida (ver lección [`01`](../01-dependencias-sin-fijar/) sobre `tj-actions/changed-files`), el atacante puede usar el token para lo que sea que el token pueda hacer: publicar releases falsos, borrar ramas, modificar el código del repositorio, escribir en Packages...

## Por qué importa

El principio es simple: **el radio de explosión de un `GITHUB_TOKEN` comprometido es exactamente su nivel de permisos**. Un pipeline de CI que solo necesita leer el código (`contents: read`) pero que corre con los permisos por defecto (`contents: write`, `issues: write`, `pull-requests: write`...) convierte cualquier acción de terceros comprometida en la lección 01 en una vía para:

- Modificar el repositorio directamente (`contents: write`).
- Fusionar sus propios pull requests maliciosos (`contents: write`) y aprobarlos, si la organización tiene activado *Allow GitHub Actions to create and approve pull requests* (`pull-requests: write`).
- Publicar paquetes falsos bajo tu nombre (`packages: write`).

## Cómo solucionarlo

1. Declara **siempre** un bloque `permissions:` a nivel de workflow con el mínimo posible, y sube el nivel solo en el job concreto que lo necesite:
   ```yaml
   permissions:
     contents: read

   jobs:
     release:
       permissions:
         contents: write   # solo este job necesita escribir
   ```
2. Si el repositorio necesita permisos amplios *en algún* job, no los pongas a nivel global; decláralos únicamente en ese job (permisos "de mínimos" por job, no por workflow).
3. Antes de dar acceso al token a una acción de terceros (`with: token: ${{ secrets.GITHUB_TOKEN }}` o similar), comprueba que la organización está verificada (ver `engine/verified_organizations.txt`) y que el permiso que le das es el mínimo indispensable.
4. Activa el ajuste de organización **"Workflow permissions" → "Read repository contents permission"** en GitHub, que cambia el permiso por defecto de todo el repositorio a solo lectura salvo que un workflow pida explícitamente más.

5. **No dejes el token en disco si no hace falta.** `actions/checkout` guarda el `GITHUB_TOKEN` en `.git/config` por defecto; con `persist-credentials: false` no lo hace. Unos permisos mínimos limitan lo que puede hacer el token; esto limita quién llega a verlo.

## Ejecuta la simulación

```bash
cd educational/es/02-permisos-excesivos-github-token
pip install pyyaml requests
python3 simulate.py
```

El script no solo replica `R1003`/`R1011`: **construye la tabla de permisos efectivos** que tendría el `GITHUB_TOKEN` en cada job del workflow (igual que aparecería en la pestaña "Permissions" de la ejecución en GitHub) y muestra, para el job vulnerable, qué operaciones concretas de la API de GitHub quedarían al alcance de una acción de terceros comprometida.

## Tu turno

[`ejercicio.yml`](ejercicio.yml) etiqueta los PRs nuevos y da la bienvenida a su autor. No declara permisos y le entrega el `GITHUB_TOKEN` a una acción de un autor desconocido. Corrígelo manteniendo los parámetros (`with:`) de cada step.

```bash
cp ejercicio.yml mi_solucion.yml     # trabaja sobre la copia
python3 ../comprobar.py              # repite hasta ver "SUPERADO"
python3 ../comprobar.py --todas      # reto extra: todas las reglas del motor
```

El comprobador ejecuta las mismas reglas reales de esta lección y además verifica que no hayas "resuelto" el ejercicio borrando lo que fallaba.

<details>
<summary>Pistas</summary>

- Declara `permissions:` a nivel de workflow con lo mínimo, y sube solo en el job lo que haga falta para etiquetar y comentar.
- Etiquetar PRs según los ficheros cambiados es exactamente lo que hace `actions/labeler`, de una organización verificada.
- El comprobador exige que `repo-token` siga existiendo: la solución no es quitarle el token, sino dárselo a quien se lo merece.

</details>

La solución está en [`../soluciones/02.yml`](../soluciones/02.yml). Inténtalo antes de mirarla.
