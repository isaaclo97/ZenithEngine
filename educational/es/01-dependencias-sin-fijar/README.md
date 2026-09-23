# 01. Dependencias sin fijar (UDW: Unpinned Dependency Weakness)

**CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Categoría OWASP CI/CD:** CICD-SEC-8 (Ungoverned Usage of 3rd Party Services)
**Reglas Zenith Engine:** `R1002` (acción sin hash fijo), `R1012` (rama usada como versión), `R1017` (uso de `@latest`)
**Frecuencia real observada:** 10.345 alertas, **la debilidad más común con diferencia** (47% de todo lo detectado).

## Qué es

Cuando un `step` usa `uses: owner/accion@REF`, `REF` puede ser tres cosas muy distintas en cuanto a garantías de seguridad:

1. **Un hash de commit** (`@a1b2c3...`, 40 caracteres hexadecimales): inmutable. Ese contenido nunca cambia.
2. **Un tag** (`@v4`, `@v4.1.0`): **mutable**. El propietario de la acción (o cualquiera que comprometa su cuenta) puede reasignar el tag `v4` a un commit completamente distinto en cualquier momento, y tu workflow lo ejecutará automáticamente en la siguiente ejecución sin que nadie haya tocado tu `.yml`.
3. **Una rama** (`@main`, `@master`) o **`@latest`**: se mueve con cada commit nuevo del repositorio de la acción. Tu pipeline puede ejecutar código distinto en cada `run` sin ningún control ni revisión.

Zenith Engine separa esto en tres reglas:
- `R1002` salta con cualquier referencia que no sea un hash (severidad MEDIUM, el caso general).
- `R1012` sube a HIGH cuando la referencia ni siquiera es un tag con forma de versión (`v4`, `4.1.0`) ni un hash, es decir, cuando parece el nombre de una rama (`main`, `master`, `develop`).
- `R1017` sube a CRITICAL cuando la referencia es literalmente `@latest`, el caso más peligroso porque apunta explícitamente a "lo último que haya", sin ni siquiera la ilusión de estabilidad de un nombre de rama fijo.

## Por qué importa

Este es exactamente el vector del ataque a **`tj-actions/changed-files`** (marzo 2025, CVE-2025-30066): un tag mutable (`v35`, `v36`...) fue reapuntado a un commit malicioso que volcaba secretos de CI en los logs de ejecución. Cualquier workflow que usara `tj-actions/changed-files@v35` (en vez de un hash) empezó a ejecutar código malicioso automáticamente, sin que nadie hubiera cambiado una sola línea de su propio `.yml`. Miles de repositorios se vieron afectados de la noche a la mañana.

Fijar por hash no es paranoia: es la única forma de que "lo que revisaste" y "lo que se ejecuta" sean garantizadamente lo mismo.

## Cómo detectarlo manualmente

Busca en tus workflows cualquier `uses:` cuya parte después de `@` no sean 40 caracteres hexadecimales:

```bash
grep -rn "uses:" .github/workflows/ | grep -vE "@[0-9a-f]{40}"
```

## Cómo solucionarlo

1. Sustituye el tag por el hash de commit exacto al que apunta hoy (`git ls-remote https://github.com/owner/accion v4` o mirando la página del release en GitHub).
2. Deja el tag como comentario al lado, para que siga siendo legible para humanos:
   ```yaml
   - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
   ```
3. Usa **Dependabot** o **Renovate** con soporte para `github-actions` en `.github/dependabot.yml`: ambos actualizan automáticamente el hash cuando sale una nueva versión, abriendo un PR revisable en vez de aplicar el cambio silenciosamente.
4. Si no puedes fijar por hash (por ejemplo, una acción interna que cambia mucho), como mínimo usa un tag de versión semántica (`@v4`) en lugar de una rama o `@latest`, y considera activar **step-security/harden-runner** con `disable-sudo` y monitorización de red (ver lección [`03-hardening-runner-egress`](../03-hardening-runner-egress/)) para detectar comportamiento anómalo si el tag es secuestrado.

## Ejecuta la simulación

```bash
cd educational/es/01-dependencias-sin-fijar
pip install pyyaml requests
python3 simulate.py
```

El script ejecuta las reglas reales `R1002`/`R1012`/`R1017` del motor, y además **simula el ataque a `tj-actions/changed-files`**: muestra cómo el mismo tag (`@v35`) puede "resolverse" a dos commits distintos en dos ejecuciones diferentes del pipeline, sin que el `.yml` cambie una sola línea.

## Tu turno

[`ejercicio.yml`](ejercicio.yml) publica la documentación del proyecto usando cinco acciones, y ninguna está fijada de forma inmutable: hay tags, una rama y un `@latest`. Haz que todo lo que ejecuta sea inmutable sin quitar ningún step.

```bash
cp ejercicio.yml mi_solucion.yml     # trabaja sobre la copia
python3 ../comprobar.py              # repite hasta ver "SUPERADO"
python3 ../comprobar.py --todas      # reto extra: todas las reglas del motor
```

El comprobador ejecuta las mismas reglas reales de esta lección y además verifica que no hayas "resuelto" el ejercicio borrando lo que fallaba.

<details>
<summary>Pistas</summary>

- Cada `uses:` tiene que acabar en `@` seguido de 40 caracteres hexadecimales.
- Para saber el hash de una versión: `git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>`. Si la etiqueta es anotada, el commit es la línea que acaba en `^{}`.
- Deja la versión en un comentario (`# v7.0.1`) para que un humano sepa qué hay detrás del hash.

</details>

**Termina con `python3 ../comprobar.py --online`.** Sin red, el comprobador solo puede ver que el hash tiene 40 caracteres: aceptaría uno inventado. Con `--online` pregunta a GitHub si ese hash es de verdad la versión que dice tu comentario.

La solución está en [`../soluciones/01.yml`](../soluciones/01.yml). Inténtalo antes de mirarla.
