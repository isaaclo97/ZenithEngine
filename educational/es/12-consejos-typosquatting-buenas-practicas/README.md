# 12. Consejos: typosquatting y buenas prácticas de cadena de suministro

**Tipo de lección:** consejos prácticos. No corresponde a una regla de Zenith Engine: usa un detector educativo propio ([`tools/typosquat.py`](../../tools/typosquat.py)) y reúne lo que conviene hacer siempre, más allá de lo que detecta cualquier herramienta.
**Relacionada con:** [01](../01-dependencias-sin-fijar/) (fijar por hash), [04](../04-integridad-acciones-artefactos/) (procedencia de las acciones), [10](../10-componentes-con-cve-conocido/) (vulnerabilidades conocidas).

## Qué es el typosquatting

Es registrar un nombre **casi idéntico** al de algo muy usado y esperar a que alguien se equivoque al escribirlo. Funciona igual con acciones de GitHub, paquetes de npm o PyPI, imágenes de Docker Hub y dominios. Las variantes más habituales:

| Truco | Ejemplo | Nombre real |
|---|---|---|
| Letra que falta | `actons/checkout` | `actions/checkout` |
| Letras cambiadas de sitio | `reqeusts`, `actions/setup-pyhton` | `requests`, `actions/setup-python` |
| Guion quitado o añadido | `crossenv` | `cross-env` |
| Singular por plural | `action/cache` | `actions/cache` |
| Homoglifos: letras que parecen otras | `jeIlyfish` (I mayúscula) | `jellyfish` |
| Variante ortográfica | `colourama` | `colorama` |

El paquete falso suele funcionar igual que el original (a veces lo copia entero), así que nadie nota nada: el código malicioso va aparte, normalmente en un script de instalación.

## Casos reales

- **`crossenv` (npm, 2017):** imitaba a `cross-env` y, al instalarse, enviaba las variables de entorno de la máquina (donde suelen estar las credenciales) a un servidor del atacante.
- **`colourama` (PyPI, 2018):** la ortografía británica de `colorama`. Vigilaba el portapapeles y cambiaba las direcciones de bitcoin copiadas por las del atacante.
- **`jeIlyfish` (PyPI, 2019):** con una I mayúscula en lugar de la primera l de `jellyfish`. Robaba claves SSH y GPG. Estuvo publicado cerca de un año.
- **Acciones de GitHub (2024):** investigadores de Orca Security mostraron que el truco funciona igual con acciones: registraron organizaciones con nombres casi idénticos a otras populares y encontraron workflows reales que las usaban por error.
- **Confusión de dependencias (2021):** Alex Birsan publicó en npm y PyPI paquetes con los mismos nombres que paquetes *internos* de grandes empresas (Apple, Microsoft, PayPal, entre otras) y una versión más alta. Sus sistemas de build los instalaron en lugar de los internos.
- **Este mismo laboratorio:** al revisarlo encontramos que varios hashes "fijados" no eran la versión que decía su comentario, y uno ni siquiera existía en el repositorio. Nadie lo había notado porque el comentario parecía correcto. Es la razón del modo `--online` de la simulación.

## Consejos

### Antes de añadir una acción o una dependencia

1. **Copia el nombre desde la fuente oficial** (el Marketplace, la documentación del proyecto, la página del registro). No lo teclees de memoria.
2. **Comprueba quién la publica.** Organización con insignia de creador verificado, repositorio enlazado desde la web oficial, historial largo. Las estrellas y las descargas se pueden inflar: no son una garantía.
3. **Mira qué ejecuta de verdad.** Lee el `action.yml`: si es un contenedor, un script o JavaScript compilado en `dist/`, y si descarga más cosas en tiempo de ejecución.
4. **Menos dependencias es menos riesgo.** Si lo que hace la acción son tres líneas de shell, escribe esas tres líneas.

### Al fijar versiones

5. **Fija por hash de commit completo**, con la versión en un comentario (lección [01](../01-dependencias-sin-fijar/)).
6. **Comprueba que el hash es esa versión y es de ese repositorio:**
   ```bash
   git ls-remote https://github.com/actions/checkout refs/tags/v7.0.1
   ```
   Ojo con los **commits impostores** (documentados por Chainguard en 2023): GitHub resuelve un hash de cualquier fork a través del nombre del repositorio original, así que `actions/checkout@<hash de un fork>` funciona aunque ese commit nunca haya estado en `actions/checkout`. Herramientas como `zizmor` lo detectan.
7. **Automatiza las actualizaciones** con Dependabot o Renovate: cambian hash y comentario a la vez y te abren un PR que puedes revisar.
8. **No adoptes una versión el mismo día que sale.** Muchos paquetes maliciosos se detectan y retiran en horas. Renovate (`minimumReleaseAge`) y Dependabot (`cooldown`) permiten esperar unos días.

### En la organización

9. **Lista de acciones permitidas:** en *Settings > Actions > General* se puede limitar qué acciones se pueden usar. GitHub también permite exigir que todas estén fijadas por hash completo.
10. **Protege los workflows con CODEOWNERS** (`/.github/workflows/ @equipo-seguridad`) para que ningún cambio en ellos entre sin revisión.
11. **Revisa las dependencias nuevas en cada PR** con `actions/dependency-review-action`, que puede bloquear las que tengan vulnerabilidades conocidas.

12. **No dejes que Actions apruebe sus propios PRs.** Desactiva *Settings > Actions > General > Allow GitHub Actions to create and approve pull requests*, y en la protección de rama exige al menos **dos** revisores humanos y activa *Require approval of the most recent reviewable push*. Si no, un workflow con `pull-requests: write` puede aprobar y fusionar su propio PR (o el de un atacante) usando el `GITHUB_TOKEN` y saltarse la revisión: es el bypass de branch protection clásico (ver lección [02](../02-permisos-excesivos-github-token/)).

13. **Cuidado con los self-hosted runners.** A diferencia de los de GitHub, no se destruyen entre ejecuciones: un compromiso persiste (malware, credenciales en disco, caché envenenada) y afecta al siguiente job. Hazlos efímeros (uno nuevo por ejecución, por ejemplo con Actions Runner Controller en Kubernetes), no los compartas entre repositorios de distinta confianza, añádeles controles de red de salida y **no los uses en repositorios públicos**: un PR desde un fork podría ejecutar código en tu propia máquina. Ver lección [11](../11-exfiltracion-red-y-superficie-ataque/).

### Paquetes (npm, PyPI...)

14. **Instala desde el lockfile:** `npm ci` en lugar de `npm install`; `pip install --require-hashes -r requirements.txt`, con el fichero generado por `pip-compile --generate-hashes`.
15. **Nombres internos con *scope* y un único índice:** `@empresa/utils` con el registro configurado para ese scope; en pip, un solo `--index-url` que haga de proxy, **nunca** `--extra-index-url`.
16. **Desactiva los scripts de instalación cuando puedas** (`npm ci --ignore-scripts`): `postinstall` es la vía habitual de los paquetes maliciosos.
17. **Publica sin tokens de larga duración:** npm y PyPI admiten *trusted publishing*, que autentica el workflow por OIDC (`permissions: id-token: write`) en lugar de guardar un `NPM_TOKEN` o un token de PyPI como secreto. Si no hay token, no hay token que robar.
18. **Nada de `curl ... | bash`:** descarga una versión concreta, verifica su checksum o su firma y después ejecútala.

### Si ya ha pasado

19. **Rota todos los secretos** a los que tuvo acceso el pipeline, revisa los logs de las ejecuciones afectadas, busca el nombre malicioso en todos tus repositorios y avisa al registro (npm, PyPI) o a GitHub para que lo retiren.

## Ejecuta la simulación

```bash
cd educational/es/12-consejos-typosquatting-buenas-practicas
pip install pyyaml requests
python3 simulate.py            # sin red
python3 simulate.py --online   # además comprueba cada hash contra GitHub
```

El script analiza `vulnerable.yml` y `fixed.yml`, explica con ejemplos cómo decide que un nombre es sospechoso (distancia de Levenshtein respecto a una lista de nombres populares, más normalización de homoglifos) y cuáles son sus límites. Con `--online`, además, pregunta a GitHub con `git ls-remote` a qué commit apunta de verdad cada versión del comentario: en `vulnerable.yml` hay un hash que no corresponde a nada.

## Tu turno

[`ejercicio.yml`](ejercicio.yml) es el CI de una API en Python. Se han colado erratas que podrían ser typosquatting y alguna forma arriesgada de instalar cosas. Corrígelo sin quitar ningún step.

```bash
cp ejercicio.yml mi_solucion.yml
python3 ../comprobar.py
```

<details>
<summary>Pistas</summary>

- Hay dos acciones con el nombre mal escrito. Una tiene el propietario en singular.
- Hay dos paquetes de PyPI con el nombre mal escrito. Los buenos van mejor en `requirements.txt`, con hashes.
- El linter se instala con `wget ... | sh`. Descarga una versión concreta y comprueba su SHA-256 antes de ejecutarla.
- Cuando corrijas los nombres, fija las acciones por hash (con la versión en un comentario).

</details>

**Termina con `python3 ../comprobar.py --online`**, que comprueba en GitHub que los hashes que has puesto existen y son la versión de su comentario. Es el mismo error que tuvo este laboratorio.

La solución está en [`../soluciones/12.yml`](../soluciones/12.yml).
