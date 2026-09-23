# 00. Fundamentos de GitHub Actions

**Para quién:** si nunca has escrito un workflow, o si términos como *job*, *runner* o `GITHUB_TOKEN` te suenan pero no sabrías explicarlos. Las lecciones 01 a 12 dan todo esto por sabido.
**Qué te llevas:** saber leer cualquier workflow y hacerte las cuatro preguntas de seguridad que se repiten en todo el curso.

## Qué es CI/CD y dónde encaja GitHub Actions

**CI** (*integración continua*) es ejecutar automáticamente la compilación y los tests cada vez que alguien propone un cambio. **CD** (*entrega o despliegue continuo*) es publicar automáticamente el resultado: un paquete, una imagen Docker, una web. GitHub Actions es el sistema de CI/CD integrado en GitHub: describes qué hacer en un fichero YAML y GitHub lo ejecuta en sus máquinas.

Desde el punto de vista de la seguridad, un pipeline de CI/CD es un objetivo muy atractivo: **ejecuta código automáticamente, tiene credenciales para publicar y todo lo que produce acaba en manos de tus usuarios.** Quien lo controla, controla lo que distribuyes. De eso trata la seguridad de la **cadena de suministro** (*supply chain*): de todo lo que entra en tu software sin que lo hayas escrito tú.

## Las piezas de un workflow

Abre [`ejemplo.yml`](ejemplo.yml) mientras lees esta tabla: está comentado línea a línea.

| Pieza | Dónde aparece | Qué es |
|---|---|---|
| **Workflow** | `.github/workflows/*.yml` | Un fichero YAML con un proceso automatizado. Un repositorio puede tener varios. |
| **Evento** | `on:` | Qué lo dispara: un `push`, un pull request, un comentario, un horario (`schedule`), un botón (`workflow_dispatch`)... |
| **Job** | `jobs:` | Un bloque de trabajo. Cada job corre en su propia máquina. Por defecto van en paralelo; `needs:` los encadena. |
| **Runner** | `runs-on:` | La máquina donde corre el job. `ubuntu-latest` es una máquina de GitHub, nueva en cada ejecución. `self-hosted` es una máquina tuya que **no** se borra entre ejecuciones. |
| **Step** | `steps:` | Cada paso de un job, en orden. Es de uno de dos tipos: `uses:` o `run:`. |
| **Acción** | `uses: owner/repo@versión` | Código de **otro repositorio** que se ejecuta dentro de tu job. Es la dependencia más habitual (y más olvidada) de un pipeline. |
| **Script** | `run:` | Comandos de shell escritos en tu propio workflow. |
| **Parámetros** | `with:` / `env:` | `with:` son las entradas de una acción; `env:` son variables de entorno del step o del job. |
| **Expresión** | `${{ ... }}` | GitHub la **sustituye por su valor antes** de ejecutar el step. Da acceso a contextos: `github.*` (datos del evento), `secrets.*`, `vars.*`, `steps.*`, `needs.*`... |
| **Condición** | `if:` | Decide si un job o un step se ejecuta. |
| **Secreto** | `secrets.NOMBRE` | Un valor cifrado (token, contraseña) que se configura en *Settings > Secrets*. |
| **`GITHUB_TOKEN`** | automático | Un token temporal que GitHub crea en cada ejecución para hablar con su API. Lo que puede hacer se controla con `permissions:`. |
| **Artefacto** | `upload-artifact` | Un fichero que sobrevive al job, para pasarlo a otro job o descargarlo después. |

## Las cuatro preguntas de seguridad

Todas las lecciones son variaciones de estas cuatro preguntas. Hazlas siempre que leas un workflow:

1. **¿Quién puede disparar esto?** Un `push` solo lo hace alguien con permiso de escritura. Un `pull_request` o un `issue_comment` lo puede provocar **cualquier persona con cuenta en GitHub**.
2. **¿Con qué privilegios corre?** Qué permisos tiene el `GITHUB_TOKEN`, a qué secretos accede y en qué máquina se ejecuta.
3. **¿Qué código ajeno ejecuta?** Cada `uses:` es código de un tercero; cada `npm install` o `pip install`, también. Si cambia, cambia tu pipeline sin que nadie toque tu repositorio.
4. **¿Qué datos que no controlo entran?** El título de un PR, el cuerpo de un comentario, el nombre de una rama: los escribe quien dispara el evento, y pueden llegar a un script o a un comando.

## Eventos: quién los dispara y con qué acceso

| Evento | Quién lo puede provocar | ¿Secretos y token con escritura? |
|---|---|---|
| `push` | Quien tenga permiso de escritura | Sí |
| `pull_request` | **Cualquiera**, desde un fork | Desde un fork, **no**: token de solo lectura y sin secretos. Es el diseño seguro. |
| `pull_request_target` | **Cualquiera**, desde un fork | **Sí**, con los privilegios del repositorio. Peligroso si ejecuta el código del PR (lección 06). |
| `issue_comment`, `issues` | **Cualquiera** que pueda comentar o abrir issues | Sí |
| `workflow_dispatch` | Quien tenga permiso de escritura | Sí |
| `schedule` | Nadie: lo lanza un horario | Sí |
| `workflow_run` | Otro workflow al terminar | Sí, aunque el workflow anterior haya procesado datos de un fork |

## El `GITHUB_TOKEN` y `permissions:`

Si un workflow no declara `permissions:`, el token recibe los **permisos por defecto** del repositorio o de la organización. En los repositorios creados en los últimos años suelen ser de solo lectura, pero muchos repositorios y organizaciones antiguos siguen dando escritura sobre casi todo. Por eso la buena práctica es declararlo siempre, con el mínimo necesario:

```yaml
permissions:
  contents: read        # a nivel de workflow: solo leer

jobs:
  publicar:
    permissions:
      contents: write   # y más solo en el job que lo necesita
```

Un detalle que verás en todos los workflows corregidos del curso: `actions/checkout` **guarda el token en `.git/config`** por defecto, para que los steps siguientes puedan hacer `git push`. Si el job no va a hacer push, se desactiva con `persist-credentials: false`. Así el token no se queda en disco al alcance de cualquier step posterior, ni acaba dentro de un artefacto que suba esa carpeta.

```yaml
- uses: actions/checkout@<hash> # v7.0.1
  with:
    persist-credentials: false
```

## Mapa del curso

| Pieza del workflow | Lecciones |
|---|---|
| Acciones (`uses:`) y dependencias | [01](../01-dependencias-sin-fijar/), [04](../04-integridad-acciones-artefactos/), [05](../05-runtime-obsoleto-runner-desconocido/), [10](../10-componentes-con-cve-conocido/), [12](../12-consejos-typosquatting-buenas-practicas/) |
| `GITHUB_TOKEN` y `permissions:` | [02](../02-permisos-excesivos-github-token/) |
| Runner y red | [03](../03-hardening-runner-egress/), [05](../05-runtime-obsoleto-runner-desconocido/), [11](../11-exfiltracion-red-y-superficie-ataque/) |
| Eventos (`on:`) | [06](../06-triggers-privilegiados-pull-request-target/), [11](../11-exfiltracion-red-y-superficie-ataque/) |
| Expresiones `${{ }}` y datos no confiables | [07](../07-inyeccion-de-expresiones/) |
| Secretos | [08](../08-exposicion-de-secretos/) |
| Condiciones `if:` | [09](../09-condiciones-if-siempre-true/) |

## Ejecuta la simulación

```bash
cd educational/es/00-fundamentos-github-actions
pip install pyyaml requests
python3 simulate.py
```

El script lee `ejemplo.yml` con el parser real de Zenith Engine y dibuja su **mapa de confianza**: qué eventos lo disparan y quién puede provocarlos, dónde corre cada job y con qué permisos, qué acciones de terceros ejecuta y cómo están fijadas, y qué expresiones traen datos no confiables o secretos. Es exactamente el razonamiento de las cuatro preguntas, hecho de forma automática.

## Tu turno

[`ejercicio.yml`](ejercicio.yml) tiene seis errores de estructura (y le falta el bloque `permissions:`): GitHub no llegaría ni a ejecutarlo. Corrígelo con `ejemplo.yml` como referencia.

```bash
cp ejercicio.yml mi_solucion.yml     # trabaja sobre la copia
python3 ../comprobar.py              # repite hasta ver "SUPERADO"
```

El comprobador revisa la estructura (evento, runner, steps, versiones, dependencias entre jobs), que haya `permissions:` y que no hayas borrado ningún step con nombre.

<details>
<summary>Pistas</summary>

- Todo workflow necesita `on:` y todo job necesita `runs-on:`.
- Un step es `uses:` **o** `run:`, nunca los dos. Si necesitas ambos, son dos steps.
- `uses:` siempre lleva `@` y una versión. Mejor aún, un hash de commit (lección 01).
- `needs:` tiene que nombrar un job que exista, escrito exactamente igual.

</details>

La solución está en [`../soluciones/00.yml`](../soluciones/00.yml). Inténtalo antes de mirarla.
