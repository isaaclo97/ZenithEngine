# 06. Triggers privilegiados: `pull_request_target` y TOCTOU (PTW: Privileged Trigger Weakness)

**CWE:** CWE-862 (Missing Authorization)
**Categoría OWASP CI/CD:** CICD-SEC-4 (Poisoned Pipeline Execution)
**Reglas Zenith Engine:** `R1000` (`pull_request_target` detectado), `R1001` (checkout del HEAD del PR bajo `pull_request_target`), `R1021` (patrón TOCTOU)
**Frecuencia real observada:** 131 alertas (0,6% del total). Poco frecuente, pero de las de **mayor severidad** cuando aparece.

## Qué es

`pull_request` y `pull_request_target` son casi idénticos salvo por un detalle crítico: `pull_request_target` se ejecuta **en el contexto del repositorio base**, con acceso a sus secretos y con el `GITHUB_TOKEN` con permisos de escritura por defecto, **incluso si el PR viene de un fork externo**. Esto es intencionado: sirve para automatizar acciones sobre PRs de forks (etiquetarlos, comentar, ejecutar checks) sin exponer secretos al código del fork.

El problema aparece cuando, además de usar `pull_request_target`, el workflow **hace checkout del código del propio PR** (`ref: ${{ github.event.pull_request.head.ref }}`) y luego lo ejecuta (build, tests, linters con plugins...). En ese momento estás ejecutando **código no confiable, escrito por quien abrió el PR**, con acceso a los secretos del repositorio base. Es la puerta de entrada clásica al **Pwn Request** / *Poisoned Pipeline Execution*.

Zenith Engine detecta tres capas del mismo problema:
- `R1000` (HIGH): el workflow usa `pull_request_target`. No es necesariamente un fallo, pero marca el punto donde hay que revisar con más cuidado.
- `R1001` (CRITICAL): además, hace `checkout` con `ref: github.event.pull_request.head...`, con lo que el código del atacante entra al entorno privilegiado.
- `R1021` (CRITICAL): patrón **TOCTOU** (*Time-Of-Check to Time-Of-Use*): el workflow hace `gh pr checkout <número>` usando el número de PR, que en el momento de ejecutarse puede apuntar ya a un commit *distinto* del que se revisó/aprobó. Aparece cuando hay un control previo (un mantenedor revisa el PR y añade una etiqueta como `safe-to-test`, comenta `/ok-to-test`, aprueba un `environment`...): el atacante hace push de un nuevo commit malicioso justo después de esa aprobación, pero antes de que se haga el checkout.

## Por qué importa

Este patrón es responsable de múltiples incidentes reales de alto perfil en proyectos open source (desde 2021 documentados públicamente por GitHub Security Lab): un PR aparentemente inocuo modifica un fichero de test o de configuración que después el workflow privilegiado ejecuta (`npm test`, `make`, un script de build), y ese código exfiltra `secrets.*` a un servidor externo, sin que el mantenedor apruebe nada manualmente, porque `pull_request_target` no requiere aprobación como sí la requiere `pull_request` desde forks en algunos ajustes de organización.

## Cómo solucionarlo

1. **Evita `pull_request_target` salvo que sea estrictamente necesario.** Si solo necesitas etiquetar o comentar el PR, usa `pull_request` normal (sin acceso a secretos) más un job separado con `pull_request_target` que **no haga checkout del código del PR**, solo llame a la API de GitHub.
2. Si necesitas ejecutar el código del PR (tests, build), sepáralo en un workflow con `pull_request` (sin `_target`). Pierde el acceso automático a secretos, que es exactamente lo que quieres.
3. Si de verdad necesitas `pull_request_target` + ejecutar código del fork, exige **aprobación manual** de un mantenedor antes de cada ejecución (`environment:` con *required reviewers*), y haz checkout siempre por el **SHA exacto ya validado**, nunca por `head.ref` o por número de PR en el momento de la ejecución.
4. Para el patrón TOCTOU: usa siempre `ref: ${{ github.event.pull_request.head.sha }}` (el commit exacto evaluado), no `gh pr checkout <número>`, que resuelve dinámicamente al último commit del PR en el momento en que se ejecuta ese paso. Ojo: `head.sha` **solo cierra el hueco TOCTOU**; el código sigue siendo del autor del PR y se ejecuta en contexto privilegiado. Combínalo siempre con el punto 3 (revisión previa), sin secretos en el entorno y con `persist-credentials: false` en el checkout.

5. **Usa `actions/checkout` v7 o posterior.** Desde la v7 (2026), `actions/checkout` **se niega** a descargar el código de un PR de un fork cuando el workflow se dispara con `pull_request_target` o `workflow_run`, salvo que lo pidas explícitamente con `allow-unsafe-pr-checkout: true`. Con la v4 que usa `vulnerable.yml`, el ataque funciona sin más; con la v7, el mismo workflow falla en lugar de ejecutar código del atacante. En `fixed.yml`, el job `test-approved` pone ese parámetro a propósito, después de haber aplicado los puntos 3 y 4: que haya que escribirlo obliga a tomar la decisión de forma consciente y deja rastro en la revisión de código.

## Nota sobre los límites de la detección automática

`R1001` busca la subcadena `github.event.pull_request.head` dentro del `ref:` del checkout, así que **`fixed.yml` sigue disparando la alerta** en el job `test-approved`. Y es correcto que lo haga: `head.sha` fija *qué* commit se ejecuta (cierra el TOCTOU), pero ese commit sigue siendo código del autor del PR, ejecutado bajo `pull_request_target`. El riesgo que señala R1001 sigue ahí; lo que lo hace aceptable son controles que un análisis estático basado en patrones no ve: la revisión humana previa (el job solo se dispara con el evento `labeled` + `safe-to-test`), la ausencia de secretos en el entorno, `permissions: contents: read` y `persist-credentials: false`.

Una alerta que sigue saltando tras corregir no es necesariamente un falso positivo: hay que entender qué riesgo señala la regla y si los controles que la herramienta no puede ver lo mitigan de verdad.

## Ejecuta la simulación

```bash
cd educational/es/06-triggers-privilegiados-pull-request-target
pip install pyyaml requests
python3 simulate.py
```

El script detecta `R1000`/`R1001`/`R1021`, y además **simula el ataque TOCTOU**: modela la línea de tiempo de un PR real (el mantenedor revisa el commit y añade la etiqueta `safe-to-test` → el autor hace push de un commit malicioso adicional → checkout tardío del workflow) y muestra qué código exacto habría terminado ejecutándose con acceso a los secretos del repositorio base.

## Tu turno

[`ejercicio.yml`](ejercicio.yml) ejecuta los tests de los PRs de forks con los privilegios del repositorio, sube la cobertura con un secreto y reintenta con `gh pr checkout` por número. Consigue que los tests se sigan ejecutando en cada PR sin exponer secretos ni un token con permisos al código del fork.

```bash
cp ejercicio.yml mi_solucion.yml     # trabaja sobre la copia
python3 ../comprobar.py              # repite hasta ver "SUPERADO"
python3 ../comprobar.py --todas      # reto extra: todas las reglas del motor
```

El comprobador ejecuta las mismas reglas reales de esta lección y además verifica que no hayas "resuelto" el ejercicio borrando lo que fallaba.

<details>
<summary>Pistas</summary>

- Para ejecutar el código de un PR no hace falta `pull_request_target`. ¿Qué evento da el código del PR con un token de solo lectura y sin secretos?
- Con ese evento, `actions/checkout` sin `ref:` ya trae el código del PR.
- La cobertura se puede guardar como artefacto, sin secreto. Si hace falta enviarla a un servicio, eso va en otro workflow que no ejecute código del PR.

</details>

La solución está en [`../soluciones/06.yml`](../soluciones/06.yml). Inténtalo antes de mirarla.
