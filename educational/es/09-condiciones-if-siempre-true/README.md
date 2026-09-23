# 09. Condiciones `if` que siempre evalúan a true (CFW: Control Flow Weakness)

**CWE:** CWE-571 (Expression is Always True)
**Categoría OWASP CI/CD:** CICD-SEC-1 (Insufficient Flow Control Mechanisms)
**Reglas Zenith Engine:** `R1022` (`R1022_JOB` / `R1022_STEP`)
**Frecuencia real observada:** 6 alertas (<0,1% del total). Es la más rara del catálogo, casi un "code smell" de copy-paste, pero cuando aparece suele desactivar por completo un control de seguridad que alguien creyó que estaba activo.

## Qué es

Un `if:` de job o de step en GitHub Actions solo se evalúa como condición cuando está escrito como **una única expresión completa**: `if: ${{ condición }}`. Hay un error de formato extremadamente fácil de cometer y muy difícil de detectar a simple vista que hace que la condición **siempre sea verdadera**, sin importar su contenido:

```yaml
# Se ejecuta SIEMPRE, pase lo que pase con vars.DEPLOY_ENABLED:
if: "${{ vars.DEPLOY_ENABLED == 'true' }} == true"

# También se ejecuta SIEMPRE: dos expresiones en el mismo if,
# GitHub solo evalúa como condición un ${{ }} único y completo:
if: ${{ github.ref == 'refs/heads/main' }} && ${{ github.actor == 'trusted-bot' }}
```

`R1022` detecta exactamente este patrón: una cadena que contiene `${{` pero que **no es, en su totalidad, una única expresión** (no empieza en `${{`, no termina en `}}`, o contiene más de un `${{` en el mismo campo `if`). En ese caso GitHub Actions no evalúa el campo como *una* condición: sustituye cada `${{ }}` por su resultado como texto (por ejemplo `false && true`) y el `if:` recibe ese string no vacío, que **siempre es "truthy"**.

## Por qué importa

Es el tipo de fallo más peligroso posible porque **es completamente invisible en la práctica cotidiana**: el workflow "funciona", los jobs se ejecutan, nadie recibe ningún error. La única señal de que algo va mal es que un job que **debería** haberse saltado (por ejemplo, un deploy a producción que solo debería correr si `github.ref == 'refs/heads/main'`) se ejecuta también en cualquier otra rama, incluyendo ramas de PRs de forks externos.

Es habitual que aparezca por un error tipográfico al combinar dos condiciones con `&&` sin darse cuenta de que cada una necesita ir dentro del mismo `${{ }}`, o al copiar un `if:` de otro workflow y añadir una comprobación extra "rápida" al final sin encerrarla correctamente.

## Cómo solucionarlo

Encierra **toda la condición**, incluidos los operadores lógicos, dentro de un único bloque `${{ ... }}`:

```yaml
# Mal (siempre true)
if: ${{ github.ref == 'refs/heads/main' }} && ${{ github.actor == 'trusted-bot' }}

# Bien (se evalúa de verdad)
if: ${{ github.ref == 'refs/heads/main' && github.actor == 'trusted-bot' }}
```

Como buena práctica adicional, evita anidar `${{ }}` dentro de un `if:`. GitHub Actions ya evalúa el contenido completo de `if:` como expresión, así que ni siquiera hace falta escribir `${{ }}` en absoluto:

```yaml
if: github.ref == 'refs/heads/main' && github.actor == 'trusted-bot'
```

> **Nota:** el interruptor de despliegue de esta lección es una *variable de configuración* (`vars.DEPLOY_ENABLED`), no un secreto. El contexto `secrets` **no se puede usar en `if:`**: GitHub rechaza el workflow con `Unrecognized named-value: 'secrets'`. Si la condición depende de un secreto, pásalo antes a `env:` a nivel de job y comprueba `env.MI_VARIABLE`.

## Ejecuta la simulación

```bash
cd educational/es/09-condiciones-if-siempre-true
pip install pyyaml requests
python3 simulate.py
```

El script ejecuta la regla real `R1022` y además **evalúa las condiciones tal y como lo haría el runner de GitHub**: para cada `if:` del workflow, muestra si GitHub lo trataría como una expresión real a evaluar o como un string literal (siempre verdadero), y simula qué jobs se ejecutarían en dos escenarios distintos (`push a main` vs. `push a una rama de feature`) con `vulnerable.yml` y con `fixed.yml`.

## Tu turno

[`ejercicio.yml`](ejercicio.yml) tiene tres condiciones `if:` que parecen correctas y se evalúan siempre como verdaderas. Haz que cada una se evalúe de verdad. Ninguna puede desaparecer.

```bash
cp ejercicio.yml mi_solucion.yml     # trabaja sobre la copia
python3 ../comprobar.py              # repite hasta ver "SUPERADO"
python3 ../comprobar.py --todas      # reto extra: todas las reglas del motor
```

El comprobador ejecuta las mismas reglas reales de esta lección y además verifica que no hayas "resuelto" el ejercicio borrando lo que fallaba.

<details>
<summary>Pistas</summary>

- Una condición tiene que ser **una sola** expresión.
- Dentro de un `if:` no hace falta escribir `${{ }}`: GitHub ya lo evalúa todo como expresión.
- `failure()` y `cancelled()` son funciones: se combinan con `||` dentro de la misma expresión.

</details>

La solución está en [`../soluciones/09.yml`](../soluciones/09.yml). Inténtalo antes de mirarla.
