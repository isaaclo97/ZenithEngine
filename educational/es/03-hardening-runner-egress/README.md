# 03. Falta de hardening del runner (HGW: Hardening Gap Weakness)

**CWE:** CWE-223 (Omission of Security-relevant Information)
**Categoría OWASP CI/CD:** CICD-SEC-10 (Insufficient Logging & Visibility / falta de aislamiento de red)
**Reglas Zenith Engine:** `R1004` (harden-runner ausente o en modo `audit`)
**Frecuencia real observada:** 5.197 alertas (23,7% del total), **la segunda debilidad más común**.

## Qué es

Por defecto, un `job` de GitHub Actions se ejecuta en una máquina efímera con **salida de red sin restricciones**: cualquier `step` puede hacer `curl`, `wget`, resolver DNS o abrir sockets hacia cualquier destino de Internet, sin que nada lo registre ni lo bloquee.

[`step-security/harden-runner`](https://github.com/step-security/harden-runner) es la acción estándar de facto para cerrar esto: se coloca como primer step del job y, según la política (`egress-policy: block` + `allowed-endpoints: ...`), **bloquea cualquier conexión saliente no explícitamente permitida** y genera un log de auditoría de todo el tráfico de red del job.

Zenith Engine detecta dos variantes:
- **`R1004_MISSING`** (LOW): el job no tiene `harden-runner` en absoluto: cero visibilidad y cero filtrado de red.
- **`R1004_AUDIT`** (MEDIUM): `harden-runner` está presente pero configurado en `egress-policy: audit`, que solo **registra** el tráfico sin bloquearlo. Sirve para depurar la política antes de pasarla a `block`, pero mientras esté en `audit` no impide nada.

## Por qué importa

Casi todos los ataques a la cadena de suministro de CI/CD (dependencia comprometida, acción con backdoor, secretos filtrados) tienen un paso final en común: **sacar el dato robado o descargar la siguiente etapa del payload por la red**. Si el job tiene salida sin restricciones:

- Un secreto capturado por una dependencia comprometida puede exfiltrarse por HTTP/DNS a un servidor externo sin que quede ningún rastro más allá de los logs del propio comando (que el atacante controla, ver lección [`08`](../08-exposicion-de-secretos/)).
- No hay ninguna alerta ni bloqueo automático: el equipo se entera, si se entera, por el uso indebido del secreto días o semanas después.

Con `harden-runner` en `block`, la exfiltración a un dominio no autorizado simplemente **falla** en el momento, y queda registrada con el nombre del proceso y el destino exacto que intentó contactar.

## Cómo solucionarlo

Añade `step-security/harden-runner` como primer step de cada job:

```yaml
steps:
  - uses: step-security/harden-runner@e14015d583714f6e62063499dc959a02595150a1 # v2.21.1
    with:
      egress-policy: audit   # fase 1: solo observar y generar la lista de endpoints reales
```

1. **Fase de observación**: despliega con `egress-policy: audit` durante unas ejecuciones y revisa el log de step-security (o la insight generada automáticamente en el summary del job) para ver qué dominios contacta legítimamente el pipeline (registry de npm, PyPI, GitHub API...).
2. **Fase de aplicación**: cambia a `egress-policy: block` y añade esos dominios a `allowed-endpoints`:
   ```yaml
   - uses: step-security/harden-runner@e14015d583714f6e62063499dc959a02595150a1 # v2.21.1
     with:
       egress-policy: block
       allowed-endpoints: >
         github.com:443
         api.github.com:443
         registry.npmjs.org:443
   ```
3. Repite para todos los jobs, incluidos los "triviales" (lint, tests): son precisamente los que menos atención reciben y más se reutilizan copiando y pegando de otros workflows.

## Ejecuta la simulación

```bash
cd educational/es/03-hardening-runner-egress
pip install pyyaml requests
python3 simulate.py
```

El script detecta `R1004_MISSING`/`R1004_AUDIT` job por job y **simula la política de egress**: dada una lista de dominios que el job intenta contactar durante la ejecución, muestra qué conexiones se habrían permitido o bloqueado bajo cada configuración (`sin harden-runner`, `audit`, `block` con la allowlist de `fixed.yml`).

## Tu turno

[`ejercicio.yml`](ejercicio.yml) tiene dos jobs: uno sin ningún control de red y otro con `harden-runner` en modo `audit`. Limita la salida de red de ambos a lo que de verdad necesitan: GitHub y el registro de npm.

```bash
cp ejercicio.yml mi_solucion.yml     # trabaja sobre la copia
python3 ../comprobar.py              # repite hasta ver "SUPERADO"
python3 ../comprobar.py --todas      # reto extra: todas las reglas del motor
```

El comprobador ejecuta las mismas reglas reales de esta lección y además verifica que no hayas "resuelto" el ejercicio borrando lo que fallaba.

<details>
<summary>Pistas</summary>

- `harden-runner` va como **primer** step de cada job.
- `egress-policy: block` bloquea todo lo que no esté en `allowed-endpoints`.
- Para descubrir la lista real de destinos se usa `audit` durante unas ejecuciones; aquí te damos una de partida: `github.com`, `api.github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com` (descargas de Node.js) y `registry.npmjs.org`, todos en el puerto 443.

</details>

La solución está en [`../soluciones/03.yml`](../soluciones/03.yml). Inténtalo antes de mirarla.
