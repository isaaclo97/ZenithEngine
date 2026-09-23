# 08. Exposición de secretos (SEW: Secrets Exposure Weakness)

**CWE:** CWE-200 (Exposure of Sensitive Information) / CWE-522 (Insufficiently Protected Credentials)
**Categoría OWASP CI/CD:** CICD-SEC-6 (Insufficient Credential Hygiene)
**Reglas Zenith Engine:** `R1014` (credencial u token hardcodeado), `R1019` (secreto expuesto en logs)
**Frecuencia real observada:** 63 alertas (0,3% del total). Poco frecuente, pero **siempre CRITICAL**: cuando aparece, el secreto queda comprometido de forma inmediata y permanente (hay que rotarlo, no basta con corregir el `.yml`).

## Qué es

Dos formas distintas de que un secreto deje de ser secreto:

- **`R1014`**: un campo con nombre sensible (`password`, `token`, `secret`, `api_key`, `access_key`, `private_key`, `auth*`, `credential*`) en `env:` o `with:` de un step tiene un **valor literal** en vez de `${{ secrets.X }}`. El valor queda escrito en texto plano dentro del `.yml`, visible para cualquiera con acceso de lectura al repositorio y, si el repo es público, para cualquiera en Internet, indexado además por buscadores de código y por herramientas automáticas de escaneo de secretos que recorren GitHub constantemente.
- **`R1019`**: el workflow sí usa `${{ secrets.X }}` correctamente (no está hardcodeado), pero luego el valor de esa variable se **imprime** en un `run:` con `echo`, `print`, `cat` o similar, normalmente sin mala intención, casi siempre para depurar ("a ver qué valor tiene esta variable"). El resultado es el mismo: el secreto queda en texto plano, esta vez en los **logs de ejecución** del workflow, visibles para cualquiera con acceso de lectura a las Actions del repositorio (que en muchos repos es más gente que la que tiene acceso de escritura).

## Por qué importa

GitHub enmascara automáticamente en los logs cualquier valor que coincida *exactamente* con un secreto ya conocido por el sistema (lo sustituye por `***`). Pero esa protección tiene huecos conocidos y ampliamente documentados:
- Si el secreto se transforma antes de imprimirse (`base64`, se concatena con otro texto, se divide en partes), el enmascarado ya no lo reconoce como el valor original.
- Un secreto hardcodeado (`R1014`) ni siquiera pasa por el sistema de enmascarado: GitHub no sabe que ese string es sensible.
- Cualquiera con permiso para re-ejecutar el workflow con un `debug` habilitado, o con acceso a un fork que también reciba el secreto vía `pull_request_target`, puede llegar a extraerlo.

Y a diferencia de casi cualquier otro fallo de este catálogo, **la solución no es solo corregir el `.yml`**: un secreto que ha aparecido en texto plano (en un commit, en un log) debe considerarse comprometido y **rotarse**, porque el historial de git y los logs de ejecuciones pasadas pueden seguir siendo accesibles aunque se corrija el fichero actual.

## Cómo solucionarlo

**Para `R1014`:**
```yaml
# Mal
- uses: some-action@v1
  with:
    api_key: "sk_live_EXAMPLE-not-a-real-key"

# Bien
- uses: some-action@v1
  with:
    api_key: ${{ secrets.STRIPE_API_KEY }}
```
Si el secreto ya se filtró en un commit, **rótalo inmediatamente** en el proveedor correspondiente además de corregir el `.yml`. Reescribir el historial de git no basta, GitHub y cualquier clon ya pudieron haberlo indexado.

**Para `R1019`:**
```yaml
# Mal
- env:
    TOKEN: ${{ secrets.DEPLOY_TOKEN }}
  run: echo "Usando token: $TOKEN"

# Bien: no lo imprimas. Si necesitas depurar que la variable existe, comprueba
# solo su longitud o su presencia, nunca el valor:
- env:
    TOKEN: ${{ secrets.DEPLOY_TOKEN }}
  run: |
    if [ -z "$TOKEN" ]; then echo "TOKEN no está definido"; exit 1; fi
    echo "TOKEN configurado (longitud: ${#TOKEN})"
```

## Ejecuta la simulación

```bash
cd educational/es/08-exposicion-de-secretos
pip install pyyaml requests
python3 simulate.py
```

El script detecta `R1014`/`R1019` y **simula el log de ejecución real** que produciría GitHub Actions para cada step de `vulnerable.yml` (incluyendo qué partes GitHub sí enmascararía automáticamente y cuáles no), comparándolo con el log que produciría `fixed.yml`.

## Tu turno

[`ejercicio.yml`](ejercicio.yml) despliega una aplicación, pero tiene una contraseña escrita en el fichero y dos formas distintas de imprimir un secreto en los logs. Una de ellas **evade** el enmascarado de GitHub. Que ningún secreto quede en el fichero ni en los logs, sin quitar los parámetros de los steps.

```bash
cp ejercicio.yml mi_solucion.yml     # trabaja sobre la copia
python3 ../comprobar.py              # repite hasta ver "SUPERADO"
python3 ../comprobar.py --todas      # reto extra: todas las reglas del motor
```

El comprobador ejecuta las mismas reglas reales de esta lección y además verifica que no hayas "resuelto" el ejercicio borrando lo que fallaba.

<details>
<summary>Pistas</summary>

- La contraseña del registro tiene que venir de `secrets.*`. Y en la vida real, además, habría que rotarla.
- Cortar un secreto con `cut` produce un texto que ya no coincide con el secreto, así que GitHub no lo enmascara.
- Si necesitas comprobar que un secreto está configurado, mira si está vacío o cuánto mide, nunca su contenido.

</details>

La solución está en [`../soluciones/08.yml`](../soluciones/08.yml). Inténtalo antes de mirarla.
