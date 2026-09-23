# 05. Runtime obsoleto y runner desconocido (GRCW: GitHub Runner Compatibility Weakness)

**CWE:** CWE-477 (Use of Obsolete Function) / CWE-440 (Expected Behavior Violation)
**Categoría OWASP CI/CD:** CICD-SEC-8
**Reglas Zenith Engine:** `R1023` (acción con runtime obsoleto: Node 12/16), `R1024` (etiqueta de runner desconocida o no soportada)
**Frecuencia real observada:** 876 alertas (4,0% del total).

## Qué es

A diferencia de las lecciones anteriores, esta no trata de un atacante activo, sino de **fiabilidad y "future-proofing"**:

- **`R1023`**: muchas acciones antiguas (`actions/checkout@v2`, `actions/setup-node@v2`...) se ejecutan sobre un runtime **Node.js 12 o 16**, ambos ya fuera de soporte. GitHub ha ido retirando progresivamente el soporte para estas versiones en sus runners hospedados. El resultado no es predecible: el step puede fallar directamente, degradarse silenciosamente, o GitHub puede forzar una migración a Node 20 que rompa comportamiento asumido por la acción.
- **`R1024`**: el valor de `runs-on` no coincide con ninguna etiqueta de runner reconocida (`ubuntu-latest`, `windows-2022`, `macos-14`...). Puede ser un typo (`runs-on: bunutu-latest`), una etiqueta de runner self-hosted mal escrita, o el nombre de un runner que existía pero fue retirado.

## Por qué importa

No es una vulnerabilidad de seguridad en el sentido clásico, pero sí un **fallo de disponibilidad de la cadena de CI/CD**: un pipeline de deploy que deja de ejecutarse (o falla de forma no determinista) el día que GitHub retira soporte para Node 16 es tan grave operativamente como una vulnerabilidad, especialmente si nadie lo nota hasta que un release urgente no puede salir.

Además, una acción con runtime obsoleto suele ser también una acción **sin mantenimiento activo**, que es exactamente el tipo de acción con más probabilidad de acumular CVEs sin parchear (ver lección [`10`](../10-componentes-con-cve-conocido/)).

## Cómo solucionarlo

**Para `R1023`:**
1. Identifica las acciones afectadas: `engine/outdated_runtime_actions.txt` en este repo mantiene la lista que usa Zenith Engine.
2. Actualiza a la major version más reciente de cada acción (por ejemplo `actions/checkout@v2` → `@v7`, `actions/setup-node@v2` → `@v7`), que ya corre sobre Node 24. No basta con subir a una versión "no tan vieja": Node 20 también llegó al final de su vida en abril de 2026, y GitHub pasó sus runners a Node 24 por defecto en junio de 2026 y retiró Node 20 en septiembre de 2026. Para saber sobre qué corre una acción, mira `runs.using` en su `action.yml`.
3. Revisa el *changelog* de la major version nueva: los cambios de major suelen incluir breaking changes en los `with:` disponibles.

**Para `R1024`:**
1. Revisa la lista oficial de runners hospedados por GitHub y corrige el typo o la etiqueta obsoleta.
2. Si es un runner self-hosted con etiqueta personalizada, verifica que la etiqueta coincide exactamente (sensible a mayúsculas/minúsculas) con la configurada en el runner registrado en el repositorio/organización.

## Límite de R1023 que conviene conocer

La lista `engine/outdated_runtime_actions.txt` solo recoge versiones que corren sobre Node 12 o 16. Tras la retirada de Node 20, versiones como `actions/checkout@v4` o `actions/setup-node@v4` también están desfasadas, y R1023 todavía no las marca. Es otro ejemplo de que una regla solo sabe lo que su lista de datos le cuenta: revisa `runs.using` por tu cuenta.

## Ejecuta la simulación

```bash
cd educational/es/05-runtime-obsoleto-runner-desconocido
pip install pyyaml requests
python3 simulate.py
```

El script carga `engine/outdated_runtime_actions.txt` del proyecto (la misma fuente de datos que usa `R1023` en producción) y la lista de etiquetas conocidas de `R1024`, y muestra para cada acción de `vulnerable.yml` si sigue funcionando garantizado en los runners actuales de GitHub o no.

## Tu turno

[`ejercicio.yml`](ejercicio.yml) lleva meses sin tocarse: sus runners no existen y dos acciones usan un runtime de Node.js retirado. Haz que vuelva a funcionar.

```bash
cp ejercicio.yml mi_solucion.yml     # trabaja sobre la copia
python3 ../comprobar.py              # repite hasta ver "SUPERADO"
python3 ../comprobar.py --todas      # reto extra: todas las reglas del motor
```

El comprobador ejecuta las mismas reglas reales de esta lección y además verifica que no hayas "resuelto" el ejercicio borrando lo que fallaba.

<details>
<summary>Pistas</summary>

- Lee despacio la etiqueta del runner de Linux.
- `macos-10.15` se retiró hace años: busca una etiqueta de macOS vigente.
- Sube `actions/setup-python` y `actions/cache` a una versión mayor actual y fíjalas por hash.

</details>

La solución está en [`../soluciones/05.yml`](../soluciones/05.yml). Inténtalo antes de mirarla.
