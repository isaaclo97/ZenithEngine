# 11. Exfiltración de red y superficie de ataque (reglas específicas de Zenith Engine)

**Categoría OWASP CI/CD:** CICD-SEC-10 (mayoría) / CICD-SEC-1 / CICD-SEC-7
**Reglas Zenith Engine:** `R1005` (dominio fraudulento conocido), `R1009` (IP directa), `R1015` (exfiltración por DNS), `R1018` (exfiltración vía API de GitHub), `R1006` (runner self-hosted), `R1013` (`pull_request` sin restricción de rama), `R1020` (runner en nube sin hardening)
**Frecuencia real observada:** 587 alertas conjuntas (2,7% del total) bajo la categoría "OTRO" del paper de referencia. Estas reglas están **fuera de la taxonomía de las 10 debilidades comunes**, son detecciones de Zenith Engine que el paper no clasifica en ninguna de ellas. Algunas tienen parecido en otros escáneres (por ejemplo, `zizmor` y `poutine` también avisan de runners self-hosted), pero las de exfiltración por red (R1005, R1009, R1015, R1018) son propias de Zenith.

## Qué es

Esta lección agrupa siete reglas más pequeñas que comparten un mismo hilo conductor: **qué puede salir, y hacia dónde, desde un job de CI/CD, y en qué máquina se está ejecutando ese job**.

| Regla | Qué detecta | Por qué importa |
|---|---|---|
| `R1005` | Un `curl`/`wget` hacia un dominio de la lista `engine/fraudulent_domains.txt` (dominios conocidos por typosquatting/phishing de paquetes) | El pipeline descarga o envía datos a un dominio con reputación conocida de abuso |
| `R1009` | Una llamada de red a una IP literal (no privada) en vez de a un nombre de dominio | Sin DNS de por medio no hay forma de auditar/bloquear por dominio; suele ser señal de C2 o exfiltración directa |
| `R1015` | `dig`/`nslookup` con un subdominio anormalmente largo (≥20 caracteres) | Patrón clásico de **exfiltración por DNS**: se codifica el dato robado en el propio nombre de subdominio consultado, que casi ningún firewall de egress bloquea porque el tráfico DNS "siempre debe salir" |
| `R1018` | Una llamada a `api.github.com/repos/<owner>/<repo>` de un repositorio que **no es** el propio (`github.repository`) | Usar la API de GitHub como canal de exfiltración: subir el dato robado como contenido de un fichero, issue o release en un repositorio bajo control del atacante, con tráfico hacia `api.github.com`, que casi ningún filtro de egress bloquea por ser "tráfico de GitHub legítimo" |
| `R1006` | `runs-on: self-hosted` | Un runner propio, fuera de la infraestructura efímera de GitHub. Persiste entre ejecuciones, lo que amplía enormemente el impacto de cualquier compromiso (lección [`01`](../01-dependencias-sin-fijar/)) |
| `R1013` | Trigger `pull_request` sin `branches`/`branches-ignore` | El workflow se dispara para PRs contra **cualquier** rama del repositorio, ampliando la superficie de ataque sin necesidad |
| `R1020` | Runner self-hosted con etiqueta de nube (`ec2`, `aws`, `azure`...) sin `harden-runner` | Una máquina propia en la nube sin ningún control de egress combina lo peor de ambos mundos: su identidad da acceso a la infraestructura cloud (por ejemplo, credenciales del servicio de metadatos) y no hay visibilidad de red |

## Cómo solucionarlo

- **`R1005`/`R1009`**: nunca contactes IPs literales ni dominios de la lista de bloqueo; usa siempre nombres de dominio de proveedores conocidos, y añade `harden-runner` (lección [`03`](../03-hardening-runner-egress/)) con una allowlist explícita.
- **`R1015`**: si necesitas resolución DNS dentro del pipeline, hazlo solo contra dominios controlados por ti; cualquier `dig`/`nslookup` con un subdominio "raro" y largo debería levantar sospechas en revisión de código.
- **`R1018`**: si el pipeline necesita escribir en otro repositorio (por ejemplo, publicar documentación generada), usa siempre `github.repository` o una constante explícita y auditable, nunca una expresión que un atacante pueda controlar para decidir a qué repo se escribe.
- **`R1006`/`R1020`**: en runners self-hosted, especialmente en la nube, añade siempre `harden-runner`, revisa que la máquina se destruye tras cada job (no persiste estado entre ejecuciones) y nunca la compartas entre repositorios con distinto nivel de confianza.
- **`R1013`**: restringe siempre `pull_request` a las ramas que realmente lo necesitan: `branches: [main, develop]`.

## Ejecuta la simulación

```bash
cd educational/es/11-exfiltracion-red-y-superficie-ataque
pip install pyyaml requests
python3 simulate.py
```

El script ejecuta las siete reglas reales sobre `vulnerable.yml`/`fixed.yml`, y decodifica el payload simulado de exfiltración por DNS (R1015) para mostrar qué dato concreto viajaría oculto en el nombre de subdominio.

### Con Docker (opcional): observar la exfiltración de verdad

`docker/` levanta un **receptor HTTP local** (aislado, en tu propia máquina, sin salir a Internet) que simula el servidor del atacante: ejecuta literalmente el `curl` de `vulnerable.yml` contra él y verás llegar la petición con el secreto en la propia terminal del receptor.

```bash
cd educational/es/11-exfiltracion-red-y-superficie-ataque/docker
docker compose up --build
```

## Tu turno

[`ejercicio.yml`](ejercicio.yml) envía datos a un servicio externo, consulta un subdominio con datos codificados, publica en el repositorio de otro y copia el binario a una IP, todo desde una máquina propia en la nube sin controles y para cualquier PR. Consigue que haga lo mismo (compilar, medir, comprobar y publicar) sin esos riesgos.

```bash
cp ejercicio.yml mi_solucion.yml     # trabaja sobre la copia
python3 ../comprobar.py              # repite hasta ver "SUPERADO"
python3 ../comprobar.py --todas      # reto extra: todas las reglas del motor
```

El comprobador ejecuta las mismas reglas reales de esta lección y además verifica que no hayas "resuelto" el ejercicio borrando lo que fallaba.

<details>
<summary>Pistas</summary>

- Limita el trigger `pull_request` a las ramas que lo necesiten.
- Un runner hospedado por GitHub es efímero y no tiene acceso a tu nube.
- Las métricas pueden quedarse en el propio workflow como artefacto.
- Para publicar en tu propio repositorio usa `${{ github.repository }}`, y para el servidor de despliegue, un nombre de dominio en lugar de una IP.

</details>

La solución está en [`../soluciones/11.yml`](../soluciones/11.yml). Inténtalo antes de mirarla.
