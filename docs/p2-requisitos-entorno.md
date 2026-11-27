# Requisitos y preparación del entorno (entregable P2)

> Sección reproducible para el documento final. Describe lo que hay que tener y verificar **antes** de ejecutar la guía de P3 o las contramedidas de P4.
> Basada en `README.md`, `lab-environment/docker-compose.yml` y los tres `Dockerfile` del commit `03b49fb`.

## 1. Alcance y advertencia

El entorno es un laboratorio **vulnerable a propósito**, aislado en Docker y con datos 100 % ficticios. No debe desplegarse fuera de la máquina del estudiante ni conectarse a infraestructura cloud real. No se requiere ninguna cuenta de AWS: `fake-metadata` simula localmente el servicio de metadatos.

## 2. Requisitos de hardware y software

Valores recomendados para un portátil de trabajo (no son mínimos certificados por el proyecto):

| Concepto | Recomendación | Motivo |
|---|---|---|
| CPU | 2 núcleos (4 recomendados) | Tres contenedores Python simultáneos |
| Memoria RAM | 4 GB libres (8 GB recomendados) | Docker Desktop + imágenes `python:3.12-slim` |
| Disco | 10 GB libres | Imagen base, capas de dependencias y caché de build |
| Red local | Puerto `8080/TCP` libre en el host | Es el único puerto publicado |
| Sistema | Windows, macOS o Linux con Docker Engine/Desktop | Compose v2 (`docker compose`) |
| Herramientas | Git, Docker Compose v2, `curl` (o navegador) | Clonar, levantar y verificar el entorno |

No es necesario instalar Python ni Flask en el host: todo se construye dentro de los contenedores. Solo se necesita conexión a Internet la primera vez, para descargar `python:3.12-slim` y las dependencias fijadas; después el laboratorio funciona sin salida externa.

## 3. Dependencias del entorno

| Dependencia | Versión | Dónde se declara |
|---|---|---|
| Imagen base | `python:3.12-slim` | Los tres `Dockerfile` |
| Framework web | `flask==3.0.3` | Los tres `Dockerfile` (`pip install --no-cache-dir`) |
| Cliente HTTP del frontend | `requests==2.32.3` | `lab-environment/frontend-service/Dockerfile` |
| Orquestación | Docker Compose v2 | `lab-environment/docker-compose.yml` (`name: ssrf-lab`) |

Las versiones están fijadas para que el laboratorio sea reproducible. No hay `requirements.txt`: las dependencias se instalan directamente en cada `Dockerfile`.

## 4. Topología que debe quedar montada

- **`public-net`**: red `bridge` ordinaria. Conecta al frontend con el exterior y permite la publicación `8080:5000`.
- **`internal-net`**: red `bridge` declarada con `internal: true` y subnet estática `172.28.0.0/24`. En Docker, esa opción crea una red **aislada respecto del exterior**: los contenedores que **solo** pertenecen a ella pueden comunicarse entre sí dentro de la subnet, pero no tienen salida NAT/masquerade a Internet ni conectividad con otras redes Docker, y no pueden publicar puertos en el host. No debe entenderse como aislamiento absoluto frente al propio host: Docker asigna una dirección al puente, por lo que procesos locales pueden alcanzar esa red; por eso los servicios internos se apoyan además en la ausencia de publicación de puertos. `frontend-service` es la excepción deliberada: al estar también en `public-net`, conserva su propia salida a Internet, pero los servicios internos no la comparten. Las directivas `expose` de `5001` y `80` solo documentan los puertos del contenedor; no crean publicaciones en el host.
- **`frontend-service`**: pertenece a ambas redes; IP fija `172.28.0.10` en `internal-net`; Flask escucha `0.0.0.0:5000`.
- **`internal-admin-service`**: solo `internal-net`; `172.28.0.20:5001`; sin publicación de puertos.
- **`fake-metadata`**: solo `internal-net`; `172.28.0.30:80`; sin publicación de puertos.
- **Arranque**: `depends_on` espera a que ambos servicios internos estén `healthy` (healthchecks HTTP cada 5 s, timeout 3 s, 5 reintentos).

Detalle de precisión: la cadena `"8080:5000"` publica el puerto en todas las interfaces del host. El README lo usa como `localhost:8080` por simplicidad; si se quiere restringir al loopback, la forma correcta sería `127.0.0.1:8080:5000`. **No se ha modificado el compose de P1**; se registra aquí como observación de documentación.

## 5. Procedimiento de preparación

Desde la raíz del repositorio:

```bash
git checkout develop
git pull
cd lab-environment
docker compose config          # valida sintaxis y muestra la configuración resuelta
docker compose up --build
```

Esperar a que los tres contenedores estén `healthy` (o `Up`) antes de continuar:

```bash
docker compose ps
docker compose logs -f         # Ctrl+C para salir
```

Comprobación de que el entorno quedó como se documentó:

```bash
curl http://localhost:8080/health
```

Debe responder `{"status":"ok"}`.

Para apagar y limpiar:

```bash
docker compose down
docker compose down --rmi local   # apaga y elimina las imágenes construidas
```

## 6. Matriz de verificación del aislamiento

| Comprobación | Comando | Resultado esperado | Qué demuestra |
|---|---|---|---|
| Superficie pública | `curl http://localhost:8080/health` | `200` con `{"status":"ok"}` | El frontend es el único punto de entrada |
| Servicio interno desde el host | `curl http://localhost:5001/health` | Fallo de conexión | El puerto `5001` no está publicado |
| Metadatos desde el host | `curl http://172.28.0.30/health` | Fallo / sin ruta | La subnet interna no es enrutable desde el host |
| Servicio interno desde el frontend | `docker compose exec frontend-service python -c "import urllib.request; print(urllib.request.urlopen('http://172.28.0.20:5001/health').read().decode())"` | `{"status":"ok"}` | El frontend sí alcanza `internal-net`: es el pivote |
| Metadatos desde el frontend | `docker compose exec frontend-service python -c "import urllib.request; print(urllib.request.urlopen('http://172.28.0.30/latest/meta-data/').read().decode())"` | Lista de claves simuladas | Existe la segunda víctima del SSRF |

> Se usa `python -c` en lugar de `curl` porque las imágenes `python:3.12-slim` no incluyen `curl` por defecto.

Si la última fila falla, revisar `docker compose ps` y los healthchecks antes de avanzar a la guía de P3.

## 7. Incidencias habituales

| Síntoma | Causa probable | Acción |
|---|---|---|
| `Bind for 0.0.0.0:8080 failed` | Otro proceso usa el puerto | Liberar `8080` o cambiar el mapeo en el compose (y avisar a P1/P3) |
| `docker: 'compose' is not a docker command` | Compose v1 | Instalar/activar el plugin Compose v2 |
| Contenedores `unhealthy` | Puertos o rutas modificados | Revisar `docker compose logs` y restaurar el compose base |
| Cambios de código sin efecto | Caché de imagen | `docker compose up --build --force-recreate` |
| Confusión con la IP de metadatos real | AWS usa `169.254.169.254` | En el lab se usa `172.28.0.30`; ver `docs/puertos-y-protocolos.md` |

## 8. Handoff a P3 y P4

- **P3** puede iniciar la explotación en cuanto la matriz anterior pase. Los comandos exactos y las rutas están en `docs/p2-arquitectura-vulnerable.md`, apartado 5.
- **P4** debe conservar este entorno como «antes» y crear su versión corregida en `/hardening`, sin sobrescribir `lab-environment/`.
- Cualquier cambio de IP, puerto o red debe actualizar simultáneamente este archivo, `docs/puertos-y-protocolos.md`, el diagrama y la guía de ataque.
