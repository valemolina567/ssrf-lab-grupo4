# Endurecimiento de Seguridad (Hardening) — Mitigación de SSRF

## 1. Contramedidas Implementadas

1. **Validación estricta y Allowlist (`frontend-service`)**:
   - Restricción de esquemas únicamente a `http` y `https`.
   - Lista blanca explícita de dominios permitidos (`ALLOWED_DOMAINS`).
   - Resolución DNS previa con validación de IP (`ipaddress`) bloqueando rangos privados RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`) y link-local/metadata (`169.254.0.0/16`).
   - Deshabilitación de redirecciones HTTP automáticas (`allow_redirects=False`) para evitar bypasses mediante *Open Redirect*.
2. **Segmentación de Red (Principio de Mínimo Privilegio)**:
   - Separación en tres redes: `public-net`, `admin-mtls-net` (interna) y `metadata-isolated-net` (interna).
   - `frontend-service` ya no comparte interfaz de red con `fake-metadata`.
3. **Autenticación Mutua (mTLS)**:
   - PKI interna (`ca.crt`) con certificados individuales para servidor (`internal-admin-service`) y cliente (`frontend-service`), exigiendo `ssl.CERT_REQUIRED`.
4. **Monitoreo y Alertas**:
   - Emisión de eventos `SECURITY_ALERT` ante intentos de acceso a rangos internos, dominios no autorizados o fallos de mTLS.

---

## 2. Comandos de Ejecución y Pruebas (Antes vs. Después)

### Levantar entorno endurecido
```bash
cd hardening
bash certs/generate-certs.sh
docker compose -f docker-compose.hardened.yml up --build -d
