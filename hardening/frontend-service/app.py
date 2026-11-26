import ipaddress
import logging
import socket
from urllib.parse import urlparse
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger("frontend-security")

# Allowlist estricta de dominios legítimos permitidos para /preview
ALLOWED_DOMAINS = {
    "example.com",
    "www.example.com",
    "httpbin.org"
}

# Rangos internos y de metadata bloqueados
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # Privada Clase A
    ipaddress.ip_network("172.16.0.0/12"),    # Privada Clase B (incluye 172.28.0.0/24)
    ipaddress.ip_network("192.168.0.0/16"),   # Privada Clase C
    ipaddress.ip_network("169.254.0.0/16"),   # Metadata AWS/Cloud (169.254.169.254)
    ipaddress.ip_network("0.0.0.0/8"),        # Red local actual
    ipaddress.ip_network("::1/128"),          # Loopback IPv6
    ipaddress.ip_network("fc00::/7"),         # Privada IPv6
    ipaddress.ip_network("fe80::/10"),        # Link-local IPv6
]

def validate_target_url(raw_url: str):
    try:
        parsed = urlparse(raw_url.strip())
    except Exception:
        return False, "URL malformada"

    if parsed.scheme not in ("http", "https"):
        logger.warning(f"SECURITY_ALERT [SSRF_BLOCKED] Esquema no permitido: {parsed.scheme} | URL: {raw_url}")
        return False, "Solo se permiten esquemas HTTP y HTTPS"

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "Host vacío"

    if hostname in ("localhost", "localhost.localdomain"):
        logger.warning(f"SECURITY_ALERT [SSRF_BLOCKED] Intento de acceso a localhost | URL: {raw_url}")
        return False, "Acceso a localhost denegado"

    if hostname not in ALLOWED_DOMAINS:
        logger.warning(f"SECURITY_ALERT [SSRF_BLOCKED] Dominio fuera de allowlist: {hostname} | URL: {raw_url}")
        return False, f"El dominio '{hostname}' no está en la lista de destinos permitidos"

    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror:
        return False, "No se pudo resolver el dominio"

    for family, _, _, _, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, "Dirección IP inválida"

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or any(ip_obj in net for net in BLOCKED_NETWORKS)
        ):
            logger.critical(
                f"SECURITY_ALERT [SSRF_INTERNAL_IP] Bloqueado acceso a rango interno/metadata "
                f"({ip_str}) para URL: {raw_url} | Origen: {request.remote_addr}"
            )
            return False, "Destino bloqueado: dirección IP interna o reservada no permitida"

    return True, "OK"

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "mode": "hardened"}), 200

@app.route("/preview", methods=["GET", "POST"])
def preview():
    target_url = request.args.get("url")
    if not target_url and request.is_json:
        target_url = (request.json or {}).get("url")
    if not target_url:
        return jsonify({"error": "Parámetro 'url' requerido"}), 400

    is_valid, reason = validate_target_url(target_url)
    if not is_valid:
        return jsonify({
            "error": "Solicitud bloqueada por política de seguridad",
            "reason": reason
        }), 403

    try:
        resp = requests.get(target_url, timeout=5, allow_redirects=False)
        return jsonify({
            "status_code": resp.status_code,
            "url": target_url,
            "preview": resp.text[:500]
        }), 200
    except requests.RequestException as e:
        return jsonify({"error": f"Error al obtener recurso externo: {str(e)}"}), 502

@app.route("/internal-status", methods=["GET"])
def internal_status():
    try:
        resp = requests.get(
            "https://internal-admin-service:8443/status",
            cert=("/app/certs/client.crt", "/app/certs/client.key"),
            verify="/app/certs/ca.crt",
            timeout=5
        )
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.SSLError as e:
        logger.critical(f"SECURITY_ALERT [MTLS_FAILURE] Fallo de autenticación mTLS: {str(e)}")
        return jsonify({"error": "Fallo de verificación mTLS con servicio interno"}), 502

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
