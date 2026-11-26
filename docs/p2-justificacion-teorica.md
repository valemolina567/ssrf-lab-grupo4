# Justificación teórica del vector SSRF (entregable P2)

> Sección de fundamentación para el documento final. Preparada sobre el commit `03b49fb` del entorno de P1.
> Laboratorio académico aislado: todas las credenciales y datos son ficticios.

## 1. Definición y clasificación del vector

El *Server-Side Request Forgery* (SSRF) ocurre cuando una aplicación web obtiene un recurso remoto **sin validar la URL proporcionada por el usuario**. El atacante coerciona al servidor para que emita una petición hacia un destino inesperado, incluso cuando ese destino está protegido por un firewall, una VPN o una ACL de red. Está catalogado como **CWE-918** y como la categoría **A10:2021 – Server-Side Request Forgery** del OWASP Top 10 [R1][R2]. OWASP señala que su incidencia crece y que su severidad aumenta por la adopción de servicios cloud y por la complejidad arquitectónica [R1].

En este laboratorio el patrón se reproduce de forma deliberada en el único servicio expuesto:

| Elemento del patrón | Abstracción | Evidencia en el entorno de P1 |
|---|---|---|
| Fuente (*source*) | Entrada no confiable | `request.args.get("url")` en `lab-environment/frontend-service/app.py` (`/preview`) |
| Sumidero (*sink*) | Cliente HTTP del servidor | `requests.get(url, timeout=5)` en el mismo handler |
| Control ausente | Validación de destino | El propio código marca el punto como «VULNERABLE A PROPÓSITO (CWE-918)» |
| Pivote | Nodo con acceso a dos redes | `frontend-service` pertenece a `public-net` **y** `internal-net` (`docker-compose.yml`) |
| Objetivo | Servicios que no deberían ser alcanzables | `internal-admin-service:5001` y `fake-metadata:80` |

La consecuencia es un **agente confuso** (*confused deputy*): el atacante no alcanza la red interna directamente, sino que abusa de la identidad de red legítima del frontend para que sea él quien realice la petición.

## 2. Contextualización en reportes globales

> **Nota metodológica.** Las cifras siguientes dimensionan la clase de riesgo (explotación de aplicaciones expuestas y robo de credenciales de metadatos). Ninguna de estas fuentes publica un porcentaje específico de incidentes SSRF; por ello no se atribuyen sus cifras al SSRF. ENISA trabaja con incidentes observados y CrowdStrike con telemetría de sus clientes: no son censos globales.

### 2.1 ENISA

- **ENISA Threat Landscape 2026** [R6] analiza 8 257 incidentes ocurridos entre el 1 de enero y el 31 de diciembre de 2025 (p. 9). Las DDoS (51,3 %) y los accesos no autorizados (39,5 %) son los tipos predominantes tanto en el resumen ejecutivo (p. 7) como en el capítulo de tendencias (p. 11). La explotación de vulnerabilidades, incluidas N-day y 0-day, aparece en el **60,4 % de los accesos no autorizados cuyo vector de entrada pudo identificarse**; ese vector solo se conoció en el **5,2 % de dichos accesos**, y en ese mismo subconjunto la configuración errónea o la exposición accidental representan el 20,7 % (p. 11). En intrusiones de actores estatales el vector se identificó en ~20 % de los casos y, dentro de ese subconjunto, la explotación de vulnerabilidades fue el más frecuente (70 %; p. 60). Denominadores: 8 257 = total de incidentes; 5,2 % y 20,7 % = subconjunto de accesos no autorizados con vector conocido; 70 % = subconjunto de intrusiones estatales con vector conocido.
- **ENISA Threat Landscape 2025** [R7], con 4 875 incidentes (julio 2024–junio 2025), situó la explotación de vulnerabilidades en el 21,3 % de los vectores de intrusión y las amenazas web en el 27,3 % de las categorías de amenaza.

**Lectura para el laboratorio:** el escenario modelado —un endpoint HTTP público explotado para obtener acceso a servicios internos— pertenece a la categoría «explotación de aplicaciones expuestas», una de las vías de entrada persistentes en el panorama europeo. La segmentación y el parcheo reducen la superficie, pero no sustituyen la validación del destino en la aplicación [R1].

### 2.2 CrowdStrike

- **2026 Global Threat Report** [R8]: el informe registra un **incremento del 42 %** en vulnerabilidades de día cero explotadas antes de su divulgación pública respecto al periodo anterior; no afirma que el 42 % del total de vulnerabilidades fueran explotadas de esa forma. El 40 % de las vulnerabilidades explotadas por actores China-nexus afectaron a dispositivos de borde; el 82 % de las detecciones fueron *malware-free*, lo que refleja el abuso de identidades y relaciones de confianza para moverse lateralmente. El tiempo medio de *breakout* cayó a 29 minutos.
- **2025 Global Threat Report** [R9]: el 52 % de las vulnerabilidades observadas se relacionaron con acceso inicial; el informe documenta además que los actores obtenían credenciales cloud de fuentes no aseguradas como el **Instance Metadata Service** de máquinas virtuales, práctica ya común en 2023 y que continuó en 2024.

**Lectura para el laboratorio:** la cadena explotada aquí (endpoint público → servicio interno → metadatos) reproduce, en miniatura y con datos ficticios, dos patrones observados por CrowdStrike: explotación de superficie expuesta y recolección de credenciales desde metadatos de instancia.

### 2.3 MITRE ATT&CK y casos documentados

| Referencia | Táctica | Aportación al análisis |
|---|---|---|
| **T1190 – Exploit Public-Facing Application** [R3] | *Initial Access* | Define la explotación de una debilidad en un sistema expuesto a Internet. Indica explícitamente que, en aplicaciones cloud o containerizadas, puede abrir un camino hacia las APIs cloud/contenedor, por ejemplo mediante la **Cloud Instance Metadata API**. |
| **T1552.005 – Unsecured Credentials: Cloud Instance Metadata API** [R4] | *Credential Access* | Describe el abuso de SSRF en un proxy web público para consultar la API de metadatos y señala `169.254.169.254` como dirección de facto. Sus mitigaciones incluyen restringir el tráfico hacia metadatos y limitar el acceso por red. |
| **Campaña C0029 – Cutting Edge** [R5] | *Initial Access* | Caso real de SSRF (CVE-2024-21893) encadenado con otras vulnerabilidades en Ivanti Connect Secure para eludir mitigaciones previas. Ilustra que el SSRF suele ser un eslabón, no el impacto final. |

En el laboratorio, `fake-metadata` **reproduce de forma simplificada el patrón SSRF hacia un servicio de metadatos**, no una implementación idéntica al servicio real de AWS. Se sustituye la dirección link-local `169.254.169.254` por `172.28.0.30:80` porque Docker no garantiza la asignación de aquella, y se sirve un endpoint Flask con respuestas y credenciales inventadas. No hay IMDSv2 (petición `PUT` de token y cabecera `X-aws-ec2-metadata-token`), TTL de sesión, IAM real ni respuesta de AWS: solo se modela la forma de la petición y el hecho de que el frontend pueda alcanzarla. Por tanto, esta sección apoya la justificación del vector, no una replicación funcional del *Instance Metadata Service* de AWS. La dirección usada está documentada en `docs/puertos-y-protocolos.md`.

## 3. Modelo causal del "punto ciego" de confianza

1. **Entrada controlada por el atacante.** `/preview?url=<URL>` acepta cualquier valor sin validación de esquema, host ni rango IP.
2. **Ejecución en el servidor.** El frontend resuelve y solicita esa URL con `requests`, desde su propia identidad de red.
3. **Cruce de frontera sin control.** El frontend tiene interfaces en `public-net` e `internal-net` (`172.28.0.10`). Los servicios internos solo pertenecen a `internal-net`. Para ellos, la petición parece legítima: viene de un vecino de su red.
4. **Confianza implícita.** `internal-admin-service` registra la IP de origen pero **no autentica ni autoriza** ninguna petición. No hay mTLS, token ni verificación de Host. La confianza se delega por completo a la pertenencia a la red.
5. **Impacto.** Se leen `/admin/users` y `/admin/config` y las credenciales ficticias de `fake-metadata`. El frontend devuelve el cuerpo al atacante, cerrando el ciclo.

La red `internal-net` está declarada con `internal: true`, lo que aísla a los contenedores que solo pertenecen a ella del exterior y de otras redes Docker; sin embargo, **no filtra el tráfico que el propio frontend emite hacia ella**, porque el frontend también es miembro de esa red. Por tanto, la segmentación por sí sola no corrige el fallo: reduce la exposición, pero el nodo que hace las peticiones por cuenta del usuario está dentro del perímetro. La defensa debe combinar allowlist/resolución controlada en la aplicación con autenticación y restricciones de red en los servicios internos (competencia de P4).

Dos matices adicionales que deben considerarse al diseñar la corrección:

- `requests` sigue redirecciones HTTP por defecto: una validación aplicada solo a la URL original puede evadirse en un salto posterior.
- La validación debe hacerse **después de resolver DNS** y contra la IP efectiva, para no depender de representaciones textuales alternativas del mismo destino.

## 4. Impacto esperado y límites del modelo

| Activo | Ruta abusada | Dato expuesto | Impacto en el laboratorio |
|---|---|---|---|
| `internal-admin-service` | `/admin/users` | Listado de usuarios y roles ficticios | Pérdida de confidencialidad; reconocimiento interno |
| `internal-admin-service` | `/admin/config` | `db_password`, `api_key` ficticios | Pérdida de confidencialidad de configuración |
| `fake-metadata` | `/latest/meta-data/iam/security-credentials/lab-ec2-role` | Credenciales AWS simuladas | Escalada simulada a identidad cloud |

**Límites:** no hay servicios reales de AWS, no se contacta a `169.254.169.254`, los secretos son cadenas ficticias y `internal-net` no tiene salida a Internet. El frontend, en cambio, sí pertenece a `public-net` y podría alcanzar destinos externos; el laboratorio se centra en los destinos internos para mantener el ejercicio reproducible y seguro.

## 5. Aportación al documento final

Esta sección cubre la **justificación técnica** (criterio 1): definición normalizada del vector, clasificación en OWASP/CWE y MITRE ATT&CK, contexto empírico de ENISA y CrowdStrike con sus denominadores, y el modelo causal aplicado al `docker-compose.yml` de P1. P3 puede reutilizar la cadena del apartado 3 como guion del ataque; P4 debe usar los dos matices del apartado 3 como requisitos de la corrección.

## 6. Referencias

- **[R1]** OWASP Foundation. (2021). *A10:2021 – Server-Side Request Forgery (SSRF)*. <https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/>
- **[R2]** MITRE Corporation. (n.d.). *CWE-918: Server-Side Request Forgery* (Versión 5.0). Recuperado el 26 de noviembre de 2026, de https://cwe.mitre.org/data/definitions/918.html
- **[R3]** MITRE Corporation. (2026, 12 de mayo). *Exploit public-facing application* (T1190). MITRE ATT&CK Enterprise. https://attack.mitre.org/techniques/T1190/
- **[R4]** MITRE Corporation. (2026, 12 de mayo). *Unsecured credentials: Cloud Instance Metadata API* (T1552.005). MITRE ATT&CK Enterprise. https://attack.mitre.org/techniques/T1552/005/
- **[R5]** MITRE Corporation. (2026, 31 de julio). *Cutting Edge* (C0029). MITRE ATT&CK. https://attack.mitre.org/campaigns/C0029/
- **[R6]** European Union Agency for Cybersecurity (ENISA). (2026, 22 de septiembre). *ENISA Threat Landscape 2026*. https://www.enisa.europa.eu/publications/enisa-threat-landscape-2026 (PDF: https://www.enisa.europa.eu/sites/default/files/2026-09/ENISA%20Threat%20Landscape%202026_Final.pdf)
- **[R7]** European Union Agency for Cybersecurity (ENISA). (2025, 1 de octubre). *ENISA Threat Landscape 2025*. https://www.enisa.europa.eu/publications/enisa-threat-landscape-2025
- **[R8]** CrowdStrike. (2026, 24 de febrero). *2026 Global Threat Report*. https://www.crowdstrike.com/en-us/global-threat-report/ (Resumen ejecutivo: https://www.crowdstrike.com/en-us/resources/reports/global-threat-report-executive-summary-2026)
- **[R9]** CrowdStrike. (2025, 27 de febrero). *2025 Global Threat Report: Executive summary*. https://www.crowdstrike.com/en-us/resources/reports/global-threat-report-executive-summary-2025/
- **[R10]** OWASP Foundation. (n.d.). *Server Side Request Forgery Prevention Cheat Sheet*. OWASP Cheat Sheet Series. Recuperado el 26 de noviembre de 2026, de https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- **[R11]** valemolina567. (2026, 26 de noviembre). *ssrf-lab-grupo4: docs/puertos-y-protocolos.md y lab-environment/docker-compose.yml* (Commit `03b49fb`) [Repositorio de código]. GitHub. https://github.com/valemolina567/ssrf-lab-grupo4

*Fuentes consultadas el 26 de noviembre de 2026.*
