"""
Spectra Recon - Vulnerability Assessment.

Cruza los servicios detectados (con sus versiones) contra
bases de datos de vulnerabilidades conocidas (CVEs).

Dos fuentes de datos:

1. Base local (KNOWN_VULNS) - Diccionario hardcoded con CVEs
   de alta criticidad para servicios comunes. Rapida, offline,
   pero limitada a lo que incluyamos manualmente.

2. NVD API v2 (NIST) - La base de datos oficial de CVEs del
   gobierno de EEUU. Busca por CPE string (el identificador
   estandar de software que nmap nos da).
   API: https://services.nvd.nist.gov/rest/json/cves/2.0
   Sin API key: 5 requests / 30 segundos (suficiente para nosotros).

El flujo:
  1. Recibe los hosts con sus puertos y servicios
  2. Para cada servicio, extrae el CPE y/o producto+version
  3. Busca en la base local (instantaneo)
  4. Busca en NVD por CPE (si disponible)
  5. Deduplica y devuelve lista de Vulnerability

Uso basico:
    assessor = VulnAssessment()
    vulns = assessor.assess(hosts)
    for v in vulns:
        print(f"  {v.vuln_id} [{v.severity}] {v.description}")
"""

from __future__ import annotations

import logging
import time

import httpx

from recon.models import Host, Severity, Vulnerability

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Base local de vulnerabilidades conocidas
# ---------------------------------------------------------------------------
# Formato: (producto_lower, version_prefix) -> lista de CVEs
#
# Esto es un subset minimo para aprender. En produccion se usaria
# una base de datos completa (NVD dump, Vulners, etc.)
#
# Cada entrada es un dict con los campos de nuestro modelo Vulnerability.
# La clave es (producto, version_prefix): si el servicio detectado
# tiene ese producto y su version empieza por ese prefix, hay match.

KNOWN_VULNS: dict[tuple[str, str], list[dict]] = {
    # Apache HTTP Server
    ("apache", "2.4.7"): [
        {
            "vuln_id": "CVE-2021-44790",
            "severity": Severity.CRITICAL,
            "score": 9.8,
            "description": "Apache HTTP Server 2.4.x buffer overflow in mod_lua. "
            "Allows RCE via crafted request body.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44790"],
        },
        {
            "vuln_id": "CVE-2021-41773",
            "severity": Severity.CRITICAL,
            "score": 9.8,
            "description": "Apache HTTP Server 2.4.49 path traversal. "
            "Allows reading files outside document root.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        },
        {
            "vuln_id": "CVE-2017-15715",
            "severity": Severity.HIGH,
            "score": 8.1,
            "description": "Apache HTTP Server 2.4.0-2.4.29 bypass of FilesMatch "
            "via malicious filename with trailing newline.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-15715"],
        },
    ],
    ("apache", "2.4.6"): [
        {
            "vuln_id": "CVE-2021-44790",
            "severity": Severity.CRITICAL,
            "score": 9.8,
            "description": "Apache HTTP Server 2.4.x buffer overflow in mod_lua. "
            "Allows RCE via crafted request body.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44790"],
        },
        {
            "vuln_id": "CVE-2014-0226",
            "severity": Severity.HIGH,
            "score": 7.5,
            "description": "Apache HTTP Server race condition in mod_status. "
            "Heap buffer overflow allows DoS or information disclosure.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0226"],
        },
    ],
    # OpenSSH
    ("openssh", "6.6"): [
        {
            "vuln_id": "CVE-2016-0777",
            "severity": Severity.HIGH,
            "score": 8.1,
            "description": "OpenSSH client before 7.1p2 roaming feature "
            "information leak. Allows private key theft.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2016-0777"],
        },
        {
            "vuln_id": "CVE-2015-5600",
            "severity": Severity.HIGH,
            "score": 8.5,
            "description": "OpenSSH before 6.9 MaxAuthTries bypass. "
            "Allows brute force keyboard-interactive authentication.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-5600"],
        },
        {
            "vuln_id": "CVE-2023-38408",
            "severity": Severity.CRITICAL,
            "score": 9.8,
            "description": "OpenSSH before 9.3p2 ssh-agent remote code execution "
            "via PKCS#11 provider.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
        },
    ],
    ("openssh", "7."): [
        {
            "vuln_id": "CVE-2023-38408",
            "severity": Severity.CRITICAL,
            "score": 9.8,
            "description": "OpenSSH before 9.3p2 ssh-agent remote code execution "
            "via PKCS#11 provider.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
        },
        {
            "vuln_id": "CVE-2020-15778",
            "severity": Severity.HIGH,
            "score": 7.8,
            "description": "OpenSSH through 8.3p1 scp command injection "
            "allows executing arbitrary commands.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-15778"],
        },
    ],
    ("openssh", "8."): [
        {
            "vuln_id": "CVE-2023-38408",
            "severity": Severity.CRITICAL,
            "score": 9.8,
            "description": "OpenSSH before 9.3p2 ssh-agent remote code execution "
            "via PKCS#11 provider.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
        },
    ],
    # nginx
    ("nginx", "1.18"): [
        {
            "vuln_id": "CVE-2021-23017",
            "severity": Severity.CRITICAL,
            "score": 9.4,
            "description": "nginx resolver off-by-one heap write. "
            "Allows RCE via forged DNS response.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
        },
    ],
    ("nginx", "1.14"): [
        {
            "vuln_id": "CVE-2019-9511",
            "severity": Severity.HIGH,
            "score": 7.5,
            "description": "nginx HTTP/2 Data Dribble DoS. "
            "Attacker exhausts server resources via slow reads.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-9511"],
        },
        {
            "vuln_id": "CVE-2021-23017",
            "severity": Severity.CRITICAL,
            "score": 9.4,
            "description": "nginx resolver off-by-one heap write. "
            "Allows RCE via forged DNS response.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
        },
    ],
    # Microsoft IIS
    ("iis", "10."): [
        {
            "vuln_id": "CVE-2021-31166",
            "severity": Severity.CRITICAL,
            "score": 9.8,
            "description": "HTTP Protocol Stack RCE in Windows IIS. "
            "Wormable, allows unauthenticated remote code execution.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-31166"],
        },
    ],
}


# ---------------------------------------------------------------------------
# Vulnerability Assessment
# ---------------------------------------------------------------------------


class VulnAssessment:
    """Evaluacion de vulnerabilidades cruzando servicios con bases de CVEs.

    Ejemplo:
        assessor = VulnAssessment()

        # Desde hosts escaneados con port_scanner
        vulns = assessor.assess(hosts)

        # Solo NVD para un CPE especifico
        vulns = assessor.query_nvd("cpe:/a:apache:http_server:2.4.7")
    """

    def __init__(
        self,
        use_nvd: bool = True,
        nvd_api_key: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        """Inicializa el evaluador.

        Args:
            use_nvd: Consultar NVD API (requiere conexion a internet).
            nvd_api_key: API key de NVD (opcional, aumenta rate limit de 5 a 50 req/30s).
                         Obtener en: https://nvd.nist.gov/developers/request-an-api-key
            timeout: Timeout para peticiones HTTP a NVD.
        """
        self._use_nvd = use_nvd
        self._nvd_api_key = nvd_api_key
        self._timeout = timeout
        # Control de rate limiting para NVD
        self._last_nvd_request: float = 0.0
        # Sin API key: 5 req/30s = 1 req/6s
        # Con API key: 50 req/30s = 1 req/0.6s
        self._nvd_delay = 0.6 if nvd_api_key else 6.0

    def assess(self, hosts: list[Host]) -> list[Vulnerability]:
        """Evalua vulnerabilidades de todos los hosts.

        Recorre cada host -> cada puerto abierto -> cada servicio,
        y busca CVEs conocidos.

        Args:
            hosts: Lista de hosts con puertos y servicios detectados.

        Returns:
            Lista de vulnerabilidades encontradas (deduplicadas).
        """
        logger.info(f"Evaluacion de vulnerabilidades para {len(hosts)} host(s)")

        all_vulns: dict[str, Vulnerability] = {}  # Dedup por vuln_id

        for host in hosts:
            for port in host.open_ports:
                if not port.service:
                    continue

                svc = port.service
                service_label = (
                    f"{host.address}:{port.number} "
                    f"({svc.product or svc.name} {svc.version or ''})"
                )

                # 1. Busqueda local (instantanea)
                local_vulns = self._search_local(svc.product, svc.version)
                for v in local_vulns:
                    v.affected_service = service_label
                    all_vulns[v.vuln_id] = v

                if local_vulns:
                    logger.info(
                        f"  {service_label}: {len(local_vulns)} CVE(s) en base local"
                    )

                # 2. Busqueda NVD por CPE (si tenemos CPE y NVD habilitado)
                if self._use_nvd and svc.cpe:
                    nvd_vulns = self.query_nvd(svc.cpe)
                    for v in nvd_vulns:
                        v.affected_service = service_label
                        if v.vuln_id not in all_vulns:
                            all_vulns[v.vuln_id] = v

                    if nvd_vulns:
                        logger.info(
                            f"  {service_label}: {len(nvd_vulns)} CVE(s) en NVD"
                        )

        results = sorted(
            all_vulns.values(),
            key=lambda v: v.score or 0.0,
            reverse=True,  # Mas criticos primero
        )
        logger.info(f"Total vulnerabilidades unicas: {len(results)}")
        return results

    # -------------------------------------------------------------------
    # Busqueda local
    # -------------------------------------------------------------------

    def _search_local(
        self,
        product: str | None,
        version: str | None,
    ) -> list[Vulnerability]:
        """Busca en la base local de vulnerabilidades conocidas.

        Compara el producto+version del servicio contra las claves
        de KNOWN_VULNS. El match es por prefijo de version:
        si la clave es ("apache", "2.4.7") y el servicio tiene
        version "2.4.7", hay match.

        Args:
            product: Nombre del producto (ej: "OpenSSH", "Apache httpd")
            version: Version del producto (ej: "2.4.7", "6.6.1p1")

        Returns:
            Lista de Vulnerability que coinciden.
        """
        if not product:
            return []

        # Normalizar producto: "Apache httpd" -> "apache", "OpenSSH" -> "openssh"
        product_lower = product.lower().split()[0]

        vulns: list[Vulnerability] = []

        for (known_product, version_prefix), cve_list in KNOWN_VULNS.items():
            if product_lower != known_product:
                continue

            # Si no tenemos version, reportamos todo (mejor pecar de mas)
            if not version or version.startswith(version_prefix):
                for cve_data in cve_list:
                    vulns.append(Vulnerability(**cve_data))

        return vulns

    # -------------------------------------------------------------------
    # NVD API v2
    # -------------------------------------------------------------------

    def query_nvd(self, cpe: str, max_results: int = 10) -> list[Vulnerability]:
        """Consulta la NVD API v2 por CPE string.

        El CPE (Common Platform Enumeration) es un identificador estandar
        para software. nmap nos lo da en formato 2.2:
            cpe:/a:apache:http_server:2.4.7

        La NVD acepta formato 2.3:
            cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*

        Convertimos automaticamente entre formatos.

        Args:
            cpe: CPE string (formato 2.2 o 2.3)
            max_results: Maximo de CVEs a devolver.

        Returns:
            Lista de Vulnerability encontradas en NVD.
        """
        cpe_23 = self._cpe_to_23(cpe)
        if not cpe_23:
            return []

        # Rate limiting
        self._wait_for_rate_limit()

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "cpeName": cpe_23,
            "resultsPerPage": str(max_results),
        }
        headers = {}
        if self._nvd_api_key:
            headers["apiKey"] = self._nvd_api_key

        logger.info(f"Consultando NVD para: {cpe_23}")

        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.get(url, params=params, headers=headers)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPError as e:
            logger.warning(f"Error consultando NVD: {e}")
            return []
        except Exception as e:
            logger.warning(f"Error inesperado con NVD: {e}")
            return []

        return self._parse_nvd_response(data)

    def _parse_nvd_response(self, data: dict) -> list[Vulnerability]:
        """Parsea la respuesta JSON de la NVD API v2.

        La estructura de NVD es:
            {
              "vulnerabilities": [
                {
                  "cve": {
                    "id": "CVE-2021-44790",
                    "descriptions": [{"lang": "en", "value": "..."}],
                    "metrics": {
                      "cvssMetricV31": [{
                        "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}
                      }]
                    },
                    "references": [{"url": "..."}]
                  }
                }
              ]
            }
        """
        vulns: list[Vulnerability] = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            # Descripcion (preferir ingles)
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # CVSS score y severity
            score, severity = self._extract_cvss(cve.get("metrics", {}))

            # Referencias
            references = [
                ref.get("url", "")
                for ref in cve.get("references", [])
                if ref.get("url")
            ][:5]  # Max 5 referencias

            if cve_id:
                vulns.append(
                    Vulnerability(
                        vuln_id=cve_id,
                        severity=severity,
                        score=score,
                        description=description[:500],  # Limitar longitud
                        references=references,
                    )
                )

        return vulns

    def _extract_cvss(self, metrics: dict) -> tuple[float | None, Severity]:
        """Extrae CVSS score y severity de los metrics de NVD.

        NVD puede tener CVSS v3.1, v3.0, o v2. Preferimos v3.1.
        """
        # Intentar CVSS v3.1 primero, luego v3.0, luego v2
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity_str = cvss_data.get("baseSeverity", "").lower()

                if score is not None:
                    severity = self._map_severity(float(score))
                    return float(score), severity

        return None, Severity.INFO

    @staticmethod
    def _map_severity(score: float) -> Severity:
        """Mapea un CVSS score numerico a nuestro enum Severity.

        CVSS v3 ranges:
          9.0 - 10.0 = Critical
          7.0 -  8.9 = High
          4.0 -  6.9 = Medium
          0.1 -  3.9 = Low
          0.0        = Info
        """
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0.0:
            return Severity.LOW
        return Severity.INFO

    @staticmethod
    def _cpe_to_23(cpe: str) -> str | None:
        """Convierte CPE 2.2 a formato 2.3 (que acepta la NVD API).

        CPE 2.2: cpe:/a:apache:http_server:2.4.7
        CPE 2.3: cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*

        Si ya esta en 2.3, lo devuelve tal cual.
        Si el formato es invalido, devuelve None.
        """
        if not cpe:
            return None

        # Ya en formato 2.3
        if cpe.startswith("cpe:2.3:"):
            return cpe

        # Formato 2.2: cpe:/tipo:vendor:product:version
        if cpe.startswith("cpe:/"):
            parts = cpe.replace("cpe:/", "").split(":")
            # Rellenar con * hasta tener 11 campos
            while len(parts) < 11:
                parts.append("*")
            return "cpe:2.3:" + ":".join(parts[:11])

        logger.warning(f"Formato CPE no reconocido: {cpe}")
        return None

    def _wait_for_rate_limit(self) -> None:
        """Espera si es necesario para respetar el rate limit de NVD."""
        elapsed = time.time() - self._last_nvd_request
        if elapsed < self._nvd_delay:
            wait = self._nvd_delay - elapsed
            logger.debug(f"Rate limit NVD: esperando {wait:.1f}s")
            time.sleep(wait)
        self._last_nvd_request = time.time()
