"""
Spectra Recon - Vulnerability Assessment.

Cruza los servicios detectados (con sus versiones) contra la
base de datos oficial de vulnerabilidades del NIST (NVD API v2).

Todas las vulnerabilidades reportadas son organicas: provienen
de consultas reales a la NVD API usando los CPE strings que
nmap detecta en cada servicio. No hay datos hardcodeados.

API: https://services.nvd.nist.gov/rest/json/cves/2.0
Sin API key: 5 requests / 30 segundos.
Con API key: 50 requests / 30 segundos.

El flujo:
  1. Recibe los hosts con sus puertos y servicios
  2. Para cada servicio, extrae el CPE que nmap detecto
  3. Convierte el CPE de formato 2.2 a 2.3 (requerido por NVD)
  4. Consulta la NVD API en tiempo real
  5. Deduplica y devuelve lista de Vulnerability

Si un servicio no tiene CPE (nmap no lo detecto), no se reportan
vulnerabilidades para ese servicio. Prefiere no reportar a inventar.

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
# Vulnerability Assessment
# ---------------------------------------------------------------------------


class VulnAssessment:
    """Evaluacion de vulnerabilidades consultando la NVD API del NIST.

    Todas las vulnerabilidades reportadas provienen de la NVD (National
    Vulnerability Database) del gobierno de EEUU. El matching se hace
    por CPE string — el identificador estandar de software que nmap
    detecta durante el service scan (-sV).

    Ejemplo:
        assessor = VulnAssessment()

        # Desde hosts escaneados con port_scanner
        vulns = assessor.assess(hosts)

        # Consultar NVD para un CPE especifico
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
        """Evalua vulnerabilidades de todos los hosts via NVD API.

        Recorre cada host -> cada puerto abierto -> cada servicio,
        y consulta la NVD si el servicio tiene un CPE detectado por nmap.

        Servicios sin CPE se omiten — no se inventan vulnerabilidades.

        Args:
            hosts: Lista de hosts con puertos y servicios detectados.

        Returns:
            Lista de vulnerabilidades encontradas (deduplicadas).
        """
        logger.info(f"Evaluacion de vulnerabilidades para {len(hosts)} host(s)")

        if not self._use_nvd:
            logger.info("NVD deshabilitado, no se reportan vulnerabilidades")
            return []

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

                # Solo consultar NVD si nmap detecto un CPE para este servicio
                if not svc.cpe:
                    logger.debug(f"  {service_label}: sin CPE, omitiendo consulta NVD")
                    continue

                nvd_vulns = self.query_nvd(svc.cpe)
                for v in nvd_vulns:
                    v.affected_service = service_label
                    if v.vuln_id not in all_vulns:
                        all_vulns[v.vuln_id] = v

                if nvd_vulns:
                    logger.info(f"  {service_label}: {len(nvd_vulns)} CVE(s) en NVD")

        results = sorted(
            all_vulns.values(),
            key=lambda v: v.score or 0.0,
            reverse=True,  # Mas criticos primero
        )
        logger.info(f"Total vulnerabilidades unicas: {len(results)}")
        return results

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

        # Descartar CPEs sin version concreta — la NVD no los acepta en cpeName.
        # Formato CPE 2.3: cpe:2.3:part:vendor:product:version:...
        # El campo version es el indice 5. Si es "*" no hay version especifica.
        cpe_parts = cpe_23.split(":")
        if len(cpe_parts) > 5 and cpe_parts[5] == "*":
            logger.debug(f"CPE sin version concreta, omitiendo: {cpe_23}")
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
