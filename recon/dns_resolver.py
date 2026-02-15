"""
Spectra Recon - DNS Resolver.

Modulo centralizado para toda resolucion DNS. Cualquier otro
modulo que necesite resolver hostnames a IPs (o consultar
registros MX, NS, TXT, CNAME) importa desde aqui.

Separarlo tiene dos ventajas:
  1. Un solo punto donde configurar timeouts, nameservers, retries
  2. Otros modulos no duplican logica de resolucion

Registros DNS que resolvemos y POR QUE importan en recon:
  - A/AAAA: IPs del host (la base de todo escaneo)
  - MX:     Servidores de correo (revelan infraestructura interna)
  - NS:     Nameservers (revelan proveedor DNS: Cloudflare, AWS, etc.)
  - TXT:    SPF/DKIM/DMARC (a veces contienen tokens o config interna)
  - CNAME:  Alias (app.example.com -> lb-123.aws.com revela cloud provider)

Uso basico:
    resolver = DnsResolver()

    # Resolver IPs
    ips = resolver.resolve_ips("scanme.nmap.org")

    # Todos los registros de un dominio
    records = resolver.resolve_all("nmap.org")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Modelo de resultado DNS
# ---------------------------------------------------------------------------


@dataclass
class DnsRecords:
    """Todos los registros DNS de un dominio.

    Usamos dataclass en vez de Pydantic aqui porque es un
    contenedor interno de trabajo, no un modelo que serialicemos
    a JSON. Pydantic es para los modelos de salida (models.py).
    """

    hostname: str
    a: list[str] = field(default_factory=list)  # IPv4
    aaaa: list[str] = field(default_factory=list)  # IPv6
    mx: list[str] = field(default_factory=list)  # Mail servers
    ns: list[str] = field(default_factory=list)  # Nameservers
    txt: list[str] = field(default_factory=list)  # TXT records
    cname: list[str] = field(default_factory=list)  # Aliases

    @property
    def all_ips(self) -> list[str]:
        """Todas las IPs (v4 + v6) combinadas."""
        return self.a + self.aaaa

    def summary(self) -> str:
        """Resumen legible de los registros encontrados."""
        parts: list[str] = [f"DNS records for {self.hostname}:"]
        if self.a:
            parts.append(f"  A:     {', '.join(self.a)}")
        if self.aaaa:
            parts.append(f"  AAAA:  {', '.join(self.aaaa)}")
        if self.cname:
            parts.append(f"  CNAME: {', '.join(self.cname)}")
        if self.mx:
            parts.append(f"  MX:    {', '.join(self.mx)}")
        if self.ns:
            parts.append(f"  NS:    {', '.join(self.ns)}")
        if self.txt:
            parts.append(f"  TXT:   {', '.join(self.txt)}")
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# DNS Resolver
# ---------------------------------------------------------------------------


class DnsResolver:
    """Resolver DNS centralizado para todo Spectra.

    Ejemplo:
        resolver = DnsResolver()

        # Solo IPs (lo mas comun)
        ips = resolver.resolve_ips("scanme.nmap.org")
        # -> ["45.33.32.156"]

        # Todos los registros (recon profundo)
        records = resolver.resolve_all("nmap.org")
        print(records.mx)   # -> ["mail.nmap.org"]
        print(records.ns)   # -> ["ns1.linode.com", ...]
        print(records.txt)  # -> ["v=spf1 ..."]
    """

    def __init__(
        self,
        timeout: float = 3.0,
        nameservers: list[str] | None = None,
    ) -> None:
        """Inicializa el resolver.

        Args:
            timeout: Timeout en segundos por consulta DNS.
            nameservers: Servidores DNS a usar. Si None, usa los del sistema.
                         Util para forzar 8.8.8.8 o 1.1.1.1 si el DNS
                         local es lento o filtra.
        """
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

        if nameservers:
            self._resolver.nameservers = nameservers
            logger.info(f"DNS nameservers: {nameservers}")

    # -------------------------------------------------------------------
    # Metodos publicos
    # -------------------------------------------------------------------

    def resolve_ips(self, hostname: str) -> list[str]:
        """Resuelve un hostname a sus IPs (A records, IPv4).

        Este es el metodo mas usado. Lo llaman subdomain_discovery,
        port_scanner, y cualquier modulo que necesite IPs.

        Args:
            hostname: FQDN a resolver (ej: "scanme.nmap.org")

        Returns:
            Lista de IPs como strings. Vacia si no resuelve.
        """
        return self._query(hostname, "A")

    def resolve_ipv6(self, hostname: str) -> list[str]:
        """Resuelve un hostname a sus IPs IPv6 (AAAA records)."""
        return self._query(hostname, "AAAA")

    def resolve_mx(self, domain: str) -> list[str]:
        """Obtiene servidores de correo (MX records).

        Los MX revelan infraestructura de email:
        - Google Workspace: "aspmx.l.google.com"
        - Microsoft 365: "*.mail.protection.outlook.com"
        - Propio: "mail.example.com" (potencial target)
        """
        return self._query(domain, "MX")

    def resolve_ns(self, domain: str) -> list[str]:
        """Obtiene nameservers (NS records).

        Los NS revelan el proveedor DNS:
        - Cloudflare: "*.ns.cloudflare.com"
        - AWS Route53: "ns-*.awsdns-*.com"
        - Linode: "ns*.linode.com"
        """
        return self._query(domain, "NS")

    def resolve_txt(self, domain: str) -> list[str]:
        """Obtiene registros TXT.

        Los TXT contienen:
        - SPF: "v=spf1 include:_spf.google.com ~all"
        - DKIM: claves publicas de firma de email
        - DMARC: politica de autenticacion de email
        - Verificaciones: "google-site-verification=..."
        - A veces tokens o config sensible por error
        """
        return self._query(domain, "TXT")

    def resolve_cname(self, hostname: str) -> list[str]:
        """Obtiene alias CNAME.

        Los CNAME revelan infraestructura cloud:
        - "app.example.com -> d1234.cloudfront.net" (AWS CloudFront)
        - "api.example.com -> lb-prod.us-east-1.elb.amazonaws.com" (AWS ELB)
        - "shop.example.com -> shops.myshopify.com" (Shopify)

        Un CNAME a un servicio que ya no existe es un "subdomain takeover"
        (vulnerabilidad critica).
        """
        return self._query(hostname, "CNAME")

    def resolve_all(self, domain: str) -> DnsRecords:
        """Resuelve TODOS los tipos de registros DNS de un dominio.

        Util para reconocimiento profundo: da una foto completa
        de la configuracion DNS del target.

        Args:
            domain: Dominio a consultar (ej: "nmap.org")

        Returns:
            DnsRecords con todos los registros encontrados.
        """
        logger.info(f"Resolucion DNS completa para: {domain}")

        records = DnsRecords(
            hostname=domain,
            a=self.resolve_ips(domain),
            aaaa=self.resolve_ipv6(domain),
            mx=self.resolve_mx(domain),
            ns=self.resolve_ns(domain),
            txt=self.resolve_txt(domain),
            cname=self.resolve_cname(domain),
        )

        logger.info(f"DNS completado: {len(records.all_ips)} IPs encontradas")
        return records

    # -------------------------------------------------------------------
    # Metodo interno
    # -------------------------------------------------------------------

    def _query(self, hostname: str, record_type: str) -> list[str]:
        """Ejecuta una consulta DNS y maneja todos los errores posibles.

        Args:
            hostname: Nombre a resolver.
            record_type: Tipo de registro DNS (A, AAAA, MX, NS, TXT, CNAME).

        Returns:
            Lista de resultados como strings. Vacia si falla.
        """
        try:
            answers = self._resolver.resolve(hostname, record_type)
            # Convertir cada respuesta a string limpio.
            # MX devuelve "10 mail.example.com." -> extraemos solo el hostname
            # NS devuelve "ns1.linode.com." -> quitamos el punto final
            results: list[str] = []
            for rdata in answers:
                value = str(rdata).rstrip(".")
                # MX tiene formato "prioridad hostname" -> solo hostname
                if record_type == "MX" and " " in value:
                    value = value.split(" ", 1)[1].rstrip(".")
                results.append(value)
            return results

        except dns.resolver.NXDOMAIN:
            # El dominio no existe
            return []
        except dns.resolver.NoAnswer:
            # El dominio existe pero no tiene ese tipo de registro
            return []
        except dns.resolver.Timeout:
            logger.debug(f"Timeout resolviendo {record_type} para {hostname}")
            return []
        except dns.resolver.NoNameservers:
            logger.debug(f"Sin nameservers para {hostname}")
            return []
        except dns.exception.DNSException as e:
            logger.debug(f"Error DNS ({record_type}) para {hostname}: {e}")
            return []
