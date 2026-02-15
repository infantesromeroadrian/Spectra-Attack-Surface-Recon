"""
Spectra Recon - Modelos de datos.

Define TODAS las estructuras que usaremos para representar
lo que descubrimos durante el reconocimiento.

Piense en esto como el "vocabulario" de nuestra herramienta:
si no tenemos palabras para describir un puerto, un servicio
o una vulnerabilidad, no podemos comunicar resultados.

Usamos Pydantic por 3 razones:
  1. Validacion automatica (un puerto fuera de 1-65535 peta al instante)
  2. Serializacion gratis (a JSON, dict, etc.)
  3. Documentacion viva (los tipos SON la documentacion)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums - Valores posibles fijos
# ---------------------------------------------------------------------------


class PortState(str, Enum):
    """Estado de un puerto segun nmap.

    - open: acepta conexiones (lo que buscamos)
    - closed: responde pero no hay servicio
    - filtered: un firewall bloquea la sonda (no sabemos)
    """

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class Protocol(str, Enum):
    """Protocolo de transporte.

    - tcp: el 99% de lo que escanearemos (HTTP, SSH, etc.)
    - udp: DNS, SNMP, algunos servicios legacy
    """

    TCP = "tcp"
    UDP = "udp"


class Severity(str, Enum):
    """Nivel de severidad de una vulnerabilidad (CVSS-based)."""

    CRITICAL = "critical"  # 9.0 - 10.0
    HIGH = "high"  # 7.0 - 8.9
    MEDIUM = "medium"  # 4.0 - 6.9
    LOW = "low"  # 0.1 - 3.9
    INFO = "info"  # 0.0 (informativo, no es vuln real)


# ---------------------------------------------------------------------------
# Modelos de entidades descubiertas
# ---------------------------------------------------------------------------


class ServiceInfo(BaseModel):
    """Un servicio corriendo en un puerto.

    Ejemplo real de lo que nmap devuelve para el puerto 22:
        name="ssh", product="OpenSSH", version="8.9p1",
        banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

    El campo `cpe` es el Common Platform Enumeration, un ID
    estandar para identificar software. Util para buscar CVEs.
    Ejemplo: "cpe:/a:openbsd:openssh:8.9p1"
    """

    name: str = Field(description="Nombre del servicio: ssh, http, mysql...")
    product: str | None = Field(
        default=None, description="Software concreto: OpenSSH, Apache, nginx"
    )
    version: str | None = Field(
        default=None, description="Version: 8.9p1, 2.4.52, etc."
    )
    banner: str | None = Field(
        default=None, description="Banner crudo que devuelve el servicio"
    )
    cpe: str | None = Field(default=None, description="CPE identifier para buscar CVEs")


class PortInfo(BaseModel):
    """Un puerto descubierto en un host.

    Combina la info del puerto (numero, estado, protocolo)
    con el servicio que corre en el (si lo detectamos).

    Ejemplo:
        PortInfo(number=22, state="open", protocol="tcp",
                 service=ServiceInfo(name="ssh", product="OpenSSH", version="8.9p1"))
    """

    number: int = Field(ge=1, le=65535, description="Numero de puerto (1-65535)")
    state: PortState = Field(default=PortState.OPEN, description="Estado del puerto")
    protocol: Protocol = Field(default=Protocol.TCP, description="TCP o UDP")
    service: ServiceInfo | None = Field(
        default=None, description="Servicio detectado en este puerto"
    )


class Host(BaseModel):
    """Un host (IP) descubierto con sus puertos y servicios.

    Representa una maquina en la red. Puede tener multiples
    puertos abiertos, cada uno con su servicio.

    Ejemplo:
        Host(address="45.33.32.156", hostname="scanme.nmap.org",
             os="Linux 5.x", ports=[...])
    """

    address: str = Field(description="Direccion IP (v4 o v6)")
    hostname: str | None = Field(
        default=None, description="Hostname resuelto por DNS inverso"
    )
    os: str | None = Field(default=None, description="Sistema operativo detectado")
    ports: list[PortInfo] = Field(
        default_factory=list, description="Puertos descubiertos"
    )

    @property
    def open_ports(self) -> list[PortInfo]:
        """Devuelve solo los puertos abiertos."""
        return [p for p in self.ports if p.state == PortState.OPEN]


class Subdomain(BaseModel):
    """Un subdominio descubierto.

    Ejemplo:
        Subdomain(name="mail.nmap.org", ips=["45.33.32.100"],
                  source="crt.sh")

    El campo `source` nos dice COMO lo encontramos, importante
    para saber la fiabilidad del hallazgo.
    """

    name: str = Field(description="FQDN del subdominio: mail.example.com")
    ips: list[str] = Field(
        default_factory=list, description="IPs resueltas para este subdominio"
    )
    source: str = Field(
        description="Fuente del descubrimiento: crt.sh, bruteforce, hackertarget"
    )


class WebTechnology(BaseModel):
    """Una tecnologia web detectada en un servicio HTTP.

    Ejemplo:
        WebTechnology(name="nginx", version="1.18.0",
                      category="web-server")

    Categorias tipicas:
        web-server, cms, framework, language, cdn, waf, analytics
    """

    name: str = Field(description="Nombre: nginx, WordPress, React, Cloudflare")
    version: str | None = Field(default=None, description="Version detectada")
    category: str = Field(description="Categoria: web-server, cms, framework, cdn, waf")


class Vulnerability(BaseModel):
    """Una vulnerabilidad descubierta.

    Ejemplo:
        Vulnerability(
            vuln_id="CVE-2021-44228", severity="critical", score=10.0,
            description="Log4Shell RCE in Apache Log4j",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
        )
    """

    vuln_id: str = Field(description="Identificador: CVE-2021-44228, GHSA-xxx, etc.")
    severity: Severity = Field(description="Nivel de severidad")
    score: float | None = Field(
        default=None, ge=0.0, le=10.0, description="CVSS score (0-10)"
    )
    description: str = Field(description="Descripcion de la vulnerabilidad")
    references: list[str] = Field(
        default_factory=list, description="URLs de referencia"
    )
    affected_service: str | None = Field(
        default=None, description="Servicio afectado: OpenSSH 8.9p1"
    )


# ---------------------------------------------------------------------------
# Modelos de agregacion (contienen a los anteriores)
# ---------------------------------------------------------------------------


class Target(BaseModel):
    """El objetivo completo de reconocimiento.

    Es el contenedor principal: un dominio con todos sus
    subdominios, hosts, tecnologias y vulnerabilidades.

    Todo lo que descubrimos se cuelga de aqui.
    """

    domain: str = Field(description="Dominio raiz: nmap.org, example.com")
    subdomains: list[Subdomain] = Field(default_factory=list)
    hosts: list[Host] = Field(default_factory=list)
    technologies: list[WebTechnology] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)

    @property
    def total_open_ports(self) -> int:
        """Cuenta total de puertos abiertos en todos los hosts."""
        return sum(len(h.open_ports) for h in self.hosts)

    @property
    def unique_services(self) -> set[str]:
        """Set de nombres de servicios unicos encontrados."""
        services: set[str] = set()
        for host in self.hosts:
            for port in host.open_ports:
                if port.service:
                    services.add(port.service.name)
        return services


class ScanResult(BaseModel):
    """Resultado completo de un pipeline de reconocimiento.

    Contiene el target con todos los hallazgos, mas metadatos
    del escaneo: cuando empezo, cuando acabo, que fases se
    ejecutaron, etc.

    El scan_id es un UUID unico para identificar este escaneo
    concreto (util para guardar historico y comparar).
    """

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: Target
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = Field(default=None)
    phases_completed: list[str] = Field(default_factory=list)

    def complete(self) -> None:
        """Marca el escaneo como completado con timestamp."""
        self.finished_at = datetime.now(timezone.utc)

    @property
    def duration_seconds(self) -> float | None:
        """Duracion del escaneo en segundos."""
        if self.finished_at and self.started_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def to_json(self, indent: int = 2) -> str:
        """Serializa el resultado completo a JSON."""
        return self.model_dump_json(indent=indent)
