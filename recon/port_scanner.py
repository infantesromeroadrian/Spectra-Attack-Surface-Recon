"""
Spectra Recon - Port Scanner.

Wrapper sobre nmap que escanea puertos, detecta servicios
y versiones, y devuelve los resultados como nuestros modelos.

nmap es EL estandar de la industria para escaneo de puertos.
En vez de reinventar la rueda, lo envolvemos con python-nmap
y mapeamos su salida a nuestros modelos Pydantic.

Uso basico:
    scanner = PortScanner()
    hosts = scanner.scan("scanme.nmap.org")
    for host in hosts:
        for port in host.open_ports:
            print(f"  :{port.number} -> {port.service.name}")

Perfiles de escaneo:
    - quick:    Top 100 puertos, sin version detection (~5s)
    - standard: Top 1000 puertos, con version detection (~30s)
    - full:     Todos los 65535 puertos, con version + OS (~5min)
"""

from __future__ import annotations

import logging
from enum import Enum

import nmap

from recon.models import Host, PortInfo, PortState, Protocol, ServiceInfo

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Perfiles de escaneo
# ---------------------------------------------------------------------------


class ScanProfile(str, Enum):
    """Perfiles predefinidos para distintos niveles de profundidad.

    Cada perfil define los argumentos que se le pasan a nmap.
    Los argumentos clave de nmap:
        -sS  : SYN scan (stealth, requiere root)
        -sT  : TCP connect scan (sin root, mas lento)
        -sV  : Detectar version de servicios
        -O   : Detectar sistema operativo
        -T4  : Velocidad agresiva (T0=paranoid ... T5=insane)
        --top-ports N : Escanear solo los N puertos mas comunes
    """

    QUICK = "quick"
    STANDARD = "standard"
    FULL = "full"


# Argumentos de nmap para cada perfil
# Usamos -sT (TCP connect) por defecto para no requerir root.
# Si el usuario ejecuta con sudo, puede cambiar a -sS (SYN scan).
SCAN_PROFILES: dict[ScanProfile, str] = {
    ScanProfile.QUICK: "-sT -T4 --top-ports 100",
    ScanProfile.STANDARD: "-sT -sV -T4 --top-ports 1000",
    ScanProfile.FULL: "-sT -sV -O -T4 -p 1-65535",
}


# ---------------------------------------------------------------------------
# Port Scanner
# ---------------------------------------------------------------------------


class PortScanner:
    """Wrapper sobre nmap para escaneo de puertos y servicios.

    Ejemplo:
        scanner = PortScanner()

        # Escaneo rapido
        hosts = scanner.scan("scanme.nmap.org", profile=ScanProfile.QUICK)

        # Escaneo con puertos especificos
        hosts = scanner.scan("192.168.1.1", ports="22,80,443,8080")
    """

    def __init__(self) -> None:
        """Inicializa el scanner y verifica que nmap este disponible."""
        try:
            self._nm = nmap.PortScanner()
            logger.info("nmap inicializado correctamente")
        except nmap.PortScannerError as e:
            raise RuntimeError(
                "nmap no esta instalado o no se encuentra en PATH. "
                "Instale con: sudo apt install nmap"
            ) from e

    def scan(
        self,
        target: str,
        profile: ScanProfile = ScanProfile.STANDARD,
        ports: str | None = None,
    ) -> list[Host]:
        """Ejecuta un escaneo nmap y devuelve los hosts descubiertos.

        Args:
            target: IP, rango de IPs, o dominio a escanear.
                    Ejemplos: "192.168.1.1", "10.0.0.0/24", "scanme.nmap.org"
            profile: Perfil de escaneo (quick, standard, full).
            ports: Override de puertos. Si se especifica, ignora el perfil.
                   Formato nmap: "22,80,443" o "1-1000" o "22,80,443,8000-9000"

        Returns:
            Lista de Host con sus puertos y servicios descubiertos.
        """
        # Construir argumentos
        if ports:
            # Si el usuario especifica puertos, usamos esos
            # pero mantenemos -sV para detectar servicios
            arguments = f"-sT -sV -T4 -p {ports}"
            logger.info(f"Escaneando {target} | puertos: {ports}")
        else:
            arguments = SCAN_PROFILES[profile]
            logger.info(f"Escaneando {target} | perfil: {profile.value}")

        # Ejecutar nmap
        logger.info(f"Comando nmap: nmap {arguments} {target}")
        self._nm.scan(hosts=target, arguments=arguments)

        # Parsear resultados
        hosts = self._parse_results()
        logger.info(f"Escaneo completado: {len(hosts)} host(s) encontrado(s)")

        return hosts

    def _parse_results(self) -> list[Host]:
        """Convierte la salida de nmap a nuestros modelos.

        nmap devuelve un diccionario anidado con esta estructura:
            nm[host_ip] = {
                'hostnames': [{'name': 'scanme.nmap.org', 'type': 'user'}],
                'tcp': {
                    22: {
                        'state': 'open',
                        'name': 'ssh',
                        'product': 'OpenSSH',
                        'version': '6.6.1p1',
                        'cpe': 'cpe:/a:openbsd:openssh:6.6.1p1',
                        ...
                    },
                    80: { ... },
                },
                'osmatch': [{'name': 'Linux 3.x', 'accuracy': '95'}]
            }

        Nuestro trabajo: mapear eso a Host -> PortInfo -> ServiceInfo.
        """
        hosts: list[Host] = []

        for host_ip in self._nm.all_hosts():
            host_data = self._nm[host_ip]

            # Extraer hostname (si existe)
            hostname = None
            hostnames = host_data.get("hostnames", [])
            if hostnames and hostnames[0].get("name"):
                hostname = hostnames[0]["name"]

            # Extraer OS (si se detecto)
            os_match = None
            os_matches = host_data.get("osmatch", [])
            if os_matches:
                os_match = os_matches[0].get("name")

            # Extraer puertos para cada protocolo (tcp, udp)
            ports: list[PortInfo] = []

            for proto_str in ["tcp", "udp"]:
                if proto_str not in host_data:
                    continue

                protocol = Protocol.TCP if proto_str == "tcp" else Protocol.UDP

                for port_num, port_data in host_data[proto_str].items():
                    port_info = self._parse_port(port_num, port_data, protocol)
                    ports.append(port_info)

            hosts.append(
                Host(
                    address=host_ip,
                    hostname=hostname,
                    os=os_match,
                    ports=ports,
                )
            )

        return hosts

    def _parse_port(
        self,
        port_num: int,
        port_data: dict,
        protocol: Protocol,
    ) -> PortInfo:
        """Convierte los datos de un puerto de nmap a PortInfo.

        Args:
            port_num: Numero de puerto (22, 80, etc.)
            port_data: Dict con state, name, product, version, cpe...
            protocol: TCP o UDP

        Returns:
            PortInfo con ServiceInfo si hay datos de servicio.
        """
        # Mapear estado del puerto
        raw_state = port_data.get("state", "filtered")
        try:
            state = PortState(raw_state)
        except ValueError:
            state = PortState.FILTERED

        # Construir ServiceInfo si hay datos de servicio
        service = None
        service_name = port_data.get("name", "")

        if service_name:
            service = ServiceInfo(
                name=service_name,
                product=port_data.get("product") or None,
                version=port_data.get("version") or None,
                banner=port_data.get("extrainfo") or None,
                cpe=port_data.get("cpe") or None,
            )

        return PortInfo(
            number=port_num,
            state=state,
            protocol=protocol,
            service=service,
        )
