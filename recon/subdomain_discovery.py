"""
Spectra Recon - Subdomain Discovery.

Descubre subdominios de un dominio objetivo usando dos tecnicas:

1. crt.sh (pasivo) - Consulta certificados SSL publicos.
   Cuando alguien emite un certificado para "*.example.com",
   los subdominios quedan registrados en Certificate Transparency
   logs. crt.sh los indexa y expone via API gratuita.

2. DNS brute force (activo) - Prueba una wordlist de nombres
   comunes (www, mail, ftp, admin, dev...) contra el DNS del
   dominio. Si responde con una IP, el subdominio existe.

Uso basico:
    discovery = SubdomainDiscovery()
    subdomains = discovery.discover("nmap.org")
    for sub in subdomains:
        print(f"  {sub.name} -> {sub.ips} (via {sub.source})")
"""

from __future__ import annotations

import logging
import uuid

import httpx

from recon.dns_resolver import DnsResolver
from recon.models import Subdomain

logger = logging.getLogger(__name__)


# Wordlist minima para brute force.
# En produccion se usaria una wordlist mas grande (SecLists tiene miles),
# pero para aprender y testear, estas cubren los nombres mas comunes.
DEFAULT_WORDLIST: list[str] = [
    "www",
    "mail",
    "ftp",
    "admin",
    "blog",
    "dev",
    "staging",
    "test",
    "api",
    "app",
    "portal",
    "vpn",
    "remote",
    "ns1",
    "ns2",
    "mx",
    "smtp",
    "pop",
    "imap",
    "webmail",
    "cpanel",
    "shop",
    "store",
    "cdn",
    "media",
    "static",
    "assets",
    "img",
    "images",
    "docs",
    "wiki",
    "git",
    "gitlab",
    "jenkins",
    "ci",
    "monitoring",
    "grafana",
    "prometheus",
    "elastic",
    "kibana",
    "db",
    "database",
    "mysql",
    "postgres",
    "redis",
    "mongo",
    "backup",
    "old",
    "new",
    "beta",
    "alpha",
    "demo",
    "sandbox",
    "internal",
    "intranet",
    "extranet",
    "sso",
    "auth",
    "login",
    "oauth",
    "proxy",
    "gateway",
    "lb",
    "edge",
]


class SubdomainDiscovery:
    """Descubrimiento de subdominios combinando tecnicas pasivas y activas.

    Ejemplo:
        discovery = SubdomainDiscovery()

        # Usar ambas tecnicas (por defecto)
        subs = discovery.discover("nmap.org")

        # Solo pasivo (no toca el target)
        subs = discovery.discover("nmap.org", use_bruteforce=False)

        # Con wordlist personalizada
        subs = discovery.discover("nmap.org", wordlist=["www", "mail", "api"])
    """

    def __init__(
        self,
        timeout: float = 10.0,
        dns_resolver: DnsResolver | None = None,
    ) -> None:
        """Inicializa el descubridor.

        Args:
            timeout: Timeout en segundos para peticiones HTTP (crt.sh).
            dns_resolver: Resolver DNS a usar. Si None, crea uno por defecto.
                          Inyectarlo permite compartir el mismo resolver
                          entre modulos (misma config, mismo cache).
        """
        self._timeout = timeout
        self._dns = dns_resolver or DnsResolver()

    def discover(
        self,
        domain: str,
        use_crtsh: bool = True,
        use_bruteforce: bool = True,
        wordlist: list[str] | None = None,
    ) -> list[Subdomain]:
        """Ejecuta el descubrimiento de subdominios.

        Args:
            domain: Dominio raiz a investigar (ej: "nmap.org")
            use_crtsh: Usar crt.sh (pasivo, recomendado)
            use_bruteforce: Usar DNS brute force (activo)
            wordlist: Lista de prefijos a probar. Si None, usa DEFAULT_WORDLIST.

        Returns:
            Lista de Subdomain encontrados, deduplicados.
        """
        logger.info(f"Descubrimiento de subdominios para: {domain}")

        # Paso 0: Detectar wildcard DNS ANTES de hacer brute force.
        # Si *.nmap.org resuelve a una IP, cualquier nombre inventado
        # tambien resolvera y nos llenaria de falsos positivos.
        wildcard_ips = self._detect_wildcard(domain)

        # Acumulamos subdominios de todas las fuentes
        # Usamos dict para deduplicar por nombre (el ultimo source gana)
        found: dict[str, Subdomain] = {}

        # Tecnica 1: crt.sh (pasivo)
        if use_crtsh:
            for sub in self._query_crtsh(domain):
                found[sub.name] = sub

        # Tecnica 2: DNS brute force (activo)
        if use_bruteforce:
            words = wordlist or DEFAULT_WORDLIST
            for sub in self._dns_bruteforce(domain, words):
                # Si ya lo encontramos por crt.sh, enriquecemos con IPs
                if sub.name in found and not found[sub.name].ips:
                    found[sub.name] = sub
                elif sub.name not in found:
                    found[sub.name] = sub

        # Filtrar falsos positivos de wildcard DNS.
        # Si un subdominio resuelve SOLO a IPs del wildcard,
        # es un falso positivo y lo descartamos.
        if wildcard_ips:
            before = len(found)
            found = {
                name: sub
                for name, sub in found.items()
                if not self._is_wildcard_match(sub.ips, wildcard_ips)
            }
            filtered = before - len(found)
            if filtered:
                logger.info(
                    f"Wildcard filter: descartados {filtered} falsos positivos "
                    f"(IPs wildcard: {wildcard_ips})"
                )

        results = list(found.values())
        logger.info(f"Total subdominios encontrados: {len(results)}")
        return results

    # -------------------------------------------------------------------
    # Deteccion de Wildcard DNS
    # -------------------------------------------------------------------

    def _detect_wildcard(self, domain: str) -> set[str]:
        """Detecta si el dominio tiene un wildcard DNS (*.domain.com).

        Genera un subdominio aleatorio imposible (UUID) y lo resuelve.
        Si resuelve a una IP, hay wildcard. Repetimos 3 veces para
        confirmar (a veces hay round-robin DNS).

        Args:
            domain: Dominio raiz a comprobar.

        Returns:
            Set de IPs del wildcard. Vacio si no hay wildcard.
        """
        wildcard_ips: set[str] = set()

        # Probamos 3 nombres aleatorios para estar seguros
        for _ in range(3):
            random_name = uuid.uuid4().hex[:16]
            fqdn = f"{random_name}.{domain}"
            ips = self._dns.resolve_ips(fqdn)
            wildcard_ips.update(ips)

        if wildcard_ips:
            logger.warning(
                f"WILDCARD DNS detectado en {domain} -> {wildcard_ips}. "
                f"Se filtraran falsos positivos."
            )
        else:
            logger.info(f"No hay wildcard DNS en {domain}")

        return wildcard_ips

    @staticmethod
    def _is_wildcard_match(subdomain_ips: list[str], wildcard_ips: set[str]) -> bool:
        """Comprueba si TODAS las IPs de un subdominio son del wildcard.

        Si un subdominio resuelve a 2 IPs y ambas son wildcard -> falso positivo.
        Si resuelve a 2 IPs y solo 1 es wildcard -> podria ser real, lo mantenemos.
        Si no tiene IPs (solo encontrado por crt.sh) -> lo mantenemos.
        """
        if not subdomain_ips:
            return False
        return all(ip in wildcard_ips for ip in subdomain_ips)

    # -------------------------------------------------------------------
    # Tecnica 1: crt.sh
    # -------------------------------------------------------------------

    def _query_crtsh(self, domain: str) -> list[Subdomain]:
        """Consulta crt.sh para encontrar subdominios via certificados SSL.

        crt.sh expone una API JSON simple:
            GET https://crt.sh/?q=%.domain.com&output=json

        El "%" es un wildcard que significa "cualquier subdominio".

        Cada entrada devuelta tiene un campo "name_value" con los
        nombres del certificado (pueden ser wildcards como *.nmap.org
        o nombres concretos como svn.nmap.org).
        """
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        logger.info(f"Consultando crt.sh para {domain}...")

        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.get(url)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPError as e:
            logger.warning(f"Error consultando crt.sh: {e}")
            return []
        except Exception as e:
            logger.warning(f"Error inesperado con crt.sh: {e}")
            return []

        # Extraer nombres unicos de los certificados
        names: set[str] = set()
        for entry in data:
            # name_value puede tener multiples nombres separados por \n
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                # Ignorar wildcards (*.nmap.org) y el dominio raiz
                if name and not name.startswith("*") and name != domain:
                    # Asegurarse de que es subdominio del target
                    if name.endswith(f".{domain}"):
                        names.add(name)

        logger.info(f"crt.sh: {len(names)} subdominios encontrados")

        # Resolver IPs para cada subdominio
        subdomains: list[Subdomain] = []
        for name in sorted(names):
            ips = self._dns.resolve_ips(name)
            subdomains.append(Subdomain(name=name, ips=ips, source="crt.sh"))

        return subdomains

    # -------------------------------------------------------------------
    # Tecnica 2: DNS Brute Force
    # -------------------------------------------------------------------

    def _dns_bruteforce(self, domain: str, wordlist: list[str]) -> list[Subdomain]:
        """Prueba nombres comunes como subdominios via DNS.

        Para cada palabra en la wordlist, intenta resolver
        "{word}.{domain}". Si el DNS responde con una IP,
        el subdominio existe.

        Ejemplo: wordlist=["www", "mail"]
            -> intenta resolver www.nmap.org, mail.nmap.org
        """
        logger.info(f"DNS brute force: probando {len(wordlist)} nombres...")

        subdomains: list[Subdomain] = []

        for word in wordlist:
            fqdn = f"{word}.{domain}"
            ips = self._dns.resolve_ips(fqdn)

            if ips:
                logger.info(f"  [+] {fqdn} -> {ips}")
                subdomains.append(Subdomain(name=fqdn, ips=ips, source="bruteforce"))

        logger.info(f"DNS brute force: {len(subdomains)} subdominios encontrados")
        return subdomains
