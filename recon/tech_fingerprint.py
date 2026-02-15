"""
Spectra Recon - Technology Fingerprinting.

Detecta que tecnologias web corren en un servicio HTTP
analizando tres fuentes de informacion:

1. HTTP Headers - El servidor se delata con cabeceras como
   "Server: nginx/1.18.0" o "X-Powered-By: PHP/8.1"

2. HTML Content - El codigo fuente contiene patrones reveladores:
   "/wp-content/" = WordPress, "react" en scripts = React, etc.

3. Cookies - Los nombres de cookies son firma de tecnologias:
   "PHPSESSID" = PHP, "JSESSIONID" = Java, etc.

Herramientas profesionales como Wappalyzer tienen miles de firmas.
Nosotros implementamos las mas comunes (~50) para entender el
concepto. La mecanica es la misma, solo cambia el volumen.

Uso basico:
    fingerprinter = TechFingerprinter()
    techs = fingerprinter.fingerprint("http://scanme.nmap.org")
    for tech in techs:
        print(f"  {tech.name} {tech.version or ''} ({tech.category})")
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import httpx

from recon.models import WebTechnology

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Firmas de deteccion
# ---------------------------------------------------------------------------
# Cada firma define: donde buscar, que patron buscar, y que tecnologia es.
# Esto es una version simplificada de lo que hace Wappalyzer con ~3000 firmas.


@dataclass
class Signature:
    """Una firma de deteccion de tecnologia.

    source: donde buscar ("header", "html", "cookie")
    key: la cabecera, patron HTML, o nombre de cookie
    pattern: regex para extraer el match (y opcionalmente la version)
    tech_name: nombre de la tecnologia
    category: categoria (web-server, cms, framework, etc.)
    version_group: grupo del regex que contiene la version (0 = no version)
    """

    source: str
    key: str
    pattern: str
    tech_name: str
    category: str
    version_group: int = 0


# --- Firmas en HTTP Headers ---

HEADER_SIGNATURES: list[Signature] = [
    # Web Servers
    Signature("header", "server", r"nginx/?(\S+)?", "nginx", "web-server", 1),
    Signature("header", "server", r"Apache/?(\S+)?", "Apache", "web-server", 1),
    Signature("header", "server", r"Microsoft-IIS/?(\S+)?", "IIS", "web-server", 1),
    Signature("header", "server", r"LiteSpeed", "LiteSpeed", "web-server"),
    Signature("header", "server", r"Caddy", "Caddy", "web-server"),
    Signature("header", "server", r"cloudflare", "Cloudflare", "cdn"),
    Signature("header", "server", r"gws", "Google Web Server", "web-server"),
    Signature("header", "server", r"openresty/?(\S+)?", "OpenResty", "web-server", 1),
    # Languages / Runtimes
    Signature("header", "x-powered-by", r"PHP/?(\S+)?", "PHP", "language", 1),
    Signature("header", "x-powered-by", r"Express", "Express.js", "framework"),
    Signature("header", "x-powered-by", r"ASP\.NET", "ASP.NET", "framework"),
    Signature(
        "header", "x-powered-by", r"Next\.js\s?(\S+)?", "Next.js", "framework", 1
    ),
    Signature(
        "header", "x-powered-by", r"Phusion Passenger", "Passenger", "web-server"
    ),
    # CMS indicators
    Signature("header", "x-generator", r"WordPress\s?(\S+)?", "WordPress", "cms", 1),
    Signature("header", "x-generator", r"Drupal\s?(\S+)?", "Drupal", "cms", 1),
    Signature("header", "x-generator", r"Joomla", "Joomla", "cms"),
    # CDN / WAF / Proxy
    Signature("header", "cf-ray", r".+", "Cloudflare", "cdn"),
    Signature("header", "x-cache", r"HIT|MISS", "Cache Layer", "cache"),
    Signature("header", "x-varnish", r".+", "Varnish", "cache"),
    Signature("header", "x-amz-cf-id", r".+", "AWS CloudFront", "cdn"),
    Signature("header", "x-vercel-id", r".+", "Vercel", "hosting"),
    Signature("header", "x-served-by", r"cache-", "Fastly", "cdn"),
    Signature("header", "strict-transport-security", r".+", "HSTS", "security"),
    Signature(
        "header",
        "x-content-type-options",
        r"nosniff",
        "X-Content-Type-Options",
        "security",
    ),
    Signature("header", "x-frame-options", r".+", "X-Frame-Options", "security"),
]

# --- Firmas en HTML Content ---

HTML_SIGNATURES: list[Signature] = [
    # CMS
    Signature("html", "", r"/wp-content/", "WordPress", "cms"),
    Signature("html", "", r"/wp-includes/", "WordPress", "cms"),
    Signature("html", "", r"wp-json", "WordPress", "cms"),
    Signature("html", "", r"Drupal\.settings", "Drupal", "cms"),
    Signature("html", "", r"/sites/default/files", "Drupal", "cms"),
    Signature("html", "", r"content=\"Joomla", "Joomla", "cms"),
    # Frameworks JS
    Signature("html", "", r"/_next/static", "Next.js", "framework"),
    Signature("html", "", r"__NEXT_DATA__", "Next.js", "framework"),
    Signature("html", "", r"react(?:\.min)?\.js", "React", "js-framework"),
    Signature("html", "", r"react-dom", "React", "js-framework"),
    Signature("html", "", r"vue(?:\.min)?\.js", "Vue.js", "js-framework"),
    Signature("html", "", r"ng-version=\"(\d[\d.]+)\"", "Angular", "js-framework", 1),
    Signature("html", "", r"angular(?:\.min)?\.js", "Angular", "js-framework"),
    # CSS Frameworks
    Signature(
        "html", "", r"bootstrap(?:\.min)?\.(?:css|js)", "Bootstrap", "css-framework"
    ),
    Signature(
        "html", "", r"tailwindcss|tailwind\.min\.css", "Tailwind CSS", "css-framework"
    ),
    # Libraries
    Signature("html", "", r"jquery(?:\.min)?\.js", "jQuery", "js-library"),
    # Analytics
    Signature(
        "html", "", r"google-analytics\.com|gtag", "Google Analytics", "analytics"
    ),
    Signature("html", "", r"googletagmanager\.com", "Google Tag Manager", "analytics"),
    # Meta generators
    Signature(
        "html",
        "",
        r"<meta[^>]+generator[^>]+content=\"([^\"]+)\"",
        "Generator",
        "cms",
        1,
    ),
]

# --- Firmas en Cookies ---

COOKIE_SIGNATURES: list[Signature] = [
    Signature("cookie", "PHPSESSID", r".+", "PHP", "language"),
    Signature("cookie", "JSESSIONID", r".+", "Java", "language"),
    Signature("cookie", "ASP.NET_SessionId", r".+", "ASP.NET", "framework"),
    Signature("cookie", "wp-settings", r".+", "WordPress", "cms"),
    Signature("cookie", "laravel_session", r".+", "Laravel", "framework"),
    Signature("cookie", "csrftoken", r".+", "Django", "framework"),
    Signature("cookie", "connect.sid", r".+", "Express.js", "framework"),
    Signature("cookie", "__cfduid", r".+", "Cloudflare", "cdn"),
    Signature("cookie", "cf_clearance", r".+", "Cloudflare", "cdn"),
    Signature("cookie", "_ga", r".+", "Google Analytics", "analytics"),
]


# ---------------------------------------------------------------------------
# Tech Fingerprinter
# ---------------------------------------------------------------------------


class TechFingerprinter:
    """Detecta tecnologias web analizando headers, HTML y cookies.

    Ejemplo:
        fp = TechFingerprinter()

        # Un solo URL
        techs = fp.fingerprint("http://scanme.nmap.org")

        # Multiples URLs (batch)
        all_techs = fp.fingerprint_many([
            "http://45.33.32.156",
            "https://nmap.org",
        ])
    """

    def __init__(self, timeout: float = 10.0) -> None:
        """Inicializa el fingerprinter.

        Args:
            timeout: Timeout en segundos para peticiones HTTP.
        """
        self._timeout = timeout

    def fingerprint(self, url: str) -> list[WebTechnology]:
        """Analiza un URL y devuelve las tecnologias detectadas.

        Hace un GET al URL y analiza la respuesta completa:
        headers, body HTML, y cookies.

        Args:
            url: URL completo (ej: "http://scanme.nmap.org")

        Returns:
            Lista de WebTechnology detectadas (deduplicadas).
        """
        logger.info(f"Fingerprinting: {url}")

        try:
            with httpx.Client(
                timeout=self._timeout,
                follow_redirects=True,  # Seguir 301/302
                verify=False,  # No validar SSL (recon, no produccion)
            ) as client:
                response = client.get(url)
        except httpx.HTTPError as e:
            logger.warning(f"Error conectando a {url}: {e}")
            return []
        except Exception as e:
            logger.warning(f"Error inesperado con {url}: {e}")
            return []

        # Analizar las tres fuentes
        techs: dict[str, WebTechnology] = {}

        for tech in self._analyze_headers(dict(response.headers)):
            # Usamos nombre+categoria como clave para deduplicar
            key = f"{tech.name}:{tech.category}"
            # Si ya existe pero sin version, preferimos el que tiene version
            if key not in techs or (tech.version and not techs[key].version):
                techs[key] = tech

        for tech in self._analyze_html(response.text):
            key = f"{tech.name}:{tech.category}"
            if key not in techs or (tech.version and not techs[key].version):
                techs[key] = tech

        for tech in self._analyze_cookies(response.cookies):
            key = f"{tech.name}:{tech.category}"
            if key not in techs or (tech.version and not techs[key].version):
                techs[key] = tech

        results = list(techs.values())
        logger.info(f"Tecnologias detectadas: {len(results)}")
        return results

    def fingerprint_many(self, urls: list[str]) -> list[WebTechnology]:
        """Analiza multiples URLs y devuelve tecnologias combinadas.

        Util cuando un host tiene varios puertos HTTP (80, 443, 8080).

        Args:
            urls: Lista de URLs a analizar.

        Returns:
            Lista combinada y deduplicada de WebTechnology.
        """
        all_techs: dict[str, WebTechnology] = {}

        for url in urls:
            for tech in self.fingerprint(url):
                key = f"{tech.name}:{tech.category}"
                if key not in all_techs or (
                    tech.version and not all_techs[key].version
                ):
                    all_techs[key] = tech

        return list(all_techs.values())

    # -------------------------------------------------------------------
    # Analisis de cada fuente
    # -------------------------------------------------------------------

    def _analyze_headers(self, headers: dict[str, str]) -> list[WebTechnology]:
        """Analiza HTTP headers buscando firmas de tecnologias.

        Ejemplo: "Server: Apache/2.4.7 (Ubuntu)"
        -> Match con regex "Apache/?(\\S+)?" -> version="2.4.7"
        -> WebTechnology(name="Apache", version="2.4.7", category="web-server")
        """
        techs: list[WebTechnology] = []

        for sig in HEADER_SIGNATURES:
            # Buscar la cabecera (case-insensitive)
            header_value = headers.get(sig.key, "")
            if not header_value:
                # Intentar con variantes de case
                for k, v in headers.items():
                    if k.lower() == sig.key.lower():
                        header_value = v
                        break

            if not header_value:
                continue

            match = re.search(sig.pattern, header_value, re.IGNORECASE)
            if match:
                version = None
                if sig.version_group and sig.version_group <= len(match.groups()):
                    version = match.group(sig.version_group)

                techs.append(
                    WebTechnology(
                        name=sig.tech_name,
                        version=version,
                        category=sig.category,
                    )
                )

        return techs

    def _analyze_html(self, html: str) -> list[WebTechnology]:
        """Analiza el body HTML buscando patrones de tecnologias.

        Ejemplo: HTML contiene "/wp-content/themes/..."
        -> Match con regex "/wp-content/" -> WordPress detectado
        """
        techs: list[WebTechnology] = []

        # Limitar analisis a los primeros 100KB (rendimiento)
        html_chunk = html[:102400]

        for sig in HTML_SIGNATURES:
            match = re.search(sig.pattern, html_chunk, re.IGNORECASE)
            if match:
                version = None
                if sig.version_group and sig.version_group <= len(match.groups()):
                    version = match.group(sig.version_group)

                # Caso especial: meta generator extrae el nombre del CMS
                name = sig.tech_name
                if name == "Generator" and version:
                    name = version.split()[0]  # "WordPress 6.4" -> "WordPress"
                    version = version.split(None, 1)[1] if " " in version else None

                techs.append(
                    WebTechnology(
                        name=name,
                        version=version,
                        category=sig.category,
                    )
                )

        return techs

    def _analyze_cookies(self, cookies: httpx.Cookies) -> list[WebTechnology]:
        """Analiza nombres de cookies buscando firmas de tecnologias.

        Ejemplo: Cookie "PHPSESSID=abc123"
        -> El nombre "PHPSESSID" es firma de PHP
        -> WebTechnology(name="PHP", category="language")
        """
        techs: list[WebTechnology] = []
        cookie_names = {name.lower(): name for name in cookies.keys()}

        for sig in COOKIE_SIGNATURES:
            if sig.key.lower() in cookie_names:
                techs.append(
                    WebTechnology(
                        name=sig.tech_name,
                        version=None,
                        category=sig.category,
                    )
                )

        return techs
