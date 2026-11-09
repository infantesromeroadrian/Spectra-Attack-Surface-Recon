"""
Spectra Recon - Pipeline principal.

Orquesta las 5 fases del reconocimiento en secuencia:
  1. Subdomain Discovery (crt.sh + DNS brute force)
  2. DNS Resolution (registros completos del dominio)
  3. Port Scanning (nmap: puertos + servicios + versiones)
  4. Tech Fingerprinting (headers + HTML + cookies)
  5. Vulnerability Assessment (base local + NVD API)

Genera un ScanResult completo, lo guarda como JSON, y
opcionalmente ingesta los resultados en Neo4j como grafo.

Uso CLI:
    python -m recon.main --target scanme.nmap.org
    python -m recon.main --target scanme.nmap.org --profile full --no-nvd
    python -m recon.main --target scanme.nmap.org --no-graph

Uso Docker (lee variables de entorno):
    SCAN_TARGET=scanme.nmap.org SCAN_PROFILE=standard python -m recon.main
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from recon.dns_resolver import DnsResolver
from recon.models import Host, ScanResult, Target
from recon.port_scanner import PortScanner, ScanProfile
from recon.subdomain_discovery import SubdomainDiscovery
from recon.tech_fingerprint import TechFingerprinter
from recon.vuln_assessment import VulnAssessment

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuracion
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parsea argumentos CLI con fallback a variables de entorno.

    Prioridad: CLI args > env vars > defaults
    """
    parser = argparse.ArgumentParser(
        prog="spectra-recon",
        description="Spectra Recon - Automated reconnaissance pipeline",
    )
    parser.add_argument(
        "--target",
        default=os.environ.get("SCAN_TARGET", ""),
        help="Dominio o IP a escanear (ej: scanme.nmap.org)",
    )
    parser.add_argument(
        "--profile",
        default=os.environ.get("SCAN_PROFILE", "standard"),
        choices=["quick", "standard", "full"],
        help="Perfil de escaneo nmap (default: standard)",
    )
    parser.add_argument(
        "--ports",
        default=None,
        help="Override de puertos (ej: 22,80,443 o 1-1000)",
    )
    parser.add_argument(
        "--no-nvd",
        action="store_true",
        default=os.environ.get("USE_NVD", "true").lower() == "false",
        help="No consultar NVD API (solo base local de CVEs)",
    )
    parser.add_argument(
        "--no-subs",
        action="store_true",
        help="Saltar descubrimiento de subdominios",
    )
    parser.add_argument(
        "--output",
        default=os.environ.get("OUTPUT_DIR", "output"),
        help="Directorio de salida para el JSON (default: output/)",
    )
    parser.add_argument(
        "--no-graph",
        action="store_true",
        help="No ingestar resultados en Neo4j",
    )
    parser.add_argument(
        "--neo4j-uri",
        default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        help="URI de conexion a Neo4j (default: bolt://localhost:7687)",
    )
    parser.add_argument(
        "--neo4j-user",
        default=os.environ.get("NEO4J_USER", "neo4j"),
        help="Usuario de Neo4j",
    )
    parser.add_argument(
        "--neo4j-password",
        default=os.environ.get("NEO4J_PASSWORD", "spectrapass"),
        help="Password de Neo4j",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Mostrar logs de debug",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def run_pipeline(
    target: str,
    profile: ScanProfile,
    ports: str | None = None,
    use_nvd: bool = True,
    discover_subs: bool = True,
    output_dir: str = "output",
    neo4j_uri: str | None = None,
    neo4j_user: str = "neo4j",
    neo4j_password: str = "spectrapass",
) -> ScanResult:
    """Ejecuta el pipeline completo de reconocimiento.

    Args:
        target: Dominio o IP a escanear.
        profile: Perfil de nmap (quick, standard, full).
        ports: Override de puertos (None = usa el perfil).
        use_nvd: Consultar NVD API para CVEs.
        discover_subs: Ejecutar descubrimiento de subdominios.
        output_dir: Directorio donde guardar el JSON.
        neo4j_uri: URI de Neo4j (None = no ingestar en grafo).
        neo4j_user: Usuario de Neo4j.
        neo4j_password: Password de Neo4j.

    Returns:
        ScanResult con todos los hallazgos.
    """
    # Inicializar resultado
    scan = ScanResult(target=Target(domain=target))

    banner(target, profile.value)

    # Componentes compartidos
    dns = DnsResolver()

    # =================================================================
    # FASE 1: Subdomain Discovery
    # =================================================================
    if discover_subs:
        phase("1", "SUBDOMAIN DISCOVERY")
        discovery = SubdomainDiscovery(dns_resolver=dns)
        subdomains = discovery.discover(target)
        scan.target.subdomains = subdomains
        scan.phases_completed.append("subdomain_discovery")

        if subdomains:
            for sub in subdomains:
                ips = ", ".join(sub.ips) if sub.ips else "sin resolver"
                logger.info(f"  {sub.name} -> {ips} ({sub.source})")
        else:
            logger.info("  No se encontraron subdominios adicionales")
    else:
        logger.info("[*] Subdomain discovery desactivado (--no-subs)")

    # =================================================================
    # FASE 2: DNS Resolution
    # =================================================================
    phase("2", "DNS RESOLUTION")
    records = dns.resolve_all(target)
    scan.phases_completed.append("dns_resolution")
    logger.info(records.summary())

    # =================================================================
    # FASE 3: Port Scanning
    # =================================================================
    phase("3", "PORT SCANNING")

    # Targets a escanear: dominio principal + IPs de subdominios
    scan_targets: set[str] = {target}
    for sub in scan.target.subdomains:
        scan_targets.update(sub.ips)
    # Añadir IPs del dominio raiz
    scan_targets.update(records.a)

    scanner = PortScanner()
    all_hosts: list[Host] = []

    for scan_target in sorted(scan_targets):
        hosts = scanner.scan(scan_target, profile=profile, ports=ports)
        all_hosts.extend(hosts)

    # Deduplicar hosts por IP
    unique_hosts: dict[str, Host] = {}
    for host in all_hosts:
        if host.address not in unique_hosts:
            unique_hosts[host.address] = host
        else:
            # Merge puertos si escaneamos la misma IP desde distintos targets
            existing = unique_hosts[host.address]
            existing_ports = {p.number for p in existing.ports}
            for port in host.ports:
                if port.number not in existing_ports:
                    existing.ports.append(port)

    scan.target.hosts = list(unique_hosts.values())
    scan.phases_completed.append("port_scanning")

    total_open = scan.target.total_open_ports
    logger.info(f"  Hosts: {len(scan.target.hosts)} | Puertos abiertos: {total_open}")

    # =================================================================
    # FASE 4: Tech Fingerprinting
    # =================================================================
    phase("4", "TECH FINGERPRINTING")

    # Construir URLs desde los puertos HTTP abiertos
    http_urls: list[str] = []
    for host in scan.target.hosts:
        for port in host.open_ports:
            if port.service and port.service.name in ("http", "https", "http-proxy"):
                scheme = "https" if port.number == 443 else "http"
                http_urls.append(f"{scheme}://{host.address}:{port.number}")

    if http_urls:
        fingerprinter = TechFingerprinter()
        techs = fingerprinter.fingerprint_many(http_urls)
        scan.target.technologies = techs
        for tech in techs:
            ver = f" {tech.version}" if tech.version else ""
            logger.info(f"  [{tech.category}] {tech.name}{ver}")
    else:
        logger.info("  No hay servicios HTTP para analizar")

    scan.phases_completed.append("tech_fingerprinting")

    # =================================================================
    # FASE 5: Vulnerability Assessment
    # =================================================================
    phase("5", "VULNERABILITY ASSESSMENT")
    assessor = VulnAssessment(use_nvd=use_nvd)
    vulns = assessor.assess(scan.target.hosts)
    scan.target.vulnerabilities = vulns
    scan.phases_completed.append("vuln_assessment")

    if vulns:
        for v in vulns:
            logger.info(
                f"  {v.vuln_id} [{v.severity.value}] CVSS:{v.score} {v.affected_service}"
            )
    else:
        logger.info("  No se encontraron vulnerabilidades conocidas")

    # =================================================================
    # RESULTADO FINAL
    # =================================================================
    scan.complete()

    # Guardar JSON
    output_path = save_result(scan, output_dir)

    # =================================================================
    # FASE 6: Graph Ingestion (opcional)
    # =================================================================
    # Si Neo4j esta disponible, ingesta los resultados como grafo.
    # Si no, el pipeline sigue funcionando solo con JSON.
    graph_ok = False
    if neo4j_uri:
        phase("6", "GRAPH INGESTION")
        graph_ok = ingest_to_graph(scan, neo4j_uri, neo4j_user, neo4j_password)

    summary(scan, output_path, graph_ok)

    return scan


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def ingest_to_graph(
    scan: ScanResult,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
) -> bool:
    """Ingesta el ScanResult en Neo4j como grafo.

    Conexion graceful: si Neo4j no esta disponible, loguea un
    warning y devuelve False (no rompe el pipeline).

    Args:
        scan: Resultado del escaneo.
        neo4j_uri: URI bolt de Neo4j.
        neo4j_user: Usuario.
        neo4j_password: Password.

    Returns:
        True si la ingesta fue exitosa, False si fallo.
    """
    try:
        from graph.client import GraphClient
        from graph.ingest import GraphIngestor

        with GraphClient(neo4j_uri, neo4j_user, neo4j_password) as client:
            client.init_schema()
            ingestor = GraphIngestor(client.driver)
            stats = ingestor.ingest(scan)
            logger.info(
                f"  Neo4j: {stats['nodes_created']} nodos, "
                f"{stats['relationships_created']} relaciones"
            )
            return True

    except ImportError:
        logger.warning("  Modulo graph/ no disponible, saltando ingesta")
        return False
    except Exception as e:
        logger.warning(f"  Neo4j no disponible: {e}")
        logger.info("  (Los resultados JSON se guardaron correctamente)")
        return False


def save_result(scan: ScanResult, output_dir: str) -> Path:
    """Guarda el ScanResult como JSON en el directorio de salida."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    filename = f"spectra_{scan.target.domain}_{scan.scan_id[:8]}.json"
    filepath = out / filename

    filepath.write_text(scan.to_json(), encoding="utf-8")
    logger.info(f"Resultado guardado: {filepath}")

    return filepath


# ---------------------------------------------------------------------------
# Formato de consola
# ---------------------------------------------------------------------------


def banner(target: str, profile: str) -> None:
    """Imprime el banner inicial."""
    sep = "=" * 60
    print(f"\n{sep}")
    print("  SPECTRA RECON - Automated Reconnaissance Pipeline")
    print(sep)
    print(f"  Target:  {target}")
    print(f"  Profile: {profile}")
    print(f"{sep}\n")


def phase(number: str, name: str) -> None:
    """Imprime el header de una fase."""
    print(f"\n--- FASE {number}: {name} ---\n")


def summary(scan: ScanResult, output_path: Path, graph_ok: bool = False) -> None:
    """Imprime el resumen final del escaneo."""
    t = scan.target
    sep = "=" * 60

    print(f"\n{sep}")
    print("  SCAN COMPLETE")
    print(sep)
    print(f"  Target:          {t.domain}")
    print(f"  Subdomains:      {len(t.subdomains)}")
    print(f"  Hosts:           {len(t.hosts)}")
    print(f"  Open ports:      {t.total_open_ports}")
    print(f"  Services:        {', '.join(sorted(t.unique_services)) or 'none'}")
    print(f"  Technologies:    {len(t.technologies)}")
    print(f"  Vulnerabilities: {len(t.vulnerabilities)}")

    # Desglose por severidad
    if t.vulnerabilities:
        by_sev: dict[str, int] = {}
        for v in t.vulnerabilities:
            by_sev[v.severity.value] = by_sev.get(v.severity.value, 0) + 1
        sev_str = " | ".join(f"{k}: {v}" for k, v in sorted(by_sev.items()))
        print(f"    Breakdown:     {sev_str}")

    print(f"  Duration:        {scan.duration_seconds:.1f}s")
    print(f"  Output JSON:     {output_path}")
    print(f"  Output Graph:    {'Neo4j (synced)' if graph_ok else 'skipped'}")
    print(f"{sep}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point del pipeline."""
    args = parse_args()

    # Configurar logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    # Validar target
    if not args.target:
        print("Error: --target es requerido (o SCAN_TARGET env var)")
        print("Uso: python -m recon.main --target scanme.nmap.org")
        sys.exit(1)

    # Mapear profile string a enum
    profile_map = {
        "quick": ScanProfile.QUICK,
        "standard": ScanProfile.STANDARD,
        "full": ScanProfile.FULL,
    }
    profile = profile_map[args.profile]

    # Ejecutar pipeline
    run_pipeline(
        target=args.target,
        profile=profile,
        ports=args.ports,
        use_nvd=not args.no_nvd,
        discover_subs=not args.no_subs,
        output_dir=args.output,
        neo4j_uri=None if args.no_graph else args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password,
    )


if __name__ == "__main__":
    main()
