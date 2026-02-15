"""
Spectra Graph - Ingesta de resultados de recon en Neo4j.

Transforma un ScanResult (Pydantic) en nodos y relaciones Cypher.

La operacion clave es MERGE (no CREATE):
  - CREATE siempre crea un nodo nuevo (puede duplicar)
  - MERGE busca si ya existe y lo reutiliza; si no, lo crea

Esto hace la ingesta IDEMPOTENTE: ejecutar el mismo scan dos
veces no crea nodos duplicados, solo actualiza propiedades.

El grafo resultante tiene esta estructura:

    Scan ──SCANNED──> Domain ──HAS_SUBDOMAIN──> Subdomain
                        │                            │
                        └──RESOLVES_TO──┐   ┌──RESOLVES_TO
                                        ▼   ▼
                                        Host
                                         │
                                      HAS_PORT
                                         ▼
                                        Port ──RUNS──> Service
                                                          │
                                                      HAS_VULN
                                                          ▼
                                                    Vulnerability

                      Domain ──USES_TECH──> Technology

Uso:
    from graph.client import GraphClient
    from graph.ingest import GraphIngestor

    with GraphClient() as client:
        client.init_schema()
        ingestor = GraphIngestor(client)
        ingestor.ingest(scan_result)
"""

from __future__ import annotations

import logging

from neo4j import Driver, ManagedTransaction

from recon.models import (
    Host,
    ScanResult,
    Subdomain,
    Vulnerability,
    WebTechnology,
)

logger = logging.getLogger(__name__)


class GraphIngestor:
    """Ingesta ScanResult en Neo4j como grafo.

    Cada metodo crea un tipo de nodo y sus relaciones.
    Todos usan MERGE para idempotencia.

    Ejemplo:
        ingestor = GraphIngestor(client)
        stats = ingestor.ingest(scan_result)
        print(stats)  # {"nodes_created": 25, "relationships_created": 30}
    """

    def __init__(self, driver: Driver) -> None:
        """Inicializa el ingestor.

        Args:
            driver: Driver Neo4j ya conectado.
        """
        self._driver = driver

    def ingest(self, scan: ScanResult) -> dict[str, int]:
        """Ingesta un ScanResult completo en el grafo.

        Ejecuta toda la ingesta en UNA transaccion. Si algo falla,
        se hace rollback completo (atomicidad). Esto evita grafos
        a medias que confundirian al agente IA.

        Args:
            scan: Resultado completo de un pipeline de recon.

        Returns:
            Estadisticas: nodos y relaciones creados/actualizados.
        """
        target = scan.target
        logger.info(f"Ingesta en Neo4j: {target.domain} (scan {scan.scan_id[:8]})")

        with self._driver.session() as session:
            stats = session.execute_write(self._ingest_transaction, scan)

        logger.info(
            f"Ingesta completada: {stats['nodes_created']} nodos, "
            f"{stats['relationships_created']} relaciones"
        )
        return stats

    @staticmethod
    def _ingest_transaction(tx: ManagedTransaction, scan: ScanResult) -> dict[str, int]:
        """Ejecuta toda la ingesta dentro de una transaccion.

        Este metodo es estatico porque Neo4j lo requiere asi
        para execute_write (el primer argumento es tx).

        Cada bloque de Cypher usa MERGE para idempotencia.
        Las propiedades se actualizan con SET para reflejar
        el escaneo mas reciente.
        """
        target = scan.target
        nodes_created = 0
        rels_created = 0

        # =============================================================
        # 1. Nodo Scan (metadatos del escaneo)
        # =============================================================
        # Registramos cada ejecucion del pipeline como un nodo Scan.
        # Esto permite comparar escaneos historicos del mismo target.
        result = tx.run(
            """
            MERGE (s:Scan {scan_id: $scan_id})
            SET s.started_at = $started_at,
                s.finished_at = $finished_at,
                s.phases = $phases
            RETURN s
            """,
            scan_id=scan.scan_id,
            started_at=scan.started_at.isoformat(),
            finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
            phases=scan.phases_completed,
        )
        result.consume()
        nodes_created += 1

        # =============================================================
        # 2. Nodo Domain + relacion Scan->Domain
        # =============================================================
        result = tx.run(
            """
            MERGE (d:Domain {name: $domain})
            WITH d
            MATCH (s:Scan {scan_id: $scan_id})
            MERGE (s)-[:SCANNED]->(d)
            RETURN d
            """,
            domain=target.domain,
            scan_id=scan.scan_id,
        )
        result.consume()
        nodes_created += 1
        rels_created += 1

        # =============================================================
        # 3. Nodos Subdomain + relaciones Domain->Subdomain
        # =============================================================
        for sub in target.subdomains:
            result = tx.run(
                """
                MERGE (sub:Subdomain {name: $name})
                SET sub.source = $source
                WITH sub
                MATCH (d:Domain {name: $domain})
                MERGE (d)-[:HAS_SUBDOMAIN]->(sub)
                RETURN sub
                """,
                name=sub.name,
                source=sub.source,
                domain=target.domain,
            )
            result.consume()
            nodes_created += 1
            rels_created += 1

            # Subdomain -> Host (si tiene IPs resueltas)
            for ip in sub.ips:
                result = tx.run(
                    """
                    MERGE (h:Host {address: $address})
                    WITH h
                    MATCH (sub:Subdomain {name: $subname})
                    MERGE (sub)-[:RESOLVES_TO]->(h)
                    RETURN h
                    """,
                    address=ip,
                    subname=sub.name,
                )
                result.consume()
                rels_created += 1

        # =============================================================
        # 4. Nodos Host + relaciones Domain->Host + puertos + servicios
        # =============================================================
        for host in target.hosts:
            # Crear/actualizar Host
            result = tx.run(
                """
                MERGE (h:Host {address: $address})
                SET h.hostname = $hostname,
                    h.os = $os
                WITH h
                MATCH (d:Domain {name: $domain})
                MERGE (d)-[:RESOLVES_TO]->(h)
                RETURN h
                """,
                address=host.address,
                hostname=host.hostname,
                os=host.os,
                domain=target.domain,
            )
            result.consume()
            nodes_created += 1
            rels_created += 1

            # Puertos de este host
            for port in host.ports:
                # Nodo Port (unico por host+numero+protocolo)
                # Usamos una clave compuesta como propiedad 'key'
                port_key = f"{host.address}:{port.number}/{port.protocol.value}"
                result = tx.run(
                    """
                    MERGE (p:Port {key: $port_key})
                    SET p.number = $number,
                        p.state = $state,
                        p.protocol = $protocol
                    WITH p
                    MATCH (h:Host {address: $address})
                    MERGE (h)-[:HAS_PORT]->(p)
                    RETURN p
                    """,
                    port_key=port_key,
                    number=port.number,
                    state=port.state.value,
                    protocol=port.protocol.value,
                    address=host.address,
                )
                result.consume()
                nodes_created += 1
                rels_created += 1

                # Nodo Service (si hay servicio detectado)
                if port.service:
                    svc = port.service
                    # Clave unica: producto+version (o solo nombre)
                    svc_key = f"{svc.product or svc.name}:{svc.version or 'unknown'}"
                    result = tx.run(
                        """
                        MERGE (svc:Service {key: $svc_key})
                        SET svc.name = $name,
                            svc.product = $product,
                            svc.version = $version,
                            svc.cpe = $cpe,
                            svc.banner = $banner
                        WITH svc
                        MATCH (p:Port {key: $port_key})
                        MERGE (p)-[:RUNS]->(svc)
                        RETURN svc
                        """,
                        svc_key=svc_key,
                        name=svc.name,
                        product=svc.product,
                        version=svc.version,
                        cpe=svc.cpe,
                        banner=svc.banner,
                        port_key=port_key,
                    )
                    result.consume()
                    nodes_created += 1
                    rels_created += 1

        # =============================================================
        # 5. Nodos Technology + relaciones Domain->Technology
        # =============================================================
        for tech in target.technologies:
            tech_key = f"{tech.name}:{tech.category}"
            result = tx.run(
                """
                MERGE (t:Technology {key: $tech_key})
                SET t.name = $name,
                    t.version = $version,
                    t.category = $category
                WITH t
                MATCH (d:Domain {name: $domain})
                MERGE (d)-[:USES_TECH]->(t)
                RETURN t
                """,
                tech_key=tech_key,
                name=tech.name,
                version=tech.version,
                category=tech.category,
                domain=target.domain,
            )
            result.consume()
            nodes_created += 1
            rels_created += 1

        # =============================================================
        # 6. Nodos Vulnerability + relaciones Service->Vulnerability
        # =============================================================
        for vuln in target.vulnerabilities:
            # Crear nodo Vulnerability
            result = tx.run(
                """
                MERGE (v:Vulnerability {vuln_id: $vuln_id})
                SET v.severity = $severity,
                    v.score = $score,
                    v.description = $description,
                    v.references = $references
                RETURN v
                """,
                vuln_id=vuln.vuln_id,
                severity=vuln.severity.value,
                score=vuln.score,
                description=vuln.description,
                references=vuln.references,
            )
            result.consume()
            nodes_created += 1

            # Conectar Vulnerability al Service afectado.
            # affected_service tiene formato "IP:port (product version)"
            # Buscamos el Service por su producto+version
            if vuln.affected_service:
                # Extraer producto y version del string
                # Formato: "45.33.32.156:22 (OpenSSH 6.6.1p1 ...)"
                svc_product, svc_version = _parse_affected_service(
                    vuln.affected_service
                )
                if svc_product:
                    svc_key = f"{svc_product}:{svc_version or 'unknown'}"
                    result = tx.run(
                        """
                        MATCH (v:Vulnerability {vuln_id: $vuln_id})
                        MATCH (svc:Service {key: $svc_key})
                        MERGE (svc)-[:HAS_VULN]->(v)
                        RETURN v, svc
                        """,
                        vuln_id=vuln.vuln_id,
                        svc_key=svc_key,
                    )
                    result.consume()
                    rels_created += 1

                # Conectar Vulnerability al Host afectado.
                # Extraer IP del affected_service
                host_ip = _parse_host_ip(vuln.affected_service)
                if host_ip:
                    result = tx.run(
                        """
                        MATCH (v:Vulnerability {vuln_id: $vuln_id})
                        MATCH (h:Host {address: $address})
                        MERGE (v)-[:AFFECTS]->(h)
                        RETURN v, h
                        """,
                        vuln_id=vuln.vuln_id,
                        address=host_ip,
                    )
                    result.consume()
                    rels_created += 1

        return {
            "nodes_created": nodes_created,
            "relationships_created": rels_created,
        }


# ---------------------------------------------------------------------------
# Helpers para parsear affected_service
# ---------------------------------------------------------------------------


def _parse_affected_service(affected: str) -> tuple[str | None, str | None]:
    """Extrae producto y version del string affected_service.

    Formato esperado: "45.33.32.156:22 (OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13)"
    Devuelve: ("OpenSSH", "6.6.1p1")

    Formato alternativo: "45.33.32.156:80 (Apache httpd 2.4.7)"
    Devuelve: ("Apache httpd", "2.4.7")
    """
    if "(" not in affected:
        return None, None

    # Extraer lo que hay entre parentesis
    inner = affected.split("(", 1)[1].rstrip(")")
    parts = inner.strip().split()

    if not parts:
        return None, None

    # Heuristica: la version suele ser el primer token que empieza con digito
    product_parts: list[str] = []
    version: str | None = None

    for part in parts:
        if version is None and part[0].isdigit():
            version = part
            break
        product_parts.append(part)

    product = " ".join(product_parts) if product_parts else None
    return product, version


def _parse_host_ip(affected: str) -> str | None:
    """Extrae la IP del string affected_service.

    Formato: "45.33.32.156:22 (OpenSSH ...)"
    Devuelve: "45.33.32.156"
    """
    if ":" not in affected:
        return None
    return affected.split(":")[0]
