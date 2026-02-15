"""
Spectra Webapp - API endpoints para consultar el grafo Neo4j.

Estos endpoints exponen los datos de la superficie de ataque
como JSON para que el frontend los consuma.

Cada endpoint ejecuta una query Cypher contra Neo4j via el
GraphClient almacenado en app.state (inyectado por el lifespan).

Endpoints:
    GET /api/health         -> Estado del servicio
    GET /api/graph/stats    -> Conteo de nodos por tipo
    GET /api/graph/hosts    -> Lista de hosts con puertos y vulns
    GET /api/graph/vulns    -> Vulnerabilidades (filtrable por severidad)
    GET /api/graph/paths    -> Cadenas de ataque completas
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["graph"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _neo4j_query(
    request: Request, cypher: str, params: dict | None = None
) -> list[dict]:
    """Ejecuta una query Cypher usando el driver del GraphClient."""
    driver = request.app.state.graph_client.driver
    with driver.session() as session:
        result = session.run(cypher, params or {})
        return [dict(record) for record in result]


# ---------------------------------------------------------------------------
# GET /api/health
# ---------------------------------------------------------------------------


@router.get("/health")
def health(request: Request) -> dict:
    """Estado del servicio: conectividad Neo4j y resumen del grafo."""
    try:
        stats = request.app.state.graph_client.stats()
        total = sum(v for k, v in stats.items() if k != "_relationships")
        return {
            "status": "ok",
            "neo4j": "connected",
            "nodes": total,
            "relationships": stats.get("_relationships", 0),
            "agent": "ready" if request.app.state.agent else "disabled",
        }
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "detail": str(e)},
        )


# ---------------------------------------------------------------------------
# GET /api/graph/stats
# ---------------------------------------------------------------------------


@router.get("/graph/stats")
def get_stats(request: Request) -> dict:
    """Conteo de nodos por tipo y total de relaciones.

    Devuelve algo como:
    {
        "Domain": 1, "Host": 1, "Port": 4, "Service": 6,
        "Technology": 2, "Vulnerability": 16, "Scan": 2,
        "Subdomain": 0, "relationships": 44
    }
    """
    stats = request.app.state.graph_client.stats()
    rels = stats.pop("_relationships", 0)
    stats["relationships"] = rels
    return stats


# ---------------------------------------------------------------------------
# GET /api/graph/hosts
# ---------------------------------------------------------------------------


@router.get("/graph/hosts")
def get_hosts(request: Request) -> list[dict]:
    """Lista de hosts con sus puertos abiertos y conteo de vulnerabilidades.

    Cada host incluye:
    - address, hostname, os
    - ports: lista de puertos abiertos con servicio
    - vuln_count: total de vulnerabilidades
    """
    records = _neo4j_query(
        request,
        """
        MATCH (h:Host)
        OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port {state: 'open'})
        OPTIONAL MATCH (p)-[:RUNS]->(s:Service)
        WITH h, p, s
        ORDER BY p.number
        WITH h,
             collect(DISTINCT {
                 number: p.number,
                 protocol: p.protocol,
                 service: COALESCE(s.product, s.name, 'unknown'),
                 version: s.version
             }) AS ports
        OPTIONAL MATCH (h)-[:HAS_PORT]->(:Port)-[:RUNS]->(:Service)-[:HAS_VULN]->(v:Vulnerability)
        WITH h, ports, count(DISTINCT v) AS vuln_count
        RETURN h.address AS address,
               h.hostname AS hostname,
               h.os AS os,
               ports,
               vuln_count
        """,
    )
    # Limpiar ports: quitar entradas con number=null (de OPTIONAL MATCH)
    for r in records:
        r["ports"] = [p for p in r["ports"] if p.get("number") is not None]
    return records


# ---------------------------------------------------------------------------
# GET /api/graph/vulns
# ---------------------------------------------------------------------------


@router.get("/graph/vulns")
def get_vulns(
    request: Request,
    severity: str = Query(
        default="all", description="Filter: critical, high, medium, low, all"
    ),
    min_score: float = Query(default=0.0, description="Minimum CVSS score"),
) -> list[dict]:
    """Lista de vulnerabilidades con servicio y host afectado.

    Filtrable por severidad y score minimo.
    Ordenada por score descendente.
    """
    where_clauses = ["v.score >= $min_score"]
    if severity != "all":
        where_clauses.append("v.severity = $severity")

    where = " AND ".join(where_clauses)

    records = _neo4j_query(
        request,
        f"""
        MATCH (s:Service)-[:HAS_VULN]->(v:Vulnerability)
        WHERE {where}
        OPTIONAL MATCH (p:Port)-[:RUNS]->(s)
        OPTIONAL MATCH (h:Host)-[:HAS_PORT]->(p)
        RETURN v.vuln_id AS vuln_id,
               v.severity AS severity,
               v.score AS score,
               v.description AS description,
               s.product AS service,
               s.version AS version,
               p.number AS port,
               h.address AS host
        ORDER BY v.score DESC
        """,
        {"severity": severity, "min_score": min_score},
    )
    return records


# ---------------------------------------------------------------------------
# GET /api/graph/paths
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# GET /api/graph/visual
# ---------------------------------------------------------------------------


@router.get("/graph/visual")
def get_visual_graph(request: Request) -> dict:
    """Todos los nodos y relaciones del grafo para visualizacion force-directed.

    Devuelve:
        nodes: lista de {id, type, label, props}
        links: lista de {source, target, type}
    """
    # Nodos con ID, tipo, label legible y propiedades
    node_records = _neo4j_query(
        request,
        """
        MATCH (n)
        WITH n, labels(n)[0] AS type
        RETURN elementId(n) AS id,
               type,
               CASE type
                   WHEN 'Domain' THEN n.name
                   WHEN 'Subdomain' THEN n.name
                   WHEN 'Host' THEN n.address
                   WHEN 'Port' THEN toString(n.number) + '/' + n.protocol
                   WHEN 'Service' THEN COALESCE(n.product, n.name, 'unknown')
                   WHEN 'Technology' THEN n.name
                   WHEN 'Vulnerability' THEN n.vuln_id
                   WHEN 'Scan' THEN 'scan-' + LEFT(n.scan_id, 8)
                   ELSE 'unknown'
               END AS label,
               CASE type
                   WHEN 'Vulnerability' THEN n.severity
                   WHEN 'Port' THEN n.state
                   ELSE null
               END AS extra
        """,
    )

    # Relaciones
    link_records = _neo4j_query(
        request,
        """
        MATCH (a)-[r]->(b)
        RETURN elementId(a) AS source,
               elementId(b) AS target,
               type(r) AS type
        """,
    )

    return {
        "nodes": node_records,
        "links": link_records,
    }


# ---------------------------------------------------------------------------
# GET /api/graph/paths
# ---------------------------------------------------------------------------


@router.get("/graph/paths")
def get_attack_paths(
    request: Request,
    severity: str = Query(default="all", description="Filter by severity"),
) -> list[dict]:
    """Cadenas de ataque completas: Domain -> Host -> Port -> Service -> Vuln.

    Muestra COMO un atacante podria alcanzar una vulnerabilidad.
    """
    where = "WHERE v.severity = $severity" if severity != "all" else ""

    records = _neo4j_query(
        request,
        f"""
        MATCH (d:Domain)-[:RESOLVES_TO]->(h:Host)-[:HAS_PORT]->(p:Port)
              -[:RUNS]->(s:Service)-[:HAS_VULN]->(v:Vulnerability)
        {where}
        RETURN d.name AS domain,
               h.address AS host,
               p.number AS port,
               p.protocol AS protocol,
               s.product AS service,
               s.version AS version,
               v.vuln_id AS cve,
               v.severity AS severity,
               v.score AS score,
               v.description AS description
        ORDER BY v.score DESC
        """,
        {"severity": severity},
    )
    return records
