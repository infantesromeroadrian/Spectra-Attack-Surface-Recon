"""
Spectra Agent - Tools para consultar el grafo Neo4j.

Cada tool es una funcion que el agente IA puede invocar.
El LLM decide CUANDO y CON QUE PARAMETROS llamar cada tool
basandose en el docstring y la firma de la funcion.

Por eso los docstrings aqui son tan detallados: no son para
nosotros, son para el LLM. Si el docstring es vago, el LLM
usara mal el tool.

Patron: tool recibe parametros simples (strings, ints) ->
ejecuta query Cypher en Neo4j -> devuelve string formateado.
Devolvemos strings (no dicts) porque el LLM procesa texto.

Tools disponibles:
  1. get_attack_surface  - Resumen global del grafo
  2. find_vulns          - Buscar vulnerabilidades filtradas
  3. find_attack_paths   - Caminos Domain -> Vulnerability
  4. get_host_details    - Info detallada de un host
  5. run_cypher          - Query Cypher libre (escape hatch)
"""

from __future__ import annotations

import json
import logging

from langchain_core.tools import tool
from neo4j import Driver

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# El driver Neo4j se inyecta al crear los tools (ver create_tools())
# ---------------------------------------------------------------------------

_driver: Driver | None = None


def _get_driver() -> Driver:
    """Obtiene el driver Neo4j. Falla si no se ha inicializado."""
    if _driver is None:
        raise RuntimeError(
            "Neo4j driver no inicializado. Llama a create_tools() primero."
        )
    return _driver


def _run_query(cypher: str, params: dict | None = None) -> list[dict]:
    """Ejecuta una query Cypher y devuelve los resultados como lista de dicts."""
    driver = _get_driver()
    with driver.session() as session:
        result = session.run(cypher, params or {})
        return [dict(record) for record in result]


# ---------------------------------------------------------------------------
# Tool 1: Attack Surface Summary
# ---------------------------------------------------------------------------


@tool
def get_attack_surface() -> str:
    """Get a high-level summary of the entire attack surface in the graph.

    Returns counts of domains, hosts, open ports, services, technologies,
    and vulnerabilities grouped by severity. Use this FIRST to understand
    the scope before diving into specifics.

    No parameters needed.
    """
    records = _run_query("""
        MATCH (d:Domain)
        OPTIONAL MATCH (d)-[:RESOLVES_TO]->(h:Host)
        OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
        OPTIONAL MATCH (p)-[:RUNS]->(s:Service)
        OPTIONAL MATCH (d)-[:USES_TECH]->(t:Technology)
        OPTIONAL MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
        WITH d,
             collect(DISTINCT h.address) AS hosts,
             collect(DISTINCT {port: p.number, state: p.state, protocol: p.protocol}) AS ports,
             collect(DISTINCT {name: s.name, product: s.product, version: s.version}) AS services,
             collect(DISTINCT {name: t.name, version: t.version, category: t.category}) AS techs,
             collect(DISTINCT {id: v.vuln_id, severity: v.severity, score: v.score}) AS vulns
        RETURN d.name AS domain, hosts, ports, services, techs, vulns
    """)

    if not records:
        return "No data in the graph. Run a recon scan first."

    lines: list[str] = []
    for r in records:
        lines.append(f"Domain: {r['domain']}")
        lines.append(f"Hosts: {r['hosts']}")

        # Ports
        open_ports = [p for p in r["ports"] if p.get("state") == "open"]
        lines.append(f"Open ports ({len(open_ports)}):")
        for p in open_ports:
            lines.append(f"  {p['port']}/{p['protocol']}")

        # Services
        svcs = [s for s in r["services"] if s.get("name")]
        lines.append(f"Services ({len(svcs)}):")
        for s in svcs:
            ver = f" {s['version']}" if s.get("version") else ""
            lines.append(f"  {s.get('product') or s['name']}{ver}")

        # Technologies
        techs = [t for t in r["techs"] if t.get("name")]
        lines.append(f"Technologies ({len(techs)}):")
        for t in techs:
            ver = f" {t['version']}" if t.get("version") else ""
            lines.append(f"  [{t['category']}] {t['name']}{ver}")

        # Vulnerabilities
        vulns = [v for v in r["vulns"] if v.get("id")]
        lines.append(f"Vulnerabilities ({len(vulns)}):")
        by_sev: dict[str, int] = {}
        for v in vulns:
            sev = v.get("severity", "unknown")
            by_sev[sev] = by_sev.get(sev, 0) + 1
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_sev:
                lines.append(f"  {sev}: {by_sev[sev]}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool 2: Find Vulnerabilities
# ---------------------------------------------------------------------------


@tool
def find_vulns(
    severity: str = "all",
    min_score: float = 0.0,
) -> str:
    """Find vulnerabilities in the attack surface, optionally filtered.

    Args:
        severity: Filter by severity level. Options: "critical", "high",
                  "medium", "low", or "all" for no filter. Default: "all".
        min_score: Minimum CVSS score (0.0 to 10.0). Default: 0.0.

    Returns details of matching vulnerabilities including CVE ID, severity,
    CVSS score, description, and the affected service.
    """
    where_clauses = ["v.score >= $min_score"]
    if severity != "all":
        where_clauses.append("v.severity = $severity")

    where = " AND ".join(where_clauses)

    records = _run_query(
        f"""
        MATCH (s:Service)-[:HAS_VULN]->(v:Vulnerability)
        WHERE {where}
        OPTIONAL MATCH (v)-[:AFFECTS]->(h:Host)
        RETURN v.vuln_id AS cve, v.severity AS severity, v.score AS score,
               v.description AS description, s.product AS product,
               s.version AS version, h.address AS host
        ORDER BY v.score DESC
        """,
        {"severity": severity, "min_score": min_score},
    )

    if not records:
        return f"No vulnerabilities found (filter: severity={severity}, min_score={min_score})"

    lines = [f"Found {len(records)} vulnerabilities:"]
    for r in records:
        svc = f"{r.get('product') or '?'} {r.get('version') or ''}"
        host = r.get("host") or "unknown"
        lines.append(
            f"\n{r['cve']} [{r['severity']}] CVSS:{r['score']}"
            f"\n  Service: {svc} on {host}"
            f"\n  {r['description'][:200]}"
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool 3: Attack Paths
# ---------------------------------------------------------------------------


@tool
def find_attack_paths(
    severity: str = "critical",
) -> str:
    """Find complete attack paths from domain to vulnerabilities through the graph.

    Shows the full chain: Domain -> Host -> Port -> Service -> Vulnerability.
    This reveals HOW an attacker could reach a vulnerable service.

    Args:
        severity: Filter paths to vulnerabilities of this severity.
                  Options: "critical", "high", "medium", "low". Default: "critical".
    """
    records = _run_query(
        """
        MATCH (d:Domain)-[:RESOLVES_TO]->(h:Host)-[:HAS_PORT]->(p:Port)
              -[:RUNS]->(s:Service)-[:HAS_VULN]->(v:Vulnerability)
        WHERE v.severity = $severity
        RETURN d.name AS domain, h.address AS host, p.number AS port,
               p.protocol AS proto, s.product AS service, s.version AS version,
               v.vuln_id AS cve, v.score AS score, v.description AS description
        ORDER BY v.score DESC
        """,
        {"severity": severity},
    )

    if not records:
        return f"No attack paths found for severity={severity}"

    lines = [f"Attack paths to {severity} vulnerabilities ({len(records)}):"]
    for r in records:
        svc = f"{r.get('service') or '?'} {r.get('version') or ''}"
        lines.append(
            f"\n  {r['domain']} -> {r['host']}:{r['port']}/{r['proto']}"
            f" -> {svc} -> {r['cve']} (CVSS {r['score']})"
            f"\n    {r['description'][:150]}"
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool 4: Host Details
# ---------------------------------------------------------------------------


@tool
def get_host_details(address: str) -> str:
    """Get detailed information about a specific host (IP address).

    Returns all open ports, services running on them, technologies detected,
    and vulnerabilities affecting this host.

    Args:
        address: IP address of the host (e.g., "45.33.32.156").
    """
    # Basic info + ports + services
    records = _run_query(
        """
        MATCH (h:Host {address: $address})
        OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)-[:RUNS]->(s:Service)
        OPTIONAL MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
        RETURN h.address AS address, h.hostname AS hostname, h.os AS os,
               p.number AS port, p.state AS state, p.protocol AS proto,
               s.name AS svc_name, s.product AS product, s.version AS version,
               collect(DISTINCT {id: v.vuln_id, severity: v.severity, score: v.score}) AS vulns
        ORDER BY p.number
        """,
        {"address": address},
    )

    if not records:
        return f"Host {address} not found in the graph."

    first = records[0]
    lines = [
        f"Host: {first['address']}",
        f"Hostname: {first.get('hostname') or 'unknown'}",
        f"OS: {first.get('os') or 'unknown'}",
        "",
        "Ports and Services:",
    ]

    for r in records:
        if r.get("port"):
            svc = f"{r.get('product') or r.get('svc_name') or '?'} {r.get('version') or ''}"
            vuln_count = len([v for v in r.get("vulns", []) if v.get("id")])
            vuln_str = f" ({vuln_count} vulns)" if vuln_count else ""
            lines.append(
                f"  {r['port']}/{r['proto']} [{r['state']}] -> {svc}{vuln_str}"
            )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool 5: Free Cypher Query
# ---------------------------------------------------------------------------


@tool
def run_cypher(query: str) -> str:
    """Execute a custom Cypher query on the Neo4j graph database.

    Use this when the other tools don't cover your specific question.

    IMPORTANT - Exact node labels and their property names:

      Domain       -> name
      Subdomain    -> name, source
      Host         -> address, hostname, os
      Port         -> key, number, state, protocol
                      (use p.number for the port number, NOT p.port)
      Service      -> key, name, product, version, cpe, banner
      Technology   -> key, name, version, category
      Vulnerability -> vuln_id, severity, score, description, references
      Scan         -> scan_id, started_at, finished_at, phases

    Relationships:
      (Scan)-[:SCANNED]->(Domain)
      (Domain)-[:HAS_SUBDOMAIN]->(Subdomain)
      (Domain)-[:RESOLVES_TO]->(Host)
      (Subdomain)-[:RESOLVES_TO]->(Host)
      (Host)-[:HAS_PORT]->(Port)
      (Port)-[:RUNS]->(Service)
      (Service)-[:HAS_VULN]->(Vulnerability)
      (Vulnerability)-[:AFFECTS]->(Host)
      (Domain)-[:USES_TECH]->(Technology)

    Args:
        query: A valid Cypher query. ONLY use read queries (MATCH/RETURN).
               Do NOT use CREATE, DELETE, SET, or MERGE.

    Example queries:
      MATCH (p:Port) WHERE p.number = 22 RETURN p.number, p.state
      MATCH (s:Service) WHERE s.product = 'Apache' RETURN s.product, s.version
      MATCH (v:Vulnerability) RETURN v.vuln_id, v.score ORDER BY v.score DESC
    """
    # Safety: block write operations
    query_upper = query.upper().strip()
    for forbidden in ["CREATE", "DELETE", "SET ", "MERGE", "REMOVE", "DROP"]:
        if forbidden in query_upper:
            return f"Error: Write operations are not allowed. Query contained '{forbidden}'."

    try:
        records = _run_query(query)
    except Exception as e:
        return f"Cypher error: {e}"

    if not records:
        return "Query returned no results."

    # Format results as readable text
    lines = [f"Results ({len(records)} rows):"]
    for i, record in enumerate(records[:20]):  # Limit to 20 rows
        row_parts = []
        for k, v in record.items():
            row_parts.append(f"{k}={v}")
        lines.append(f"  [{i + 1}] {', '.join(row_parts)}")

    if len(records) > 20:
        lines.append(f"  ... and {len(records) - 20} more rows")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Factory: crear los tools con el driver Neo4j inyectado
# ---------------------------------------------------------------------------


def create_tools(driver: Driver) -> list:
    """Crea la lista de tools con el driver Neo4j inyectado.

    Esto se llama una vez al inicializar el agente. Los tools
    usan el driver via la variable de modulo _driver.

    Args:
        driver: Driver Neo4j ya conectado.

    Returns:
        Lista de tools listos para usar con LangGraph.
    """
    global _driver
    _driver = driver
    logger.info("Agent tools inicializados con Neo4j driver")

    return [
        get_attack_surface,
        find_vulns,
        find_attack_paths,
        get_host_details,
        run_cypher,
    ]
