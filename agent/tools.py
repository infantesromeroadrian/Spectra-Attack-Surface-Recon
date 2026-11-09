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
  5. calculate_risk_score - Risk score ponderado (0-100)
  6. compare_scans       - Comparar diferencias entre scans
  7. run_cypher          - Query Cypher libre (escape hatch)
"""

from __future__ import annotations

import logging
import re

from langchain_core.tools import tool
from neo4j import Driver, ManagedTransaction

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


def _collect(tx: ManagedTransaction, cypher: str, params: dict) -> list[dict]:
    """Ejecuta la query dentro de la transaccion y materializa los registros."""
    return [dict(record) for record in tx.run(cypher, params)]


def _run_query(cypher: str, params: dict | None = None) -> list[dict]:
    """Ejecuta una query Cypher en una transaccion de LECTURA.

    Los tools del agente solo leen el grafo. Una transaccion de lectura
    hace que Neo4j rechace cualquier escritura con un error en tiempo de
    ejecucion. No es un control de acceso completo (ver run_cypher).
    """
    driver = _get_driver()
    with driver.session() as session:
        return session.execute_read(_collect, cypher, params or {})


# Clausulas que modifican el grafo o salen de el (APOC, LOAD CSV, admin).
# CALL se bloquea entero: los procedimientos APOC de lectura pueden hacer
# peticiones HTTP o leer ficheros (apoc.load.*), y eso no es "solo lectura".
_FORBIDDEN_CYPHER = re.compile(
    r"\b(CREATE|MERGE|SET|DELETE|DETACH|REMOVE|DROP|FOREACH|CALL|LOAD|"
    r"GRANT|REVOKE|DENY|ALTER|START|STOP|TERMINATE|USE|EXPLAIN|PROFILE)\b",
    re.IGNORECASE,
)


def _query_type(cypher: str) -> str | None:
    """Pide a Neo4j el tipo de una query sin ejecutarla (EXPLAIN).

    Devuelve "r" (lectura), "rw", "w" o "s" (schema), segun el planner
    del propio servidor. Es la segunda barrera de run_cypher: no depende
    de adivinar palabras clave, sino de como Neo4j entiende la query.
    """
    driver = _get_driver()
    with driver.session() as session:
        summary = session.run("EXPLAIN " + cypher).consume()
    return summary.query_type


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

    lines: list[str] = [f"Total domains scanned: {len(records)}", ""]
    for i, r in enumerate(records):
        if i > 0:
            lines.append("")
        lines.append(f"{'=' * 40}")
        lines.append(f"DOMAIN: {r['domain']}")
        lines.append(f"{'=' * 40}")
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
                   Must be a number, not a string.

    Returns details of matching vulnerabilities including CVE ID, severity,
    CVSS score, description, and the affected service.
    """
    # Defensive: LLMs sometimes pass strings instead of numbers
    try:
        min_score = float(min_score)
    except (ValueError, TypeError):
        min_score = 0.0

    where_clauses = ["v.score >= $min_score"]
    if severity != "all":
        where_clauses.append("v.severity = $severity")

    where = " AND ".join(where_clauses)

    records = _run_query(
        f"""
        MATCH (s:Service)-[:HAS_VULN]->(v:Vulnerability)
        WHERE {where}
        OPTIONAL MATCH (v)-[:AFFECTS]->(h:Host)
        OPTIONAL MATCH (d:Domain)-[:RESOLVES_TO]->(h)
        RETURN v.vuln_id AS cve, v.severity AS severity, v.score AS score,
               v.description AS description, s.product AS product,
               s.version AS version, h.address AS host, d.name AS domain
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
        domain = r.get("domain") or ""
        domain_str = f" ({domain})" if domain else ""
        lines.append(
            f"\n{r['cve']} [{r['severity']}] CVSS:{r['score']}"
            f"\n  Service: {svc} on {host}{domain_str}"
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
    """Get detailed information about a specific host.

    Returns all open ports, services running on them, technologies detected,
    and vulnerabilities affecting this host.

    Args:
        address: IP address OR domain/hostname of the host.
                 Examples: "45.33.32.156", "scanme.nmap.org", "testphp.vulnweb.com"
    """
    # Try by IP first, then by hostname, then by domain name
    records = _run_query(
        """
        MATCH (h:Host)
        WHERE h.address = $address OR h.hostname = $address
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

    # Fallback: try resolving domain -> host via graph relationship
    if not records:
        records = _run_query(
            """
            MATCH (d:Domain {name: $address})-[:RESOLVES_TO]->(h:Host)
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
        return (
            f"Host '{address}' not found in the graph (tried IP, hostname, and domain)."
        )

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
    # La query la escribe el LLM, y el LLM lee datos del objetivo escaneado
    # (banners, registros TXT, HTML). Esos datos pueden llevar instrucciones
    # inyectadas, asi que esta query se trata como entrada no fiable.
    # Tres barreras:
    #   1. Lista de clausulas prohibidas, por palabra completa.
    #   2. EXPLAIN: Neo4j clasifica la query sin ejecutarla; solo pasa "r".
    #   3. Ejecucion en transaccion de lectura (_run_query).
    match = _FORBIDDEN_CYPHER.search(query)
    if match:
        return (
            "Error: only read-only MATCH/RETURN queries are allowed. "
            f"Query contained '{match.group(1).upper()}'."
        )

    try:
        query_type = _query_type(query)
    except Exception as e:
        return f"Cypher error: {e}"
    if query_type != "r":
        return f"Error: only read-only queries are allowed (query type: {query_type})."

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
# Tool 6: Risk Score
# ---------------------------------------------------------------------------


@tool
def calculate_risk_score(domain: str = "") -> str:
    """Calculate a weighted risk score for a domain or the entire attack surface.

    The score is computed from REAL graph data only — nothing is invented.

    Scoring methodology:
      - Each vulnerability contributes its CVSS score weighted by severity:
          critical (x4), high (x3), medium (x2), low (x1)
      - Exposure factor: number of internet-facing open ports
      - Service diversity penalty: more distinct services = larger attack surface
      - Final score normalized to 0-100 scale

    The result includes:
      - Overall risk score (0-100)
      - Risk level (CRITICAL / HIGH / MEDIUM / LOW / MINIMAL)
      - Breakdown by category (vulnerability risk, exposure, service diversity)
      - Top contributing CVEs

    Args:
        domain: Domain name to score (e.g., "scanme.nmap.org").
                If empty, scores the entire graph.
    """
    # --- Gather vulnerability data ---
    vuln_query = """
        MATCH (s:Service)-[:HAS_VULN]->(v:Vulnerability)
        OPTIONAL MATCH (s)<-[:RUNS]-(p:Port)<-[:HAS_PORT]-(h:Host)
        OPTIONAL MATCH (d:Domain)-[:RESOLVES_TO]->(h)
        WHERE CASE WHEN $domain <> '' THEN d.name = $domain ELSE true END
        RETURN v.vuln_id AS cve, v.severity AS severity, v.score AS score,
               s.product AS product, s.version AS version,
               p.number AS port, h.address AS host
    """
    vulns = _run_query(vuln_query, {"domain": domain})

    # --- Gather exposure data ---
    port_query = """
        MATCH (h:Host)-[:HAS_PORT]->(p:Port)
        WHERE p.state = 'open'
        OPTIONAL MATCH (d:Domain)-[:RESOLVES_TO]->(h)
        WHERE CASE WHEN $domain <> '' THEN d.name = $domain ELSE true END
        RETURN DISTINCT p.number AS port, p.protocol AS proto
    """
    open_ports = _run_query(port_query, {"domain": domain})

    # --- Gather service diversity ---
    svc_query = """
        MATCH (p:Port)-[:RUNS]->(s:Service)
        OPTIONAL MATCH (h:Host)-[:HAS_PORT]->(p)
        OPTIONAL MATCH (d:Domain)-[:RESOLVES_TO]->(h)
        WHERE CASE WHEN $domain <> '' THEN d.name = $domain ELSE true END
        RETURN DISTINCT s.product AS product, s.version AS version
    """
    services = _run_query(svc_query, {"domain": domain})

    if not vulns and not open_ports:
        scope = f"domain '{domain}'" if domain else "the entire graph"
        return f"No data found for {scope}. Run a recon scan first."

    # --- Calculate vulnerability risk (0-60 points max) ---
    severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    vuln_score = 0.0
    top_cves: list[dict] = []
    for v in vulns:
        weight = severity_weights.get(v.get("severity", "low"), 1)
        contribution = (v.get("score") or 0.0) * weight
        vuln_score += contribution
        top_cves.append(
            {
                "cve": v.get("cve", "?"),
                "score": v.get("score", 0),
                "severity": v.get("severity", "?"),
                "contribution": round(contribution, 1),
            }
        )

    # Normalize: assume 200 weighted points = max 60 risk points
    vuln_risk = min(60.0, (vuln_score / 200.0) * 60.0) if vuln_score > 0 else 0.0

    # --- Calculate exposure risk (0-25 points max) ---
    high_risk_ports = {
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        143,
        443,
        445,
        993,
        995,
        1433,
        1521,
        3306,
        3389,
        5432,
        5900,
        8080,
        8443,
    }
    exposed_high = sum(1 for p in open_ports if p.get("port") in high_risk_ports)
    exposed_other = len(open_ports) - exposed_high
    exposure_risk = min(25.0, (exposed_high * 3.0 + exposed_other * 1.0))

    # --- Calculate service diversity penalty (0-15 points max) ---
    unique_services = len(services)
    diversity_risk = min(15.0, unique_services * 2.5)

    # --- Final score ---
    total_score = round(vuln_risk + exposure_risk + diversity_risk, 1)

    if total_score >= 80:
        level = "CRITICAL"
    elif total_score >= 60:
        level = "HIGH"
    elif total_score >= 40:
        level = "MEDIUM"
    elif total_score >= 20:
        level = "LOW"
    else:
        level = "MINIMAL"

    # --- Format output ---
    scope_label = f"Domain: {domain}" if domain else "Entire attack surface"
    top_cves.sort(key=lambda x: x["contribution"], reverse=True)

    lines = [
        f"{'=' * 50}",
        f"RISK SCORE: {total_score}/100 — {level}",
        f"{'=' * 50}",
        f"Scope: {scope_label}",
        "",
        "Breakdown:",
        f"  Vulnerability risk:  {round(vuln_risk, 1)}/60  ({len(vulns)} CVEs found)",
        f"  Exposure risk:       {round(exposure_risk, 1)}/25  ({len(open_ports)} open ports, {exposed_high} high-risk)",
        f"  Service diversity:   {round(diversity_risk, 1)}/15  ({unique_services} distinct services)",
        "",
    ]

    if top_cves:
        lines.append("Top contributing CVEs:")
        for c in top_cves[:5]:
            lines.append(
                f"  {c['cve']} [{c['severity']}] CVSS:{c['score']} (weight: {c['contribution']})"
            )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool 7: Scan Comparison
# ---------------------------------------------------------------------------


@tool
def compare_scans(domain: str, scan_id_old: str = "", scan_id_new: str = "") -> str:
    """Compare two scans of the same domain to detect changes over time.

    Detects:
      - [NEW] ports, services, or CVEs that appeared
      - [REMOVED] ports, services, or CVEs that disappeared
      - [CHANGED] services that changed version

    If scan IDs are not provided, automatically picks the two most recent
    scans for the given domain.

    Args:
        domain: Domain name to compare scans for (e.g., "scanme.nmap.org").
        scan_id_old: (Optional) scan_id of the older scan.
        scan_id_new: (Optional) scan_id of the newer scan.

    Use this tool when the user asks about changes, differences, evolution,
    or what's new since the last scan.
    """
    # --- Find scan IDs if not provided ---
    if not scan_id_old or not scan_id_new:
        scans = _run_query(
            """
            MATCH (s:Scan)-[:SCANNED]->(d:Domain {name: $domain})
            RETURN s.scan_id AS scan_id, s.started_at AS started
            ORDER BY s.started_at DESC
            LIMIT 2
            """,
            {"domain": domain},
        )
        if len(scans) < 2:
            count = len(scans)
            return (
                f"Need at least 2 scans to compare. Found {count} for '{domain}'. "
                f"Run another scan first."
            )
        scan_id_new = scans[0]["scan_id"]
        scan_id_old = scans[1]["scan_id"]

    # --- Helper: get scan snapshot ---
    def _get_snapshot(scan_id: str) -> dict:
        rows = _run_query(
            """
            MATCH (sc:Scan {scan_id: $scan_id})-[:SCANNED]->(d:Domain)
            OPTIONAL MATCH (d)-[:RESOLVES_TO]->(h:Host)-[:HAS_PORT]->(p:Port)
            OPTIONAL MATCH (p)-[:RUNS]->(s:Service)
            OPTIONAL MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
            RETURN d.name AS domain, h.address AS host,
                   p.number AS port, p.protocol AS proto, p.state AS state,
                   s.product AS product, s.version AS version, s.name AS svc_name,
                   v.vuln_id AS cve, v.severity AS severity, v.score AS score,
                   sc.started_at AS started
            """,
            {"scan_id": scan_id},
        )
        ports = set()
        services = {}
        cves = set()
        started = None
        for r in rows:
            if r.get("port"):
                port_key = f"{r['port']}/{r.get('proto', 'tcp')}"
                ports.add(port_key)
                svc_ver = f"{r.get('product') or r.get('svc_name') or '?'}|{r.get('version') or ''}"
                services[port_key] = svc_ver
            if r.get("cve"):
                cves.add(r["cve"])
            if r.get("started"):
                started = r["started"]
        return {"ports": ports, "services": services, "cves": cves, "started": started}

    old = _get_snapshot(scan_id_old)
    new = _get_snapshot(scan_id_new)

    if not old["ports"] and not new["ports"]:
        return f"Both scans have no port data for '{domain}'."

    # --- Compute diffs ---
    new_ports = new["ports"] - old["ports"]
    removed_ports = old["ports"] - new["ports"]
    common_ports = new["ports"] & old["ports"]

    new_cves = new["cves"] - old["cves"]
    removed_cves = old["cves"] - new["cves"]

    changed_services = []
    for port in common_ports:
        old_svc = old["services"].get(port, "?")
        new_svc = new["services"].get(port, "?")
        if old_svc != new_svc:
            changed_services.append((port, old_svc, new_svc))

    # --- Format output ---
    lines = [
        f"{'=' * 55}",
        f"SCAN COMPARISON: {domain}",
        f"{'=' * 55}",
        f"Old scan: {scan_id_old} ({old.get('started') or '?'})",
        f"New scan: {scan_id_new} ({new.get('started') or '?'})",
        "",
    ]

    has_changes = (
        new_ports or removed_ports or new_cves or removed_cves or changed_services
    )

    if not has_changes:
        lines.append("No changes detected between the two scans.")
        return "\n".join(lines)

    if new_ports:
        lines.append(f"[NEW] Ports ({len(new_ports)}):")
        for p in sorted(new_ports):
            svc = new["services"].get(p, "?")
            lines.append(f"  + {p} -> {svc.replace('|', ' ')}")
        lines.append("")

    if removed_ports:
        lines.append(f"[REMOVED] Ports ({len(removed_ports)}):")
        for p in sorted(removed_ports):
            svc = old["services"].get(p, "?")
            lines.append(f"  - {p} -> {svc.replace('|', ' ')}")
        lines.append("")

    if changed_services:
        lines.append(f"[CHANGED] Services ({len(changed_services)}):")
        for port, old_svc, new_svc in changed_services:
            lines.append(
                f"  ~ {port}: {old_svc.replace('|', ' ')} -> {new_svc.replace('|', ' ')}"
            )
        lines.append("")

    if new_cves:
        lines.append(f"[NEW] CVEs ({len(new_cves)}):")
        for cve in sorted(new_cves):
            lines.append(f"  + {cve}")
        lines.append("")

    if removed_cves:
        lines.append(f"[REMOVED] CVEs ({len(removed_cves)}):")
        for cve in sorted(removed_cves):
            lines.append(f"  - {cve}")

    # Summary
    lines.append("")
    total_changes = (
        len(new_ports)
        + len(removed_ports)
        + len(new_cves)
        + len(removed_cves)
        + len(changed_services)
    )
    lines.append(f"Total changes: {total_changes}")

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
        calculate_risk_score,
        compare_scans,
        run_cypher,
    ]
