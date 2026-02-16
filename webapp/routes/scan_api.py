"""
Spectra Webapp - Scan API (lanzar escaneos desde la UI).

Endpoint POST /api/scan/start lanza un recon scan en un thread
en segundo plano. GET /api/scan/status devuelve el estado actual.

Solo se permite un scan a la vez (single-user learning project).
El estado se mantiene en memoria (se pierde si el server reinicia).

Flujo:
  1. Frontend envia POST /api/scan/start {target, profile}
  2. Backend lanza run_pipeline() en un daemon thread
  3. Frontend pollea GET /api/scan/status cada 2 segundos
  4. Cuando status='completed', el frontend recarga el dashboard
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["scan"])


# ---------------------------------------------------------------------------
# State: estado del scan en memoria (single-user)
# ---------------------------------------------------------------------------

_scan_state: dict = {
    "status": "idle",  # idle | running | completed | failed
    "target": None,
    "profile": None,
    "started_at": None,
    "error": None,
    "summary": None,  # resumen post-scan
    "analysis": None,  # auto-analysis brief from the AI agent
}
_scan_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Parametros para lanzar un scan."""

    target: str  # dominio o IP a escanear
    profile: str = "standard"  # quick, standard, full


# ---------------------------------------------------------------------------
# Background scan runner
# ---------------------------------------------------------------------------


def _run_scan_thread(
    target: str,
    profile: str,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    agent: Any | None = None,
) -> None:
    """Ejecuta el pipeline de recon en un thread en segundo plano.

    Actualiza _scan_state con el progreso y resultado.
    Si el agente IA esta disponible, genera un brief de seguridad
    automaticamente al terminar (auto-analysis).
    """
    global _scan_state

    try:
        # Import aqui (no en top-level) para no romper si falta nmap
        from recon.main import run_pipeline
        from recon.port_scanner import ScanProfile

        profile_map = {
            "quick": ScanProfile.QUICK,
            "standard": ScanProfile.STANDARD,
            "full": ScanProfile.FULL,
        }

        result = run_pipeline(
            target=target,
            profile=profile_map.get(profile, ScanProfile.STANDARD),
            use_nvd=True,
            discover_subs=True,
            output_dir="output",
            neo4j_uri=neo4j_uri,
            neo4j_user=neo4j_user,
            neo4j_password=neo4j_password,
        )

        # Extraer resumen
        t = result.target
        summary = {
            "domain": t.domain,
            "hosts": len(t.hosts),
            "open_ports": t.total_open_ports,
            "services": list(t.unique_services),
            "technologies": len(t.technologies),
            "vulnerabilities": len(t.vulnerabilities),
            "duration": f"{result.duration_seconds:.1f}s",
        }

        with _scan_lock:
            _scan_state.update(
                {
                    "status": "completed",
                    "summary": summary,
                    "error": None,
                    "analysis": None,  # reset — will be filled by auto-analysis
                }
            )

        logger.info(f"Scan completado: {target} -> {len(t.vulnerabilities)} vulns")

        # --- Auto-analysis: generate security brief ---
        if agent is not None:
            _run_auto_analysis(agent, target, summary)

    except Exception as e:
        logger.exception(f"Scan fallido: {target}")
        with _scan_lock:
            _scan_state.update(
                {
                    "status": "failed",
                    "error": str(e),
                    "summary": None,
                    "analysis": None,
                }
            )


def _run_auto_analysis(agent: Any, target: str, summary: dict) -> None:
    """Genera un brief de seguridad automatico tras un scan exitoso.

    Invoca al agente IA con un prompt especifico para generar un resumen
    ejecutivo de los hallazgos. El resultado se almacena en _scan_state["analysis"].

    Estrategia de resiliencia:
      - Intento 1: prompt completo que usa tools del agente
      - Intento 2 (fallback): prompt simple sin tools, solo texto
    """
    global _scan_state

    vuln_count = summary.get("vulnerabilities", 0)
    port_count = summary.get("open_ports", 0)
    host_count = summary.get("hosts", 0)
    services = summary.get("services", [])
    svc_str = ", ".join(services) if services else "none detected"

    # Prompt dirigido: le dice EXACTAMENTE que tool usar primero
    prompt = (
        f"A reconnaissance scan of domain '{target}' just completed. "
        f"Results: {host_count} hosts, {port_count} open ports, "
        f"{vuln_count} vulnerabilities, services: {svc_str}. "
        f"Start by calling get_attack_surface to get the full picture, "
        f"then generate a concise security brief (under 300 words) with: "
        f"1) The most critical findings, "
        f"2) The top risks ranked by exploitability, "
        f"3) Immediate recommended actions. "
        f"Be specific with CVE IDs and port numbers if available. "
        f"Do NOT include a JSON block."
    )

    # Fallback: prompt sin tools, directo al grano
    fallback_prompt = (
        f"Based on what you know: domain '{target}' has {host_count} hosts, "
        f"{port_count} open ports, services: {svc_str}, "
        f"and {vuln_count} known vulnerabilities. "
        f"Write a brief 150-word security summary. "
        f"If there are no vulnerabilities, focus on the exposed services and "
        f"attack surface. Do NOT call any tools. Do NOT include a JSON block."
    )

    for attempt, msg in enumerate([prompt, fallback_prompt], start=1):
        try:
            analysis_thread_id = f"auto-analysis-{uuid.uuid4().hex[:8]}"

            result = agent.invoke(
                {"messages": [("user", msg)]},
                config={
                    "recursion_limit": 25,
                    "configurable": {"thread_id": analysis_thread_id},
                },
            )

            messages = result.get("messages", [])
            brief = messages[-1].content if messages else "No analysis generated."

            with _scan_lock:
                _scan_state["analysis"] = brief

            return  # success

        except Exception as e:
            logger.warning(f"Auto-analysis attempt {attempt} failed: {e}")
            if attempt == 2:
                # Both attempts failed — store error
                with _scan_lock:
                    _scan_state["analysis"] = (
                        f"Security brief for {target}: "
                        f"{host_count} hosts, {port_count} open ports, "
                        f"{vuln_count} vulnerabilities found. "
                        f"Services: {svc_str}. "
                        f"(Auto-analysis could not generate a detailed brief)"
                    )


# ---------------------------------------------------------------------------
# POST /api/scan/start
# ---------------------------------------------------------------------------


@router.post("/scan/start", response_model=None)
def start_scan(body: ScanRequest, request: Request) -> dict | JSONResponse:
    """Lanza un scan de reconocimiento en segundo plano."""

    with _scan_lock:
        if _scan_state["status"] == "running":
            return JSONResponse(
                status_code=409,
                content={"error": "Ya hay un scan en ejecucion. Espera a que termine."},
            )

        # Validar target basico
        target = body.target.strip()
        if not target or " " in target:
            return JSONResponse(
                status_code=400,
                content={"error": "Target invalido."},
            )

        if body.profile not in ("quick", "standard", "full"):
            return JSONResponse(
                status_code=400,
                content={"error": "Profile debe ser: quick, standard, full."},
            )

        # Marcar como running
        _scan_state.update(
            {
                "status": "running",
                "target": target,
                "profile": body.profile,
                "started_at": time.time(),
                "error": None,
                "summary": None,
            }
        )

    # Neo4j config del entorno
    neo4j_uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.environ.get("NEO4J_USER", "neo4j")
    neo4j_password = os.environ.get("NEO4J_PASSWORD", "spectrapass")

    # Obtener el agente IA para auto-analysis post-scan
    agent = getattr(request.app.state, "agent", None)

    # Lanzar thread
    thread = threading.Thread(
        target=_run_scan_thread,
        args=(target, body.profile, neo4j_uri, neo4j_user, neo4j_password, agent),
        daemon=True,
    )
    thread.start()

    return {"status": "started", "target": target, "profile": body.profile}


# ---------------------------------------------------------------------------
# GET /api/scan/status
# ---------------------------------------------------------------------------


@router.get("/scan/status")
def scan_status() -> dict:
    """Estado actual del scan.

    Devuelve:
        status: idle | running | completed | failed
        target, profile, started_at, error, summary
    """
    with _scan_lock:
        state = dict(_scan_state)

    # Calcular elapsed si esta running
    if state["status"] == "running" and state.get("started_at"):
        state["elapsed"] = f"{time.time() - state['started_at']:.0f}s"

    return state
