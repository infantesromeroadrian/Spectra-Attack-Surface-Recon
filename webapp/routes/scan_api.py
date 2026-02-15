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
    target: str, profile: str, neo4j_uri: str, neo4j_user: str, neo4j_password: str
) -> None:
    """Ejecuta el pipeline de recon en un thread en segundo plano.

    Actualiza _scan_state con el progreso y resultado.
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
                }
            )

        logger.info(f"Scan completado: {target} -> {len(t.vulnerabilities)} vulns")

    except Exception as e:
        logger.exception(f"Scan fallido: {target}")
        with _scan_lock:
            _scan_state.update(
                {
                    "status": "failed",
                    "error": str(e),
                    "summary": None,
                }
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

    # Lanzar thread
    thread = threading.Thread(
        target=_run_scan_thread,
        args=(target, body.profile, neo4j_uri, neo4j_user, neo4j_password),
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
