"""
Spectra Webapp - FastAPI application factory.

Patron lifespan: al arrancar conecta Neo4j y crea el agente IA.
Al parar, cierra las conexiones limpiamente.

Los routers acceden a los recursos compartidos via request.app.state:
  - request.app.state.graph_client  -> GraphClient (Neo4j)
  - request.app.state.agent         -> LangGraph compilado
  - request.app.state.groq_key      -> API key de Groq

Esto evita variables globales y permite testear con facilidad.

Uso:
    uvicorn webapp.app:create_app --factory --reload
    python -m webapp
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from graph.client import GraphClient
from agent.graph import create_agent

logger = logging.getLogger(__name__)

# Directorio donde estan los ficheros estaticos (HTML, CSS, JS)
STATIC_DIR = Path(__file__).parent / "static"


# ---------------------------------------------------------------------------
# Lifespan: startup / shutdown
# ---------------------------------------------------------------------------
# FastAPI llama a este context manager al arrancar y parar.
# Todo lo que esta ANTES del yield se ejecuta al startup.
# Todo lo que esta DESPUES del yield se ejecuta al shutdown.
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Gestiona el ciclo de vida de la app: conexiones y recursos."""

    # --- STARTUP ---

    # 1. Conectar Neo4j
    neo4j_uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.environ.get("NEO4J_USER", "neo4j")
    neo4j_password = os.environ.get("NEO4J_PASSWORD", "spectrapass")

    logger.info(f"Conectando a Neo4j: {neo4j_uri}")
    graph_client = GraphClient(neo4j_uri, neo4j_user, neo4j_password)
    app.state.graph_client = graph_client

    # 2. Crear agente IA
    groq_key = os.environ.get("GROQ_API_KEY", "")
    groq_model = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

    if groq_key:
        logger.info(f"Creando agente con modelo {groq_model}")
        agent = create_agent(graph_client.driver, groq_key, groq_model)
        app.state.agent = agent
    else:
        logger.warning("GROQ_API_KEY no configurada - chat deshabilitado")
        app.state.agent = None

    # Verificar datos en el grafo
    stats = graph_client.stats()
    total = sum(v for k, v in stats.items() if k != "_relationships")
    logger.info(f"Grafo: {total} nodos, {stats.get('_relationships', 0)} relaciones")

    yield  # --- La app esta corriendo ---

    # --- SHUTDOWN ---
    logger.info("Cerrando conexiones...")
    graph_client.close()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """Crea y configura la aplicacion FastAPI."""

    app = FastAPI(
        title="Spectra",
        description="AI-powered red team reconnaissance dashboard",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS: permitir requests desde cualquier origen (dev-friendly)
    # En produccion, restringir a dominios especificos
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- Registrar routers ---
    from webapp.routes.graph_api import router as graph_router
    from webapp.routes.chat_api import router as chat_router
    from webapp.routes.scan_api import router as scan_router

    app.include_router(graph_router)
    app.include_router(chat_router)
    app.include_router(scan_router)

    # --- Ficheros estaticos (CSS, JS) ---
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # --- Ruta raiz: servir index.html ---
    @app.get("/", include_in_schema=False)
    async def root():
        return FileResponse(str(STATIC_DIR / "index.html"))

    return app
