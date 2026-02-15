# ==============================================================
# Spectra Agent Service - Dockerfile
# ==============================================================
# Multi-stage build: deps con uv, runtime ligero sin nmap.
#
# Build context: raiz de spectra/ (accede a pyproject.toml,
# agent/, graph/, recon/).
#
# Uso:
#   docker compose build agent
#   docker compose run agent
# ==============================================================

# ---------------------------------------------------------------
# Stage 1: Builder
# ---------------------------------------------------------------
FROM python:3.11-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock ./

RUN uv sync --frozen --no-dev

# ---------------------------------------------------------------
# Stage 2: Runtime (sin nmap - el agente no escanea)
# ---------------------------------------------------------------
FROM python:3.11-slim AS runtime

WORKDIR /app

# Virtualenv con todas las deps Python
COPY --from=builder /app/.venv /app/.venv

# Codigo fuente: agent + graph + recon (modelos compartidos)
COPY agent/ ./agent/
COPY graph/ ./graph/
COPY recon/ ./recon/

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Conexion a servicios
ENV NEO4J_URI="bolt://neo4j:7687"
ENV NEO4J_USER="neo4j"
ENV NEO4J_PASSWORD="spectrapass"
ENV GROQ_API_KEY=""
ENV GROQ_MODEL="llama-3.3-70b-versatile"

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import agent.graph; import graph.client"

CMD ["python", "-m", "agent"]
