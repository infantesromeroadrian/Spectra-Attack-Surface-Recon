# ==============================================================
# Spectra Recon Service - Dockerfile
# ==============================================================
# Multi-stage build:
#   Stage 1 (builder): instala dependencias Python con uv
#   Stage 2 (runtime): imagen final ligera con nmap + Python
#
# Build context debe ser la raiz de spectra/ (no recon/)
# porque necesita acceso a pyproject.toml, uv.lock, y graph/.
#
# Uso:
#   docker compose build recon
#   docker compose run recon
# ==============================================================

# ---------------------------------------------------------------
# Stage 1: Builder - instala dependencias
# ---------------------------------------------------------------
FROM python:3.11-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copiar solo archivos de dependencias primero (cache de Docker layers).
COPY pyproject.toml uv.lock ./

# --frozen: usa exactamente las versiones de uv.lock (reproducible)
# --no-dev: no instala dependencias de desarrollo
RUN uv sync --frozen --no-dev

# ---------------------------------------------------------------
# Stage 2: Runtime - imagen final
# ---------------------------------------------------------------
FROM python:3.11-slim AS runtime

# nmap: unica dependencia de sistema
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Virtualenv con todas las deps Python
COPY --from=builder /app/.venv /app/.venv

# Codigo fuente: recon (pipeline) + graph (ingesta Neo4j)
COPY recon/ ./recon/
COPY graph/ ./graph/

# Python usa el virtualenv del container
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Directorio para output JSON (montable como volumen)
RUN mkdir -p /app/output
VOLUME ["/app/output"]

# Healthcheck: verificar que Python y nmap funcionan
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import recon.models; import graph.client" && nmap --version > /dev/null 2>&1

# Variables de entorno configurables (override en docker-compose)
ENV SCAN_TARGET=""
ENV SCAN_PROFILE="standard"
ENV USE_NVD="true"
ENV NEO4J_URI="bolt://neo4j:7687"
ENV NEO4J_USER="neo4j"
ENV NEO4J_PASSWORD="spectrapass"

CMD ["python", "-m", "recon.main"]
