# ==============================================================
# Spectra Webapp Service - Dockerfile
# ==============================================================
# Multi-stage build: deps con uv, runtime con FastAPI + uvicorn.
#
# Build context: raiz de spectra/ (accede a pyproject.toml,
# webapp/, agent/, graph/, recon/).
#
# Uso:
#   docker compose build webapp
#   docker compose up webapp
#
# La webapp escucha en el puerto 8000.
# ==============================================================

# ---------------------------------------------------------------
# Stage 1: Builder - instalar dependencias
# ---------------------------------------------------------------
FROM python:3.11-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock ./

RUN uv sync --frozen --no-dev

# ---------------------------------------------------------------
# Stage 2: Runtime - solo lo necesario para servir
# ---------------------------------------------------------------
FROM python:3.11-slim AS runtime

# nmap necesario para lanzar scans desde la webapp
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Virtualenv con todas las deps Python
COPY --from=builder /app/.venv /app/.venv

# Codigo fuente: webapp + agent + graph + recon (modelos compartidos)
COPY webapp/ ./webapp/
COPY agent/  ./agent/
COPY graph/  ./graph/
COPY recon/  ./recon/

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Conexion a servicios
ENV NEO4J_URI="bolt://neo4j:7687"
ENV NEO4J_USER="neo4j"
ENV NEO4J_PASSWORD="spectrapass"
ENV GROQ_API_KEY=""
ENV GROQ_MODEL="llama-3.3-70b-versatile"

# Puerto HTTP
EXPOSE 8000

# Healthcheck: verificar que FastAPI responde
HEALTHCHECK --interval=15s --timeout=5s --retries=3 --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"

# Arrancar uvicorn
CMD ["uvicorn", "webapp.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
