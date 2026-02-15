"""
Entry point: python -m webapp

Arranca el servidor uvicorn con la app FastAPI.
Por defecto escucha en 0.0.0.0:8000 (accesible desde Docker).
"""

import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "webapp.app:create_app",
        factory=True,
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000")),
        log_level="info",
        # reload=True solo para desarrollo local, no en Docker
        reload=os.environ.get("RELOAD", "false").lower() == "true",
    )
