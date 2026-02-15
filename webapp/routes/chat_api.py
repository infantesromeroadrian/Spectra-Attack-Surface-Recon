"""
Spectra Webapp - Chat API (interaccion con el agente IA).

Endpoint unico: POST /api/chat
Recibe un mensaje del usuario, lo pasa al agente LangGraph,
y devuelve la respuesta con los tool calls que hizo.

Multi-turn: el agente mantiene memoria de la conversacion usando
un thread_id. Cada thread_id es una conversacion independiente.
El frontend genera un thread_id al cargar la pagina y lo envia
en cada request. Boton "New Chat" genera uno nuevo.

Flujo:
  1. Frontend envia {"message": "...", "thread_id": "abc123"}
  2. Backend invoca agent.invoke() con thread_id en el config
  3. LangGraph MemorySaver recupera el historial de ese thread
  4. El agente responde con contexto de toda la conversacion
  5. Backend devuelve {"response": "...", "tool_calls": [...]}
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["chat"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ChatRequest(BaseModel):
    """Mensaje del usuario al agente."""

    message: str
    thread_id: str = "default"


class ToolCallInfo(BaseModel):
    """Info resumida de un tool call (para mostrar en la UI)."""

    name: str
    args: dict


class ChatResponse(BaseModel):
    """Respuesta del agente."""

    response: str
    tool_calls: list[ToolCallInfo]


# ---------------------------------------------------------------------------
# POST /api/chat
# ---------------------------------------------------------------------------
# Definido como def (no async def) a proposito.
# FastAPI ejecuta funciones sync en un thread pool automaticamente.
# agent.invoke() es bloqueante (Groq API + Neo4j), asi que el thread
# pool evita bloquear el event loop de uvicorn.
# ---------------------------------------------------------------------------


@router.post("/chat", response_model=None)
def chat(body: ChatRequest, request: Request) -> ChatResponse | JSONResponse:
    """Envia un mensaje al agente IA y devuelve la respuesta."""

    # Verificar que el agente esta disponible
    agent = request.app.state.agent
    if agent is None:
        return JSONResponse(
            status_code=503,
            content={
                "response": "Agente no disponible. Falta GROQ_API_KEY.",
                "tool_calls": [],
            },
        )

    # Invocar el agente con thread_id para memoria multi-turn.
    # El MemorySaver usa configurable.thread_id para saber que
    # conversacion es. Mensajes previos del mismo thread se
    # recuperan automaticamente del checkpointer.
    try:
        result = agent.invoke(
            {"messages": [("user", body.message)]},
            config={
                "recursion_limit": 25,
                "configurable": {"thread_id": body.thread_id},
            },
        )
    except Exception as e:
        error_msg = str(e)
        if "recursion" in error_msg.lower():
            return ChatResponse(
                response=(
                    "He agotado mis intentos procesando esa pregunta. "
                    "Intenta reformularla o usa una pregunta mas especifica."
                ),
                tool_calls=[],
            )
        logger.exception("Error en agent.invoke()")
        return JSONResponse(
            status_code=500,
            content={
                "response": f"Error del agente: {error_msg}",
                "tool_calls": [],
            },
        )

    # Extraer respuesta final y tool calls
    messages = result["messages"]
    ai_response = messages[-1].content if messages else "Sin respuesta."

    # Recoger los tool calls que hizo el agente durante su razonamiento
    tool_calls_info: list[ToolCallInfo] = []
    for msg in messages:
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            for tc in msg.tool_calls:
                tool_calls_info.append(ToolCallInfo(name=tc["name"], args=tc["args"]))

    return ChatResponse(
        response=ai_response,
        tool_calls=tool_calls_info,
    )
