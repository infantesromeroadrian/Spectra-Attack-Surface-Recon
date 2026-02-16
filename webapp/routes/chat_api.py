"""
Spectra Webapp - Chat API (interaccion con el agente IA).

Dos endpoints:
  POST /api/chat         - Respuesta completa (legacy)
  POST /api/chat/stream  - SSE streaming token a token

Multi-turn: el agente mantiene memoria de la conversacion usando
un thread_id. Cada thread_id es una conversacion independiente.
El frontend genera un thread_id al cargar la pagina y lo envia
en cada request. Boton "New Chat" genera uno nuevo.

Flujo streaming:
  1. Frontend envia POST /api/chat/stream {message, thread_id}
  2. Backend usa graph.stream(stream_mode="messages") para tokens
  3. Cada token se envia como SSE event: data: {"type":"token","content":"..."}
  4. Tool calls se envian como: data: {"type":"tool_call","name":"...","args":{}}
  5. Final: data: {"type":"done"}
"""

from __future__ import annotations

import json
import logging
from collections.abc import Generator

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse
from langchain_core.messages import AIMessageChunk, ToolMessage
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


# ---------------------------------------------------------------------------
# POST /api/chat/stream  (SSE - Server-Sent Events)
# ---------------------------------------------------------------------------
# Usa graph.stream(stream_mode="messages") para streaming token a token.
# Cada token del LLM se envia como un SSE event al frontend.
# El frontend usa fetch() + ReadableStream (no EventSource, ya que es POST).
# ---------------------------------------------------------------------------


def _sse_event(data: dict) -> str:
    """Formatea un dict como evento SSE."""
    return f"data: {json.dumps(data)}\n\n"


def _stream_generator(
    agent: object, message: str, thread_id: str
) -> Generator[str, None, None]:
    """Generador sincrono que produce eventos SSE desde el agente.

    Usa stream_mode="messages" para obtener tokens individuales del LLM.
    Los tool calls se detectan por los AIMessageChunks con tool_call_chunks.
    """
    config = {
        "recursion_limit": 25,
        "configurable": {"thread_id": thread_id},
    }

    try:
        tool_calls_sent: list[dict] = []

        for chunk, metadata in agent.stream(
            {"messages": [("user", message)]},
            config=config,
            stream_mode="messages",
        ):
            # Token de texto del LLM (respuesta al usuario)
            if isinstance(chunk, AIMessageChunk):
                # Tokens de texto
                if chunk.content:
                    yield _sse_event({"type": "token", "content": chunk.content})

                # Tool call chunks (el LLM pide ejecutar un tool)
                if hasattr(chunk, "tool_call_chunks") and chunk.tool_call_chunks:
                    for tc in chunk.tool_call_chunks:
                        if tc.get("name"):
                            tool_info = {
                                "name": tc["name"],
                                "args": tc.get("args", ""),
                            }
                            tool_calls_sent.append(tool_info)
                            yield _sse_event({"type": "tool_call", **tool_info})

            # Resultado de un tool (feedback para el LLM)
            elif isinstance(chunk, ToolMessage):
                yield _sse_event(
                    {
                        "type": "tool_result",
                        "name": chunk.name or "unknown",
                        "preview": str(chunk.content)[:200],
                    }
                )

        yield _sse_event({"type": "done", "tool_calls": tool_calls_sent})

    except Exception as e:
        error_msg = str(e)
        if "recursion" in error_msg.lower():
            yield _sse_event(
                {
                    "type": "error",
                    "message": "He agotado mis intentos. Reformula la pregunta.",
                }
            )
        else:
            logger.exception("Error en streaming")
            yield _sse_event({"type": "error", "message": f"Error: {error_msg}"})

        yield _sse_event({"type": "done", "tool_calls": []})


@router.post("/chat/stream", response_model=None)
def chat_stream(
    body: ChatRequest, request: Request
) -> StreamingResponse | JSONResponse:
    """Streaming chat via SSE — el texto se genera token a token."""

    agent = request.app.state.agent
    if agent is None:
        return JSONResponse(
            status_code=503,
            content={"error": "Agente no disponible. Falta GROQ_API_KEY."},
        )

    return StreamingResponse(
        _stream_generator(agent, body.message, body.thread_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Nginx: disable buffering
        },
    )
