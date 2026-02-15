"""
Spectra Agent - Grafo LangGraph (ReAct agent).

Implementa un agente ReAct (Reason + Act) usando LangGraph StateGraph.

El loop es simple:
  1. El LLM recibe la pregunta del usuario + historial de mensajes
  2. El LLM decide:
     a) Llamar un tool (necesita mas datos) -> ejecuta tool -> vuelve a 1
     b) Responder directamente (ya tiene toda la info) -> fin

LangGraph orquesta este loop con dos nodos:
  - "agent": llama al LLM con los mensajes y tools disponibles
  - "tools": ejecuta el tool que el LLM pidio

La decision de si ir a "tools" o terminar la toma el LLM
(si devuelve tool_calls -> ir a tools, si no -> END).

Uso:
    from agent.graph import create_agent
    agent = create_agent(neo4j_driver, groq_api_key)
    result = agent.invoke({"messages": [("user", "que vulns criticas hay?")]})
"""

from __future__ import annotations

import logging
from typing import Annotated, TypedDict

from langchain_core.messages import BaseMessage
from langchain_groq import ChatGroq
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from neo4j import Driver

from agent.tools import create_tools

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# State: lo que fluye entre nodos del grafo
# ---------------------------------------------------------------------------


class AgentState(TypedDict):
    """Estado del agente.

    messages: Historial completo de mensajes (user + assistant + tool).
              Usa add_messages como reducer: cada update AÑADE mensajes
              en vez de sobrescribir (acumula la conversacion).
    """

    messages: Annotated[list[BaseMessage], add_messages]


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are Spectra, an AI red team analyst.
You have access to a Neo4j graph database containing reconnaissance data
about target domains: hosts, open ports, services, technologies, and
known vulnerabilities (CVEs).

Your job is to analyze the attack surface and provide actionable security insights.

Guidelines:
- Start with get_attack_surface to understand the scope
- Use find_attack_paths to trace how an attacker could reach vulnerabilities
- Be specific: mention CVE IDs, CVSS scores, affected services, and ports
- Prioritize findings by severity (critical > high > medium > low)
- Suggest concrete remediation steps when reporting vulnerabilities
- If you don't have enough data, say so honestly
- Respond in the same language the user writes in
"""


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_agent(
    driver: Driver,
    groq_api_key: str,
    model: str = "llama-3.3-70b-versatile",
) -> StateGraph:
    """Crea el agente LangGraph con tools de Neo4j.

    Args:
        driver: Driver Neo4j conectado.
        groq_api_key: API key de Groq.
        model: Modelo de Groq a usar.

    Returns:
        Grafo LangGraph compilado, listo para .invoke() o .stream().
    """
    # 1. Inicializar tools (inyecta el driver Neo4j)
    tools = create_tools(driver)
    logger.info(f"Tools: {[t.name for t in tools]}")

    # 2. Inicializar LLM con tools bindeados
    # bind_tools() le dice al LLM que formato usar para llamar tools
    # (Groq soporta tool calling nativo con Llama 3.x)
    llm = ChatGroq(
        api_key=groq_api_key,
        model_name=model,
        temperature=0,  # Determinista para analisis de seguridad
    )
    llm_with_tools = llm.bind_tools(tools)

    # 3. Definir los nodos del grafo

    def agent_node(state: AgentState) -> dict:
        """Nodo agente: invoca el LLM con el historial de mensajes.

        El LLM decide si:
        - Llamar un tool (devuelve message con tool_calls)
        - Responder al usuario (devuelve message sin tool_calls)
        """
        # Prepend system prompt al historial
        messages = [("system", SYSTEM_PROMPT)] + state["messages"]
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    # ToolNode ejecuta automaticamente el tool que el LLM pidio
    # y devuelve el resultado como ToolMessage
    tool_node = ToolNode(tools)

    # 4. Construir el grafo

    def should_continue(state: AgentState) -> str:
        """Decide si seguir con tools o terminar.

        Si el ultimo mensaje del LLM tiene tool_calls -> ir a tools.
        Si no -> ya respondio, terminamos.
        """
        last_message = state["messages"][-1]
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "tools"
        return END

    builder = StateGraph(AgentState)

    # Añadir nodos
    builder.add_node("agent", agent_node)
    builder.add_node("tools", tool_node)

    # Añadir edges
    builder.add_edge(START, "agent")  # Empieza en agent
    builder.add_conditional_edges(  # Agent decide si:
        "agent",
        should_continue,
        {"tools": "tools", END: END},  #   -> tools o -> fin
    )
    builder.add_edge("tools", "agent")  # Tras tool, vuelve a agent

    # 5. Compilar con MemorySaver para conversaciones multi-turn.
    # MemorySaver guarda el historial de mensajes en memoria (por thread_id).
    # Cada thread_id es una conversacion independiente.
    # NOTA: recursion_limit se pasa como config al invocar el grafo,
    # no se asigna aqui. Ver main.py: invoke(input, config={"recursion_limit": 25})
    memory = MemorySaver()
    graph = builder.compile(checkpointer=memory)
    logger.info(f"Agent compilado con modelo {model} (memory: MemorySaver)")

    return graph
