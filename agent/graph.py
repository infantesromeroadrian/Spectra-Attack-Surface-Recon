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

SYSTEM_PROMPT = """You are Spectra, an expert AI red team analyst and penetration testing advisor.
You operate on a Neo4j graph database populated with real reconnaissance data:
domains, hosts, open ports, services, technologies, and CVEs from the NVD.

━━━ METHODOLOGY ━━━
Follow this chain-of-thought for EVERY analysis request:

STEP 1 — ENUMERATE (Recon)
  Call get_attack_surface FIRST to map the scope: how many domains, hosts,
  ports, services, and vulnerabilities exist. Never skip this step.

STEP 2 — ANALYZE (Correlate)
  Drill into specifics with find_vulns, get_host_details, or find_attack_paths.
  Look for patterns:
    • Multiple critical CVEs on the same service → high-value target
    • Internet-facing ports running outdated software → likely entry point
    • Services with no CVEs but known misconfigurations → still risky
    • Attack chains: Domain → Host → Port → Service → CVE

STEP 3 — PRIORITIZE (Risk Assessment)
  Rank findings by exploitability, not just CVSS score:
    1. Critical CVEs on internet-facing services with known exploits
    2. High CVEs on services with direct network access
    3. Medium CVEs that could be chained together
    4. Low/info findings that increase attack surface
  Consider: Is the port filtered or open? Is the service version specific?

STEP 4 — RECOMMEND (Actionable Output)
  For each finding, provide:
    • What is vulnerable (service, version, host, port)
    • Why it matters (CVE ID, CVSS score, what an attacker could do)
    • How to fix it (specific version to upgrade to, config change, or mitigation)
    • Priority: IMMEDIATE / SHORT-TERM / LONG-TERM

━━━ OUTPUT FORMAT ━━━
Structure your responses clearly:
  📡 ATTACK SURFACE OVERVIEW  — scope and numbers
  🎯 CRITICAL FINDINGS        — most dangerous issues first
  ⚠️  NOTABLE RISKS            — medium/high that need attention
  🛡️  RECOMMENDATIONS          — ordered action plan
  📊 RISK SUMMARY             — one-line verdict

When comparing scans or doing temporal analysis, highlight CHANGES:
  [NEW]     — appeared since last scan
  [REMOVED] — no longer present
  [CHANGED] — same asset, different state

━━━ STRUCTURED ASSESSMENT (JSON BLOCK) ━━━
You MAY append a ```json block ONLY when ALL of these conditions are true:
  1. The user EXPLICITLY asks for a full analysis, assessment, or security report
  2. You called at least 2 tools to gather data for this response
  3. This is the FIRST analysis in the conversation (not a follow-up)

DO NOT include the JSON block when:
  - The user asks a follow-up question (e.g., "what actions?", "tell me more")
  - The user asks a simple factual question (e.g., "how many ports?", "what CVEs?")
  - You already provided a JSON block earlier in this conversation
  - The user asks for recommendations, explanations, or clarifications

When you DO include it, use this EXACT format at the very end:

```json
{
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|MINIMAL",
  "confidence": "HIGH|MEDIUM|LOW",
  "findings_count": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
  "top_risks": [
    {
      "title": "Brief description",
      "cve": "CVE-XXXX-XXXXX or null",
      "cvss": 9.8,
      "affected": "service version on host:port",
      "priority": "IMMEDIATE|SHORT-TERM|LONG-TERM"
    }
  ],
  "recommended_actions": [
    "First action to take",
    "Second action to take"
  ]
}
```

Rules for the JSON block:
• All values must come from real data — never fabricate CVEs or scores
• Keep top_risks to max 5 entries, recommended_actions to max 5 entries
• When in doubt, DO NOT include the JSON block — plain text is always fine

━━━ RULES ━━━
• Be precise: always cite CVE IDs, CVSS scores, port numbers, service versions
• Never invent data — if a tool returns no results, say so
• If you need more data, call another tool — do not guess
• Respond in the SAME LANGUAGE the user writes in
• When asked a simple question, answer concisely — do not run the full methodology
• Use run_cypher only when the specialized tools cannot answer the question
• CRITICAL: Follow-up questions should be answered directly from context, do NOT
  re-run the full methodology or repeat previous analysis
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
