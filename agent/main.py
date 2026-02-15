"""
Spectra Agent - CLI interactivo.

Lanza un chat en terminal para hablar con el agente de seguridad.
El agente consulta el grafo Neo4j para responder preguntas sobre
la superficie de ataque.

Uso:
    python -m agent.main
    python -m agent.main --model llama-3.1-8b-instant

Variables de entorno:
    GROQ_API_KEY: API key de Groq (requerida)
    NEO4J_URI: URI de Neo4j (default: bolt://localhost:7687)
    NEO4J_USER: Usuario Neo4j (default: neo4j)
    NEO4J_PASSWORD: Password Neo4j (default: spectrapass)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from graph.client import GraphClient
from agent.graph import create_agent

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="spectra-agent",
        description="Spectra Agent - AI red team analyst",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile"),
        help="Modelo de Groq (default: llama-3.3-70b-versatile)",
    )
    parser.add_argument(
        "--neo4j-uri",
        default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
    )
    parser.add_argument(
        "--neo4j-user",
        default=os.environ.get("NEO4J_USER", "neo4j"),
    )
    parser.add_argument(
        "--neo4j-password",
        default=os.environ.get("NEO4J_PASSWORD", "spectrapass"),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Logging
    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )

    # Groq API key
    groq_key = os.environ.get("GROQ_API_KEY", "")
    if not groq_key:
        print("Error: GROQ_API_KEY no esta configurada.")
        print("Export: export GROQ_API_KEY=gsk_...")
        sys.exit(1)

    # Conectar Neo4j
    try:
        graph_client = GraphClient(args.neo4j_uri, args.neo4j_user, args.neo4j_password)
    except Exception as e:
        print(f"Error conectando a Neo4j: {e}")
        sys.exit(1)

    # Verificar que hay datos
    stats = graph_client.stats()
    total_nodes = sum(v for k, v in stats.items() if k != "_relationships")
    if total_nodes == 0:
        print("Warning: El grafo esta vacio. Ejecute un scan primero:")
        print("  python -m recon --target scanme.nmap.org")
        graph_client.close()
        sys.exit(1)

    # Crear agente
    agent = create_agent(graph_client.driver, groq_key, args.model)

    # Banner
    sep = "=" * 60
    print(f"\n{sep}")
    print("  SPECTRA AGENT - AI Red Team Analyst")
    print(sep)
    print(f"  Model:   {args.model}")
    print(f"  Neo4j:   {args.neo4j_uri}")
    print(
        f"  Graph:   {total_nodes} nodes, {stats.get('_relationships', 0)} relationships"
    )
    print(f"{sep}")
    print("  Type your questions. 'quit' or 'exit' to leave.")
    print(f"{sep}\n")

    # Chat loop
    try:
        while True:
            try:
                user_input = input("You > ").strip()
            except EOFError:
                break

            if not user_input:
                continue
            if user_input.lower() in ("quit", "exit", "q"):
                break

            # Invocar agente
            # recursion_limit=25 -> ~12 ciclos agent->tools max.
            # Evita bucles infinitos si el LLM reintenta queries fallidas.
            try:
                result = agent.invoke(
                    {"messages": [("user", user_input)]},
                    config={"recursion_limit": 25},
                )
                # Extraer la respuesta final del agente
                ai_message = result["messages"][-1]
                print(f"\nSpectra > {ai_message.content}\n")

            except Exception as e:
                error_msg = str(e)
                if "recursion limit" in error_msg.lower():
                    print(
                        "\nSpectra > Lo siento, he agotado mis intentos "
                        "procesando esa pregunta. Intenta reformularla "
                        "o usa una pregunta mas especifica.\n"
                    )
                else:
                    print(f"\nError: {e}\n")
                    logger.exception("Agent error")

    except KeyboardInterrupt:
        pass

    print("\nHasta luego.")
    graph_client.close()


if __name__ == "__main__":
    main()
