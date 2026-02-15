"""
Spectra Graph - Cliente Neo4j.

Gestiona la conexion a Neo4j y la inicializacion del schema.

Neo4j no tiene "tablas" como SQL. Los nodos y relaciones se crean
al insertar datos. Pero SI podemos crear dos cosas importantes:

1. CONSTRAINTS de unicidad - Garantizan que no creamos un nodo
   duplicado si escaneamos el mismo target dos veces.
   Ejemplo: solo puede haber un nodo Domain con name="nmap.org".

2. INDEXES - Aceleran las busquedas. Neo4j crea un indice
   automaticamente para cada constraint de unicidad, pero podemos
   añadir mas si necesitamos buscar por otros campos.

Patron de uso:
    client = GraphClient("bolt://localhost:7687", "neo4j", "spectrapass")
    client.init_schema()   # Crear constraints (una sola vez)
    # ... usar client.driver para queries ...
    client.close()

Tambien funciona como context manager:
    with GraphClient(...) as client:
        client.init_schema()
        # ... queries ...
"""

from __future__ import annotations

import logging

from neo4j import GraphDatabase, Driver

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constraints y sus indices asociados
# ---------------------------------------------------------------------------
# Cada constraint define:
#   - label: tipo de nodo (Domain, Host, etc.)
#   - property: propiedad que debe ser unica
#
# Cuando Neo4j crea un constraint de unicidad, automaticamente
# crea un indice B-tree para esa propiedad. Doble beneficio:
# no duplicados + busquedas rapidas.

CONSTRAINTS: list[dict[str, str]] = [
    # Un dominio es unico por su nombre
    {"name": "domain_name", "label": "Domain", "property": "name"},
    # Un subdominio es unico por su FQDN
    {"name": "subdomain_name", "label": "Subdomain", "property": "name"},
    # Un host es unico por su IP
    {"name": "host_address", "label": "Host", "property": "address"},
    # Un puerto es unico por la combinacion host:numero:protocolo
    # (esto lo manejamos con MERGE, no con constraint compuesto,
    #  porque Neo4j Community no soporta constraints multi-propiedad)
    # Un servicio es unico por nombre+version (idem, usamos MERGE)
    # Una tecnologia es unica por nombre+categoria (idem)
    # Una vulnerabilidad es unica por su CVE ID
    {"name": "vuln_id", "label": "Vulnerability", "property": "vuln_id"},
    # Un escaneo es unico por su UUID
    {"name": "scan_id", "label": "Scan", "property": "scan_id"},
]


class GraphClient:
    """Cliente de conexion a Neo4j para Spectra.

    Encapsula el driver, la inicializacion del schema y
    proporciona acceso al driver para queries.

    Ejemplo:
        with GraphClient("bolt://localhost:7687", "neo4j", "pass") as client:
            client.init_schema()
            with client.driver.session() as session:
                session.run("MATCH (n) RETURN count(n)")
    """

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "spectrapass",
    ) -> None:
        """Inicializa la conexion a Neo4j.

        Args:
            uri: URI de conexion Bolt (bolt://host:port).
            user: Usuario de Neo4j.
            password: Password de Neo4j.
        """
        self._uri = uri
        self._driver: Driver = GraphDatabase.driver(uri, auth=(user, password))

        # Verificar conexion inmediatamente (fail fast)
        self._driver.verify_connectivity()
        logger.info(f"Neo4j conectado: {uri}")

    @property
    def driver(self) -> Driver:
        """Acceso al driver Neo4j para queries directas."""
        return self._driver

    def close(self) -> None:
        """Cierra la conexion al driver."""
        self._driver.close()
        logger.info("Neo4j desconectado")

    def __enter__(self) -> GraphClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # -------------------------------------------------------------------
    # Schema
    # -------------------------------------------------------------------

    def init_schema(self) -> None:
        """Crea constraints de unicidad e indices en Neo4j.

        Idempotente: si los constraints ya existen, no hace nada.
        Seguro ejecutar multiples veces (primera ejecucion y sucesivas).

        Los constraints garantizan que:
          - No se creen nodos Domain duplicados para "nmap.org"
          - No se creen nodos Host duplicados para "45.33.32.156"
          - No se creen nodos Vulnerability duplicados para "CVE-2021-44790"
          - etc.
        """
        with self._driver.session() as session:
            for constraint in CONSTRAINTS:
                cypher = (
                    f"CREATE CONSTRAINT {constraint['name']} "
                    f"IF NOT EXISTS "
                    f"FOR (n:{constraint['label']}) "
                    f"REQUIRE n.{constraint['property']} IS UNIQUE"
                )
                session.run(cypher)
                logger.debug(
                    f"Constraint: {constraint['name']} "
                    f"({constraint['label']}.{constraint['property']})"
                )

        logger.info(f"Schema inicializado: {len(CONSTRAINTS)} constraints")

    def wipe(self) -> None:
        """Borra TODOS los nodos y relaciones.

        PELIGROSO: solo para desarrollo/testing.
        Borra todo el grafo sin posibilidad de recuperacion.
        """
        with self._driver.session() as session:
            # DETACH DELETE borra nodos Y sus relaciones
            result = session.run("MATCH (n) DETACH DELETE n RETURN count(n) AS deleted")
            record = result.single()
            count = record["deleted"] if record else 0
            logger.info(f"Grafo limpiado: {count} nodos eliminados")

    def stats(self) -> dict[str, int]:
        """Devuelve conteo de nodos por tipo y total de relaciones.

        Util para verificar que la ingesta funciono correctamente.

        Returns:
            Dict con conteos: {"Domain": 1, "Host": 3, ..., "relationships": 15}
        """
        counts: dict[str, int] = {}

        with self._driver.session() as session:
            # Contar nodos por label
            result = session.run(
                "CALL db.labels() YIELD label "
                "CALL apoc.cypher.run('MATCH (n:`' + label + '`) "
                "RETURN count(n) AS c', {}) YIELD value "
                "RETURN label, value.c AS count"
            )
            for record in result:
                counts[record["label"]] = record["count"]

            # Contar relaciones totales
            result = session.run("MATCH ()-[r]->() RETURN count(r) AS count")
            record = result.single()
            counts["_relationships"] = record["count"] if record else 0

        return counts
