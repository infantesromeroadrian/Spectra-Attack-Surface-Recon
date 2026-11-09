"""Barreras de solo lectura de los tools del agente, con un driver Neo4j falso."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from agent import tools


class _Summary:
    def __init__(self, query_type: str) -> None:
        self.query_type = query_type


class _Result:
    def __init__(self, query_type: str) -> None:
        self._query_type = query_type

    def consume(self) -> _Summary:
        return _Summary(self._query_type)


class _Session:
    def __init__(self, driver: FakeDriver) -> None:
        self._driver = driver

    def __enter__(self) -> _Session:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def run(self, cypher: str, _params: dict | None = None) -> _Result:
        self._driver.explained.append(cypher)
        return _Result(self._driver.query_type)

    def execute_read(self, fn: Callable[..., Any], cypher: str, params: dict) -> list[dict]:
        self._driver.read_calls.append((fn, cypher, params))
        return self._driver.rows


class FakeDriver:
    def __init__(self, query_type: str = "r", rows: list[dict] | None = None) -> None:
        self.query_type = query_type
        self.rows = rows if rows is not None else []
        self.explained: list[str] = []
        self.read_calls: list[tuple[Callable[..., Any], str, dict]] = []

    def session(self) -> _Session:
        return _Session(self)


@pytest.fixture
def driver(monkeypatch: pytest.MonkeyPatch) -> FakeDriver:
    fake = FakeDriver(rows=[{"port": 22}])
    monkeypatch.setattr(tools, "_driver", fake)
    return fake


@pytest.mark.parametrize(
    "query",
    [
        "MATCH (n) DETACH DELETE n",
        "MATCH (n) SET\tn.owned = true",
        "match (n) set n.owned = true",
        "CREATE (n:Pwned)",
        "MERGE (n:Pwned)",
        "CALL apoc.load.json('http://169.254.169.254/latest/meta-data')",
        "LOAD CSV FROM 'file:///etc/passwd' AS line RETURN line",
        "MATCH (n) FOREACH (x IN [1] | REMOVE n.name)",
    ],
)
def test_run_cypher_blocks_write_and_escape_clauses_before_touching_neo4j(
    driver: FakeDriver, query: str
) -> None:
    result = tools.run_cypher.invoke({"query": query})

    assert result.startswith("Error: only read-only")
    assert driver.explained == []
    assert driver.read_calls == []


def test_run_cypher_rejects_queries_neo4j_classifies_as_writes(driver: FakeDriver) -> None:
    driver.query_type = "rw"

    result = tools.run_cypher.invoke({"query": "MATCH (n) RETURN n"})

    assert "query type: rw" in result
    assert driver.read_calls == []


def test_run_cypher_runs_read_queries_in_a_read_transaction(driver: FakeDriver) -> None:
    query = "MATCH (s:Subdomain) WHERE s.name STARTS WITH 'mail' RETURN s.name"

    result = tools.run_cypher.invoke({"query": query})

    assert driver.explained == ["EXPLAIN " + query]
    assert [call[1] for call in driver.read_calls] == [query]
    assert result.startswith("Results (1 rows):")


def test_every_agent_query_goes_through_a_read_transaction(driver: FakeDriver) -> None:
    rows = tools._run_query("MATCH (h:Host) RETURN h.address AS address", {"limit": 5})

    assert rows == [{"port": 22}]
    assert driver.read_calls[0][1:] == ("MATCH (h:Host) RETURN h.address AS address", {"limit": 5})
    assert driver.read_calls[0][0] is tools._collect
