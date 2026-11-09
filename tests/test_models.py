"""Modelos de datos: validacion y propiedades derivadas."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from recon.models import (
    Host,
    PortInfo,
    PortState,
    ScanResult,
    ServiceInfo,
    Severity,
    Target,
    Vulnerability,
)


def _port(number: int, state: PortState, service: str | None = None) -> PortInfo:
    svc = ServiceInfo(name=service) if service else None
    return PortInfo(number=number, state=state, service=svc)


@pytest.mark.parametrize("number", [0, 65536, -1])
def test_port_outside_valid_range_is_rejected(number: int) -> None:
    with pytest.raises(ValidationError):
        PortInfo(number=number)


def test_vulnerability_score_above_ten_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Vulnerability(vuln_id="CVE-0000-0001", severity=Severity.HIGH, score=10.1, description="x")


def test_open_ports_excludes_closed_and_filtered() -> None:
    host = Host(
        address="192.0.2.10",
        ports=[
            _port(22, PortState.OPEN, "ssh"),
            _port(23, PortState.CLOSED, "telnet"),
            _port(80, PortState.FILTERED, "http"),
        ],
    )

    assert [p.number for p in host.open_ports] == [22]


def test_target_counts_open_ports_and_unique_services_across_hosts() -> None:
    target = Target(
        domain="example.com",
        hosts=[
            Host(address="192.0.2.10", ports=[_port(22, PortState.OPEN, "ssh"), _port(80, PortState.OPEN, "http")]),
            Host(address="192.0.2.11", ports=[_port(22, PortState.OPEN, "ssh"), _port(443, PortState.CLOSED, "https")]),
        ],
    )

    assert target.total_open_ports == 3
    assert target.unique_services == {"ssh", "http"}


def test_scan_duration_is_unknown_until_completed() -> None:
    scan = ScanResult(target=Target(domain="example.com"))
    assert scan.duration_seconds is None

    scan.complete()

    assert scan.duration_seconds is not None
    assert scan.duration_seconds >= 0


def test_scan_result_round_trips_through_json() -> None:
    scan = ScanResult(target=Target(domain="example.com", hosts=[Host(address="192.0.2.10")]))

    restored = ScanResult.model_validate_json(scan.to_json())

    assert restored == scan
