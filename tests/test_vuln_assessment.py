"""Evaluacion de vulnerabilidades contra NVD, sin red."""

from __future__ import annotations

import httpx
import pytest

from recon.models import Host, PortInfo, PortState, ServiceInfo, Severity, Vulnerability
from recon.vuln_assessment import VulnAssessment


def test_cpe_22_is_converted_to_23_with_eleven_fields() -> None:
    converted = VulnAssessment._cpe_to_23("cpe:/a:apache:http_server:2.4.7")

    assert converted == "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*"
    assert len(converted.split(":")) == 13


def test_cpe_23_is_returned_unchanged() -> None:
    cpe = "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"
    assert VulnAssessment._cpe_to_23(cpe) == cpe


@pytest.mark.parametrize("cpe", ["", "apache 2.4.7", "cpe:a:apache"])
def test_unrecognised_cpe_returns_none(cpe: str) -> None:
    assert VulnAssessment._cpe_to_23(cpe) is None


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (10.0, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (8.9, Severity.HIGH),
        (7.0, Severity.HIGH),
        (6.9, Severity.MEDIUM),
        (4.0, Severity.MEDIUM),
        (3.9, Severity.LOW),
        (0.1, Severity.LOW),
        (0.0, Severity.INFO),
    ],
)
def test_cvss_score_maps_to_severity_band(score: float, expected: Severity) -> None:
    assert VulnAssessment._map_severity(score) is expected


def test_cvss_v31_is_preferred_over_v2() -> None:
    metrics = {
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
    }

    assert VulnAssessment()._extract_cvss(metrics) == (9.8, Severity.CRITICAL)


def test_missing_cvss_gives_info_without_score() -> None:
    assert VulnAssessment()._extract_cvss({}) == (None, Severity.INFO)


def test_nvd_response_is_parsed_with_english_text_and_capped_fields() -> None:
    data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44790",
                    "descriptions": [
                        {"lang": "es", "value": "texto"},
                        {"lang": "en", "value": "x" * 600},
                    ],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                    "references": [{"url": f"https://example.org/{i}"} for i in range(8)],
                }
            },
            {"cve": {"descriptions": [{"lang": "en", "value": "no id"}]}},
        ]
    }

    vulns = VulnAssessment()._parse_nvd_response(data)

    assert len(vulns) == 1
    assert vulns[0].vuln_id == "CVE-2021-44790"
    assert vulns[0].severity is Severity.CRITICAL
    assert len(vulns[0].description) == 500
    assert len(vulns[0].references) == 5


def test_cpe_without_version_is_skipped_before_any_request(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("NVD must not be queried for a CPE without version")

    monkeypatch.setattr(httpx, "Client", fail)

    assert VulnAssessment().query_nvd("cpe:/a:apache:http_server") == []


def _host(*ports: PortInfo) -> Host:
    return Host(address="192.0.2.10", ports=list(ports))


def test_assess_returns_nothing_when_nvd_is_disabled() -> None:
    host = _host(PortInfo(number=22, service=ServiceInfo(name="ssh", cpe="cpe:/a:openbsd:openssh:8.9p1")))
    assert VulnAssessment(use_nvd=False).assess([host]) == []


def test_assess_deduplicates_sorts_and_skips_services_without_cpe(monkeypatch: pytest.MonkeyPatch) -> None:
    queried: list[str] = []

    def fake_query(cpe: str, max_results: int = 10) -> list[Vulnerability]:
        queried.append(cpe)
        shared = Vulnerability(vuln_id="CVE-2023-0001", severity=Severity.MEDIUM, score=5.0, description="shared")
        if "openssh" in cpe:
            return [shared, Vulnerability(vuln_id="CVE-2023-0002", severity=Severity.CRITICAL, score=9.8, description="ssh")]
        return [shared]

    assessor = VulnAssessment()
    monkeypatch.setattr(assessor, "query_nvd", fake_query)
    host = _host(
        PortInfo(number=22, service=ServiceInfo(name="ssh", product="OpenSSH", version="8.9p1", cpe="cpe:/a:openbsd:openssh:8.9p1")),
        PortInfo(number=80, service=ServiceInfo(name="http", product="Apache httpd", version="2.4.7", cpe="cpe:/a:apache:http_server:2.4.7")),
        PortInfo(number=8080, service=ServiceInfo(name="http-proxy")),
        PortInfo(number=3306, state=PortState.CLOSED, service=ServiceInfo(name="mysql", cpe="cpe:/a:mysql:mysql:5.7")),
    )

    vulns = assessor.assess([host])

    assert queried == ["cpe:/a:openbsd:openssh:8.9p1", "cpe:/a:apache:http_server:2.4.7"]
    assert [v.vuln_id for v in vulns] == ["CVE-2023-0002", "CVE-2023-0001"]
    assert vulns[0].affected_service == "192.0.2.10:22 (OpenSSH 8.9p1)"
