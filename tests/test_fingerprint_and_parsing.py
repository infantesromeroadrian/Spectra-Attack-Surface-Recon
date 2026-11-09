"""Fingerprinting web, descarte de wildcards y parsing de servicios afectados."""

from __future__ import annotations

import httpx
import pytest

from graph.ingest import _parse_affected_service, _parse_host_ip
from recon.subdomain_discovery import SubdomainDiscovery
from recon.tech_fingerprint import TechFingerprinter


def test_server_header_gives_product_and_version_case_insensitively() -> None:
    techs = TechFingerprinter()._analyze_headers({"SERVER": "Apache/2.4.7 (Ubuntu)"})

    apache = [t for t in techs if t.name == "Apache"]
    assert len(apache) == 1
    assert apache[0].version == "2.4.7"
    assert apache[0].category == "web-server"


def test_server_header_without_version_leaves_version_empty() -> None:
    techs = TechFingerprinter()._analyze_headers({"server": "nginx"})

    assert [(t.name, t.version) for t in techs if t.name == "nginx"] == [("nginx", None)]


def test_html_patterns_detect_cms_and_framework_versions() -> None:
    html = '<link href="/wp-content/themes/x/style.css"><app-root ng-version="17.3.1"></app-root>'

    found = {(t.name, t.version) for t in TechFingerprinter()._analyze_html(html)}

    assert ("WordPress", None) in found
    assert ("Angular", "17.3.1") in found


def test_cookie_names_reveal_the_backend_language() -> None:
    cookies = httpx.Cookies({"PHPSESSID": "abc"})

    assert [t.name for t in TechFingerprinter()._analyze_cookies(cookies)] == ["PHP"]


@pytest.mark.parametrize(
    ("ips", "wildcard", "expected"),
    [
        (["198.51.100.1"], {"198.51.100.1"}, True),
        (["198.51.100.1", "198.51.100.2"], {"198.51.100.1"}, False),
        ([], {"198.51.100.1"}, False),
    ],
)
def test_subdomain_is_discarded_only_when_every_ip_is_a_wildcard(
    ips: list[str], wildcard: set[str], expected: bool
) -> None:
    assert SubdomainDiscovery._is_wildcard_match(ips, wildcard) is expected


@pytest.mark.parametrize(
    ("affected", "expected"),
    [
        ("192.0.2.10:22 (OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13)", ("OpenSSH", "6.6.1p1")),
        ("192.0.2.10:80 (Apache httpd 2.4.7)", ("Apache httpd", "2.4.7")),
        ("192.0.2.10:80 (nginx )", ("nginx", None)),
        ("192.0.2.10:80", (None, None)),
    ],
)
def test_affected_service_is_split_into_product_and_version(
    affected: str, expected: tuple[str | None, str | None]
) -> None:
    assert _parse_affected_service(affected) == expected


@pytest.mark.parametrize(
    ("affected", "expected"),
    [
        ("192.0.2.10:22 (OpenSSH 8.9p1)", "192.0.2.10"),
        ("2001:db8::10:443 (nginx 1.18.0)", "2001:db8::10"),
        ("2001:db8::10:443", "2001:db8::10"),
        ("no-port", None),
        ("192.0.2.10:ssh (OpenSSH)", None),
        (":22 (OpenSSH)", None),
    ],
)
def test_host_ip_is_taken_before_the_last_colon(affected: str, expected: str | None) -> None:
    assert _parse_host_ip(affected) == expected
