from datetime import datetime, timezone
# ParseError — oryginalny błąd składni XML; sprawdzamy, że parser go zachowuje jako przyczynę
from xml.etree.ElementTree import ParseError

import pytest

from app.core.exceptions import NmapParseError
from app.nmap.xml_parser import parse_scan


# Fixture budujące gotowy ScanResult z plików XML z kroku 1.
# Korzystają z fixture typical_xml / edge_cases_xml z conftest.py
@pytest.fixture
def typical(typical_xml):
    return parse_scan(typical_xml)


@pytest.fixture
def edge(edge_cases_xml):
    return parse_scan(edge_cases_xml)


# ===== Metadane skanu i błędy na poziomie całego dokumentu =====

def test_typical_scan_metadata(typical):
    # Atrybuty <nmaprun>
    assert typical.nmap_version == "7.95"
    assert typical.args == "nmap -sT -sV -p 22,80,443 -oX - 192.168.1.1"
    # Unix timestamp 1792173600 → 16.10.2026 18:00 UTC (20:00 w Polsce)
    assert typical.started_at == datetime(2026, 10, 16, 18, 0, 0, tzinfo=timezone.utc)
    # Z <runstats><finished time=".." elapsed="..">
    assert typical.finished_at == datetime(2026, 10, 16, 18, 0, 12, tzinfo=timezone.utc)
    assert typical.elapsed_seconds == 12.34


def test_typical_scan_host_counts(typical):
    # <hosts up="1" down="0" total="1"/>
    assert (typical.hosts_up, typical.hosts_down, typical.hosts_total) == (1, 0, 1)


def test_edge_cases_host_counts(edge):
    # <hosts up="2" down="1" total="3"/>
    assert (edge.hosts_up, edge.hosts_down, edge.hosts_total) == (2, 1, 3)


# Pusty tekst, zwykły tekst, niezamknięte znaczniki → "Invalid XML"
@pytest.mark.parametrize("xml_text", ["", "not xml at all", "<nmaprun><host>"])
def test_invalid_xml_raises_parse_error(xml_text):
    with pytest.raises(NmapParseError, match="Invalid XML"):
        parse_scan(xml_text)


def test_invalid_xml_keeps_original_cause():
    with pytest.raises(NmapParseError) as excinfo:
        parse_scan("<nmaprun>")

    # "raise ... from error" zapisuje oryginalny błąd w __cause__
    assert isinstance(excinfo.value.__cause__, ParseError)


def test_wrong_root_element_is_rejected():
    # Poprawny XML, ale to nie jest wynik nmapa
    with pytest.raises(NmapParseError, match="Expected <nmaprun>"):
        parse_scan("<html><body>not nmap</body></html>")
