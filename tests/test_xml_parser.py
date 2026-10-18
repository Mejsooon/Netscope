from datetime import datetime, timezone
# ParseError — oryginalny błąd składni XML; sprawdzamy, że parser go zachowuje jako przyczynę
from xml.etree.ElementTree import ParseError

import pytest

from app.core.exceptions import NmapParseError
from app.nmap.xml_parser import parse_scan


# ===== Metadane skanu i błędy na poziomie całego dokumentu =====

def test_typical_scan_metadata(typical_xml):
    typical = parse_scan(typical_xml)
    # Atrybuty <nmaprun>
    assert typical.nmap_version == "7.95"
    assert typical.args == "nmap -sT -sV -p 22,80,443 -oX - 192.168.1.1"
    # Unix timestamp 1792173600 → 16.10.2026 18:00 UTC (20:00 w Polsce)
    assert typical.started_at == datetime(2026, 10, 16, 18, 0, 0, tzinfo=timezone.utc)
    # Z <runstats><finished time=".." elapsed="..">
    assert typical.finished_at == datetime(2026, 10, 16, 18, 0, 12, tzinfo=timezone.utc)
    assert typical.elapsed_seconds == 12.34


def test_typical_scan_host_counts(typical_xml):
    typical = parse_scan(typical_xml)
    # <hosts up="1" down="0" total="1"/>
    assert (typical.hosts_up, typical.hosts_down, typical.hosts_total) == (1, 0, 1)


def test_edge_cases_host_counts(edge_cases_xml):
    edge = parse_scan(edge_cases_xml)
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


# ===== Hosty: stan i adresy =====

def test_typical_host_status_and_address(typical_xml):
    typical = parse_scan(typical_xml)
    host = typical.hosts[0]

    assert len(typical.hosts) == 1
    assert host.state == "up"
    # IPvAnyAddress → str() daje adres jako tekst
    assert str(host.ip) == "192.168.1.1"
    # Typowy skan nie ma adresu MAC
    assert host.mac is None
    assert host.mac_vendor is None


def test_edge_cases_host_states_in_document_order(edge_cases_xml):
    edge = parse_scan(edge_cases_xml)
    # Hosty w tej samej kolejności co w XML, łącznie z hostem down
    assert [host.state for host in edge.hosts] == ["up", "down", "up"]
    assert [str(host.ip) for host in edge.hosts] == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_edge_cases_ipv4_and_mac_are_separated(edge_cases_xml):
    edge = parse_scan(edge_cases_xml)
    first, _, third = edge.hosts

    # MAC trafia do pola mac, a nie do ip (szukanie po addrtype)
    assert first.mac == "AA:BB:CC:11:22:33"
    assert first.mac_vendor == "Example Networks"
    # Host 3: MAC bez atrybutu vendor
    assert third.mac == "AA:BB:CC:44:55:66"
    assert third.mac_vendor is None


def test_ipv6_host_address(typical_xml):
    # Podmieniamy adres IPv4 na IPv6 w kopii fixture
    xml_text = typical_xml.replace(
        'addr="192.168.1.1" addrtype="ipv4"', 'addr="2001:db8::1" addrtype="ipv6"'
    )

    assert str(parse_scan(xml_text).hosts[0].ip) == "2001:db8::1"


# ===== Nazwy hostów =====

def test_hostnames_are_collected(typical_xml, edge_cases_xml):
    typical = parse_scan(typical_xml)
    edge = parse_scan(edge_cases_xml)
    assert typical.hosts[0].hostnames == ["router.lan"]
    assert edge.hosts[0].hostnames == ["router.lan"]


def test_missing_or_empty_hostnames_give_empty_list(edge_cases_xml):
    edge = parse_scan(edge_cases_xml)
    _, down_host, empty_hostnames_host = edge.hosts

    # Host down nie ma <hostnames>; host 3 ma pusty <hostnames></hostnames>
    assert down_host.hostnames == []
    assert empty_hostnames_host.hostnames == []


def test_duplicate_hostnames_are_removed_keeping_order(typical_xml):
    # Trzy nazwy, w tym duplikat "gateway"
    xml_text = typical_xml.replace(
        '<hostname name="router.lan" type="PTR"/>',
        '<hostname name="gateway" type="user"/>'
        '<hostname name="router.lan" type="PTR"/>'
        '<hostname name="gateway" type="PTR"/>',
    )

    # Duplikat usunięty, kolejność pierwszego wystąpienia zachowana
    assert parse_scan(xml_text).hosts[0].hostnames == ["gateway", "router.lan"]


# ===== Porty i usługi =====

def test_typical_ports_in_document_order(typical_xml):
    typical = parse_scan(typical_xml)
    ports = typical.hosts[0].ports

    # "22" z XML zamienione na int 22
    assert [port.port for port in ports] == [22, 80, 443]
    assert [port.state for port in ports] == ["open", "open", "closed"]
    assert all(port.protocol == "tcp" for port in ports)


def test_typical_service_details_from_version_detection(typical_xml):
    typical = parse_scan(typical_xml)
    # Porty w kolejności z XML: [0]=22, [1]=80, [2]=443
    ssh = typical.hosts[0].ports[0]

    # Pełne dane z -sV (method="probed")
    assert ssh.service_name == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "9.6p1 Ubuntu 3ubuntu13.5"
    assert ssh.extra_info == "Ubuntu Linux; protocol 2.0"
    assert ssh.reason == "syn-ack"


def test_service_guessed_from_table_has_no_product(typical_xml):
    typical = parse_scan(typical_xml)
    # Porty w kolejności z XML: [0]=22, [1]=80, [2]=443
    https = typical.hosts[0].ports[2]

    # method="table": tylko nazwa usługi, bez produktu i wersji
    assert https.service_name == "https"
    assert https.product is None
    assert https.version is None


def test_filtered_port(edge_cases_xml):
    edge = parse_scan(edge_cases_xml)
    # Porty hosta 1 w kolejności z XML: [0]=22, [1]=53, [2]=80, [3]=8080
    http = edge.hosts[0].ports[2]

    assert http.state == "filtered"
    assert http.reason == "no-response"


def test_port_without_service_element(edge_cases_xml):
    edge = parse_scan(edge_cases_xml)
    # Porty hosta 1 w kolejności z XML: [0]=22, [1]=53, [2]=80, [3]=8080
    unknown = edge.hosts[0].ports[3]

    # Brak <service> nie wywraca parsera — pola usługi to None
    assert unknown.state == "open"
    assert unknown.service_name is None
    assert unknown.product is None


def test_hosts_without_port_elements_have_no_ports(edge_cases_xml):
    edge = parse_scan(edge_cases_xml)
    _, down_host, filtered_host = edge.hosts

    # Host down: brak <ports>; host 3: <ports> tylko z <extraports>
    assert down_host.ports == []
    assert filtered_host.ports == []


# ===== Zgrupowane porty (extraports) =====

def test_extraports_summaries(edge_cases_xml):
    edge = parse_scan(edge_cases_xml)
    first, down_host, filtered_host = edge.hosts

    # Lista par (stan, liczba) dla każdego hosta
    assert [(e.state, e.count) for e in first.extra_ports] == [("closed", 997)]
    assert down_host.extra_ports == []
    assert [(e.state, e.count) for e in filtered_host.extra_ports] == [("filtered", 1001)]


def test_extraports_are_not_listed_as_ports(edge_cases_xml):
    edge = parse_scan(edge_cases_xml)
    first = edge.hosts[0]

    # 4 porty wypisane osobno + 997 zgrupowanych = 1001 skanowanych portów
    assert len(first.ports) == 4
    assert len(first.ports) + first.extra_ports[0].count == 1001


# ===== Skan bez <runstats> =====

# Przerwany skan: nmap nie zdążył zapisać <runstats>
INTERRUPTED_SCAN = """<nmaprun scanner="nmap" args="nmap -sT 10.0.0.0/30" start="1792173600" version="7.95">
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host>
<host><status state="down"/><address addr="10.0.0.2" addrtype="ipv4"/></host>
</nmaprun>"""


def test_interrupted_scan_without_runstats_counts_hosts():
    scan = parse_scan(INTERRUPTED_SCAN)

    # Liczby policzone z listy hostów: 1 up, 1 down, 2 łącznie
    assert (scan.hosts_up, scan.hosts_down, scan.hosts_total) == (1, 1, 2)
    assert scan.finished_at is None
    assert scan.elapsed_seconds is None


def test_runstats_take_priority_over_listed_hosts(edge_cases_xml):
    # Skan sieci /24: nmap wypisuje tylko część hostów, ale <runstats> zna pełne liczby
    xml_text = edge_cases_xml.replace(
        '<hosts up="2" down="1" total="3"/>', '<hosts up="2" down="254" total="256"/>'
    )
    scan = parse_scan(xml_text)

    assert len(scan.hosts) == 3
    assert (scan.hosts_up, scan.hosts_down, scan.hosts_total) == (2, 254, 256)


# ===== Zepsute dane: poprawny XML, ale wartości nie pasują do modeli =====

# Minimalny poprawny wynik nmapa: 1 host z 1 portem.
# Każdy test poniżej psuje w nim jedną rzecz przez .replace(stary_tekst, nowy_tekst)
MINIMAL_SCAN = """<nmaprun args="nmap" start="1792173600" version="7.95">
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host>
<runstats><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"""


def test_minimal_scan_is_valid():
    # Najpierw sprawdzamy, że NIEZEPSUTA wersja przechodzi —
    # inaczej testy poniżej mogłyby przechodzić z zupełnie innego powodu
    scan = parse_scan(MINIMAL_SCAN)

    assert scan.hosts[0].ports[0].port == 22


# Każda para (stary, nowy) psuje jedną wartość; ids= to nazwy przypadków w pytest -v
@pytest.mark.parametrize(
    "old, new",
    [
        ('portid="22"', ""),                                  # brak numeru portu
        ('portid="22"', 'portid="70000"'),                    # port poza zakresem 1–65535
        ('portid="22"', 'portid="ssh"'),                      # nazwa zamiast numeru
        ('<state state="open"/>', '<state state="weird"/>'),  # nieznany stan portu
        ('<state state="open"/>', ""),                        # port bez <state>
        ('protocol="tcp"', 'protocol="icmp"'),                # nieznany protokół
        ('<status state="up"/>', ""),                         # host bez <status>
        ('addr="10.0.0.1"', 'addr="999.0.0.1"'),              # niepoprawny adres IP
        ('version="7.95"', ""),                               # brak wersji nmapa
        ('start="1792173600"', 'start="yesterday"'),          # timestamp, który nie jest liczbą
    ],
    ids=[
        "port-missing-portid",
        "port-out-of-range",
        "port-not-a-number",
        "port-unknown-state",
        "port-missing-state",
        "port-unknown-protocol",
        "host-missing-status",
        "host-invalid-ip",
        "scan-missing-version",
        "scan-start-not-a-number",
    ],
)
def test_malformed_data_is_rejected(old, new):
    broken_xml = MINIMAL_SCAN.replace(old, new)

    # Każde zepsucie kończy się NASZYM wyjątkiem z komunikatem o strukturze danych
    with pytest.raises(NmapParseError, match="Unexpected nmap XML structure"):
        parse_scan(broken_xml)
