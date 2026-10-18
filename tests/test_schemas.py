from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.scan import ExtraPortsResult, HostResult, PortResult, ScanResult


# Pomocnik: poprawny port z minimalnymi danymi; overrides podmienia wybrane pola,
# więc każdy test zmienia tylko to, co sprawdza
def make_port(**overrides) -> PortResult:
    data = {"port": 22, "protocol": "tcp", "state": "open"}
    data.update(overrides)
    return PortResult(**data)


def test_port_result_minimal():
    port = make_port()

    assert port.port == 22
    # Pola opcjonalne mają domyślnie None (port bez <service>)
    assert port.service_name is None


def test_port_result_coerces_numeric_string():
    # Z XML wszystko przychodzi jako tekst; Pydantic zamienia "443" na int 443
    assert make_port(port="443").port == 443


# Poza zakresem 1–65535 → błąd
@pytest.mark.parametrize("value", [0, 65536, -1])
def test_port_result_rejects_out_of_range_port(value):
    with pytest.raises(ValidationError):
        make_port(port=value)


# Wartości spoza Literal (stan portu, protokół) → błąd
@pytest.mark.parametrize("field, value", [("state", "weird"), ("protocol", "icmp")])
def test_port_result_rejects_unknown_literals(field, value):
    with pytest.raises(ValidationError):
        make_port(**{field: value})


def test_port_result_forbids_extra_fields():
    # extra="forbid": pole, którego model nie zna, to błąd
    with pytest.raises(ValidationError):
        make_port(cpe="cpe:/a:openbsd:openssh")


def test_port_result_is_frozen():
    port = make_port()

    # frozen=True: zmiana pola po utworzeniu obiektu to błąd
    with pytest.raises(ValidationError):
        port.port = 80


def test_host_result_defaults_to_empty_collections():
    # Host down z fixture: znamy tylko stan, reszta ma rozsądne wartości domyślne
    host = HostResult(state="down")

    assert host.ip is None
    assert host.hostnames == []
    assert host.ports == []
    assert host.extra_ports == []


def test_host_results_do_not_share_lists():
    # default_factory=list: każdy host ma WŁASNĄ listę, a nie jedną wspólną
    first = HostResult(state="up")
    second = HostResult(state="up")

    assert first.ports is not second.ports


# Pydantic przyjmuje IPv4 i IPv6
@pytest.mark.parametrize("ip", ["192.168.1.1", "2001:db8::1"])
def test_host_result_accepts_ipv4_and_ipv6(ip):
    assert str(HostResult(state="up", ip=ip).ip) == ip


# Zły adres, nazwa hosta zamiast IP, sieć CIDR zamiast pojedynczego adresu → błąd
@pytest.mark.parametrize("ip", ["999.1.1.1", "router.lan", "192.168.1.0/24"])
def test_host_result_rejects_invalid_ip(ip):
    with pytest.raises(ValidationError):
        HostResult(state="up", ip=ip)


# Za krótki MAC, myślniki zamiast dwukropków, znak spoza 0-9/A-F → błąd
@pytest.mark.parametrize("mac", ["AA:BB:CC:11:22", "AA-BB-CC-11-22-33", "GG:BB:CC:11:22:33"])
def test_host_result_rejects_invalid_mac(mac):
    with pytest.raises(ValidationError):
        HostResult(state="up", mac=mac)


def test_extra_ports_rejects_negative_count():
    with pytest.raises(ValidationError):
        ExtraPortsResult(state="closed", count=-1)


def test_host_result_nests_ports():
    # Modele zagnieżdżają się: host zawiera listy PortResult i ExtraPortsResult
    host = HostResult(
        state="up",
        ports=[make_port()],
        extra_ports=[ExtraPortsResult(state="closed", count=997)],
    )

    assert host.ports[0].port == 22
    assert host.extra_ports[0].count == 997


# Pomocnik: poprawny, minimalny wynik skanu (1 host up)
def make_scan(**overrides) -> ScanResult:
    data = {
        "nmap_version": "7.95",
        "args": "nmap -sT 192.168.1.1",
        "started_at": datetime(2026, 10, 16, 18, 0, tzinfo=timezone.utc),
        "hosts_up": 1,
        "hosts_down": 0,
        "hosts_total": 1,
    }
    data.update(overrides)
    return ScanResult(**data)


def test_scan_result_minimal():
    scan = make_scan()

    # Skan bez <finished> (np. przerwany) i bez hostów jest poprawny
    assert scan.finished_at is None
    assert scan.hosts == []


def test_scan_result_rejects_inconsistent_host_counts():
    # model_validator: 2 + 0 != 3 → błąd z naszym komunikatem
    with pytest.raises(ValidationError, match="must equal hosts_total"):
        make_scan(hosts_up=2, hosts_down=0, hosts_total=3)


def test_scan_result_rejects_negative_elapsed_time():
    with pytest.raises(ValidationError):
        make_scan(elapsed_seconds=-1)


def test_scan_result_serializes_to_json_types():
    scan = make_scan(hosts=[HostResult(state="up", ip="192.168.1.1", ports=[make_port()])])

    # model_dump(mode="json") zamienia obiekty na typy JSON (tak wyśle je API w kroku 4):
    # datetime → tekst ISO 8601, IPvAnyAddress → tekst
    data = scan.model_dump(mode="json")

    assert data["started_at"] == "2026-10-16T18:00:00Z"
    assert data["hosts"][0]["ip"] == "192.168.1.1"
    assert data["hosts"][0]["ports"][0]["port"] == 22
