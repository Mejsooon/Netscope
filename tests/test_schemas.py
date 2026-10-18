from datetime import datetime, timezone

import pytest
# ValidationError — błąd, który Pydantic rzuca przy złych danych
from pydantic import ValidationError

from app.schemas.scan import ExtraPortsResult, HostResult, PortResult, ScanResult


# ===== PortResult =====

def test_port_result_minimal():
    # Tylko pola wymagane: numer, protokół, stan
    port = PortResult(port=22, protocol="tcp", state="open")

    assert port.port == 22
    # Pola opcjonalne mają domyślnie None (port bez <service>)
    assert port.service_name is None


def test_port_result_coerces_numeric_string():
    # Z XML wszystko przychodzi jako tekst; Pydantic zamienia "443" na int 443
    port = PortResult(port="443", protocol="tcp", state="open")

    assert port.port == 443


# Poza zakresem 1–65535 → błąd
@pytest.mark.parametrize("value", [0, 65536, -1])
def test_port_result_rejects_out_of_range_port(value):
    with pytest.raises(ValidationError):
        PortResult(port=value, protocol="tcp", state="open")


def test_port_result_rejects_unknown_state():
    # "weird" nie jest na liście PortState (Literal) → błąd
    with pytest.raises(ValidationError):
        PortResult(port=22, protocol="tcp", state="weird")


def test_port_result_rejects_unknown_protocol():
    # "icmp" nie jest na liście Protocol (Literal) → błąd
    with pytest.raises(ValidationError):
        PortResult(port=22, protocol="icmp", state="open")


def test_port_result_forbids_extra_fields():
    # extra="forbid": pole, którego model nie zna (cpe), to błąd
    with pytest.raises(ValidationError):
        PortResult(port=22, protocol="tcp", state="open", cpe="cpe:/a:openbsd:openssh")


def test_port_result_is_frozen():
    port = PortResult(port=22, protocol="tcp", state="open")

    # frozen=True: zmiana pola po utworzeniu obiektu to błąd
    with pytest.raises(ValidationError):
        port.port = 80


# ===== HostResult i ExtraPortsResult =====

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
    host = HostResult(state="up", ip=ip)

    # IPvAnyAddress → str() daje adres jako tekst
    assert str(host.ip) == ip


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
    # Field(ge=0): liczba portów w grupie nie może być ujemna
    with pytest.raises(ValidationError):
        ExtraPortsResult(state="closed", count=-1)


def test_host_result_nests_ports():
    # Modele zagnieżdżają się: host zawiera listy PortResult i ExtraPortsResult
    host = HostResult(
        state="up",
        ports=[PortResult(port=22, protocol="tcp", state="open")],
        extra_ports=[ExtraPortsResult(state="closed", count=997)],
    )

    assert host.ports[0].port == 22
    assert host.extra_ports[0].count == 997


# ===== ScanResult =====

def test_scan_result_minimal():
    # Minimalny skan: 1 host up, bez <finished> (np. przerwany) i bez listy hostów
    scan = ScanResult(
        nmap_version="7.95",
        args="nmap -sT 192.168.1.1",
        started_at=datetime(2026, 10, 16, 18, 0, tzinfo=timezone.utc),
        hosts_up=1,
        hosts_down=0,
        hosts_total=1,
    )

    assert scan.finished_at is None
    assert scan.hosts == []


def test_scan_result_rejects_inconsistent_host_counts():
    # model_validator: 2 + 0 != 3 → błąd z naszym komunikatem
    with pytest.raises(ValidationError, match="must equal hosts_total"):
        ScanResult(
            nmap_version="7.95",
            args="nmap -sT 192.168.1.1",
            started_at=datetime(2026, 10, 16, 18, 0, tzinfo=timezone.utc),
            hosts_up=2,
            hosts_down=0,
            hosts_total=3,
        )


def test_scan_result_rejects_negative_elapsed_time():
    # Field(ge=0): czas trwania nie może być ujemny
    with pytest.raises(ValidationError):
        ScanResult(
            nmap_version="7.95",
            args="nmap -sT 192.168.1.1",
            started_at=datetime(2026, 10, 16, 18, 0, tzinfo=timezone.utc),
            elapsed_seconds=-1,
            hosts_up=1,
            hosts_down=0,
            hosts_total=1,
        )


def test_scan_result_serializes_to_json_types():
    scan = ScanResult(
        nmap_version="7.95",
        args="nmap -sT 192.168.1.1",
        started_at=datetime(2026, 10, 16, 18, 0, tzinfo=timezone.utc),
        hosts_up=1,
        hosts_down=0,
        hosts_total=1,
        hosts=[
            HostResult(
                state="up",
                ip="192.168.1.1",
                ports=[PortResult(port=22, protocol="tcp", state="open")],
            )
        ],
    )

    # model_dump(mode="json") zamienia obiekty na typy JSON (tak wyśle je API w kroku 4):
    # datetime → tekst ISO 8601, IPvAnyAddress → tekst
    data = scan.model_dump(mode="json")

    assert data["started_at"] == "2026-10-16T18:00:00Z"
    assert data["hosts"][0]["ip"] == "192.168.1.1"
    assert data["hosts"][0]["ports"][0]["port"] == 22
