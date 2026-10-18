import pytest
# ValidationError — błąd, który Pydantic rzuca przy złych danych
from pydantic import ValidationError

from app.schemas.scan import ScanRequest


def test_scan_request_defaults():
    # Wystarczy podać cel — reszta ma bezpieczne wartości domyślne
    request = ScanRequest(target="192.168.1.1")

    assert request.scan_type == "connect"     # działa bez roota
    assert request.ports is None              # domyślne porty nmapa
    assert request.service_detection is False
    assert request.os_detection is False
    assert request.timing == 3                # domyślna szybkość nmapa


def test_scan_request_from_form_json():
    # Tak będą wyglądały dane z formularza w kroku 4/5 (słownik z JSON)
    request = ScanRequest.model_validate(
        {
            "target": "192.168.1.0/24",
            "scan_type": "syn",
            "ports": "22,80,443",
            "service_detection": True,
            "timing": 4,
        }
    )

    assert request.scan_type == "syn"
    assert request.ports == "22,80,443"
    assert request.timing == 4


# Pusty cel albo dłuższy niż 253 znaki → błąd
@pytest.mark.parametrize("target", ["", "a" * 254])
def test_scan_request_rejects_invalid_target_length(target):
    with pytest.raises(ValidationError):
        ScanRequest(target=target)


# Flaga zamiast słowa ("-sS") albo słowo spoza listy → błąd
@pytest.mark.parametrize("scan_type", ["-sS", "aggressive"])
def test_scan_request_rejects_unknown_scan_type(scan_type):
    with pytest.raises(ValidationError):
        ScanRequest(target="192.168.1.1", scan_type=scan_type)


# Szybkość spoza zakresu 0–5 → błąd
@pytest.mark.parametrize("timing", [6, -1])
def test_scan_request_rejects_timing_out_of_range(timing):
    with pytest.raises(ValidationError):
        ScanRequest(target="192.168.1.1", timing=timing)


def test_scan_request_rejects_empty_ports():
    # Pusty tekst portów jest błędem; "brak portów" zapisujemy jako None
    with pytest.raises(ValidationError):
        ScanRequest(target="192.168.1.1", ports="")


def test_scan_request_rejects_unknown_fields():
    # extra="forbid": NIE da się przemycić surowych argumentów dla nmapa
    with pytest.raises(ValidationError):
        ScanRequest(target="192.168.1.1", extra_args="--script=vuln")


# ===== Ping scan: tylko wykrywanie hostów =====

def test_ping_scan_alone_is_valid():
    # Sam ping scan (bez opcji portów) jest poprawny
    request = ScanRequest(target="192.168.1.0/24", scan_type="ping")

    assert request.scan_type == "ping"


def test_ping_scan_rejects_ports():
    # model_validator: ping scan nie skanuje portów, więc lista portów nie ma sensu
    with pytest.raises(ValidationError, match="ping scan only discovers hosts"):
        ScanRequest(target="192.168.1.0/24", scan_type="ping", ports="22")


def test_ping_scan_rejects_service_detection():
    # -sV potrzebuje otwartych portów, a ping scan ich nie szuka
    with pytest.raises(ValidationError, match="ping scan only discovers hosts"):
        ScanRequest(target="192.168.1.0/24", scan_type="ping", service_detection=True)


def test_ping_scan_rejects_os_detection():
    # -O też potrzebuje wyników skanu portów
    with pytest.raises(ValidationError, match="ping scan only discovers hosts"):
        ScanRequest(target="192.168.1.0/24", scan_type="ping", os_detection=True)
