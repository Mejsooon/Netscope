# get_args — wyciąga listę wartości z typu Literal, np. ("connect", "syn", "udp", "ping")
from typing import get_args

from app.nmap.options_catalog import (
    OS_DETECTION_FLAG,
    ROOT_ONLY_FLAGS,
    SCAN_TYPE_FLAGS,
    SERVICE_DETECTION_FLAG,
    TIMING_FLAGS,
    XML_OUTPUT_ARGS,
)
from app.schemas.scan import ScanType


def test_every_scan_type_in_schema_has_a_flag():
    # Model ScanRequest i katalog muszą znać DOKŁADNIE te same typy skanu.
    # Dopiszesz "fin" do ScanType i zapomnisz o katalogu → ten test to wyłapie
    assert set(get_args(ScanType)) == set(SCAN_TYPE_FLAGS)


def test_timing_flags_match_model_range():
    # ScanRequest przyjmuje timing od 0 do 5 — katalog musi mieć flagę dla każdej liczby
    assert set(TIMING_FLAGS) == {0, 1, 2, 3, 4, 5}


def test_root_only_flags():
    # Tylko te trzy opcje potrzebują roota/administratora
    assert ROOT_ONLY_FLAGS == {"-sS", "-sU", "-O"}


def test_every_flag_is_one_token():
    # Wszystkie flagi z katalogu w jednej liście
    all_flags = list(SCAN_TYPE_FLAGS.values()) + list(TIMING_FLAGS.values())
    all_flags.append(SERVICE_DETECTION_FLAG)
    all_flags.append(OS_DETECTION_FLAG)

    for flag in all_flags:
        # Każda flaga zaczyna się od "-" ...
        assert flag.startswith("-")
        # ... i jest JEDNYM argumentem: bez spacji i bez "=" (nie da się w niej ukryć wartości)
        assert " " not in flag
        assert "=" not in flag


def test_xml_output_goes_to_stdout():
    # "-oX -" = XML na standardowe wyjście, które runner przekaże do parsera
    assert XML_OUTPUT_ARGS == ["-oX", "-"]
