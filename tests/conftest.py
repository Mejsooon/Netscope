# Path — obiektowa obsługa ścieżek (zamiast sklejania stringów z "/")
from pathlib import Path

import pytest

# Folder tests/fixtures/ liczony od położenia TEGO pliku,
# więc działa niezależnie od miejsca uruchomienia pytest
FIXTURES_DIR = Path(__file__).parent / "fixtures"


# Fixture: zawartość typowego skanu (1 host, 3 porty) jako tekst XML.
# Test dostaje ją, wpisując nazwę jako parametr: def test_x(typical_xml)
@pytest.fixture
def typical_xml() -> str:
    # tests/fixtures/scan_typical.xml → cała zawartość pliku jako str
    # encoding="utf-8" — jawnie, żeby wynik był taki sam na Windows i Linux
    return (FIXTURES_DIR / "scan_typical.xml").read_text(encoding="utf-8")


# Fixture: zawartość skanu z przypadkami brzegowymi (3 hosty, w tym 1 down) jako tekst XML
@pytest.fixture
def edge_cases_xml() -> str:
    # tests/fixtures/scan_edge_cases.xml → cała zawartość pliku jako str
    return (FIXTURES_DIR / "scan_edge_cases.xml").read_text(encoding="utf-8")
