import pytest
from pydantic import ValidationError

from app.schemas.scan import PortResult


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
