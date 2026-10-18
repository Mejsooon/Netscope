from app.core.exceptions import (
    InsufficientPrivilegesError,
    InvalidPortsError,
    InvalidScanRequestError,
    InvalidTargetError,
    NetScopeError,
    NmapParseError,
)


def test_parse_error_is_a_netscope_error():
    # Hierarchia: każdy nasz wyjątek dziedziczy po NetScopeError,
    # więc jedno "except NetScopeError" łapie też NmapParseError
    assert issubclass(NmapParseError, NetScopeError)
    # A NetScopeError to zwykły wyjątek Pythona
    assert issubclass(NetScopeError, Exception)


def test_scan_request_errors_share_one_base():
    # Wszystkie błędy danych od użytkownika dziedziczą po InvalidScanRequestError,
    # więc API złapie je jednym "except" i zwróci 400 Bad Request
    assert issubclass(InvalidTargetError, InvalidScanRequestError)
    assert issubclass(InvalidPortsError, InvalidScanRequestError)
    assert issubclass(InsufficientPrivilegesError, InvalidScanRequestError)
    # A sam InvalidScanRequestError to nasz wyjątek aplikacji
    assert issubclass(InvalidScanRequestError, NetScopeError)


def test_parse_error_is_not_a_scan_request_error():
    # Zły XML z nmapa to NASZ problem, a nie błąd użytkownika — te dwie gałęzie są rozdzielone
    assert not issubclass(NmapParseError, InvalidScanRequestError)
