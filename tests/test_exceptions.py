from app.core.exceptions import NetScopeError, NmapParseError


def test_parse_error_is_a_netscope_error():
    # Hierarchia: każdy nasz wyjątek dziedziczy po NetScopeError,
    # więc jedno "except NetScopeError" łapie też NmapParseError
    assert issubclass(NmapParseError, NetScopeError)
    # A NetScopeError to zwykły wyjątek Pythona
    assert issubclass(NetScopeError, Exception)
