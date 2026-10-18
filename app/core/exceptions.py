# Bazowa klasa WSZYSTKICH błędów naszej aplikacji.
# Dzięki niej API w kroku 4 może jednym "except NetScopeError" złapać każdy nasz błąd
# i zamienić go na sensowną odpowiedź HTTP, a nie na 500 Internal Server Error
class NetScopeError(Exception):
    """Base class for all NetScope application errors."""


# Konkretny błąd: XML z nmapa nie dał się zamienić na ScanResult.
# Parser opakowuje w niego surowe błędy bibliotek (ParseError, ValidationError...),
# więc reszta aplikacji nie musi wiedzieć, jakich bibliotek parser używa w środku
class NmapParseError(NetScopeError):
    """Raised when nmap XML output cannot be turned into a ScanResult."""
