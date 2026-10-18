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


# Bazowa klasa błędów w danych, które przysłał UŻYTKOWNIK (formularz).
# API w kroku 4 zamieni ją na odpowiedź 400 Bad Request — "popraw dane i spróbuj ponownie"
class InvalidScanRequestError(NetScopeError):
    """Base class for errors in user-supplied scan parameters."""


# Cel skanu nie jest poprawnym adresem IP, siecią CIDR ani nazwą hosta (krok 3b)
class InvalidTargetError(InvalidScanRequestError):
    """Raised when the scan target is not a valid IP address, network or hostname."""


# Lista portów jest źle zapisana albo wychodzi poza zakres 1–65535 (krok 3b)
class InvalidPortsError(InvalidScanRequestError):
    """Raised when the port specification is malformed or out of range."""


# Wybrana opcja wymaga uprawnień roota/administratora, których aplikacja nie ma (krok 3c)
class InsufficientPrivilegesError(InvalidScanRequestError):
    """Raised when a selected option needs root/administrator rights."""
