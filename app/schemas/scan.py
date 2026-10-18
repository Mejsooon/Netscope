from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

# Literal = dozwolona jest TYLKO jedna z wymienionych wartości (allowlista na poziomie typu).
# Wartości spoza listy, np. state="hacked", dadzą ValidationError
Protocol = Literal["tcp", "udp", "sctp", "ip"]
# Wszystkie stany portu, jakie nmap może zwrócić (open|filtered to jeden stan, np. przy skanie UDP)
PortState = Literal["open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"]
HostState = Literal["up", "down", "unknown", "skipped"]

# Wyrażenie regularne dla adresu MAC: 6 par znaków szesnastkowych oddzielonych ":"
# np. AA:BB:CC:11:22:33
MAC_PATTERN = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"


# Wspólna baza dla wszystkich naszych modeli
class NetScopeModel(BaseModel):
    # frozen=True    → obiektu nie da się zmienić po utworzeniu (wynik skanu to fakt historyczny)
    # extra="forbid" → nieznane pole (np. literówka "prot=") to błąd, a nie cicho ignorowana wartość
    model_config = ConfigDict(frozen=True, extra="forbid")


# Jeden port z <port>
class PortResult(NetScopeModel):
    port: int = Field(ge=1, le=65535)     # ge = >=, le = <=; port 0 i 70000 zostaną odrzucone
    protocol: Protocol                    # tcp / udp / sctp / ip
    state: PortState                      # open / closed / filtered...
    reason: str | None = None             # np. "syn-ack"; "| None = None" = pole opcjonalne
    service_name: str | None = None       # None, gdy brak <service> (port 8080 z fixture)
    product: str | None = None            # None, gdy usługa tylko zgadnięta z tabeli
    version: str | None = None
    extra_info: str | None = None


# Podsumowanie z <extraports>, np. "997 portów closed"
class ExtraPortsResult(NetScopeModel):
    state: PortState
    count: int = Field(ge=0)              # liczba nie może być ujemna


# Jeden host z <host>
class HostResult(NetScopeModel):
    state: HostState
    ip: IPvAnyAddress | None = None       # Pydantic sprawdza, że to poprawny IPv4 albo IPv6
    mac: str | None = Field(default=None, pattern=MAC_PATTERN)   # musi pasować do wzorca MAC
    mac_vendor: str | None = None         # producent karty (nie zawsze jest)
    # default_factory=list → każdy obiekt dostaje WŁASNĄ pustą listę.
    # (Wspólna lista "= []" to klasyczna pułapka w Pythonie)
    hostnames: list[str] = Field(default_factory=list)
    ports: list[PortResult] = Field(default_factory=list)          # host down → pusta lista
    extra_ports: list[ExtraPortsResult] = Field(default_factory=list)
