from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, model_validator

# Literal = dozwolona jest TYLKO jedna z wymienionych wartości (allowlista na poziomie typu).
# Wartości spoza listy, np. state="hacked", dadzą ValidationError
Protocol = Literal["tcp", "udp", "sctp", "ip"]
# Wszystkie stany portu, jakie nmap może zwrócić (open|filtered to jeden stan, np. przy skanie UDP)
PortState = Literal["open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"]
HostState = Literal["up", "down", "unknown", "skipped"]
# Typy skanu, które użytkownik może wybrać — słowa, NIE flagi nmapa
ScanType = Literal["connect", "syn", "udp", "ping"]

# Wyrażenie regularne dla adresu MAC: 6 par znaków szesnastkowych oddzielonych ":"
# np. AA:BB:CC:11:22:33
MAC_PATTERN = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"


# Wspólna baza dla wszystkich naszych modeli
class NetScopeModel(BaseModel):
    # frozen=True    → obiektu nie da się zmienić po utworzeniu (wynik skanu to fakt historyczny)
    # extra="forbid" → nieznane pole (np. literówka "prot=") to błąd, a nie cicho ignorowana wartość
    model_config = ConfigDict(frozen=True, extra="forbid")


# To, co przychodzi z formularza: jeden skan do wykonania
class ScanRequest(NetScopeModel):
    # Cel skanu: IP, sieć CIDR albo nazwa hosta.
    # Tu sprawdzamy tylko długość (253 = maks. długość nazwy w DNS);
    # czy to POPRAWNY adres, sprawdzi walidator w kroku 3b
    target: str = Field(min_length=1, max_length=253)
    # Typ skanu z listy ScanType; domyślnie connect, bo działa bez roota
    scan_type: ScanType = "connect"
    # Porty jako tekst, np. "22,80,443" albo "1-1000"; None = domyślne porty nmapa.
    # Format sprawdzi walidator w kroku 3b
    ports: str | None = Field(default=None, min_length=1, max_length=200)
    # Wykrywanie wersji usług (-sV)
    service_detection: bool = False
    # Wykrywanie systemu operacyjnego (-O), wymaga roota
    os_detection: bool = False
    # Szybkość skanu: 0 (najwolniej) … 5 (najszybciej); 3 = domyślna w nmapie
    timing: int = Field(default=3, ge=0, le=5)

    # Ping scan (-sn) tylko sprawdza, które hosty żyją — NIE skanuje portów.
    # Porty, wersje usług i wykrywanie systemu nie mają wtedy sensu, więc je odrzucamy
    @model_validator(mode="after")
    def check_ping_scan_options(self) -> "ScanRequest":
        if self.scan_type == "ping" and (self.ports or self.service_detection or self.os_detection):
            raise ValueError("ping scan only discovers hosts: ports, service and OS detection are not allowed")
        return self


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


# Cały skan z <nmaprun>
class ScanResult(NetScopeModel):
    nmap_version: str                     # np. "7.95"
    args: str                             # pełne polecenie nmapa
    started_at: datetime                  # parser zamieni Unix timestamp na datę
    finished_at: datetime | None = None   # None, gdy skan przerwany (brak <finished>)
    elapsed_seconds: float | None = Field(default=None, ge=0)
    hosts_up: int = Field(ge=0)
    hosts_down: int = Field(ge=0)
    hosts_total: int = Field(ge=0)
    hosts: list[HostResult] = Field(default_factory=list)

    # Walidator CAŁEGO obiektu, uruchamiany po sprawdzeniu pojedynczych pól (mode="after").
    # Sprawdza zależność między polami, której nie da się wyrazić typem jednego pola
    @model_validator(mode="after")
    def check_host_counts(self) -> "ScanResult":
        if self.hosts_up + self.hosts_down != self.hosts_total:
            raise ValueError("hosts_up + hosts_down must equal hosts_total")
        return self
