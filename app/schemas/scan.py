from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Literal = dozwolona jest TYLKO jedna z wymienionych wartości (allowlista na poziomie typu).
# Wartości spoza listy, np. state="hacked", dadzą ValidationError
Protocol = Literal["tcp", "udp", "sctp", "ip"]
# Wszystkie stany portu, jakie nmap może zwrócić (open|filtered to jeden stan, np. przy skanie UDP)
PortState = Literal["open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"]


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
