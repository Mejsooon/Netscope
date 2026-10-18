# datetime/timezone — zamiana Unix timestamp z XML na datę w strefie UTC
from datetime import datetime, timezone
# Element — typ węzła drzewa XML; ParseError — błąd składni XML (np. niezamknięty znacznik)
from xml.etree.ElementTree import Element, ParseError

# DefusedXmlException — rzucany, gdy defusedxml wykryje atak (encje, XXE)
from defusedxml import DefusedXmlException
# fromstring z defusedxml zamiast z biblioteki standardowej — bezpieczny parser
from defusedxml.ElementTree import fromstring
# ValidationError — błąd z modeli Pydantic (np. port=0)
from pydantic import ValidationError

from app.core.exceptions import NmapParseError
from app.schemas.scan import HostResult, ScanResult


# JEDYNA publiczna funkcja modułu: tekst XML z nmapa → ScanResult albo NmapParseError
def parse_scan(xml_text: str) -> ScanResult:
    # Krok 1: tekst → drzewo XML (tu łapiemy zły XML i ataki)
    root = _parse_root(xml_text)
    try:
        # Krok 2: każdy <host> → HostResult
        hosts = [_parse_host(host) for host in root.findall("host")]
        # Krok 3: całość → ScanResult
        return _build_scan_result(root, hosts)
    except (ValidationError, ValueError) as error:
        # Dane nie pasują do modeli (np. port="abc") albo zły timestamp.
        # "from error" zachowuje oryginalny błąd w traceback — przydatne przy debugowaniu
        raise NmapParseError(f"Unexpected nmap XML structure: {error}") from error


# Tekst → korzeń drzewa XML. Wszystkie błędy zamienia na NmapParseError
def _parse_root(xml_text: str) -> Element:
    try:
        root = fromstring(xml_text)
    except DefusedXmlException as error:
        # XML zawiera encje lub odwołania zewnętrzne — możliwy atak (XXE, billion laughs)
        raise NmapParseError("XML contains forbidden constructs (entities or external references)") from error
    except ParseError as error:
        # Uszkodzony XML, np. "<nmaprun><host>" bez zamknięcia
        raise NmapParseError(f"Invalid XML: {error}") from error

    # Poprawny XML, ale nie z nmapa (np. inny dokument)
    if root.tag != "nmaprun":
        raise NmapParseError(f"Expected <nmaprun> root element, got <{root.tag}>")
    return root


# Składa ScanResult z atrybutów <nmaprun> i <runstats> oraz listy hostów
def _build_scan_result(root: Element, hosts: list[HostResult]) -> ScanResult:
    hosts_up, hosts_down, hosts_total = _host_counts(root, hosts)
    return ScanResult(
        nmap_version=root.get("version"),                                  # <nmaprun version="7.95">
        args=root.get("args"),                                             # <nmaprun args="nmap ...">
        started_at=_timestamp(root.get("start")),                          # <nmaprun start="1792173600">
        finished_at=_timestamp(_attr(root, "runstats/finished", "time")),  # None, gdy skan przerwany
        elapsed_seconds=_attr(root, "runstats/finished", "elapsed"),       # "12.34" → Pydantic zrobi float
        hosts_up=hosts_up,
        hosts_down=hosts_down,
        hosts_total=hosts_total,
        hosts=hosts,
    )


# Liczby hostów z <runstats><hosts up=".." down=".." total="..">
def _host_counts(root: Element, hosts: list[HostResult]) -> tuple:
    # Wartości są tekstem ("2"); Pydantic zamieni je na int.
    # Brak <runstats> da None → ValidationError (obsłużymy to w osobnym commicie)
    return (
        _attr(root, "runstats/hosts", "up"),
        _attr(root, "runstats/hosts", "down"),
        _attr(root, "runstats/hosts", "total"),
    )


# Jeden <host> → HostResult
def _parse_host(host: Element) -> HostResult:
    # Słownik {addrtype: element}, np. {"ipv4": <address>, "mac": <address>}.
    # Szukamy adresu PO TYPIE, a nie "pierwszego z brzegu" (przypadek brzegowy z fixture)
    addresses = {address.get("addrtype"): address for address in host.findall("address")}

    # IP: najpierw IPv4, a jeśli go nie ma — IPv6
    ip_element = addresses.get("ipv4")
    if ip_element is None:
        ip_element = addresses.get("ipv6")
    mac_element = addresses.get("mac")

    return HostResult(
        state=_attr(host, "status", "state"),                                    # <status state="up">
        ip=ip_element.get("addr") if ip_element is not None else None,
        mac=mac_element.get("addr") if mac_element is not None else None,
        mac_vendor=mac_element.get("vendor") if mac_element is not None else None,  # vendor bywa pusty
    )


# Bezpieczne czytanie atrybutu dziecka: element.find(path).get(name),
# ale zwraca None, gdy dziecka nie ma (zamiast wywracać się na None.get)
def _attr(element: Element, path: str, name: str) -> str | None:
    child = element.find(path)
    return child.get(name) if child is not None else None


# Unix timestamp jako tekst → datetime w UTC; None przechodzi dalej jako None
def _timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    # int("abc") rzuci ValueError → parse_scan zamieni go na NmapParseError
    return datetime.fromtimestamp(int(value), tz=timezone.utc)
