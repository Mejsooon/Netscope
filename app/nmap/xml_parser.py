# datetime/timezone — zamiana Unix timestamp z XML na datę w strefie UTC
from datetime import datetime, timezone
# ParseError — błąd składni XML (np. niezamknięty znacznik)
from xml.etree.ElementTree import ParseError

# DefusedXmlException — rzucany, gdy defusedxml wykryje atak (encje, XXE)
from defusedxml import DefusedXmlException
# fromstring z defusedxml zamiast z biblioteki standardowej — bezpieczny parser
from defusedxml.ElementTree import fromstring
# ValidationError — błąd z modeli Pydantic (np. port=0)
from pydantic import ValidationError

from app.core.exceptions import NmapParseError
from app.schemas.scan import ExtraPortsResult, HostResult, PortResult, ScanResult


# Tekst XML z nmapa → ScanResult albo NmapParseError.
# Funkcja czyta XML od góry do dołu, w tej samej kolejności, w jakiej wygląda plik
def parse_scan(xml_text: str) -> ScanResult:
    # ===== 1. TEKST → DRZEWO XML =====
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

    # Od tego miejsca błędy biorą się z DANYCH (np. portid="abc"):
    # modele rzucą ValidationError, a int("abc") rzuci ValueError
    try:
        # ===== 2. HOSTY: każdy <host> → HostResult =====
        hosts = []
        for host in root.findall("host"):

            # --- Stan hosta z <status state="up"> ---
            status = host.find("status")
            # find() zwraca None, gdy elementu nie ma — wtedy stan też jest None
            host_state = status.get("state") if status is not None else None

            # --- Adresy: szukamy PO TYPIE (addrtype), a nie "pierwszego z brzegu" ---
            ip = None
            mac = None
            mac_vendor = None
            for address in host.findall("address"):
                addrtype = address.get("addrtype")
                if addrtype == "ipv4":
                    # IPv4 ma pierwszeństwo — nadpisuje ewentualny wcześniejszy IPv6
                    ip = address.get("addr")
                elif addrtype == "ipv6" and ip is None:
                    # IPv6 bierzemy tylko wtedy, gdy nie ma IPv4
                    ip = address.get("addr")
                elif addrtype == "mac":
                    mac = address.get("addr")
                    mac_vendor = address.get("vendor")    # vendor bywa pusty → None

            # --- Nazwy hosta z <hostnames><hostname name="..."> ---
            hostnames = []
            for hostname in host.findall("hostnames/hostname"):
                name = hostname.get("name")
                # Pomijamy puste nazwy i duplikaty; kolejność zostaje taka jak w XML
                if name and name not in hostnames:
                    hostnames.append(name)

            # --- Porty: każdy <port> → PortResult ---
            # findall() zwraca pustą listę, gdy brak <ports> (host down) — pętla się nie wykona
            ports = []
            for port in host.findall("ports/port"):
                port_state = port.find("state")
                # Port bez <service> (np. 8080 z fixture) → service = None
                service = port.find("service")
                ports.append(
                    PortResult(
                        port=port.get("portid"),          # "22" → Pydantic zrobi int i sprawdzi zakres
                        protocol=port.get("protocol"),
                        state=port_state.get("state") if port_state is not None else None,
                        reason=port_state.get("reason") if port_state is not None else None,
                        service_name=service.get("name") if service is not None else None,
                        product=service.get("product") if service is not None else None,
                        version=service.get("version") if service is not None else None,
                        # w XML "extrainfo", w modelu "extra_info"
                        extra_info=service.get("extrainfo") if service is not None else None,
                    )
                )

            # --- Zgrupowane porty: <extraports state="closed" count="997"> ---
            extra_ports = []
            for extra in host.findall("ports/extraports"):
                extra_ports.append(ExtraPortsResult(state=extra.get("state"), count=extra.get("count")))

            hosts.append(
                HostResult(
                    state=host_state,
                    ip=ip,
                    mac=mac,
                    mac_vendor=mac_vendor,
                    hostnames=hostnames,
                    ports=ports,
                    extra_ports=extra_ports,
                )
            )

        # ===== 3. LICZBY HOSTÓW z <runstats><hosts up=".." down=".." total=".."> =====
        counts = root.find("runstats/hosts")
        if counts is not None:
            # Wartości są tekstem ("2"); Pydantic zamieni je na int
            hosts_up = counts.get("up")
            hosts_down = counts.get("down")
            hosts_total = counts.get("total")
        else:
            # Brak <runstats> (przerwany skan): liczymy sami z listy hostów
            hosts_up = 0
            for host_result in hosts:
                if host_result.state == "up":
                    hosts_up += 1
            hosts_total = len(hosts)
            hosts_down = hosts_total - hosts_up

        # ===== 4. CZASY: Unix timestamp (tekst) → datetime w UTC =====
        started_at = None
        start = root.get("start")                         # <nmaprun start="1792173600">
        if start is not None:
            # int("yesterday") rzuci ValueError → poniżej zamienimy go na NmapParseError
            started_at = datetime.fromtimestamp(int(start), tz=timezone.utc)

        # <runstats><finished time=".." elapsed=".."> — brak, gdy skan przerwany
        finished = root.find("runstats/finished")
        finished_at = None
        elapsed_seconds = None
        if finished is not None:
            elapsed_seconds = finished.get("elapsed")     # "12.34" → Pydantic zrobi float
            finished_time = finished.get("time")
            if finished_time is not None:
                finished_at = datetime.fromtimestamp(int(finished_time), tz=timezone.utc)

        # ===== 5. CAŁOŚĆ → ScanResult =====
        return ScanResult(
            nmap_version=root.get("version"),             # <nmaprun version="7.95">
            args=root.get("args"),                        # <nmaprun args="nmap ...">
            started_at=started_at,
            finished_at=finished_at,
            elapsed_seconds=elapsed_seconds,
            hosts_up=hosts_up,
            hosts_down=hosts_down,
            hosts_total=hosts_total,
            hosts=hosts,
        )

    except (ValidationError, ValueError) as error:
        # Dane nie pasują do modeli albo zły timestamp.
        # "from error" zachowuje oryginalny błąd w traceback — przydatne przy debugowaniu
        raise NmapParseError(f"Unexpected nmap XML structure: {error}") from error
