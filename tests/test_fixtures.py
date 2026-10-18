import pytest

# Bezpieczny parser XML (ten sam, którego użyje aplikacja): blokuje XXE i "billion laughs"
from defusedxml.ElementTree import fromstring


# Ten sam test uruchamia się 2 razy: raz z typical_xml, raz z edge_cases_xml.
# Parametr to nazwa FIXTURE, a nie nazwa pliku
@pytest.mark.parametrize("fixture_name", ["typical_xml", "edge_cases_xml"])
def test_fixture_is_valid_nmap_xml(request, fixture_name):
    # request — wbudowana fixture pytest; getfixturevalue uruchamia fixture o podanej nazwie
    xml_text = request.getfixturevalue(fixture_name)
    # Parsowanie tekstu; uszkodzony XML rzuci wyjątek i test będzie czerwony
    root = fromstring(xml_text)

    # Korzeń dokumentu to <nmaprun>, jak w prawdziwym wyjściu nmapa
    assert root.tag == "nmaprun"
    # Skan zakończył się poprawnie: <runstats><finished exit="success">
    assert root.find("runstats/finished").get("exit") == "success"


def test_typical_has_one_host_with_three_ports(typical_xml):
    root = fromstring(typical_xml)
    # Wszystkie bezpośrednie elementy <host> pod <nmaprun>
    hosts = root.findall("host")

    # Dokładnie jeden host
    assert len(hosts) == 1
    # Z trzema portami: 22, 80, 443
    assert len(hosts[0].findall("ports/port")) == 3


def test_edge_cases_cover_expected_situations(edge_cases_xml):
    root = fromstring(edge_cases_xml)
    hosts = root.findall("host")

    # Stan każdego hosta po kolei: .1 up, .2 down, .3 up
    states = [host.find("status").get("state") for host in hosts]
    assert states == ["up", "down", "up"]

    # Porty hosta 1 jako słownik {numer portu: stan}, np. {"22": "open", "80": "filtered", ...}
    first_host_ports = hosts[0].findall("ports/port")
    port_states = {p.get("portid"): p.find("state").get("state") for p in first_host_ports}
    # Jest port filtered
    assert port_states["80"] == "filtered"
    # Jest co najmniej jeden port bez elementu <service> (port 8080)
    assert any(p.find("service") is None for p in first_host_ports)

    # Host 1 ma dwa adresy w tej kolejności: IPv4 i MAC
    address_types = [a.get("addrtype") for a in hosts[0].findall("address")]
    assert address_types == ["ipv4", "mac"]

    # Host 2 (down) w ogóle nie ma sekcji <ports>
    assert hosts[1].find("ports") is None
    # Host 3 ma sekcję <ports>, ale bez żadnego <port>...
    assert hosts[2].findall("ports/port") == []
    # ...tylko zgrupowane <extraports> ze stanem filtered
    assert hosts[2].find("ports/extraports").get("state") == "filtered"


def test_edge_cases_runstats_match_hosts(edge_cases_xml):
    root = fromstring(edge_cases_xml)
    # <runstats><hosts up=".." down=".." total=".."/>
    stats = root.find("runstats/hosts")

    # Podsumowanie zgadza się z faktyczną liczbą elementów <host>
    assert int(stats.get("total")) == len(root.findall("host"))
    # 2 hosty aktywne i 1 nieaktywny
    assert int(stats.get("up")) == 2
    assert int(stats.get("down")) == 1
