import pytest
# DefusedXmlException — wyjątek z defusedxml; sprawdzamy, że to on był przyczyną błędu
from defusedxml import DefusedXmlException

from app.core.exceptions import NmapParseError
from app.nmap.xml_parser import parse_scan


# "Billion laughs": każda encja rozwija się w 10 kopii poprzedniej.
# lol4 = 10 × 10 × 10 × "lol" = 1000 kopii; prawdziwy atak ma ~10 poziomów
# i rozrasta się do miliardów kopii, zjadając całą pamięć RAM
BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<nmaprun args="&lol4;"/>"""

# XXE (XML External Entity): encja wskazuje na plik z dysku.
# Niezabezpieczony parser wstawiłby zawartość /etc/passwd do atrybutu args,
# a aplikacja pokazałaby ją w GUI — wyciek pliku z komputera użytkownika
EXTERNAL_ENTITY = """<?xml version="1.0"?>
<!DOCTYPE nmaprun [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<nmaprun args="&xxe;"/>"""

# Zwykły <!DOCTYPE nmaprun> BEZ encji — dokładnie tak zaczyna się prawdziwy wynik nmapa
PLAIN_DOCTYPE = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun args="nmap" start="1792173600" version="7.95">
<runstats><hosts up="0" down="0" total="0"/></runstats>
</nmaprun>"""


# Oba ataki muszą skończyć się NmapParseError z komunikatem o zakazanych konstrukcjach.
# ids= nadaje czytelne nazwy przypadkom w wyniku pytest -v
@pytest.mark.parametrize("xml_text", [BILLION_LAUGHS, EXTERNAL_ENTITY], ids=["billion-laughs", "xxe"])
def test_entity_attacks_are_blocked(xml_text):
    with pytest.raises(NmapParseError, match="forbidden constructs") as excinfo:
        parse_scan(xml_text)

    # Przyczyną jest blokada w defusedxml, a nie przypadkowy inny błąd
    assert isinstance(excinfo.value.__cause__, DefusedXmlException)


def test_plain_doctype_from_nmap_is_still_accepted():
    # Ochrona nie może blokować normalnego wyniku nmapa
    scan = parse_scan(PLAIN_DOCTYPE)

    assert scan.hosts_total == 0
