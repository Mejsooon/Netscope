# NetScope — nmap GUI

Lokalna aplikacja (FastAPI + przeglądarka), która dodaje interaktywne GUI do nmapa.

- **SOFT** — użytkownik wybiera opcje w formularzu i dostaje czytelną tabelę wyników
- **PRO** — dodatkowo silnik reguł ostrzeżeń i agent AI, który dobiera parametry i tłumaczy wyniki

## Status

Krok 1 z 8 gotowy — parser XML z modelami danych i testami.

| Krok | Moduł | Status |
|---|---|---|
| 1 | Parser XML | gotowe |
| 2 | Builder (allowlista + walidacja) | — |
| 3 | Runner (subprocess) | — |
| 4 | API | — |
| 5 | Frontend | — |
| 6 | Reguły ostrzeżeń | — |
| 7 | AI | — |
| 8 | Desktop | — |

## Parser XML

`parse_scan()` zamienia wynik nmapa w formacie XML (`nmap -oX -`) na obiekt `ScanResult`:

```python
from app.nmap.xml_parser import parse_scan

scan = parse_scan(xml_text)
for host in scan.hosts:
    print(host.ip, host.state, [port.port for port in host.ports])
```

Każdy błąd — uszkodzony XML, złośliwe encje (XXE, billion laughs) albo dane, które nie pasują do modeli — kończy się wyjątkiem `NmapParseError`. XML jest czytany przez `defusedxml`.

## Uruchomienie testów

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest
```

Testy nie wymagają nmapa ani dostępu do sieci — parser jest testowany na zapisanych wynikach w `tests/fixtures/`.

## Zasady

Skanuj wyłącznie systemy, do których masz uprawnienia, albo serwer testowy `scanme.nmap.org` udostępniony przez twórców nmapa.
