# NetScope — nmap GUI

Lokalna aplikacja (FastAPI + przeglądarka), która dodaje interaktywne GUI do nmapa.

- **SOFT** — użytkownik wybiera opcje w formularzu i dostaje czytelną tabelę wyników
- **PRO** — dodatkowo silnik reguł ostrzeżeń i agent AI, który dobiera parametry i tłumaczy wyniki

## Status

Krok 1 z 8 — struktura projektu i dane testowe dla parsera XML.

| Krok | Moduł | Status |
|---|---|---|
| 1 | Parser XML | w trakcie |
| 2 | Builder (allowlista + walidacja) | — |
| 3 | Runner (subprocess) | — |
| 4 | API | — |
| 5 | Frontend | — |
| 6 | Reguły ostrzeżeń | — |
| 7 | AI | — |
| 8 | Desktop | — |

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
