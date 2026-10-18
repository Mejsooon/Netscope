# Katalog opcji nmapa = ALLOWLISTA.
# Builder (krok 3c) może użyć TYLKO flag z tego pliku — innych nie da się dodać do polecenia.

# Typ skanu wybrany w formularzu → flaga nmapa
SCAN_TYPE_FLAGS = {
    "connect": "-sT",   # pełne połączenie TCP; działa bez roota
    "syn": "-sS",       # półotwarte połączenie; szybsze, wymaga roota
    "udp": "-sU",       # skan UDP; wolny, wymaga roota
    "ping": "-sn",      # tylko wykrywanie hostów, bez skanowania portów
}

# Wykrywanie wersji usług na otwartych portach
SERVICE_DETECTION_FLAG = "-sV"

# Wykrywanie systemu operacyjnego
OS_DETECTION_FLAG = "-O"

# Szablon szybkości: liczba z formularza → flaga
TIMING_FLAGS = {
    0: "-T0",   # paranoid: jedna próba co 5 minut
    1: "-T1",   # sneaky: jedna próba co 15 sekund
    2: "-T2",   # polite: zwalnia, żeby mniej obciążać sieć
    3: "-T3",   # normal: domyślne ustawienie nmapa
    4: "-T4",   # aggressive: szybciej, zakłada stabilną sieć
    5: "-T5",   # insane: bardzo szybko; może gubić porty albo przeciążyć urządzenia
}

# Flagi, które wymagają uprawnień roota/administratora (surowe gniazda sieciowe).
# Builder w kroku 3c odrzuci je, gdy aplikacja nie ma tych uprawnień
ROOT_ONLY_FLAGS = {"-sS", "-sU", "-O"}

# Wynik zawsze jako XML na standardowe wyjście — to czyta parser z kroku 2
XML_OUTPUT_ARGS = ["-oX", "-"]
