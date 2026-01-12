# SecureMail Project

SecureMail to prototyp bezpiecznego systemu pocztowego napisanego w Pythonie (Flask), skupiający się na bezpieczeństwie, prywatności i szyfrowaniu typu "Zero-Knowledge" (serwer nie ma dostępu do treści wiadomości).

## 🏗️ Architektura i Przepływ Danych

Aplikacja składa się z następujących modułów współpracujących ze sobą:

1.  **Frontend (Jinja2 Templates)**: Warstwa prezentacji wykorzystująca framework CSS **Bulma**. Formularze są obsługiwane przez **Flask-WTF** z ochroną CSRF oraz Content-Security-Policy (CSP).
2.  **Backend (Flask)**:
    * `app.py`: Punkt wejściowy aplikacji, konfiguracja nagłówków bezpieczeństwa i inicjalizacja.
    * `auth_routes.py`: Logika biznesowa uwierzytelniania (Rejestracja, Logowanie, 2FA, Reset hasła).
    * `message_routes.py`: Logika szyfrowania, wysyłania, odbierania i weryfikacji wiadomości.
    * `crypto.py`: Silnik kryptograficzny. Obsługuje haszowanie haseł (Argon2), generowanie kluczy RSA/AES, podpisy cyfrowe i szyfrowanie hybrydowe.
    * `models.py`: Modele bazy danych (SQLAlchemy) odwzorowujące strukturę tabel.
    * `forms.py`: Definicje formularzy i walidacja danych wejściowych (RegEx, Allowlisting).
3.  **Baza Danych (MS SQL Server)**: Przechowuje zaszyfrowane dane użytkowników i wiadomości. Działa w kontenerze Docker.
4.  **Reverse Proxy (Nginx)**: Obsługuje ruch przychodzący, terminację SSL/TLS i przekazuje go do aplikacji Flask.

## 🔐 Szczegóły Kryptograficzne i Model Bezpieczeństwa

Aplikacja implementuje architekturę **Zero-Knowledge** (brak wiedzy serwera). Oznacza to, że administrator bazy danych nie jest w stanie odczytać wiadomości użytkowników, ponieważ nie posiada kluczy deszyfrujących (są one chronione hasłami użytkowników).

### 1. Szyfrowanie Wiadomości (Model Hybrydowy - "Cyfrowa Koperta")
Ze względu na wydajność i ograniczenia rozmiaru danych w kryptografii asymetrycznej (RSA), stosujemy model hybrydowy (podobny do PGP/GPG):

* **Proces Wysyłania:**
    1.  Generowany jest jednorazowy, losowy **Klucz Sesji (AES-256)**.
    2.  Treść wiadomości i załączniki są szyfrowane tym **Kluczem Sesji**.
    3.  **Klucz Sesji** jest szyfrowany asymetrycznie **Kluczem Publicznym Odbiorcy** (RSA-2048).
    4.  Tworzony jest **Podpis Cyfrowy**: Skrót (Hash) wiadomości jest szyfrowany **Kluczem Prywatnym Nadawcy**.
* **Proces Odbierania:**
    1.  Odbiorca używa swojego Klucza Prywatnego, aby odszyfrować Klucz Sesji.
    2.  Kluczem Sesji odszyfrowuje treść i pliki.
    3.  Weryfikuje Podpis Cyfrowy używając Klucza Publicznego Nadawcy, aby potwierdzić autentyczność i integralność.

### 2. Zarządzanie Kluczami i Sekretami
Klucze są przechowywane i zarządzane w sposób minimalizujący ryzyko wycieku:

* **Klucz Prywatny RSA**: Jest generowany podczas rejestracji, ale **nigdy** nie jest zapisywany w bazie jawnym tekstem. Jest on szyfrowany symetrycznie (AES) kluczem pochodnym wygenerowanym z hasła użytkownika i losowej soli (PBKDF2HMAC). W bazie znajduje się tylko `encrypted_private_key`.
* **Klucz Publiczny RSA**: Przechowywany jawnie, dostępny dla każdego nadawcy.
* **Hasła Użytkowników**: Haszowane algorytmem **Argon2id** (odpornym na ataki GPU/ASIC) z unikalną solą.
* **Pamięć RAM (Sesja)**: Podczas logowania, z hasła użytkownika generowany jest `derived_key` (klucz pochodny). Tylko ten klucz trafia do sesji serwera. Oryginalne hasło jest usuwane z pamięci natychmiast po weryfikacji. Dzięki temu, nawet przy przejęciu sesji, atakujący nie poznaje hasła źródłowego.

### 3. Dlaczego to jest bezpieczne?
* **Poufność**: Tylko posiadacz klucza prywatnego (odbiorca znający swoje hasło) może otworzyć "cyfrową kopertę".
* **Autentyczność**: Podpis cyfrowy gwarantuje, że nadawca jest tym, za kogo się podaje.
* **Integralność**: Każda zmiana zaszyfrowanej treści przez osobę trzecią spowoduje błąd weryfikacji podpisu.
* **Ochrona przed wyciekiem bazy**: Wykradzenie bazy danych SQL daje atakującemu tylko zaszyfrowane bloby. Bez haseł użytkowników (które nie są tam przechowywane w formie odwracalnej) dane są bezużyteczne.

## 🚀 Wymagania i Uruchomienie

Aby uruchomić projekt, potrzebujesz zainstalowanego **Dockera** oraz **Docker Compose**.

### 1. Generowanie Certyfikatów SSL
Projekt wymaga certyfikatów SSL do działania Nginx (HTTPS). Należy je wygenerować i umieścić w folderze `nginx/certs/`.

Dla środowiska deweloperskiego (localhost) użyj polecenia OpenSSL (dostępne w Git Bash lub Linux):

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout nginx/certs/server.key -out nginx/certs/server.crt

Opis składni:

req -x509: Tworzy certyfikat z podpisem własnym (self-signed).

-nodes: Nie szyfruje klucza prywatnego hasłem (dzięki temu Nginx wstanie automatycznie bez pytania o hasło).

-days 365: Certyfikat ważny przez rok.

-newkey rsa:2048: Generuje nowy klucz RSA o długości 2048 bitów.

-keyout ...: Ścieżka zapisu klucza prywatnego.

-out ...: Ścieżka zapisu certyfikatu publicznego.

### 2. Konfiguracja `.env`
Utwórz plik `.env` w głównym katalogu projektu i uzupełnij go wg schematu z pliku .env.example

### 3.Uruchomienie 
docker-compose up -d --build lub bash start.sh
Aplikacja będzie dostępna pod adresem: https://localhost (lub na skonfigurowanym porcie Nginx).

### 4. Dostęp do bazy danych
Baza danych MSSQL jest dostępna na porcie 1433.

Server: (z docker-compose.yml)

User: (z pliku .env)

Password: (z pliku .env)