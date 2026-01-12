# SecureMail Project

SecureMail to prototyp bezpiecznego systemu pocztowego napisanego w Pythonie (Flask), skupiający się na bezpieczeństwie, prywatności i szyfrowaniu typu "Zero-Knowledge" (serwer nie ma dostępu do treści wiadomości).

## 🏗️ Architektura i Przepływ Danych

Aplikacja składa się z następujących modułów współpracujących ze sobą:

1.  **Frontend (Jinja2 Templates)**: Warstwa prezentacji wykorzystująca framework CSS **Bulma**. Formularze są obsługiwane przez **Flask-WTF** z ochroną CSRF.
2.  **Backend (Flask)**:
    * `app.py`: Punkt wejściowy aplikacji, konfiguracja i inicjalizacja.
    * `auth_routes.py`: Logika biznesowa uwierzytelniania (Rejestracja, Logowanie, 2FA, Reset hasła).
    * `crypto.py`: Warstwa kryptograficzna. Obsługuje haszowanie haseł (Argon2), generowanie kluczy RSA i szyfrowanie klucza prywatnego (AES/Fernet).
    * `models.py`: Modele bazy danych (SQLAlchemy) odwzorowujące strukturę tabel.
    * `forms.py`: Definicje formularzy i walidacja danych wejściowych.
3.  **Baza Danych (MS SQL Server)**: Przechowuje zaszyfrowane dane użytkowników i wiadomości. Działa w kontenerze Docker.
4.  **Reverse Proxy (Nginx)**: Obsługuje ruch przychodzący, SSL/TLS i przekazuje go do aplikacji Flask.

### Kluczowe Mechanizmy Bezpieczeństwa:

* **Zero-Knowledge Architecture**: Klucz prywatny RSA użytkownika jest szyfrowany algorytmem AES z użyciem hasła użytkownika. Serwer przechowuje tylko zaszyfrowaną wersję klucza (`encrypted_private_key`).
* **Argon2id**: Hasła są haszowane przy użyciu nowoczesnego algorytmu odpornego na ataki GPU.
* **2FA (TOTP)**: Obsługa uwierzytelniania dwuskładnikowego (Google Authenticator/Authy).
* **Ochrona Brute-Force**: `Flask-Limiter` ogranicza liczbę zapytań, a system blokuje konto na 5 minut po 5 nieudanych próbach logowania.
* **Session Management**: Automatyczne wylogowanie po 1 minucie bezczynności oraz po zamknięciu przeglądarki.

---

## 🚀 Wymagania i Uruchomienie

Aby uruchomić projekt, potrzebujesz zainstalowanego **Dockera** oraz **Docker Compose**.

### 1. Struktura folderu certyfikatów (`certs/`)
Projekt wymaga certyfikatów SSL do działania Nginx. Utwórz folder `certs` w głównym katalogu projektu i umieść tam pliki:
* `fullchain.pem` (Certyfikat publiczny)
* `privkey.pem` (Klucz prywatny)

*(Dla środowiska deweloperskiego można użyć certyfikatów self-signed lub mkcert).*

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