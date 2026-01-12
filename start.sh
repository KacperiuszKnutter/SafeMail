#!/bin/bash
# skrypt do konfiguracji i uruchamiania środowiska Docker dla projektu SecureMail z odpowiednimi uprawnieniami do .env



echo -e "=== Startowanie Projektu SecureMail ===${NC}"

# Sprawdzenie czy plik .env istnieje
if [ ! -f .env ]; then
    echo -e "Błąd: Nie znaleziono pliku .env!${NC}"
    echo "Upewnij się, że utworzyłeś plik .env na podstawie .env.example"
    exit 1
fi

# Automatyczna naprawa uprawnień (Działa na Linux/WSL)
echo "Konfigurowanie uprawnień do plików..."

# Jeśli jesteśmy na Linuxie/WSL, ustawiamy restrykcyjne uprawnienia
# "chmod 600" sprawia, że tylko właściciel może czytać plik 
chmod 600 .env 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "Uprawnienia .env ustawione na 600 (Secure).${NC}"
else
    echo -e "Nie udało się ustawić chmod 600 (czy jesteś na Windows NTFS?). Ignoruję.${NC}"
    # Na czystym Windowsie to nie zadziała, ale tam Docker Desktop i tak radzi sobie inaczej.
fi

# Zatrzymanie starych kontenerów 
echo "Sprzątanie starego środowiska..."
docker-compose down --remove-orphans

# Budowanie i start (wymuszamy przebudowę, żeby uwzględnić zmiany w kodzie)
echo "Budowanie i uruchamianie kontenerów..."
# od razu tutaj dodajemy komende dockerowa
# --build żeby mieć pewność, że zmiany w Pythonie/Dockerfile wejdą w życie
docker-compose up -d --build

# Dajemy czas dla Dockera na uruchomienie usług
echo "Czekanie na start usług..."
sleep 5 

# Sprawdzamy czy kontenery wstały
if [ $(docker ps -q -f name=flask_app) ]; then
    echo -e "Aplikacja działa!${NC}"
    echo -e "   Frontend:  https://localhost"
    echo -e "   Backend:   https://localhost/db-test"
else
    echo -e "Coś poszło nie tak. Sprawdź logi komendą: docker logs flask_app${NC}"
fi