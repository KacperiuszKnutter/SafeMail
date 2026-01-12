FROM python:3.10-slim

WORKDIR /app

# Ustawiamy zmienną środowiskową EULA globalnie (unikanie błęędów przy instalacji)
ENV ACCEPT_EULA=Y
# Ustawiamy brak interakcji z instalatorem (wywalało wcześniej błąd podczas instalacji)
ENV DEBIAN_FRONTEND=noninteractive

#  Instalacja podstawowych narzędzi i kluczy GPG
RUN apt-get update && apt-get install -y \
    curl \
    gnupg2 \
    apt-transport-https \
    unixodbc \
    unixodbc-dev \
    locales \
    && rm -rf /var/lib/apt/lists/*

#  Generowanie języka UTF-8 (wymagane przez sterownik MS SQL)
RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# dodanie oficjalnego repozytorium Microsoft dla Debiana 12 (Bookworm)
# Python 3.10-slim to teraz Debian 12 korzystamy z konkretnego repo
RUN curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
    && curl https://packages.microsoft.com/config/debian/12/prod.list | tee /etc/apt/sources.list.d/mssql-release.list

# Instalacja sterownika z repozytorium
# Zmienna ACCEPT_EULA=Y jest już ustawiona na górze pliku
# msodbcsql18 zainstaluje się teraz poprawnie.
RUN apt-get update && apt-get install -y \
    msodbcsql18 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# biblioteki Python 
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopiowanie kodu
COPY . .

# Tworzenie użytkownika i uprawnienia do folderu /app zeby nie działać jako root
RUN useradd -m appuser
RUN chown -R appuser:appuser /app

# Przełączamy się na użytkownika
USER appuser

CMD ["python", "app.py"]