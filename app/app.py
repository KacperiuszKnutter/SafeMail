import os
import time
from flask import Flask, jsonify, render_template
import sqlalchemy
# ProxyFix naprawia nagłówki IP, gdy Flask działa za Nginx (ważne dla Limitera)
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager
# Biblioteka do limitowania liczby zapytań (ochrona przed Brute Force)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from mutual_imports import mail
from datetime import timedelta

# Importy z innych modułów aplikacji
from models import DATABASE, User
# Importujemy blueprint z pliku auth_routes.py, aby zarejestrować go w aplikacji i mieć dostęp do tras rejestracji i logowania itd.
from auth_routes import auth_bp 

def get_env_variable(name):
    # Pobiera zmienną środowiskową lub zgłasza wyjątek, jeśli nie istnieje
    try:
        return os.environ[name]
    except KeyError:
        raise Exception(f"Błąd krytyczny: Nie znaleziono zmiennej środowiskowej '{name}'.")

def ensure_database_ready(server, user, password, db_name, max_retries=15):
    # Funkcja oczekująca na gotowość SQL Servera (Docker MSSQL wstaje wolniej niż Flask)
    # Jeśli baza nie istnieje, tworzy ją
    master_uri = f"mssql+pyodbc://{user}:{password}@{server}:1433/master?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes&autocommit=true"
    engine_master = sqlalchemy.create_engine(master_uri, isolation_level="AUTOCOMMIT")
    # Próby połączenia i tworzenia bazy danych
    for i in range(max_retries):
        try:
            print(f"[DATABASE] Próba połączenia z SQL Server ({i+1}/{max_retries})...")
            # Sprawdzenie istnienia bazy danych
            with engine_master.connect() as connection:
                connection.execute(sqlalchemy.text("SELECT 1"))
                result = connection.execute(sqlalchemy.text(f"SELECT database_id FROM sys.databases WHERE Name = '{db_name}'")).fetchone()
                # Jeśli baza nie istnieje, tworzymy ją
                if not result:
                    connection.execute(sqlalchemy.text(f"CREATE DATABASE [{db_name}]"))
                    print(f"[DATABASE] Utworzono bazę '{db_name}'.")
                else:
                    print(f"[DATABASE] Baza '{db_name}' już istnieje.")
                return True 
        except Exception as e:
            print(f"[DATABASE] Błąd połączenia: {e}")
            # Czekamy 5 sekund przed kolejną próbą
            time.sleep(5)
    raise Exception("[DATABASE] Nie udało się połączyć z SQL Serverem po wielu próbach.")

def create_app():
    # Fabryka aplikacji Flask
    app = Flask(__name__)
    # Middleware ProxyFix dla poprawnego działania za reverse proxy (Nginx)
    # Konfiguracja ProxyFix (x_for=1 oznacza, że ufamy jednemu proxy - Nginxowi), nagłówki X-Forwarded-* oznaczają oryginalne IP, protokół itp.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # Zmienne środowiskowe pobierane z systemu (.env przekazane przez Docker)
    server = os.getenv('DB_SERVER')
    db_name = os.getenv('DB_NAME')
    username = os.getenv('DB_USER')
    password = os.getenv('DB_PASSWORD')
    secret_key = get_env_variable('FLASK_SECRET_KEY')
    
    # Baza danych start
    ensure_database_ready(server, username, password, db_name)

    # Konfiguracja App
    # Connection string do bazy danych
    app.config['SQLALCHEMY_DATABASE_URI'] = f"mssql+pyodbc://{username}:{password}@{server}:1433/{db_name}?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = secret_key 
    # Sesje użytkowników - czas trwania 1 minuta (dla testów)
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)
    
    # Konfiguracja Mail (Console Backend)
    app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

    # Inicjalizacja Rozszerzeń
    DATABASE.init_app(app)
    mail.init_app(app)
    
    # konfiguracja Login Managera
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login' # Wskazujemy na blueprint 'auth'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        # Funkcja ładująca użytkownika z bazy na podstawie ID zapisanego w sesji
        return User.query.get(int(user_id))

    # Limiter (Ochrona Brute-force)
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )

    # registracja blueprintów
    # tutaj rejestrujemy blueprint auth_bp z auth_routes.py
    # to pozwala na modularne zarządzanie trasami związanymi z uwierzytelnianiem
    app.register_blueprint(auth_bp) 
    # Tworzenie tabel w bazie danych (jeśli nie istnieją)
    with app.app_context():
        DATABASE.create_all()
        print("[DATABASE]: Tabele zweryfikowane.")

    @app.route('/')
    def index():
        # Strona główna
        return render_template('base.html')

    return app

if __name__ == '__main__':
    try:
        app = create_app()
        # Uruchomienie serwera deweloperskiego host 0.0.0.0 pozwala na dostęp z zewnątrz kontenera
        # tylko do celów deweloperskich na produkcje NIE (debug=True tylko na potrzeby testów potem zmienić na False)
        app.run(host='0.0.0.0', port=8000, debug=True)
    except Exception as e:
        print(f"Błąd krytyczny startu: {e}")