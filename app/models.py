from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
# UserMixin dostarcza domyślne implementacje metod wymaganych przez Flask-Login (is_authenticated, itp.)
from flask_login import UserMixin
# Biblioteka do generowania bezpiecznych, czasowych tokenów (używana przy resecie hasła)
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import current_app

DATABASE = SQLAlchemy()
db = DATABASE
class User(db.Model, UserMixin):
    # Nazwa tabeli w bazie danych
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    #username to będzie po prostu mail użytkownika
    username = db.Column(db.String(255), unique=True, nullable=False)
    # Hasło zahashowane przy pomocy argona2 o stałej długości
    password_hash = db.Column(db.String(255), nullable=False)
    # Jawny klucz RSA w formacie PEM
    # Używamy Text, bo klucz RSA jest długi
    public_key = db.Column(db.Text, nullable=False)
    # Klucz prywatny RSA zaszyfrowany symetrycznie (AES)
    encrypted_private_key = db.Column(db.Text, nullable=False)
    # Sekret do generowania kodów 2FA
    totp_secret = db.Column(db.String(255), nullable=False)
    # Sól dla każdego użytkownika do szyfrowania klucza prywatnego
    salt = db.Column(db.LargeBinary, nullable=False)
    
    # Domyślnie False, użytkownik musi sam włączyć 2FA w ustawieniach
    is_2fa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    
    # Liczba nieudanych prób logowania i kolumny do audytu i blokowania konta po wielu nieudanych próbach
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    #Relacje z innymi tabelami
    # do nawigacji w ORM
    messages_sent = db.relationship('Message',backref='sender', lazy='dynamic', foreign_keys='Message.sender_id')
    messages_received = db.relationship('Message',backref='recipient', lazy='dynamic', foreign_keys='Message.recipient_id')

    def get_reset_token(self):
        # token do resetowania hasła za pomocą itsdangerous (domyslnie 30 minut)
        # serializator do generowania tokenów z kluczem sekretu aplikacji
        s = Serializer(current_app.config['SECRET_KEY'])
        # Generujemy token zawierający ID użytkownika
        return s.dumps({'user_id': self.id})
    
    @staticmethod
    def verify_reset_token(token):
        #metoda do weryfikacji tokenu resetującego hasło zwraca uzytkownika lub None
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            # Próbujemy odczytać token, sprawdzając czy nie jest starszy niż 1800 sekund (30 min)
            user_id = s.loads(token, max_age=1800)['user_id']
        except:
            # Jeśli token wygasł lub jest nieprawidłowy, zwracamy None
            return None
        # Zwracamy użytkownika o danym ID
        return User.query.get(user_id)

class Message(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
        #tu wiążemy z user.id z tabelą users
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        #  Wiadomość zaszyfrowana kluczem publicznym odbiorcy, pole jako tekst a nie string bo może być długie
        # to bedzie odpowiednik nvarchar(max) w SQL Server
    encrypted_content = db.Column(db.Text, nullable=False)
        # Losowy klucz sesyjny zaszyfrowany kluczem publicznym odbiorcy (RSA)
    encrypted_aes_key = db.Column(db.Text, nullable=False)
        # Podpis cyfrowy wiadomości
    signature = db.Column(db.Text, nullable=False)
        #data i czas wysłania wiadomości, przydatne do sortowania po dacie
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        # czy wiadomość została odczytana
    is_read = db.Column(db.Boolean, default=False)

class LoginAttempt(db.Model):
    # Tabela audytowa do śledzenia prób logowania (obsoletna, ale może być przydatna)
    __tablename__ = 'login_attempts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    successful = db.Column(db.Boolean, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 kompatybilne

    user = db.relationship('User', backref=db.backref('login_attempts', lazy='dynamic'))
