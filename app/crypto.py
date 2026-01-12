import base64
# Biblioteka do haszowania haseł odporna na ataki GPU/ASIC
from argon2 import PasswordHasher
# Moduły kryptograficzne do obsługi kluczy asymetrycznych (RSA)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
# Algorytm do  tworzenia klucza kryptograficznego z hasła tekstowego
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# Implementacja szyfrowania symetrycznego (AES w trybie CBC z HMAC)
from cryptography.fernet import Fernet
# Obsługa błędów weryfikacji hasła
from argon2.exceptions import VerifyMismatchError

class PasswordManager:
    def __init__(self):
       #domyślnie korzystamy z argon2 do hashowania haseł
       # Inicjalizacja obiektu hashera z domyślnymi, bezpiecznymi parametrami (t=3, m=65536, p=4)
       self.passwordhasher = PasswordHasher()

    # wykorzystywane przy rejestracji i logowaniu użytkownika
    def hash_password(self, password):
        #haszowanie hasła przy użyyciu argon2
        # zwracamy gotowy hash zawierający sól, parametry i wynik haszowania
        return self.passwordhasher.hash(password)

    def verify_password(self, hashed_password, plain_password):
        #weryfikacja hasła przy użyciu argon2
        try:
            return self.passwordhasher.verify(hashed_password, plain_password)
        except VerifyMismatchError:
            # Zwracamy False, jeśli hasło jest niepoprawne
            return False

    # wykorzystywane przy generowaniu i szyfrowaniu kluczy RSA użytkownika

    def generate_key_from_password(self, password, salt):
        # Tworzymy klucz na podstawie hasała użytkownika i soli
        # w ten sposób nie przchowujemy hasła w bazie danych
        # 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), # Funkcja skrótu używana wewnątrz KDF
            length=32,              # Długość generowanego klucza (32 bajty dla AES-256)
            salt=salt,              #Unikalna sól użytkownika 
            iterations=480000,      # Liczba iteracji (spowalnia atak brute-force)
        )
        # Generowanie klucza i kodowanie go do formatu base64 potrzebne dla Fernet by połączyć AES i HMAC 16 na enkrypcję i integralność oraz 16 na podpis
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def encrypt_private_key(self, private_key_pem, password, salt):
        # szyfrujemy klucz prywatny użytkownika przy użyciu hasła użytkownika
        # generujemy klucz symetryczny z hasła i soli
        key = self.generate_key_from_password(password, salt)
        f = Fernet(key)
        # szyfrujemy bajty klucza prywatnego i dekodujemy wynik do stringa (utf-8) do zapisu w bazie
        return f.encrypt(private_key_pem).decode('utf-8')
    
    def generate_rsa_keys(self):
        #Generuje parę kluczy RSA (prywatny i publiczny)
        # Generowanie klucza prywatnego RSA o długości 2048 bitów
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Eksport klucza prywatnego do PEM (niezaszyfrowany w locie)
        # szyfrowanie następuje dopiero w metodzie encrypt_private_key
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8, # standardowy format PKCS8
            encryption_algorithm=serialization.NoEncryption()
        )

        # Eksport klucza publicznego do PEM
        pem_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo # Standard formatu klucza publicznego
        )

        return pem_private, pem_public
    
# sigleton do zarządzania hasłami i kluczami
password_manager = PasswordManager()