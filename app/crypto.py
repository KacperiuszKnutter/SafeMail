import base64
# Biblioteka do haszowania haseł odporna na ataki GPU/ASIC
from argon2 import PasswordHasher
# Moduły kryptograficzne do obsługi kluczy asymetrycznych (RSA)
from cryptography.hazmat.primitives.asymmetric import rsa, padding
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
        # to pole trafia do bazy danych 
        return self.passwordhasher.hash(password)

    def verify_password(self, hashed_password, plain_password):
        #weryfikacja hasła przy użyciu argon2
        # wykorzystujemy podczas logowania do weryfikacji wpisanego hasla z tym co jest w bazie
        try:
            return self.passwordhasher.verify(hashed_password, plain_password)
        except VerifyMismatchError:
            # Zwracamy False, jeśli hasło jest niepoprawne
            return False

    # wykorzystywane przy generowaniu i szyfrowaniu kluczy RSA użytkownika

    def generate_key_from_password(self, password, salt):
        # Tworzymy klucz na podstawie hasała użytkownika i soli
        # w ten sposób nie przchowujemy hasła w bazie danych
        # uzywa PBKDF2 (Password-Based Key Derivation Function 2) zalecany do tworzenia hashy z haslaze zwzgledu na duza liczbe iteracji oraz sol unikalna uzytkownika
        # Czyli tworzymy 32-bajtowy klucz symetryczny na podstawie hasla oraz soli potem taki hasz jest traktowany argonem

        # używamy:
        # tworzymy na etapie rejestracji do zaszyfrowania klucza prywatnego RSA przed zapisem w bazie
        # na etapie logowania: Aby odtworzyć ten sam klucz i zapisać go w sesji (jako decryption_key), co pozwoli potem "otworzyć" klucz prywatny.
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), # Funkcja skrótu używana wewnątrz KDF (Key Deriviative Func)
            length=32,              # Długość generowanego klucza (32 bajty dla AES-256)
            salt=salt,              #Unikalna sól użytkownika 
            iterations=480000,      # Liczba iteracji (spowalnia atak brute-force)
        )
        # Generowanie klucza i kodowanie go do formatu base64 potrzebne dla Fernet by połączyć AES i HMAC 16 na enkrypcję i integralność oraz 16 na podpis
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def encrypt_private_key(self, private_key_pem, password, salt):
        # szyfrujemy klucz prywatny użytkownika przy użyciu hasła użytkownika
        # generujemy klucz symetryczny z hasła i soli
        # tu wykorzystujemy funkcje generate_key_from_password, konkretnie w tej metodzie szyfrujemy sobie jeden z pary kluczy RSA (PEM) ten prywatny 
        # kluczem wygenerowanym powyzej z hasla uzytkownika 
        key = self.generate_key_from_password(password, salt)
        f = Fernet(key)
        # szyfrujemy bajty klucza prywatnego i dekodujemy wynik do stringa (utf-8) do zapisu w bazie
        return f.encrypt(private_key_pem).decode('utf-8')
    
    def generate_rsa_keys(self):
        #Generuje parę kluczy RSA (prywatny i publiczny)
        #Generowanie klucza prywatnego RSA o długości 2048 bitów
        # Robimy to na etapie rejestracji
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
    
    # metody do szyfrowania i deszyfrowania wiadomości cyfrowej koperty
     
    def get_decrypted_private_key_with_derived_key(self, encrypted_private_key_pem, derived_key_b64):
        # odszyfrowujemy klucz prywatny z bazy uzywajac gotowego klucza symetrycznego (z sesji) - derived_key
        # by zapobiegac przechowywaniu hasła w pamięci aplikacji i ryzyka wycieku podczas przejecia sesji
        
        #używamy podczas wysyłania: gdy nadawca porzebuje swojego klucza prywatnego by podpisać podczas sesji wiadomość żeby była autentyczna
        # używamy podczas odbierania wiadomości: odbiorca potrzebuje swojego klucza prywatnego by odszyfrować klucz sesji wiadomości
        try:
            # Klucz z sesji jest stringiem base64, konwertujemy na bajty 
            if isinstance(derived_key_b64, str):
                key = derived_key_b64.encode('utf-8')
            else:
                key = derived_key_b64

            f = Fernet(key)
            
            # Odszyfrowujemy PEM
            decrypted_pem = f.decrypt(encrypted_private_key_pem.encode('utf-8'))
            
            # Ładujemy do obiektu kluczaPEM
            private_key = serialization.load_pem_private_key(
                decrypted_pem,
                password=None
            )
            return private_key
        except Exception as e:
            print(f"Błąd deszyfrowania klucza prywatnego: {e}")
            return None
        
    def generate_session_key(self):
        # generujemy losowy klucz AES (Fernet) dla jednej wiadomości, dla każdej wiadomości generowany jest nowy
        # szybki klucz fizycznie szyfrujący treść maila
        return Fernet.generate_key()

    def encrypt_data_symmetric(self, data_bytes, session_key):
        # Szyfrujemy treść (bajty tekstu lub pliku) kluczem sesji (AES)
        # zwracamy zaszyfrowane bajty jako base64 do przeechowywania w bazie
        # używamy na etapie wysyłania wiadomości z załącznikami + treść
        f = Fernet(session_key)
        encrypted_data = f.encrypt(data_bytes)
        # Zwracamy jako string, bo w bazie trzymamy Text/LargeBinary
        return encrypted_data

    def decrypt_data_symmetric(self, encrypted_data_bytes, session_key):
        # Odszyfrowujemy treść kluczem sesji podczas odbierania (wyświetlania treści) i pobierania załącznika
        f = Fernet(session_key)
        return f.decrypt(encrypted_data_bytes)

    def encrypt_session_key(self, session_key, recipient_public_key_pem):
        # szyfrujemy klucz sesji (AES) za pomocą klucza publicznego Odbiorcy (RSA)
        # klucz publiczny jest powiązany z publicznym więc tylko odbiorca będzie mógł ją odszyfrować (jeśli zmieni hasło po wysłaniu wiadomości nie będzie mógł jej odczytać!)

        # Ładowanie klucza publicznego odbiorcy
        public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode('utf-8'))
        
        # Szyfrowanie asymetryczne (OAEP jest bezpiecznym standardem paddingu)
        encrypted_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Zwracamy jako base64 string, żeby zapisać w bazie Text
        return base64.b64encode(encrypted_key).decode('utf-8')

    def decrypt_session_key(self, encrypted_session_key_b64, recipient_private_key):
        #Odszyfrowuje klucz sesji za pomocą prywatnego klucza Odbiorcy
        # podczas odbbierania wiadomosci
        # Dekodujemy z base64 do bajtów
        encrypted_key_bytes = base64.b64decode(encrypted_session_key_b64)
        
        # Odszyfrowanie RSA z OAEP dodajemy randomowy padding do wiadomosci 
        # (przy dwukrotnej enkrypcji z OAEP padding bedzie inny co zwieksza losowosc)
        session_key = recipient_private_key.decrypt(
            encrypted_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return session_key

    def sign_message(self, message_bytes, sender_private_key):
        #Tworzymy podpis cyfrowy wiadomości to gwarantuje autentyczność (to ja wysłałem) i Integralność (nikt nie zmienił)
        # przy pomocy klucza prywatnego nadawcy wiadomości
        signature = sender_private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, message_bytes, signature_b64, sender_public_key_pem):
        # Weryfikujemy podpis zwracamt True jeśli ok, False jeśli fałszywy
        # podpis weryfikujemy kluczem publicznym nadawcy
        # podczas odbierania wiadomości, odszyfrowujemy podpisaną treść wiadomości kluczem publicznym nadawcy który jest związany z kluczem prywatnym nadawcy
        # jeśli treść wiadomości nie została w locie zmodyfikowana przez atakującego treść wiadomości i zawartość podpisu będzie taka sama
        try:
            # Ładujemy klucz publiczny nadawcy
            public_key = serialization.load_pem_public_key(sender_public_key_pem.encode('utf-8'))
            # Dekodujemy podpis z base64
            signature_bytes = base64.b64decode(signature_b64)
            # Weryfikujemy podpis
            public_key.verify(
                signature_bytes,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True # Weryfikacja powiodła się
        except Exception as e:
            print(f"Błąd weryfikacji podpisu: {e}")
            return False
        
    
# sigleton do zarządzania hasłami i kluczami
password_manager = PasswordManager()