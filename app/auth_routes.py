import time
import pyotp
import os
import io
import base64
import qrcode
from flask import Blueprint, request, render_template, redirect, url_for, flash, session 
# Import obiektu mail z pliku mutual_imports (rozwiązanie problemu cyklicznych importów)
from mutual_imports import mail
# Funkcje Flask-Login do zarządzania sesją użytkownika
from flask_login import login_user, logout_user, login_required, current_user
# Narzędzie do pobierania IP (dla Limitera i logów)
from flask_limiter.util import get_remote_address
from argon2.exceptions import VerifyMismatchError
# Obsługa czasu i stref czasowych
from datetime import datetime, timedelta, timezone
from flask_mail import Message
from models import DATABASE, User, LoginAttempt
from forms import RegisterForm, LoginForm, TwoFactorForm, ResetPasswordRequestForm, ResetPasswordForm
from crypto import password_manager as crypto_manager

# blueprint (schemat tras) dla scieżek autoryzacyjnych
auth_bp = Blueprint('auth', __name__)

# funkcja helper do blokowania logowania na dane konto przy zbyt wielu nieudanych próbach
def check_account_lock(user):
    #Sprawdza, czy konto jest zablokowane.
    #Zwraca (True, czas_do_odblokowania) lub (False, None).

    if user.locked_until:
        # Pobieramy czas blokady z bazy
        lock_time = user.locked_until
        
        # zakładamy UTC jeśli brak info o strefie w całej aplikacji zeby było spójnie
        if lock_time.tzinfo is None:
            lock_time = lock_time.replace(tzinfo=timezone.utc)
            
        now = datetime.now(timezone.utc)

        if lock_time > now:
            # Konto nadal zablokowane
            remaining = lock_time - now
            # Zaokrąglamy do minut w górę 
            minutes_left = int(remaining.total_seconds() / 60) + 1
            return True, minutes_left
        else:
            # Blokada minęła - czyścimy flagi w bazie przy okazji
            return False, None
            
    return False, None


@auth_bp.before_app_request
def check_inactivity():
    # Funkcja uruchamiana przed każdym żądaniem - sprawdza timeout sesji (1 min bezczynności)
    if current_user.is_authenticated:
        # Ustawienie sesji jako tymczasowej (znika po zamknięciu przeglądarki)
        session.permanent = False
        present_time = datetime.now(timezone.utc)
        # Pobranie czasu ostatniej aktywności z sesji
        last_active = session.get('last_active') 
        
        if last_active:
            if isinstance(last_active, (int, float)):
                # Konwersja timestampa lub daty na obiekt datetime z UTC
                last_active_time = datetime.fromtimestamp(last_active, timezone.utc)
            else:
                last_active_time = last_active
            # Zabezpieczenie przed brakiem strefy czasowej
            if last_active_time.tzinfo is None:
                last_active_time = last_active_time.replace(tzinfo=timezone.utc)

            delta = present_time - last_active_time

            # Jeśli minęło więcej niż 60 sekund -> wyloguj
            if delta.total_seconds() > 60:
                logout_user()
                session.clear()
                flash("Zostałeś wylogowany z powodu braku aktywności przez 1 minutę.", "info")
                return redirect(url_for('auth.login'))
        # Aktualizacja czasu ostatniej aktywności
        session['last_active'] = present_time


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    # Jeśli user już zalogowany, przekieruj na stronę główną
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegisterForm()

    if form.validate_on_submit():
        try:
            # Generowanie bezpiecznej, losowej soli (16 bajtów
            salt = os.urandom(16)
            # Generowanie pary kluczy RSA
            pem_private, pem_public = crypto_manager.generate_rsa_keys()
            # Szyfrowanie klucza prywatnego hasłem użytkownika i solą AES-256
            encrypted_priv = crypto_manager.encrypt_private_key(pem_private, form.password.data, salt)
            # Haszowanie hasła użytkownika za pomocą Argon2
            hashed_pw = crypto_manager.hash_password(form.password.data)
            # Generowanie sekretu TOTP dla 2FA
            totp_sec = pyotp.random_base32()
            # Tworzenie nowego użytkownika w bazie danych
            new_user = User(
                username=form.username.data,
                password_hash=hashed_pw,
                public_key=pem_public.decode('utf-8'),
                encrypted_private_key=encrypted_priv,
                totp_secret=totp_sec,
                salt=salt
            )
            # Zapis do bazy danych
            DATABASE.session.add(new_user)
            DATABASE.session.commit()

            flash("Konto utworzone pomyślnie. Teraz możesz się zalogować!", "success")
            return redirect(url_for('auth.login'))

        except Exception as e:
            print(f"BŁĄD KRYTYCZNY w /register: {e}")
            # Cofnięcie transakcji w przypadku błędu
            DATABASE.session.rollback()
            if "IntegrityError" in str(e) or "UNIQUE constraint" in str(e):
                flash("Ten adres email jest już zajęty.", "error")
            else:
                flash(f"Wystąpił nieoczekiwany błąd systemu.", "error")
            return render_template('register.html', form=form)

    return render_template('register.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    # w momencie zatwierdzenia formularza
    if form.validate_on_submit():
        try:
            ip = get_remote_address()
            user = User.query.filter_by(username=form.username.data).first()
            
            # Domyślny komunikat błędu 
            error_msg = "Nieprawidłowy email lub hasło."

            if user:
                #  sprawdzamy czy konto jest zablokowane
                is_locked, minutes_left = check_account_lock(user)
                if is_locked:
                    flash(f"Konto jest zablokowane ze względów bezpieczeństwa. Spróbuj ponownie za {minutes_left} min.", "error")
                    return render_template('login.html', form=form)

                # jak nie jest zablokowane, to sprawdzamy hasło
                try:
                    is_valid = crypto_manager.verify_password(user.password_hash, form.password.data)
                except VerifyMismatchError:
                    is_valid = False

                if is_valid:
                    # Resetujemy liczniki błędów i blokadę, bo użytkownik wszedł poprawnie
                    user.failed_login_attempts = 0
                    user.locked_until = None
                    DATABASE.session.commit()
                    # jeśli hasło poprawne, sprawdzamy 2FA, zapisuje ID w sesji tymczasowej i przekierowujemy do 2FA
                    if user.is_2fa_enabled:
                        session['pre_2fa_user_id'] = user.id
                        flash("Hasło poprawne. Wymagana weryfikacja 2FA.", "success")
                        return redirect(url_for('auth.login_2fa'))
                    else:
                        # Jeśli 2FA wyłączone -> zaloguj od razu
                        login_user(user)
                        session['last_active'] = datetime.now(timezone.utc)
                        # Logujemy udane logowanie
                        DATABASE.session.add(LoginAttempt(user_id=user.id, ip_address=ip, successful=True))
                        DATABASE.session.commit()
                        flash(f"Witaj ponownie, {user.username}!", "success")
                        # przekierowanie na stronę główną lub poprzednią
                        return redirect(url_for('index'))
                
                else:
                    # Nieprawidłowe hasło
                    time.sleep(1) # Opóźnienie
                    
                    # Zwiększamy licznik nieudanych prób
                    current_attempts = (user.failed_login_attempts or 0) + 1
                    user.failed_login_attempts = current_attempts
                    
                    # Sprawdzamy czy przekroczono limit 5 prób
                    if current_attempts >= 5:
                        # Ustawiamy blokadę na 5 minut od teraz (UTC)
                        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=5)
                        DATABASE.session.commit()
                        flash("Zbyt wiele nieudanych prób. Konto zostało zablokowane na 5 minut.", "error")
                    else:
                        # Logujemy próbę i wyświetlamy błąd
                        DATABASE.session.add(LoginAttempt(user_id=user.id, ip_address=ip, successful=False))
                        DATABASE.session.commit()
                        flash(f"Nieprawidłowy email lub hasło.", "error")

            else:
                # Użytkownik nie istnieje
                time.sleep(1)
                flash(error_msg, "error")

        except Exception as e:
            print(f"KYTYCZNY BŁĄD w /login: {e}")
            flash("Błąd serwera podczas logowania.", "error")

    return render_template('login.html', form=form)


@auth_bp.route('/login-2fa', methods=['GET', 'POST'])
def login_2fa():
    try:
        # Sprawdzamy, czy użytkownik przeszedł pomyślnie etap 1 (hasło)
        user_id = session.get('pre_2fa_user_id')
        if not user_id:
            flash("Sesja wygasła. Zaloguj się ponownie.", "error")
            return redirect(url_for('auth.login'))
        
        form = TwoFactorForm()
        # Weryfikacja kodu 2FA
        if form.validate_on_submit():
            user = User.query.get(user_id)
            code = form.otp_token.data

            # Weryfikacja kodu TOTP
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(code):
                login_user(user)
                session.pop('pre_2fa_user_id', None) # Czyszczenie sesji tymczasowej
                session['last_active'] = datetime.now(timezone.utc)
                # Logujemy udane logowanie
                DATABASE.session.add(LoginAttempt(user_id=user.id, ip_address=get_remote_address(), successful=True))
                DATABASE.session.commit()
                
                flash(f"Witaj, {user.username}!", "success")
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
            else:
                flash("Nieprawidłowy kod 2FA.", "error")
    
    except Exception as e:
        print(f"BŁĄD KRYTYCZNY w /login-2fa: {e}")
        flash("Wystąpił błąd weryfikacji.", "error")
        return redirect(url_for('auth.login'))

    return render_template('verify_2fa.html', form=form)

@auth_bp.route('/settings')
@login_required
def settings():
    # Strona ustawień konta
    return render_template('settings.html')

@auth_bp.route('/settings/enable-2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    # Logika włączania 2FA
    user = current_user
    if user.is_2fa_enabled:
        flash("2FA jest już włączone.", "info")
        return redirect(url_for('auth.settings'))

    form = TwoFactorForm()
    # Generowanie kodu QR dla aplikacji Authenticator
    totp = pyotp.TOTP(current_user.totp_secret).provisioning_uri(name=current_user.username, issuer_name="SecureMail")
    # Generowanie obrazu QR
    img = qrcode.make(totp)
    # Konwersja obrazu do formatu base64 do osadzenia w HTML
    buffered = io.BytesIO()
    # Zapis obrazu do bufora
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    # Obsługa formularza włączenia 2FA
    if form.validate_on_submit():
        # Weryfikacja kodu TOTP podanego przez użytkownika
        totp = pyotp.TOTP(current_user.totp_secret)
        if totp.verify(form.otp_token.data):
            current_user.is_2fa_enabled = True
            DATABASE.session.commit()
            flash("Dwuetapowa weryfikacja została włączona! ", "success")
            return redirect(url_for('auth.settings'))
        else:
            flash("Nieprawidłowy kod 2FA. Spróbuj ponownie.", "error")
    return render_template('enable_2fa.html', form=form, qr_code=img_str)

# Wyłączanie 2FA
@auth_bp.route('/settings/disable_2fa', methods=['POST'])
@login_required
def disable_2fa():
    # Logika wyłączania 2FA
    user = current_user
    if not user.is_2fa_enabled:
        flash("2FA jest już wyłączone.", "info")
        return redirect(url_for('auth.settings'))
    # akceptacja wyłączenia 2FA, zmiana flagi w tabeli użytkowników
    user.is_2fa_enabled = False
    DATABASE.session.commit()
    flash("Dwuetapowa weryfikacja została wyłączona.", "success")
    return redirect(url_for('auth.settings'))


@auth_bp.route('/logout')
@login_required
def logout():
    user = current_user
    # czyścimy blokady i liczniki nieudanych prób przy wylogowaniu
    user.failed_login_attempts = 0 
    DATABASE.session.commit()

    logout_user()
    # Czyścimy sesję
    session.clear()
    flash("Zostałeś wylogowany.", "info")
    return redirect(url_for('auth.login'))


# funkcja helper do wysyłania maili
def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Reset hasła - SecureMail',
                  sender='noreply@securemail.com', 
                  recipients=[user.username])
    
    # Tworzymy pełny link (z domeną)
    link = url_for('auth.reset_passwd', token=token, _external=True)
    
    msg.body = f'''Aby zresetować hasło, kliknij w poniższy link:
{link}
Link do resetu hasła jest ważny przez 30 minut.
Jeśli to nie Ty wysłałeś to żądanie, zignoruj tę wiadomość.
Uwaga: Zmiana hasła spowoduje utratę dostępu do starych zaszyfrowanych wiadomości (zmiana klucza prywatnego).
'''
    try:
        mail.send(msg)
        print(f"[DEBUG] Email wysłany do {user.username}. Link: {link}")
    except Exception as e:
        print(f"[ERROR] Nie udało się wysłać maila: {e}")

@auth_bp.route('/reset_password', methods=['GET', 'POST'])
def reset_passwd_request():
    # Strona do wpisania emaila w celu zresetowania hasła
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    # Po zatwierdzeniu formularza
    if form.validate_on_submit():
        # wysyłamy maila z linkiem do resetu
        user = User.query.filter_by(username=form.username.data).first()
        send_reset_email(user)
        flash("Na podany adres email wysłano instrukcje resetu hasła.", "info")
        return redirect(url_for('auth.login'))
    return render_template('reset_password_request.html', form=form)

@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_passwd(token):
    # Strona do ustawienia nowego hasła po kliknięciu w link z maila 
    # wysyłamy na stronę z tokenem danego użytkownika
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_token(token)

    if user is None:
        flash("Token do resetu hasła jest nieprawidłowy lub wygasł.", "warning")
        return redirect(url_for('auth.reset_passwd_request'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        # Generujemy nową sól i haszujemy nowe hasło
        new_salt = os.urandom(16)
        hashed_pw = crypto_manager.hash_password(form.password.data)
        
        # Generujemy NOWĄ parę kluczy RSA, stary klucz prywatny jest zaszyfrowany starym hasłem, którego nie znamy
        # musimy go nadpisać nowym, co oznacza utratę starych wiadomości
        pem_private, pem_public = crypto_manager.generate_rsa_keys()
        encrypted_priv = crypto_manager.encrypt_private_key(pem_private, form.password.data, new_salt)
        
        # Aktualizujemy dane użytkownika
        user.password_hash = hashed_pw
        user.salt = new_salt
        user.public_key = pem_public.decode('utf-8')
        user.encrypted_private_key = encrypted_priv
        
        # czyścimy blokady i nieudane próby
        user.locked_until = None
        user.failed_login_attempts = 0
        
        DATABASE.session.commit()
        
        flash("Twoje hasło zostało zmienione! Możesz się teraz zalogować.", "success")
        return redirect(url_for('auth.login'))
    
    return render_template('reset_password_form.html', form=form)