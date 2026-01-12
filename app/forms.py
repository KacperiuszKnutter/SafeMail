from flask_wtf import FlaskForm
# Import pól formularza (tekstowe, hasło, przycisk)
from wtforms import StringField, PasswordField, SubmitField
# Import walidatorów (wymagane pole, długość, zgodność haseł, wyrażenia regularne)
from wtforms.validators import DataRequired, Length, EqualTo, Regexp


class RegisterForm(FlaskForm):
    # Pole na adres email z walidacją , pole nie może być puste, długość od 4 do 100 znaków, poprawny format email
    # regex do sprawdzenia poprawności formatu email inspiracja ze stackoverflow
    username = StringField('Adres Email', validators=[DataRequired(message="Email jest wymagany"),Length(min=4, max=100),
        Regexp(r'^[\w\.-]+@[\w\.-]+\.\w+$', message=f"Email niepoprawny, adres email powinien wyglądać następująco: user@example.com")
    ])
    # Pole na hasło z walidacją: pole nie może być puste, długość od 8 do 24 znaków, złożoność hasła
    password = PasswordField('Hasło', validators=[
        DataRequired(message="Hasło jest wymagane"),
        Length(min=8, max=24, message="Hasło musi mieć od 8 do 24 znaków"),
        #Regex do wymuszenia złożoności hasła jedna mała litera, jedna duża litera, jedna cyfra, jeden znak specjalny
        # (?=.*?[A-Z]) - Lookahead sprawdzający obecność dużej litery
        # (?=.*?[^A-Za-z0-9]) - Lookahead sprawdzający znak specjalny (nie alfanumeryczny)
        Regexp(r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^A-Za-z0-9]).{8,24}$', message="Hasło musi zawierać małą i dużą literę, cyfrę oraz znak specjalny")
    ])
    
    confirm_password = PasswordField('Potwierdź hasło', validators=[
        DataRequired(),
        EqualTo('password', message='Hasła muszą być identyczne')
    ])  # EqualTo sprawdza, czy wartość tego pola jest identyczna z polem 'password'
    
    submit = SubmitField('Zarejestruj się')

class LoginForm(FlaskForm):
    # Prosty formularz logowania bez skomplikowanej walidacji regex (sprawdzamy tylko obecność danych)
    username = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Hasło', validators=[DataRequired()])
    submit = SubmitField('Zaloguj')

class TwoFactorForm(FlaskForm):
    # Formularz do wpisywania kodu 2FA (TOTP)
    otp_token = StringField('Kod z aplikacji Authenticator', validators=[
        DataRequired(),
        Length(min=6, max=6, message="Kod musi mieć 6 cyfr"),# Kod TOTP ma zawsze 6 cyfr
        Regexp(r'^\d{6}$', message="Wpisz tylko cyfry")
    ])
    submit = SubmitField('Weryfikuj')


class ResetPasswordRequestForm(FlaskForm):
    # Formularz, w którym użytkownik podaje email, aby zresetować hasło
    username = StringField('Adres Email', validators=[DataRequired(message="Podaj adres email, na który chcesz otrzymać kod do resetu hasła"),Length(min=4, max=100),
        Regexp(r'^[\w\.-]+@[\w\.-]+\.\w+$', message=f"Email niepoprawny, adres email powinien wyglądać następująco: user@example.com")
    ])
    submit = SubmitField('Wyślij kod resetu hasła')
    # Niestandardowa walidacja (metody zaczynające się od validate_ są automatycznie uruchamiane przez Flask-WTF)
    def validate_provided_email(self, field):
        # import User modelu wewnątrz metody, aby uniknąć cyklicznych importów
        from app.models import User
        user = User.query.filter_by(username=field.data).first()
        if user is None:
            print(f"[VALIDATION] Nie znaleziono użytkownika z emailem: {field.data}")
        
class ResetPasswordForm(FlaskForm):
    # Formularz do ustawienia nowego hasła po kliknięciu w link resetujący
    password = PasswordField('Hasło', validators=[
        DataRequired(message="Wpisz nowe hasło"),
        Length(min=8, max=24, message="Nowe Hasło musi mieć od 8 do 24 znaków"),
        #Regex do wymuszenia złożoności hasła jedna mała litera, jedna duża litera, jedna cyfra, jeden znak specjalny
        Regexp(r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^A-Za-z0-9]).{8,24}$', message="Nowe Hasło musi zawierać małą i dużą literę, cyfrę oraz znak specjalny")
    ])
    
    confirm_password = PasswordField('Potwierdź hasło', validators=[
        DataRequired(),
        EqualTo('password', message='Hasła muszą być identyczne')
    ])

    submit = SubmitField('Zmień hasło')