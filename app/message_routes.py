from flask import Blueprint, render_template, redirect, url_for, flash, session, request, send_file
from flask_login import login_required, current_user
from datetime import datetime, timezone
import io
from werkzeug.utils import secure_filename

from models import DATABASE, User, Message, Attachment
from forms import  CreateMessageForm
from crypto import password_manager as crypto_manager

# Definiujemy blueprint dla scieżki wiadomości
message_bp = Blueprint('message', __name__)

@message_bp.route('/inbox')
@login_required
def inbox():
    # Pobieramy wiadomości posortowane od najnowszych gdzie recipient to obecnie zalogowany uzytkownik
    # sortujemy po dacie ( pobieramy same metadane)
    messages = current_user.messages_received.order_by(Message.timestamp.desc()).all()
    return render_template('inbox.html', messages=messages)

# tworzenie wiadomości
@message_bp.route('/compose', methods=['GET', 'POST'])
@login_required
def compose():
    form = CreateMessageForm()
    # sprawdzamy wypełniony formularz
    if form.validate_on_submit():
        #czy odbiorca podany istnieje w bazie?
        recipient = User.query.filter_by(username=form.recipient.data).first()
        #jak nie:
        if not recipient:
            flash("Nie znaleziono użytkownika o takim adresie email.", "error")
            return render_template('compose.html', form=form)
        # jak tak:
        try:
            # pobieramy klucz pochodny z sesji przeglądarki, zapisany podczas logowania 
            # będzie to klucz do odszyfrowania naszego klucza prywatnego, niezbędne jeśli chodzi o cykl życia wiadomości
            derived_key = session.get('decryption_key')
            
            if not derived_key:
                flash("Sesja kryptograficzna wygasła. Zaloguj się ponownie.", "error")
                return redirect(url_for('auth.login'))

            #  Odszyfrowujemy klucz prywatny RSA z bazy używając klucza z sesji przegladarki
            # (nie potrzebujemy już soli ani hasła tutaj, bo klucz jest gotowy), natomiast musimy odzyskać klucz z bazy by użyc go do podpisu
            my_private_key = crypto_manager.get_decrypted_private_key_with_derived_key(
                current_user.encrypted_private_key,
                derived_key
            )
            
            if not my_private_key:
                 flash("Błąd klucza szyfrującego. Zmień hasło lub zaloguj się ponownie.", "error")
                 return redirect(url_for('auth.login'))

            # Generujemy jednorazowy KLUCZ SESJI (AES) ten konkretny jednorazowy klucz jest dla tej konkretnej wiadomosci 
            # potrzebujemy go bo normalnie RSA z kluczem 2048 bit moze zakodowac tylko ok 255 bajtow a tak to uzywamy hybrydy
            session_key = crypto_manager.generate_session_key()

            # szyfrujemy wiadomość powyżej utworzonym jednorazowym kluczem wiadomości
            encrypted_content = crypto_manager.encrypt_data_symmetric(
                form.content.data.encode('utf-8'), 
                session_key
            )

            # Szyfrujemy dodatkowo klucz sesji wiadomości, kluczem publicznym Odbiorcy (może wtedy prywatnym go sobie odszyfrować i odczytać wiadomość)
            encrypted_aes_key = crypto_manager.encrypt_session_key(
                session_key, 
                recipient.public_key
            )

            #  Tworzymy podpis cyfrowy (skrót wiadomości zaszyfrowany naszym kluczem prywatnym)
            # Podpisujemy oryginalną (jawną) treść
            signature = crypto_manager.sign_message(
                form.content.data.encode('utf-8'),
                my_private_key
            )

            # Zapisujemy wiadomość w bazie 
            new_msg = Message(
                sender=current_user,
                recipient=recipient,
                subject=form.subject.data, # Temat jawny
                encrypted_content=encrypted_content.decode('utf-8'), # Text w bazie
                encrypted_aes_key=encrypted_aes_key,
                signature=signature,
                timestamp=datetime.now(timezone.utc)
            )
            DATABASE.session.add(new_msg)
            
            #  Obsługa załącznika
            if form.attachment.data:
                # jeśli plik istnieje to go wczytujemy
                file = form.attachment.data
                filename = secure_filename(file.filename)
                file_bytes = file.read()
                
                if len(file_bytes) > 5 * 1024 * 1024:
                    flash("Podano zbyt duży plik! Maksymalny rozmiar to 5MB.", "error")
                    DATABASE.session.rollback()
                    # cofnelismy wiadomosc bo nie chcemy jej wysylac bez załącznika
                    return render_template('compose.html',form=form)

                # Szyfrujemy plik (w postaci bajtów) TYM SAMYM kluczem sesji co treść
                encrypted_file = crypto_manager.encrypt_data_symmetric(file_bytes, session_key)
                # i tak samo zapisujemy tylko, że w tabeli attachments
                attachment = Attachment(
                    message=new_msg,
                    filename=filename,
                    content_type=file.content_type,
                    encrypted_data=encrypted_file, # Binary
                    file_size=len(file_bytes)
                )
                DATABASE.session.add(attachment)
            # logujemy sesje
            DATABASE.session.commit()
            flash("Wiadomość została zaszyfrowana i wysłana bezpiecznie.", "success")
            return redirect(url_for('message.inbox'))

        except Exception as e:
            print(f"Błąd szyfrowania: {e}")
            flash("Wystąpił błąd podczas szyfrowania wiadomości.", "error")
            
    return render_template('compose.html', form=form)


# odbieranie wiadomości 
@message_bp.route('/message/<int:message_id>')
@login_required
def view_message(message_id):
    msg = Message.query.get_or_404(message_id)
    
    # Sprawdzamy czy to nasza wiadomość
    if msg.recipient_id != current_user.id and msg.sender_id != current_user.id:
        flash("Brak dostępu.", "error")
        return redirect(url_for('message.inbox'))

    # Oznaczamy jako przeczytaną bo już w nią weszliśmy, ikona w template z inbox się zmieni gdy ustawimy flagę is_read na 1
    if msg.recipient_id == current_user.id and not msg.is_read:
        msg.is_read = True
        DATABASE.session.commit()

    decrypted_content = None
    signature_valid = None
    verification_error = False

    # Próba odszyfrowania (tylko jeśli jesteśmy ODBIORCĄ)
    # Nadawca nie może odszyfrować własnej wysłanej wiadomości (bo zaszyfrował ją kluczem publicznym odbiorcy!)
    if msg.recipient_id == current_user.id:
        try:
            # Odszyfrowujemy swój klucz prywatny
            # najpierw pobieramy klucz z sesji przeglądarki potrzebny do wydobycia klucza prywatnego RSA
            derived_key = session.get('decryption_key')
            if not derived_key:
                flash("Sesja kryptograficzna wygasła. Zaloguj się ponownie.", "warning")
            else:
                # Odszyfrowujemy klucz prywatny z bazy przy pomocy klucza sesji przeglądarki
                my_private_key = crypto_manager.get_decrypted_private_key_with_derived_key(
                    current_user.encrypted_private_key,
                    derived_key
                )
                # jeśli coś poszło nie tak to lipa xd
                if not my_private_key:
                    flash("Błąd klucza. Zaloguj się ponownie.", "error")
                    return redirect(url_for('auth.login'))

                # Odszyfrowujemy klucz sesji wiadomości (AES) tej konkretnej wiadomości przy pomocy odkopanego private_key z bazy (pamiętamy jest on powiązany z puvlicznym użytym do zakodowania!)
                # (Musimy to zrobić zanim spróbujemy go zapisać lub użyć!)
                session_key = crypto_manager.decrypt_session_key(
                    msg.encrypted_aes_key,
                    my_private_key
                )
                
                # Zapisujemy klucz sesji wiadomości (bajty) w sesji przeglądarki (dla pobierania załączników)
                # Musi być serializowalny, więc najlepiej jako bytes
                session[f'msg_key_{msg.id}'] = session_key

                #  Odszyfrowujemy treść
                content_bytes = crypto_manager.decrypt_data_symmetric(
                    msg.encrypted_content.encode('utf-8'),
                    session_key 
                )
                decrypted_content = content_bytes.decode('utf-8')

                #  Weryfikujemy podpis nadawcy, biorąc odszyfrowaną treść i podpis oraz klucz publiczny nadawcy z bazy w końcu dostępny
                # i przy użyciu tego klucza jeśli po odszyfrowaniu podpisu bajty zgadzają się z kontentem wiadomości mamy sukces jeśli nie to znaczy że ktoś 
                # grzebał w treści wiadomości 
                signature_valid = crypto_manager.verify_signature(
                    content_bytes,
                    msg.signature,
                    msg.sender.public_key
                )

        except Exception as e:
            print(f"Błąd deszyfrowania: {e}")
            verification_error = True

    return render_template('view_message.html', 
                           msg=msg, 
                           content=decrypted_content, 
                           signature_valid=signature_valid,
                           error=verification_error)

# metoda na obszarze ikonki śmietnika przy wiadomości
@message_bp.route('/message/<int:message_id>/delete', methods=['POST'])
@login_required
def delete_message(message_id):
    msg = Message.query.get_or_404(message_id)
    # tylko właściciel wiadomości może usunąć wiadomość z bazy
    if msg.recipient_id != current_user.id:
        flash("Nie możesz usunąć tej wiadomości.", "error")
        return redirect(url_for('message.inbox'))
    # logujemy kwerende
    DATABASE.session.delete(msg)
    DATABASE.session.commit()
    flash("Wiadomość usunięta.", "info")
    return redirect(url_for('message.inbox'))

@message_bp.route('/attachment/<int:attachment_id>')
@login_required
def download_attachment(attachment_id):
    att = Attachment.query.get_or_404(attachment_id)
    msg = att.message
    # sprawdzamy czy jesteśmy odbiorcą
    if msg.recipient_id != current_user.id:
        return "Brak dostępu", 403

    # Pobieramy klucz sesji z sesji użytkownika (zapisany przy otwieraniu wiadomości)
    session_key = session.get(f'msg_key_{msg.id}')
    
    if not session_key:
        flash("Musisz najpierw otworzyć wiadomość, aby odblokować załączniki.", "warning")
        return redirect(url_for('message.view_message', message_id=msg.id))

    try:
        # Odszyfrowanie pliku w locie na tej samej zasadzie co treść tylko że później
        decrypted_file = crypto_manager.decrypt_data_symmetric(
            att.encrypted_data,
            session_key
        )
        
        # wysyłamy odszyfrowane bajty do przeglądarki przy pomocy send_file 
        return send_file(
            io.BytesIO(decrypted_file),
            download_name=att.filename,
            as_attachment=True,
            mimetype=att.content_type
        )
    except Exception as e:
        print(f"Błąd pobierania: {e}")
        flash("Błąd odszyfrowywania pliku.", "error")
        return redirect(url_for('message.view_message', message_id=msg.id))