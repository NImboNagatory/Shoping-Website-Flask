import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_mail(username, message_user, receiver_email):
    sender_email = 'NiceWebPassCode@proton.me'
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = "Nice Shop"
    message = f"Hello {username}\n\nPasscode:\n{message_user}"
    msg.attach(MIMEText(message))
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL('localhost', 465, context=context) as server:
        server.login(sender_email, "Charly68686")
        server.sendmail(sender_email, receiver_email, msg.as_string())


send_mail("nika", "hello", "lukashinjikashvili84@gmail.com")
