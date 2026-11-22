
import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()


def send_otp_email(receiver_email, otp):
    smtp_server = os.getenv("BREVO_SMTP_SERVER")
    smtp_port = int(os.getenv("BREVO_SMTP_PORT", 587))
    smtp_login = os.getenv("BREVO_SMTP_LOGIN")
    smtp_key = os.getenv("BREVO_SMTP_KEY")
    sender_email = os.getenv("BREVO_SENDER_EMAIL")
    sender_name = os.getenv("BREVO_SENDER_NAME", "ARGUS")

    if not all([smtp_server, smtp_login, smtp_key, sender_email]):
        raise ValueError("Brevo SMTP configuration is incomplete.")

    message = EmailMessage()
    message["Subject"] = "ARGUS - Email Verification OTP"
    message["From"] = f"{sender_name} <{sender_email}>"
    message["To"] = receiver_email

    message.set_content(
        f"""
Hello,

Your ARGUS email verification OTP is: {otp}

This OTP is valid for 5 minutes.

If you did not request this verification, please ignore this email.

Regards,
ARGUS Security Team
"""
    )

    with smtplib.SMTP(smtp_server, smtp_port, timeout=20) as server:
        server.starttls()
        server.login(smtp_login, smtp_key)
        server.send_message(message)

    return True
