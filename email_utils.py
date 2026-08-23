import os
import random
import resend
from dotenv import load_dotenv

load_dotenv()

resend.api_key = os.getenv("RESEND_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL")

def generate_otp() -> str:
    return str(random.randint(100000, 999999))

def send_otp_email(to_email: str, otp_code: str, purpose: str = "verify"):
    if purpose == "reset":
        subject = "Reset your Elitexbets password"
        body = f"Your password reset code is: {otp_code}\n\nThis code expires in 10 minutes. If you didn't request this, you can safely ignore this email."
    else:
        subject = "Your Picks by Elitexbets verification code"
        body = f"Your verification code is: {otp_code}\n\nThis code expires in 10 minutes."

    resend.Emails.send({
        "from": f"Picks by Elitexbets <{FROM_EMAIL}>",
        "to": [to_email],
        "subject": subject,
        "text": body,
    })