#Local Imports
from account.models import User
from django.core.mail import EmailMessage
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
import random
from django.core.mail import send_mail
from django.utils.timezone import now
from datetime import timedelta
import smtplib
import requests
#from account.models import User


def generate_otp():
    """Generate a 6-digit OTP."""
    return str(random.randint(100000, 999999))



MAILBOXLAYER_API_KEY = "174a091903d7498d28a646f6c9f85d29"

def is_valid_email(email):
    """Check if the email exists using MailboxLayer API with improved validation."""
    url = f"http://apilayer.net/api/check?access_key={MAILBOXLAYER_API_KEY}&email={email}&smtp=1&format=1"

    try:
        response = requests.get(url)
        data = response.json()
        
        print("📩 MailboxLayer Response:", data)  # Debugging response

        # Validate based on multiple fields
        if (
            data.get("format_valid")  # Valid email format
            and data.get("mx_found")  # Domain has MX records
            and not data.get("disposable", False)  # Not a temporary email
        ):
            return True  # Email is valid enough for registration

        return False  # Invalid email based on our criteria

    except Exception as e:
        print(f"❌ Error validating email: {e}")
        return False


def send_otp_email(user):
    """Send OTP to user's email using SMTP settings with UTF-8 encoding."""
    otp = generate_otp()
    user.otp = otp
    user.otp_expires_at = now() + timedelta(minutes=1)  # OTP valid for 1 minutes
    user.save()

    subject = "Your OTP Code"
    message = f"Hello {user.name},\n\nYour OTP for registration is {otp}. It will expire in 1 minutes.\n\nThank you."

    # Ensure no non-breaking spaces or special characters
    message = message.replace("\xa0", " ").strip()
    subject = subject.strip()

    # Ensure user email is clean
    recipient_email = user.email.strip()

    # Create and send email
    email = EmailMessage(
        subject,
        message,
        settings.EMAIL_HOST_USER,  # Sender email from settings.py
        [recipient_email],  # Recipient
    )
    email.content_subtype = "plain"  # Ensure plain text email
    email.encoding = "utf-8"  # Explicitly set UTF-8 encoding

    try:
        email.send(fail_silently=False)
        print(f"OTP email sent successfully to {recipient_email}")
    except smtplib.SMTPException as e:
        print(f"Error sending email: {e}")



# def verify_otp(user, otp):
#     """Verify OTP."""
#     if user.is_otp_valid() and user.otp == otp:
#         user.is_active = True  # Activate user after successful OTP verification
#         user.otp = None
#         user.otp_expires_at = None
#         user.save()
#         return True
#     return False

def verify_otp(user, otp):
    """Verify OTP with expiration handling."""
    if not user.otp:  
        return "invalid"  # No OTP exists

    if not user.is_otp_valid():  
        return "expired"  # OTP has expired

    if user.otp != otp:  
        return "invalid"  # OTP is incorrect

    # OTP is valid, activate the user
    user.is_active = True
    user.otp = None
    user.otp_expires_at = None
    user.save()
    return "valid"


def get_user_by_email(email):
  users = User.objects.filter(email=email)
  if users.exists():
    return users.first()
  return None


def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  access = refresh.access_token

  access['name'] = user.name
  access['email'] = user.email
  access['is_admin'] = user.is_admin

  return {
    'refresh': str(refresh),
    'access': str(access),
  }
