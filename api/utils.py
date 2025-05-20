

# import random
# from django.core.mail import EmailMessage
# from .models import User, OneTimePassword
# from django.conf import settings

# def generate_verification_code():
#     """Generate a random 6-digit verification code."""
#     verification_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
#     return verification_code

# def send_verification_code_to_user(email):
#     """Generate a verification code and send it to the user's email."""
#     # Generate the verification code
#     verification_code = generate_verification_code()

#     # Retrieve user by email
#     user = User.objects.get(email=email)

#     # Site name (can be dynamically set based on your environment)
#     #current_site = "myAuth.com"

#     # Prepare the email body
#     email_body = f"Hi {user.name},\n\nThank you for signing up on. Please use the following verification code to verify your email:\n\n{verification_code}\n\nBest regards,\n Team"

#     # Send email using the system's configured email host
#     subject = "Email Verification Code"
#     from_email = settings.EMAIL_HOST_USER  # Make sure this is set in your settings

#     # Save the generated verification code in the OneTimePassword model (or a related model)
#     OneTimePassword.objects.create(user=user, code=verification_code)

#     # Send the email with the verification code
#     email = EmailMessage(subject=subject, body=email_body, from_email=from_email, to=[email])
#     email.send(fail_silently=True)


import random
import string
import logging
from django.core.mail import EmailMessage
from django.conf import settings
from django.db import transaction
from .models import User, OneTimePassword

logger = logging.getLogger(__name__)

def generate_verification_code(length=6):
    
    return ''.join([str(random.randint(0, 9)) for _ in range(length)])

def get_user_by_email(email):
    """
    Safely retrieve a user by email.
    
    Args:
        email (str): Email address to look up.
        
    Returns:
        tuple: (User object, error message). If user is found, error is None.
    """
    try:
        return User.objects.get(email=email), None
    except User.DoesNotExist:
        error_msg = f"User with email {email} not found"
        logger.error(error_msg)
        return None, error_msg

def create_verification_code_for_user(user, code_length=6, expiry_minutes=10):
    """
    Create a new verification code for a user, removing any existing ones.
    
    Args:
        user (User): User object to create code for.
        code_length (int): Length of verification code to generate.
        expiry_minutes (int): Minutes until the code expires.
        
    Returns:
        str: The generated verification code.
    """
    code = generate_verification_code(code_length)
    
    with transaction.atomic():
        # Delete any existing codes for this user
        OneTimePassword.objects.filter(user=user).delete()
        
        # Create new code
        # Note: You may need to add an 'expires_at' field to your OneTimePassword model
        # and set it here using: from django.utils import timezone
        # expires_at = timezone.now() + timezone.timedelta(minutes=expiry_minutes)
        OneTimePassword.objects.create(
            user=user, 
            code=code,
            # expires_at=expires_at  # Uncomment if you add this field
        )
    
    return code

def format_verification_email(user_name, verification_code, expiry_minutes=10):
    """
    Format the email body with verification code.
    
    Args:
        user_name (str): Name of the user.
        verification_code (str): The verification code.
        expiry_minutes (int): Minutes until the code expires.
        
    Returns:
        str: Formatted email body.
    """
    site_name = settings.SITE_NAME if hasattr(settings, 'SITE_NAME') else "our platform"
    
    return f"""Hello {user_name},

Thank you for signing up on {site_name}. To complete your registration, please use the verification code below:

{verification_code}

This code will expire in {expiry_minutes} minutes.

If you didn't request this code, please ignore this email.

Best regards,
The {site_name} Team
"""

def send_email(to_email, subject, body, from_email=None):
    """
    Send an email with proper error handling.
    
    Args:
        to_email (str): Recipient email address.
        subject (str): Email subject.
        body (str): Email body.
        from_email (str, optional): Sender email. Defaults to settings value.
        
    Returns:
        bool: True if sent successfully, False otherwise.
    """
    if from_email is None:
        # Prefer DEFAULT_FROM_EMAIL over EMAIL_HOST_USER for better configurability
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', settings.EMAIL_HOST_USER)
    
    try:
        email = EmailMessage(
            subject=subject,
            body=body,
            from_email=from_email,
            to=[to_email]
        )
        email.send(fail_silently=False)
        logger.info(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.exception(f"Failed to send email to {to_email}: {str(e)}")
        return False