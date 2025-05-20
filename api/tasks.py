# from celery import shared_task
# from django.core.mail import EmailMessage
# from django.conf import settings
# from .models import User, OneTimePassword
# import random

# @shared_task
# def send_verification_code_to_user(email):
#     """Generate a verification code and send it to the user's email."""
#     verification_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])

#     user = User.objects.get(email=email)

#     email_body = f"Hi {user.name},\n\nThank you for signing up. Please use the following verification code to verify your email:\n\n{verification_code}\n\nBest regards,\nTeam"

#     subject = "Email Verification Code"
#     from_email = settings.EMAIL_HOST_USER

#     OneTimePassword.objects.create(user=user, code=verification_code)

#     # Send the email asynchronously with Celery
#     email = EmailMessage(subject=subject, body=email_body, from_email=from_email, to=[email])
#     email.send(fail_silently=True)


from celery import shared_task
from django.core.mail import EmailMessage
from django.conf import settings
from django.db import transaction
from api.utils import generate_verification_code
from .models import User, OneTimePassword
import random
import logging

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3)
def send_verification_code_to_user(self, email):
    
    try:
        # Generate a more secure verification code
        verification_code =  generate_verification_code()

        
        # Use get_or_404 or add proper error handling for non-existent users
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.error(f"Failed to send verification code: User with email {email} not found")
            return False
            
        # Create email content with better formatting
        email_body = f"""
        Hi {user.name},
        
        Thank you for signing up. Please use the following verification code to verify your email:
        
        {verification_code}
        
        This code will expire in 10 minutes.
        
        Best regards,
        Team
        """
        
        subject = "Your Email Verification Code"
        from_email = settings.DEFAULT_FROM_EMAIL  # Use DEFAULT_FROM_EMAIL instead
        
        # Use atomic transaction to ensure DB consistency
        with transaction.atomic():
            # Delete any existing OTPs for this user before creating a new one
            OneTimePassword.objects.filter(user=user).delete()
            OneTimePassword.objects.create(
                user=user, 
                code=verification_code,
                # Consider adding an expiry field in your model
            )
        
        # Send email with proper error handling
        email_message = EmailMessage(
            subject=subject, 
            body=email_body, 
            from_email=from_email, 
            to=[email]
        )
        email_message.send(fail_silently=False)  # Changed to raise exceptions
        
        logger.info(f"Verification code sent to {email}")
        return True
        
    except Exception as e:
        logger.exception(f"Error sending verification code to {email}: {str(e)}")
        # Retry the task with exponential backoff
        self.retry(exc=e, countdown=2 ** self.request.retries * 60)
        return False
    