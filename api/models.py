from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.hashers import make_password
import uuid
import os
from cryptography.fernet import Fernet
from django.conf import settings


 # Load encryption key securely from env
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    raise Exception("ENCRYPTION_KEY environment variable not set!")
fernet = Fernet(ENCRYPTION_KEY.encode())


class UserManager(BaseUserManager):
    def create_user(self, email, name, phonenumber, password=None,**extra_fields):

    
    
        if not email:
            raise ValueError(_("The Email field must be set"))
        email = self.normalize_email(email)
        user = self.model(email=email, name=name, phonenumber=phonenumber, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, phonenumber, password=None, **extra_fields):
        """
        Create and return a superuser with an email, name, phone number, and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_verified', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', 'admin')

        return self.create_user(email, name, phonenumber, password, **extra_fields)


# Custom User Model

ROLE_CHOICES = (
    ('user', 'User'),
    ('admin', 'Admin'),
)

class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, verbose_name=_("name"))
    phonenumber = models.CharField(max_length=20, blank=True, null=True, verbose_name=_("phone number"))
    email = models.EmailField(max_length=255, unique=True, verbose_name=_("E-mail"))
    password = models.CharField(max_length=128, verbose_name=_("password"))
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    verification_token = models.UUIDField(default=uuid.uuid4,  editable=False)
    role = models.CharField(max_length=10, choices= ROLE_CHOICES, default='user')

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "phonenumber", "password"]

    objects = UserManager()

    # Adding related_name to prevent clashes in reverse relationships
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_groups',  # This will resolve the conflict
        blank=True,
        verbose_name=_('groups')
    )

    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_permissions',  # This will resolve the conflict
        blank=True,
        verbose_name=_('user permissions')
    )

    def __str__(self):
        return self.email

    def get_name(self):
        return self.name

    def set_password(self, raw_password):
        """
        Sets a hashed password for the user.
        """
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        """
        Checks the raw password against the stored hashed password.
        """
        from django.contrib.auth.hashers import check_password
        return check_password(raw_password, self.password)
    

class EncryptedFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='files', blank=True, null=True)
    file = models.FileField(upload_to='encrypted_files/')
    original_filename = models.CharField(max_length=255)
    encrypted_filename = models.CharField(max_length=255, blank=True)
    file_size = models.PositiveIntegerField(default=0)
    content_type = models.CharField(max_length=100, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Encrypt file before saving
        if self.file and not self.file.closed:
            self.file.open('rb')
            data = self.file.read()
            self.file.close()

             # Store file size before encryption
            if not self.file_size:
                self.file_size = len(data)

                #encryts file data
            encrypted_data = fernet.encrypt(data)

            # Reset the file field with encrypted content
            from django.core.files.base import ContentFile
            self.file.save(self.original_filename, ContentFile(encrypted_data), save=False)

        super().save(*args, **kwargs)

    def get_decrypted_file(self):
        # Return decrypted bytes to serve for download

        if not self.file:
            return None
            
        self.file.open('rb')
        encrypted_data = self.file.read()
        self.file.close()
        decrypted_data = fernet.decrypt(encrypted_data)
        return decrypted_data
    
    def __str__(self):
        if self.owner:
            return f"{self.original_filename} (Owner: {self.owner.name})"
        return self.original_filename
    
    class Meta:
        ordering = ['-uploaded_at']
    
class OneTimePassword(models.Model):
    user=models.OneToOneField(User,on_delete=models.CASCADE)
    code=models.CharField(max_length=6, unique=True)

    def _str_(self):
        return f"{self.user.name}- passcode: {self.code}"
