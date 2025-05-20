'''from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as  _
from django.contrib.auth.hashers import make_password
from .manager import UserManager

# Create your models here.
#build user model from scratch,import abstract model

class User (AbstractBaseUser, PermissionsMixin):
    name= models.CharField(max_length=100, verbose_name=_("name"))
    phone_number = models.CharField(max_length=20, verbose_name=_("phone number"))
    email=models.EmailField(max_length=255, unique=True, verbose_name=_("E-mail"))
    password = models.CharField(max_length=128, verbose_name=_("password"))
    is_staff=models.BooleanField(default=False)
    is_superuser=models.BooleanField(default=False)
    is_verfied=models.BooleanField(default=False)
    is_active=models.BooleanField(default=True)
    date_joined =models.DateTimeField(auto_now_add=True)
    last_login=models.DateTimeField(auto_now=True)

    USERNAME_FIELDS="email"

    REQUIRED_FIELD=["name","phonenumber","password"]

    objects=UserManager()

    def __str__(self):
        return self.email
    
    def get_name(self):
        return f"{self.name}"

    def set_password(self, raw_password):
    
        #Sets a hashed password for the user.
    
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        
        #Checks the raw password against the stored hashed password.
        
        from django.contrib.auth.hashers import check_password
        return check_password(raw_password, self.password)
    
    def tokens(self):
        pass
        
        '''

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.hashers import make_password
import uuid

class UserManager(BaseUserManager):
    def create_user(self, email, name, phonenumber, password=None):
        if not email:
            raise ValueError(_("The Email field must be set"))
        email = self.normalize_email(email)
        user = self.model(email=email, name=name, phonenumber=phonenumber)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, phonenumber, password=None):
        user = self.create_user(email=email, name=name, phonenumber=phonenumber, password=password,  is_active=True)
        user.is_staff = True
        #user.is_superuser = True
        user.is_verified = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser, PermissionsMixin):
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
    
class OneTimePassword(models.Model):
    user=models.OneToOneField(User,on_delete=models.CASCADE)
    code=models.CharField(max_length=6, unique=True)

    def _str_(self):
        return f"{self.user.name}- passcode"
