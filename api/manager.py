from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _


class UserManager(BaseUserManager):
    def email_validator(self,email):
        try:
            validate_email(email)
        except ValidationError:
            raise ValueError(_("Please enter a valid email address"))
        
    def create_user(self,email,name,phonenumber,password, **extra_fields):
        if email:
            email=self.normalize_email(email)
            self.email_validator(email)
        else:
            raise ValueError(_("an email address is required"))
        if not name:
            raise ValueError(_("name is required"))
        if not phonenumber:
            raise ValueError(_("phonenumber is required"))
        user=self.model(email=email,name=name,phonenumber=phonenumber, **extra_fields)
        user.set_password(password)
        user.save(using=self.db)
        return user
    
    def create_superuser(self,email,name,phonenumber,password, **extrafields):
        extrafields.setdefault("is_staff", True)
        extrafields.setdefault("is_superuser", True)
        extrafields.setdefault("is_verified", True)

        if extrafields.get("is_staff") is not True:
            raise ValueError(_("is staff must be true for admin user"))
        
        if extrafields.get("is_superuser") is not True:
            raise ValueError(_("is staff must be true for admin user"))
        
        user=self.create_user(
            email,name,phonenumber,password, **extrafields
        )

        user.save(using=self._db)
        return user

        