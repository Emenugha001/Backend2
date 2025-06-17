from django.contrib import admin
from .models import User, EncryptedFile

# Register your models here.
admin.site.register(User)
admin.site.register(EncryptedFile)