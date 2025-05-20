from django.contrib.auth.models import User
from rest_framework import serializers
from .models import User

class UserRegisterSerializer(serializers.ModelSerializer):
        password=serializers.CharField(max_length=68, min_length=6, write_only=True)
        confirm_password=serializers.CharField(max_length=68, min_length=6,write_only=True)
        
        class Meta:
            model = User
            fields = ["name","phonenumber","email","password","confirm_password"]
            extra_kwargs = {"password": {"write_only": True}} 


        # this tell django that we want to accept password when we are 
        #creating a new user but not return the password when we are giving
        # information about the user therefore the password isn't seen.

        def validate(self,attrs):
            password=attrs.get('password', '')
            confirm_password=attrs.get('confirm_password', '')
            if password !=confirm_password: #password2=confirm password
                raise serializers.ValidationError('passwords do not match')
            return super().validate(attrs)

        def create (self,validated_data):
            user = User.objects.create_user (
                email=validated_data['email'],
                name=validated_data.get('name'),
                phonenumber=validated_data.get('phonenumber'),
                password=validated_data.get('password'),
                #is_active=False
            )
            return user
        
        