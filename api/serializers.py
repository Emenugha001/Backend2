# from django.contrib.auth.models import User
# from rest_framework import serializers
# from .models import User
# from .models import User, EncryptedFile
# from django.contrib.auth import authenticate


# class UserRegisterSerializer(serializers.ModelSerializer):
#         password=serializers.CharField(max_length=68, min_length=6, write_only=True)
#         confirm_password=serializers.CharField(max_length=68, min_length=6,write_only=True)
#         role = serializers.ChoiceField(choices=['user', 'admin'], write_only=True)  # Role selection
        
#         class Meta:
#             model = User
#             fields = ["name","phonenumber","email","password","confirm_password","role"]
#             extra_kwargs = {"password": {"write_only": True}} 


#         # this tell django that we want to accept password when we are 
#         #creating a new user but not return the password when we are giving
#         # information about the user therefore the password isn't seen.

#         def validate(self,attrs):
#             password=attrs.get('password', '')
#             confirm_password=attrs.get('confirm_password', '')

#             if password !=confirm_password: #password2=confirm password
#                 raise serializers.ValidationError('passwords do not match')
#             return super().validate(attrs)

#         def create (self,validated_data):
#             validated_data.pop('confirm_password', None)
#             role = validated_data.pop('role', 'user')  # Default to 'user' role if not provided

#             user = User.objects.create_user (
#                 email=validated_data['email'],
#                 name=validated_data.get('name'),
#                 phonenumber=validated_data.get('phonenumber'),
#                 password=validated_data.get('password'),
#                 role=role, 
#                 #is_active=False
#             )
#             return user
        

# class UserLoginSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     password = serializers.CharField(write_only=True)

#     def validate(self, data):
#         email = data.get('email')
#         password = data.get('password')

#         if email and password:
#             raise serializers.ValidationError('Both email and password are required.')
#         user = authenticate(email=email, password=password)

#         if user is None:
#             raise serializers.ValidationError('Invalid email or password.')
        
#         if not user.is_active:
#             raise serializers.ValidationError('Account is inactive.')
        
#         if not user.is_verified:
#             raise serializers.ValidationError('Email is not verified.')
        
#         data['user'] = user
#         # else:
#         # raise serializers.ValidationError('Must provide email and password.')

#         return data

        
# # class FileUploadSerializer(serializers.ModelSerializer):
# #     file = serializers.FileField(write_only=True)

# #     class Meta:
# #         model = EncryptedFile
# #         fields = ['file', 'original_filename']
# #         read_only_fields = ['owner', 'encrypted_filename', 'file_size', 'content_type']

# #     def create(self, validated_data):
# #         user = self.context['request'].user
# #         validated_data['owner'] = user
# #         validated_data['original_filename'] = validated_data['file'].name
# #         return super().create(validated_data)
    
# #     class FileListSerializer(serializers.ModelSerializer):
# #       class Meta:
# #         model = EncryptedFile
# #         fields = ['id', 'original_filename', 'file', 'owner']  # Add more fields as needed


# # class FileDownloadSerializer(serializers.ModelSerializer):
# #     class Meta:
# #         model = EncryptedFile
# #         fields = ['file', 'original_filename']  # You may need to implement logic for decryption


# class FileUploadSerializer(serializers.ModelSerializer):
#     file = serializers.FileField(write_only=True)

#     class Meta:
#         model = EncryptedFile
#         fields = ['file', 'original_filename']
#         read_only_fields = ['owner', 'encrypted_filename', 'file_size', 'content_type', 'uploaded_at']

#     def create(self, validated_data):
#         request = self.context['request']
#         user = request.user
#         uploaded_file = validated_data.pop('file')
        
#         # Create EncryptedFile instance
#         encrypted_file = EncryptedFile(
#             owner=user,
#             original_filename=uploaded_file.name,
#             file_size=uploaded_file.size,
#             content_type=mimetypes.guess_type(uploaded_file.name)[0] or 'application/octet-stream'
#         )
        
#         # Read and encrypt file content
#         file_content = uploaded_file.read()
#         encrypted_file.encrypt_file(file_content)
#         encrypted_file.save()
        
#         return encrypted_file


# class FileListSerializer(serializers.ModelSerializer):
#     owner_email = serializers.CharField(source='owner.email', read_only=True)
#     owner_name = serializers.CharField(source='owner.name', read_only=True)

#     class Meta:
#         model = EncryptedFile
#         fields = [
#             'id', 'original_filename', 'file_size', 'content_type', 
#             'uploaded_at', 'owner_email', 'owner_name'
#         ]  # Add more fields as needed


# class FileDownloadSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = EncryptedFile
#         fields = ['file', 'original_filename']  # You may need to implement logic for decryption


from django.contrib.auth import get_user_model, authenticate
from rest_framework import serializers
import mimetypes
from .models import EncryptedFile

User = get_user_model()

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    confirm_password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    role = serializers.ChoiceField(choices=['user', 'admin'], write_only=True)  # Role selection

    class Meta:
        model = User
        fields = ["name", "phonenumber", "email", "password", "confirm_password", "role"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, attrs):
        password = attrs.get('password', '')
        confirm_password = attrs.get('confirm_password', '')
        if password != confirm_password:
            raise serializers.ValidationError('Passwords do not match')
        return super().validate(attrs)

    def create(self, validated_data):
        validated_data.pop('confirm_password', None)
        role = validated_data.pop('role', 'user')  # Default role if not provided

        user = User.objects.create_user(
            email=validated_data['email'],
            name=validated_data.get('name'),
            phonenumber=validated_data.get('phonenumber'),
            password=validated_data.get('password'),
            role=role,
            # is_active=False  # Optional: activate after verification
        )
        return user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            raise serializers.ValidationError('Both email and password are required.')

        user = authenticate(email=email, password=password)

        if user is None:
            raise serializers.ValidationError('Invalid email or password.')

        if not user.is_active:
            raise serializers.ValidationError('Account is inactive.')

        if not user.is_verified:
            raise serializers.ValidationError('Email is not verified.')

        data['user'] = user
        return data
    

class FileUploadSerializer(serializers.ModelSerializer):
    # File field
    file = serializers.FileField(write_only=True)
    
    # New fields for additional metadata
    description = serializers.CharField(max_length=255, required=False)
    tags = serializers.ListField(child=serializers.CharField(max_length=50), required=False)

    class Meta:
        model = EncryptedFile
        fields = ['file', 'original_filename', 'description', 'tags']
        read_only_fields = ['owner', 'file_size', 'content_type', 'uploaded_at']

    def create(self, validated_data):
        # Extracting request and user
        request = self.context.get('request')
        user = request.user
        
        # Extract the file from the validated data
        uploaded_file = validated_data.pop('file')
        
        # Create the EncryptedFile instance (with metadata)
        encrypted_file = EncryptedFile(
            owner=user,
            original_filename=uploaded_file.name,
            file_size=uploaded_file.size,
            content_type=mimetypes.guess_type(uploaded_file.name)[0] or 'application/octet-stream',
            description=validated_data.get('description', ''),
            tags=validated_data.get('tags', [])
        )

        # Read the file content and encrypt it
        file_content = uploaded_file.read()
        encrypted_file.encrypt_file(file_content)  # Ensure this method exists in your model
        
        # Save the file
        encrypted_file.save()

        return encrypted_file



# class FileUploadSerializer(serializers.ModelSerializer):
#     file = serializers.FileField(write_only=True)

#     class Meta:
#         model = EncryptedFile
#         fields = ['file', 'original_filename']
#         read_only_fields = ['owner', 'file_size', 'content_type', 'uploaded_at']

#     def create(self, validated_data):
#         request = self.context.get('request')
#         user = request.user
#         uploaded_file = validated_data.pop('file')

#         encrypted_file = EncryptedFile(
#             owner=user,
#             original_filename=uploaded_file.name,
#             file_size=uploaded_file.size,
#             content_type=mimetypes.guess_type(uploaded_file.name)[0] or 'application/octet-stream',
#         )

#         file_content = uploaded_file.read()
#         encrypted_file.encrypt_file(file_content)  # Make sure this method exists in your model
#         encrypted_file.save()

#         return encrypted_file


class FileListSerializer(serializers.ModelSerializer):
    owner_email = serializers.CharField(source='owner.email', read_only=True)
    owner_name = serializers.CharField(source='owner.name', read_only=True)

    class Meta:
        model = EncryptedFile
        fields = [
            'id', 'original_filename', 'file_size', 'content_type',
            'uploaded_at', 'owner_email', 'owner_name'
        ]


class FileDownloadSerializer(serializers.ModelSerializer):
    class Meta:
        model = EncryptedFile
        fields = ['file', 'original_filename']  # Implement decryption logic if needed

