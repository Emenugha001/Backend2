# from datetime import timezone
# from django.shortcuts import render
# from django.contrib.auth.models import User
# from django.contrib.auth import get_user_model, authenticate
# from rest_framework.generics import GenericAPIView
# from .serializers import UserRegisterSerializer, FileUploadSerializer
# from rest_framework.response import Response
# from rest_framework import status
# from rest_framework.permissions import IsAuthenticated, AllowAny
# from django.shortcuts import get_object_or_404
# from rest_framework.views import APIView
# from .tokens import email_verification_token
# from django.http import HttpResponse, Http404
# from rest_framework import generics, permissions, status
# from .models import OneTimePassword, User, EncryptedFile
# from .tokens import email_verification_token
# from rest_framework_simplejwt.tokens import RefreshToken
# from django.contrib.auth import authenticate
# # Import only from tasks, as that's what you're actually using with .delay()
# from .tasks import send_verification_code_to_user


# # Create your views here.

# class RegisterUserView(GenericAPIView):
#     serializer_class = UserRegisterSerializer
#     permission_classes = [AllowAny]

#     def get(self, request):
#         return Response(
#             {"message": "Please use POST to register a new user."},
#             status=status.HTTP_405_METHOD_NOT_ALLOWED
#         )

#     def post(self, request):
#         """Handle user registration and send verification email with a code."""
#         user_data = request.data
#         serializer = self.serializer_class(data=user_data)

#         if serializer.is_valid(raise_exception=True):
#             # Save the user and generate a verification code
#             user = serializer.save()

#              # If admin creates user, assign appropriate role
#             # Assuming the 'role' field is set in the serializer
#             role = user_data.get('role', 'user')

#             token = email_verification_token.make_token(user)

#             # Send verification code to the user's email using Celery task
#             send_verification_code_to_user.delay(user.email)

#             return Response({"message": "User created. Please verify your email."}, status=status.HTTP_201_CREATED)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




# class VerifyEmailView(APIView):
#     permission_classes = [AllowAny]  # Open endpoint, no auth needed

#     def post(self, request):
#         email = request.data.get("email")
#         token = request.data.get("verification_code")

#         if not email or not token:
#             return Response({"error": "Email and verification code are required."}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

#         if user.is_verified:
#             return Response({"message": "Email already verified."}, status=status.HTTP_400_BAD_REQUEST)

#         # Check if code exists and is valid for user
#         try:
#             otp = OneTimePassword.objects.get(user=user, code=token)
#             # Optional: check expiry if you have expires_at field
#             if hasattr(otp, 'expires_at') and otp.expires_at < timezone.now():
#                 return Response({"error": "Verification code has expired."}, status=status.HTTP_400_BAD_REQUEST)
#         except OneTimePassword.DoesNotExist:
#             return Response({"error": "Invalid verification code."}, status=status.HTTP_400_BAD_REQUEST)

#         # Code is valid, mark user verified and active
#         user.is_verified = True
#         user.is_active = True
#         user.save()

#         # Delete used OTP code to prevent reuse
#         otp.delete()

#         return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)

# class IsOwnerOrAdmin(permissions.BasePermission):
#     def has_object_permission(self, request, view, obj):
#         return getattr(request.user, 'is_superuser', False) or obj.owner == request.user


# # Upload files
# class FileUploadView(generics.CreateAPIView):
#     serializer_class = FileUploadSerializer
#     permission_classes = [permissions.IsAuthenticated]


# # List files
# class FileListView(generics.ListAPIView):
#     serializer_class = FileUploadSerializer
#     permission_classes = [permissions.IsAuthenticated]


#     def get_queryset(self):
#         user = self.request.user
        
#         # If user is admin (is_staff or role='admin')

#         if user.is_staff or user.role == 'admin':
#             return EncryptedFile.objects.all()  # Admin sees all files
#         else:
#             return EncryptedFile.objects.filter(owner=user)  # Regular user sees only their files
        
#     # def get_queryset(self):
#     #     user = self.request.user
#     #     if getattr(user, 'is_superuser', False):
#     #         return EncryptedFile.objects.all()
#     #     return EncryptedFile.objects.filter(owner=user)


# # Download file
# class FileDownloadView(APIView):
#     permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]

#     def get(self, request, pk):
#         try:
#             file_obj = EncryptedFile.objects.get(pk=pk)
#         except EncryptedFile.DoesNotExist:
#             raise Http404

#         self.check_object_permissions(request, file_obj)

#         decrypted_data = file_obj.get_decrypted_file()
#         response = HttpResponse(decrypted_data, content_type='application/octet-stream')
#         response['Content-Disposition'] = f'attachment; filename="{file_obj.original_filename}"'
#         return response


# # Delete file
# class FileDeleteView(generics.DestroyAPIView):
#     queryset = EncryptedFile.objects.all()
#     permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]



# class LoginView(APIView):
#     permission_classes = [AllowAny]  # Make login accessible without token

#     def post(self, request):
#         email = request.data.get('email')
#         password = request.data.get('password')

#         if not email or not password:
#             return Response(
#                 {"error": "Email and password are required."},
#                 status=status.HTTP_400_BAD_REQUEST
#             )

#         user = authenticate(request, email=email, password=password)
#         if user is None:
#             return Response(
#                 {"error": "Invalid credentials."},
#                 status=status.HTTP_401_UNAUTHORIZED
#             )

#         if not user.is_active:
#             return Response(
#                 {"error": "Account is inactive."},
#                 status=status.HTTP_403_FORBIDDEN
#             )

#         if not user.is_verified:
#             return Response(
#                 {"error": "Email is not verified."},
#                 status=status.HTTP_403_FORBIDDEN
#             )

#         # Generate JWT tokens
#         refresh = RefreshToken.for_user(user)
#         return Response({
#             'refresh': str(refresh),
#             'access': str(refresh.access_token),
#             'user': {
#                 'id': user.id,
#                 'email': user.email,
#                 'name': user.name,
#             }
#         })

# User = get_user_model()
# class DashboardView(APIView):
#     permission_classes = [permissions.IsAuthenticated]  # Protect this view

#     def get(self, request):
#         user = request.user  # The authenticated user
#         data = {
#             "message": f"Welcome {user.username} to your dashboard!",
#             # You can add more user data or dashboard info here
#         }
#         return Response(data)

# from datetime import timezone
# from django.shortcuts import get_object_or_404
# from django.contrib.auth import get_user_model, authenticate
# from rest_framework import generics, permissions, status
# from rest_framework.generics import GenericAPIView
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework_simplejwt.tokens import RefreshToken
# from django.http import HttpResponse, Http404

# from .serializers import UserRegisterSerializer, FileUploadSerializer
# from .models import OneTimePassword, EncryptedFile
# from .tokens import email_verification_token
# from .tasks import send_verification_code_to_user

# User = get_user_model()


# class RegisterUserView(GenericAPIView):
#     serializer_class = UserRegisterSerializer
#     permission_classes = [permissions.AllowAny]

#     def get(self, request):
#         return Response(
#             {"message": "Please use POST to register a new user."},
#             status=status.HTTP_405_METHOD_NOT_ALLOWED,
#         )

#     def post(self, request):
#         user_data = request.data
#         serializer = self.serializer_class(data=user_data)
#         if serializer.is_valid(raise_exception=True):
#             user = serializer.save()
#             # Role is handled by serializer; here for future use if needed
#             send_verification_code_to_user.delay(user.email)
#             return Response(
#                 {"message": "User created. Please verify your email."},
#                 status=status.HTTP_201_CREATED,
#             )
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class VerifyEmailView(APIView):
#     permission_classes = [permissions.AllowAny]

#     def post(self, request):
#         email = request.data.get("email")
#         token = request.data.get("verification_code")

#         if not email or not token:
#             return Response(
#                 {"error": "Email and verification code are required."},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             return Response(
#                 {"error": "User not found."}, status=status.HTTP_404_NOT_FOUND
#             )

#         if user.is_verified:
#             return Response(
#                 {"message": "Email already verified."}, status=status.HTTP_400_BAD_REQUEST
#             )

#         try:
#             otp = OneTimePassword.objects.get(user=user, code=token)
#             if hasattr(otp, "expires_at") and otp.expires_at < timezone.now():
#                 return Response(
#                     {"error": "Verification code has expired."},
#                     status=status.HTTP_400_BAD_REQUEST,
#                 )
#         except OneTimePassword.DoesNotExist:
#             return Response(
#                 {"error": "Invalid verification code."},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         user.is_verified = True
#         user.is_active = True
#         user.save()
#         otp.delete()

#         return Response(
#             {"message": "Email verified successfully."}, status=status.HTTP_200_OK
#         )


# class IsOwnerOrAdmin(permissions.BasePermission):
#     def has_object_permission(self, request, view, obj):
#         user = request.user
#         return (user.role == "admin" or user.is_staff) or obj.owner == user


# class FileUploadView(generics.CreateAPIView):
#     serializer_class = FileUploadSerializer
#     permission_classes = [permissions.IsAuthenticated]


# class FileListView(generics.ListAPIView):
#     serializer_class = FileUploadSerializer
#     permission_classes = [permissions.IsAuthenticated]

#     def get_queryset(self):
#         user = self.request.user
#         if user.is_staff or user.role == "admin":
#             return EncryptedFile.objects.all()
#         return EncryptedFile.objects.filter(owner=user)


# class FileDownloadView(APIView):
#     permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]

#     def get(self, request, pk):
#         file_obj = get_object_or_404(EncryptedFile, pk=pk)
#         self.check_object_permissions(request, file_obj)
#         decrypted_data = file_obj.get_decrypted_file()
#         response = HttpResponse(
#             decrypted_data, content_type="application/octet-stream"
#         )
#         response["Content-Disposition"] = f'attachment; filename="{file_obj.original_filename}"'
#         return response


# class FileDeleteView(generics.DestroyAPIView):
#     queryset = EncryptedFile.objects.all()
#     permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]


# class LoginView(APIView):
#     permission_classes = [permissions.AllowAny]

#     def post(self, request):
#         email = request.data.get("email")
#         password = request.data.get("password")

#         if not email or not password:
#             return Response(
#                 {"error": "Email and password are required."},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         user = authenticate(request, email=email, password=password)
#         if user is None:
#             return Response(
#                 {"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED
#             )

#         if not user.is_active:
#             return Response(
#                 {"error": "Account is inactive."}, status=status.HTTP_403_FORBIDDEN
#             )

#         if not user.is_verified:
#             return Response(
#                 {"error": "Email is not verified."}, status=status.HTTP_403_FORBIDDEN
#             )

#         refresh = RefreshToken.for_user(user)
#         return Response(
#             {
#                 "refresh": str(refresh),
#                 "access": str(refresh.access_token),
#                 "user": {"id": user.id, "email": user.email, "name": user.name},
#             }
#         )


# class DashboardView(APIView):
#     permission_classes = [permissions.IsAuthenticated]

#     def get(self, request):
#         user = request.user
#         data = {
#             "message": f"Welcome {user.name} to your dashboard!",
#             # Add additional dashboard info here
#         }
#         return Response(data)


from datetime import timezone
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model, authenticate
from rest_framework import generics, permissions, status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import HttpResponse

from .serializers import UserRegisterSerializer, FileUploadSerializer
from .models import OneTimePassword, EncryptedFile
from .tokens import email_verification_token
from .tasks import send_verification_code_to_user

User = get_user_model()


class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return Response(
            {"message": "Please use POST to register a new user."},
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            send_verification_code_to_user.delay(user.email)
            return Response(
                {"message": "User created. Please verify your email."},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        token = request.data.get("verification_code")

        if not email or not token:
            return Response(
                {"error": "Email and verification code are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )

        if user.is_verified:
            return Response(
                {"message": "Email already verified."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            otp = OneTimePassword.objects.get(user=user, code=token)
            if hasattr(otp, "expires_at") and otp.expires_at < timezone.now():
                return Response(
                    {"error": "Verification code has expired."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except OneTimePassword.DoesNotExist:
            return Response(
                {"error": "Invalid verification code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.is_verified = True
        user.is_active = True
        user.save()
        otp.delete()

        return Response(
            {"message": "Email verified successfully."}, status=status.HTTP_200_OK
        )


class IsOwnerOrAdmin(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        user = request.user
        return (user.role == "admin" or user.is_staff) or obj.owner == user


# class FileUploadView(generics.CreateAPIView):
#     serializer_class = FileUploadSerializer
#     permission_classes = [permissions.IsAuthenticated]


class FileUploadView(generics.CreateAPIView):
    serializer_class = FileUploadSerializer
    # permission_classes = [permissions.IsAuthenticated]
    permission_classes = [permissions.AllowAny]

    def perform_create(self, serializer):
        file = serializer.validated_data.get('file')
        description = serializer.validated_data.get('description', '')
        tags = serializer.validated_data.get('tags', [])

        # Save the file and any additional metadata
        # Here you can save to your model or perform further actions
        # Example:
        file_instance =  EncryptedFile.objects.create(
            file=file,
            # description=description,
            # tags=tags
        )

        return file_instance


class FileListView(generics.ListAPIView):
    serializer_class = FileUploadSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_staff or user.role == "admin":
            return EncryptedFile.objects.all()
        return EncryptedFile.objects.filter(owner=user)


class FileDownloadView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]

    def get(self, request, pk):
        file_obj = get_object_or_404(EncryptedFile, pk=pk)
        self.check_object_permissions(request, file_obj)
        decrypted_data = file_obj.get_decrypted_file()
        response = HttpResponse(
            decrypted_data, content_type="application/octet-stream"
        )
        response["Content-Disposition"] = f'attachment; filename="{file_obj.original_filename}"'
        return response


class FileDeleteView(generics.DestroyAPIView):
    queryset = EncryptedFile.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response(
                {"error": "Email and password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(request, email=email, password=password)
        if user is None:
            return Response(
                {"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED
            )

        if not user.is_active:
            return Response(
                {"error": "Account is inactive."}, status=status.HTTP_403_FORBIDDEN
            )

        if not user.is_verified:
            return Response(
                {"error": "Email is not verified."}, status=status.HTTP_403_FORBIDDEN
            )

        refresh = RefreshToken.for_user(user)
        return Response(
            {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": {"id": user.id, "email": user.email, "name": user.name},
            }
        )


class DashboardView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        data = {
            "message": f"Welcome {user.name} to your dashboard!",
            # Add additional dashboard info here
        }
        return Response(data)
