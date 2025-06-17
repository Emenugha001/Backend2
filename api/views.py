
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


 

class FileUploadView(generics.GenericAPIView):
    serializer_class = FileUploadSerializer
    permission_classes = [permissions.IsAuthenticated]
    # permission_classes = [permissions.AllowAny]

    def post(self, request):
        """
        Handle file upload. The file is expected in the request's FILES dictionary
        with the key 'file'. The original filename can be provided in the POST data.
        """
        return file_upload(request)
    

def file_upload(request):
    file = request.FILES.get('file')
    # Uncomment this line to fix the NameError
    original_filename = request.POST.get('original_filename', file.name if file else None)

    if not file:
        return Response({"error": "No file provided."}, status=status.HTTP_400_BAD_REQUEST)
    
    if not original_filename:
        return Response({"error": "Original filename is required."}, status=status.HTTP_400_BAD_REQUEST)

    file_instance = EncryptedFile.objects.create(
        file=file,
        original_filename=original_filename,
        owner=request.user if request.user.is_authenticated else None
    )
    return Response(
        {"message": "File uploaded successfully.", "file_id": file_instance.id},
        status=status.HTTP_201_CREATED,
    )

class FileListView(generics.ListAPIView):
    serializer_class = FileUploadSerializer
    permission_classes = [permissions.IsAuthenticated]
    # permission_classes = [permissions.AllowAny]

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
