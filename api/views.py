# from django.shortcuts import render
# from django.contrib.auth.models import User
# from rest_framework.generics import GenericAPIView
# from .serializers import UserRegisterSerializer
# from rest_framework.response import Response
# from rest_framework import status
# from rest_framework.permissions import IsAuthenticated, AllowAny
# from .utils import send_verification_code_to_user 
# from django.shortcuts import get_object_or_404
# from rest_framework.views import APIView
# from .tasks import send_verification_code_to_user


# # Create your views here.

# class RegisterUserView(GenericAPIView):
#     serializer_class = UserRegisterSerializer
#     permission_classes = [AllowAny]

#     def post(self, request):
#         """Handle user registration and send verification email with a code."""
#         user_data = request.data
#         serializer = self.serializer_class(data=user_data)

#         if serializer.is_valid(raise_exception=True):
#             # Save the user and generate a verification code
#             user = serializer.save()

#             # Send verification code to the user's email
#             send_verification_code_to_user.delay(user.email)

#             return Response({"message": "User created. Please verify your email."}, status=status.HTTP_201_CREATED)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class VerifyEmailView(APIView):
#     def post(self, request):
#         """Verify the user's email using the submitted verification code."""
#         code = request.data.get("verification_code")

#         if not code:
#             return Response({"error": "Verification code is required."}, status=status.HTTP_400_BAD_REQUEST)

#         # Retrieve the user by the verification code
#         user = get_object_or_404(User, verification_token=code)

#         if user.is_verified:
#             return Response({"message": "Email already verified."}, status=status.HTTP_400_BAD_REQUEST)

#         # Mark the user as verified and active
#         user.is_verified = True
#         user.is_active = True
#         user.save()

#         return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)


from django.shortcuts import render
from django.contrib.auth.models import User
from rest_framework.generics import GenericAPIView
from .serializers import UserRegisterSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from .tokens import email_verification_token


# Import only from tasks, as that's what you're actually using with .delay()
from .tasks import send_verification_code_to_user


# Create your views here.

class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        """Handle user registration and send verification email with a code."""
        user_data = request.data
        serializer = self.serializer_class(data=user_data)

        if serializer.is_valid(raise_exception=True):
            # Save the user and generate a verification code
            user = serializer.save()
            token = email_verification_token.make_token(user)

            # Send verification code to the user's email using Celery task
            send_verification_code_to_user.delay(user.email)

            return Response({"message": "User created. Please verify your email."}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class VerifyEmailView(APIView):
#     def post(self, request):
#         """Verify the user's email using the submitted verification code."""
#         code = request.data.get("verification_code")

#         if not code:
#             return Response({"error": "Verification code is required."}, status=status.HTTP_400_BAD_REQUEST)

#         # Retrieve the user by the verification code
#         user = get_object_or_404(User, verification_token=code)

#         if user.is_verified:
#             return Response({"message": "Email already verified."}, status=status.HTTP_400_BAD_REQUEST)

#         # Mark the user as verified and active
#         user.is_verified = True
#         user.is_active = True
#         user.save()

#         return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)

class VerifyEmailView(APIView):
    def post(self, request):
        email = request.data.get("email")
        token = request.data.get("verification_code")

        if not email or not token:
            return Response({"error": "Email and verification code are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        if user.is_verified:
            return Response({"message": "Email already verified."}, status=status.HTTP_400_BAD_REQUEST)

        # Verify the token is valid for this user
        if email_verification_token.check_token(user, token):
            user.is_verified = True
            user.is_active = True
            user.save()
            return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid verification code."}, status=status.HTTP_400_BAD_REQUEST)
