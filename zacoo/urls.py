from django.contrib import admin
from django.urls import path, include
from api.views import ( RegisterUserView, VerifyEmailView, FileUploadView, FileListView, FileDownloadView, FileDeleteView, LoginView)
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView


urlpatterns = [
    path('admin/', admin.site.urls),

    #User registration and email verification endpoint
    path("api/user/register/", RegisterUserView .as_view(), name="register"),
    path("api/user/verify-email/", VerifyEmailView.as_view(), name="verify-email"),
    path('api/user/login/', LoginView.as_view(), name='login'),

    #JWT Authentication endpoints
    path("api/token/", TokenObtainPairView.as_view(), name="get_token"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="refresh"),

    #Browsable API login/logout views
    path("api-auth/", include("rest_framework.urls")),

    
    # File management endpoints
    path('api/files/upload/', FileUploadView.as_view(), name='file-upload'),
    path('api/files/', FileListView.as_view(), name='file-list'),
    path('api/files/download/<int:pk>/', FileDownloadView.as_view(), name='file-download'),
    path('api/files/delete/<int:pk>/', FileDeleteView.as_view(), name='file-delete'),
]
