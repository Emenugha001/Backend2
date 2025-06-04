from django.urls import path
from .views import RegisterUserView, VerifyEmailView, FileUploadView, \
    FileDownloadView, FileListView, FileDeleteView,LoginView, file_upload






urlpatterns=[
    path('register/', RegisterUserView.as_view(), name='register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    # path('upload/', FileUploadView.as_view(), name='file-upload'),
    path('upload/', file_upload, name='file-upload'),
    path('files/', FileListView.as_view(), name='file-list'),
    path('download/<int:pk>/', FileDownloadView.as_view(), name='file-download'),
    path('delete/<int:pk>/', FileDeleteView.as_view(), name='file-delete'),
    path('api/user/login/', LoginView.as_view(), name='login'),
]