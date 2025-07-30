from django.urls import path
from .views import (
    SigninView, SignupView, verifyOTP, SendOTP, FetchUserView,
    ResetPasswordView, ConfirmResetPasswordView,
    PermissionView, PermissionDetailView
)

urlpatterns = [
    path('signin/', SigninView.as_view()),
    path('signup/', SignupView.as_view()),
    path('verify-otp/', verifyOTP.as_view()),
    path('send-otp/', SendOTP.as_view()),
    path('fetch-user/', FetchUserView.as_view()),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('confirm-reset-password/', ConfirmResetPasswordView.as_view(), name='confirm-reset-password'),
    path('permissions/', PermissionView.as_view(), name='permission-list'),
    path('permissions/<int:pk>/', PermissionDetailView.as_view(), name='permission-detail'),
]