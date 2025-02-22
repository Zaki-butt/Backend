#Django Imports
from django.urls import path

#Local Imprts
from account.views import (
  UserRegistrationView,
  UserLoginView,
  UserProfileView,
  UserChangePasswordView,
  UserUpdateView,
  UserRegistrationView, 
  VerifyOTPView,
  ResendOTPView,
  ForgotPasswordView,
  VerifyForgotPasswordOTPView,
  ResetPasswordView,
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
  path('register/', UserRegistrationView.as_view(), name='register'),
  path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
  path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
  path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
  path('verify-password/', VerifyForgotPasswordOTPView.as_view(), name='verify-password'),
   path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
  #path('register', UserRegistrationView.as_view()),
  path('login', UserLoginView.as_view()),
  path('profile', UserProfileView.as_view()),
  path('refresh', TokenRefreshView.as_view()),
  path('change-password', UserChangePasswordView.as_view()),
  path('update-profile', UserUpdateView.as_view()),
]
