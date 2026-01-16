from django.urls import path
from .views import *

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('otp-verify/', OTPVerifyView.as_view()),
    path('login/', LoginView.as_view()),
    # path('logout/', LogoutView.as_view()),
    path('forgot-password/', ForgotPasswordView.as_view()),
    path('set-new-password/', SetNewPasswordView.as_view()),
    path('reset-password/', ResetPasswordView.as_view()),
    path('logout/', LogoutView.as_view())
]
