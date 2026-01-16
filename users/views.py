from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .models import CustomUser, OTP
from .serializers import (
    CustomUserSerializer,
    OTPVerifySerializer,
    LoginSerializer,
    ForgotPasswordSerializer,
    SetNewPasswordSerializer,
    ResetPasswordSerializer,
    LogoutSerializer,
)
from .otp_service import generate_otp
from .email_service import send_otp_email


# -----------------------------
# 1️⃣ REGISTER
# -----------------------------
class RegisterView(APIView):
    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()

            # OTP generate & send
            code = generate_otp(user, 'register')
            send_otp_email(user.email, code)

            return Response(
                {"detail": "User registered. OTP sent to email."},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# -----------------------------
# 2️⃣ OTP VERIFY
# -----------------------------
class OTPVerifyView(APIView):
    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):

            user = serializer.validated_data['user']
            otp = serializer.validated_data['otp']

            otp.is_used = True
            otp.save()

            if otp.otp_type == 'register':
                user.is_active = True
                user.save()

            return Response(
                {"detail": "OTP verified successfully."},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# -----------------------------
# 3️⃣ LOGIN
# -----------------------------
class LoginView(APIView):
    """
    User login API.
    Foydalanuvchi username va password bilan login qiladi.
    Agar muvaffaqiyatli bo'lsa, JWT token (access & refresh) qaytariladi.
    """

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):

            # serializer validation ichida authenticate qilingan
            user = serializer.validated_data['user']

            # JWT token yaratish
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            return Response({
                "username": user.username,
                "access": access_token,
                "refresh": refresh_token
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# -----------------------------
# 4️⃣ LOGOUT
# -----------------------------
class LogoutView(APIView):
    """
    Logout API.
    Foydalanuvchi refresh tokenni yuboradi va token blacklist qilinadi.
    Protected endpoint: access token header orqali berilishi kerak.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh_token = serializer.validated_data['refresh']

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            return Response(
                {"error": "Invalid or expired refresh token."},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response(
            {"detail": "Logged out successfully."},
            status=status.HTTP_200_OK
        )

# -----------------------------
# 5️⃣ FORGOT PASSWORD
# -----------------------------
class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = CustomUser.objects.filter(email=serializer.validated_data['email']).first()
        if user:
            code = generate_otp(user, 'forgot')
            send_otp_email(user.email, code)

        # Security: Do not reveal whether email exists
        return Response(
            {"detail": "If email exists, OTP sent."},
            status=status.HTTP_200_OK
        )


# -----------------------------
# 6️⃣ SET NEW PASSWORD (OTP)
# -----------------------------
class SetNewPasswordView(APIView):
    def post(self, request):
        serializer = SetNewPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = CustomUser.objects.get(username=serializer.validated_data['username'])
        otp = OTP.objects.filter(
            user=user,
            code=serializer.validated_data['code'],
            otp_type='forgot',
            is_used=False
        ).first()

        if not otp or otp.is_expired():
            return Response(
                {"error": "Invalid or expired OTP"},
                status=status.HTTP_400_BAD_REQUEST
            )

        user.set_password(serializer.validated_data['new_password1'])
        user.save()
        otp.is_used = True
        otp.save()

        return Response(
            {"detail": "Password updated successfully."},
            status=status.HTTP_200_OK
        )


# -----------------------------
# 7️⃣ RESET PASSWORD (AUTHENTICATED)
# -----------------------------
class ResetPasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        old_password = serializer.validated_data['old_password']
        if not user.check_password(old_password):
            return Response(
                {"error": "Old password is incorrect."},
                status=status.HTTP_400_BAD_REQUEST
            )

        user.set_password(serializer.validated_data['new_password1'])
        user.save()

        return Response(
            {"detail": "Password changed successfully."},
            status=status.HTTP_200_OK
        )
