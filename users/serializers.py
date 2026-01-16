from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from .models import CustomUser, OTP
from django.contrib.auth import authenticate


class CustomUserSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(write_only=True, min_length=8, max_length=64)
    password2 = serializers.CharField(write_only=True, min_length=8, max_length=64)
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password1', 'password2']


    def validate(self, attrs):
        if attrs['password1'] != attrs['password2']:
            raise serializers.ValidationError('Passwords do not match.')
        return attrs


    def create(self, validated_data):
        validated_data.pop('password2')
        user = CustomUser.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password1'],
        )
        user.save()
        return user



class OTPVerifySerializer(serializers.ModelSerializer):
    username = serializers.CharField(write_only=True)

    class Meta:
        model = OTP
        fields = ('username', 'code', 'otp_type')

    def validate(self, attrs):
        username = attrs.get('username')
        code = attrs.get('code')
        otp_type = attrs.get('otp_type')

        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError(
                {"username": "User not found"}
            )

        otp = OTP.objects.filter(
            user=user,
            code=code,
            otp_type=otp_type,
            is_used=False
        ).first()

        if not otp:
            raise serializers.ValidationError(
                {"otp": "Invalid OTP code"}
            )

        if otp.is_expired():
            raise serializers.ValidationError(
                {"otp": "OTP code has expired"}
            )

        # view uchun tayyor qilib qo‘yamiz
        attrs['user'] = user
        attrs['otp'] = otp
        return attrs





class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if not username or not password:
            raise serializers.ValidationError(
                {"detail": "Both username and password are required."}
            )

        # authenticate user
        user = authenticate(username=username, password=password)
        if not user:
            raise serializers.ValidationError(
                {"detail": "Invalid username or password."}
            )

        if not user.is_active:
            raise serializers.ValidationError(
                {"detail": "User is not verified."}
            )

        # view uchun validated_data ga user ni qo‘shamiz
        attrs['user'] = user
        return attrs



class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        """
        Email formatini tekshiradi va user mavjudligini tekshiradi.
        Security jihatidan mavjud bo'lmasa ham xato bermaymiz.
        """
        user_exists = CustomUser.objects.filter(email=value).exists()
        if not user_exists:
            # Security: email mavjud bo'lmasa ham response bir xil bo'ladi
            pass
        return value



class SetNewPasswordSerializer(serializers.Serializer):
    username = serializers.CharField()
    code = serializers.CharField(max_length=6)
    new_password1 = serializers.CharField(min_length=8, write_only=True)
    new_password2 = serializers.CharField(min_length=8, write_only=True)

    def validate(self, attrs):
        username = attrs.get('username')
        code = attrs.get('code')
        pw1 = attrs.get('new_password1')
        pw2 = attrs.get('new_password2')

        if pw1 != pw2:
            raise serializers.ValidationError({"password": "Passwords do not match."})

        # user mavjudligini tekshirish
        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError({"username": "User not found."})

        # OTP mavjudligi va validatsiyasi
        otp = OTP.objects.filter(
            user=user,
            code=code,
            otp_type='forgot',
            is_used=False
        ).first()

        if not otp:
            raise serializers.ValidationError({"otp": "Invalid OTP code."})

        if otp.is_expired():
            raise serializers.ValidationError({"otp": "OTP code has expired."})

        # view uchun validated_data ga user va otp ni qo‘shamiz
        attrs['user'] = user
        attrs['otp'] = otp

        return attrs


class ResetPasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password1 = serializers.CharField(min_length=8)
    new_password2 = serializers.CharField(min_length=8)

    def validate(self, attrs):
        if attrs['new_password1'] != attrs['new_password2']:
            raise serializers.ValidationError(
                {"password": "Passwords do not match"}
            )
        validate_password(attrs['new_password1'])
        return attrs


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(write_only=True)

    def validate_refresh(self, value):
        """
        Refresh token bo'sh bo'lmasligini va formatini tekshiradi.
        """
        if not value or not value.strip():
            raise serializers.ValidationError("Refresh token is required.")
        return value


