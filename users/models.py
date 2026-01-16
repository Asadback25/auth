import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone


class CustomUser(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=False)

    def __str__(self):
        return self.username


class OTP(models.Model):
    OTP_TYPE_CHOICES = (
        ('register', 'Register'),
        ('forgot', 'Forgot Password'),
    )

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    otp_type = models.CharField(max_length=10, choices=OTP_TYPE_CHOICES)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    def is_expired(self):
        return timezone.now() > self.expires_at

    def __str__(self):
        return self.user.username

