import random
from django.utils import timezone
from datetime import timedelta
from users.models import OTP


def generate_otp(user, otp_type):
    code = str(random.randint(100000, 999999))
    expires_at = timezone.now() + timedelta(minutes=5)

    OTP.objects.create(
        user=user,
        code=code,
        otp_type=otp_type,
        expires_at=expires_at
    )
    return code
