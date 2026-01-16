from django.core.mail import send_mail
from django.conf import settings


# def send_otp_email(email, code):
#     send_mail(
#         subject="Your OTP Code",
#         message=f"Your OTP code is: {code}",
#         from_email=settings.DEFAULT_FROM_EMAIL,
#         recipient_list=[email],
#         fail_silently=False,
#     )

def send_email(to_email, subject, message):
    """
    Email yuborish uchun universal funksiya.
    DEFAULT_FROM_EMAIL ni avtomatik ishlatadi.

    Args:
        to_email (str): qabul qiluvchi email
        subject (str): email mavzusi
        message (str): email matni
    """
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,  # default from email
        [to_email],
        fail_silently=False  # xatolikni ko‘rsatadi
    )

def send_otp_email(to_email, otp_code):
    subject = "Your OTP Code"
    message = f"Hello!\n\nYour OTP code is: {otp_code}\n\nDo not share it with anyone."
    send_email(to_email, subject, message)