from django.core.mail import send_mail
from celery import shared_task
from django.core.exceptions import ValidationError
from users.models import User
from rest_framework_simplejwt.tokens import RefreshToken
    
@shared_task(bind=True)
def send_reset_password_email(self, user_email):

    user = User.objects.get(email=user_email)
    token = RefreshToken.for_user(user).access_token

    absurl = "http://localhost:8000/reset-password" + "?token=" + str(token)
    
    email_body = (
        "Hi "
        + user.name.split(" ")[0]
        + ",\n"
        + "You Can reset yor password using the following link \n"
        + absurl
    )

    try:
        send_mail(
            subject="Reset Password",
            message= email_body,
            from_email="example@example.com",
            recipient_list=[user_email,],
            fail_silently=False
        )
    except Exception:
        raise ValidationError("Couldn't send the message to the email!")
    return "Done!"