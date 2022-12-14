
from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _    
from rest_framework_simplejwt.tokens import RefreshToken

class UserManager(BaseUserManager):
    def create_user(self, name, email, username, password=None):
        if not username:
            raise ValueError("user must have username")
        if not name:
            raise ValueError("user must have name")
        if not email:
            raise ValueError("user must have email")
        if not password:
            raise ValueError("user must have password")

        email = self.normalize_email(email=email)
        user = self.model(
            name=name,
            username=username,
            email=email
        )
        user.set_password(password)
        user.save()
        return user


    def create_superuser(self, username, email, name, password=None):
        if not username:
            raise ValueError("user must have username")
        if not name:
            raise ValueError("user must have name")
        if not email:
            raise ValueError("user must have email")
        if not password:
            raise ValueError("user must have password")

        email = self.normalize_email(email=email)
        user = self.model(
            name=name,
            username=username,
            email=email
        )
        user.set_password(password)
        user.is_superuser = True
        user.is_staff = True
        user.save()

        return user

AUTH_PROVIDERS = {'google':"google"}

user_choices = [
    ("admin" ,"Admin"),
    ("employee" ,"Employee"),
    ("client" ,"Client"),
]

class User(AbstractBaseUser, PermissionsMixin):
    name = models.CharField(_("User full name"),max_length=155)
    username = models.CharField(_("Username"),max_length=155, unique=True)
    email = models.CharField(_("Email"),max_length=155, unique=True)
    is_superuser = models.BooleanField(_("Is user a superuser"), default=False)
    is_active = models.BooleanField(_("Is user account activated"),default=True)
    is_staff = models.BooleanField(_("Is user a staff member"),default=False)
    user_type = models.CharField(max_length=50, choices=user_choices, default='admin')

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email", "name"]

    objects = UserManager()

    def tokens(self):
        token = RefreshToken.for_user(self)
        return {
            "refresh": str(token),
            "access": str(token.access_token) 
        }

    def __str__(self):
        return f"{self.username}"