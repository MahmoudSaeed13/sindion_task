from users.views import *
from rest_framework_simplejwt.views import TokenRefreshView
from django.urls import path

urlpatterns = [
    path("login/", LoginAPIView.as_view(), name="login"),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path("logout/", LogoutAPIView.as_view(), name="logout"),
    path("change-password/<int:pk>/",ChangePasswordView.as_view(),name="ChangePasswordView",),
    path('request-reset-password', RquestResetPassword.as_view(), name='request-reset-password'),
    path('reset-password', ResetPassword.as_view(), name='reset-password'),
]