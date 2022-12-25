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
    path('employees/', EmployeeListAPIView.as_view(),name='list-employees'),
    path('client/', ClientListAPIView.as_view(),name='list-clients'),
    path('user/<int:pk>', UserDetailAPIView.as_view(),name='detail-employee'),
    path('user/delete/<int:pk>', UserDeleteAPIView.as_view(),name='delete-employee'),
    path('add-employee/', AddEmployee.as_view(), name='add_employee'),
    path('add-client/', AddClient.as_view(), name='add_client'),
]