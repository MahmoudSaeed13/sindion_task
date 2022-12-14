from rest_framework.generics import GenericAPIView, UpdateAPIView, ListAPIView, RetrieveAPIView
from users.serializers import (LoginSerializer, 
                                LogoutSerializer, 
                                ChangePasswordSerializer, 
                                RequestResetPasswordSerializer,
                                UserSerializer
                                )
from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from users.models import User
from users.permissions import OwnProfilePermission
from users.tasks import send_reset_password_email
from rest_framework_simplejwt.authentication import JWTAuthentication
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404

# Create your views here.

class LoginAPIView(GenericAPIView):
    serializer_class = LoginSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

class LogoutAPIView(GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("Logged out Successfully", status=status.HTTP_204_NO_CONTENT)

class ChangePasswordView(UpdateAPIView):

    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (OwnProfilePermission,)

    def update(self, request, *args, **kwargs):
        self.object = request.user
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response(
                    {"old_password": ["Wrong password."]},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()

            return Response("Password updated successfully", status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RquestResetPassword(GenericAPIView):
    serializer_class = RequestResetPasswordSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        send_reset_password_email.delay(request.data['email'])

        return Response(f"Email sent to {request.data['email']}", status=status.HTTP_200_OK)

class ResetPassword(GenericAPIView):

    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description = 'Description',
                                            type = openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def post(self, request):
        
        if request.data["confirm_new_password"] != request.data["new_password"]:
            return Response('password and confirmation must match',status=status.HTTP_406_NOT_ACCEPTABLE )

        obj = JWTAuthentication()
        validated_token = obj.get_validated_token(request.GET["token"])
        user_id = validated_token["user_id"]
        user = User.objects.get(id=user_id)
        if user:
            user.set_password(request.data['new_password'])
            user.save()
            return Response("password updated successfully", status=status.HTTP_200_OK)

#CRUD operation on employees clients

class EmployeeListAPIView(GenericAPIView):
    serializer_class = UserSerializer
    
    def get(self, request):
        employees = User.objects.filter(user_type='Employee')
        serializer = self.serializer_class(employees, many=True)
        
        return Response(serializer.data, status=status.HTTP_200_OK)

class ClientListAPIView(GenericAPIView):
    serializer_class = UserSerializer
    
    def get(self, request):
        employees = User.objects.filter(user_type='Client')
        serializer = self.serializer_class(employees, many=True)
        
        return Response(serializer.data, status=status.HTTP_200_OK)

class UserDetailAPIView(APIView):
    serializer_class = UserSerializer

    def get_object(self, pk):
        obj = get_object_or_404(User, pk=pk)
        return obj
    def get(self, request, pk):
        user = self.get_object(pk=pk)
        serializer = UserSerializer(user)
        return Response(serializer.data)

class UserDeleteAPIView(APIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    def get_object(self, pk):
        obj = get_object_or_404(User, pk=pk)
        return obj
    def delete(self, request, pk):
        user = self.get_object(pk=pk)
        serializer = UserSerializer(user)
        return Response(serializer.data)
