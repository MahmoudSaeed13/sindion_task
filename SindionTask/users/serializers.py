from rest_framework import serializers
from rest_framework.exceptions import ParseError
from users.models import User
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed, NotFound
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from users.helpers import generate_password
class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(max_length=68, min_length=3)
    tokens = serializers.CharField(max_length=500, min_length=6, read_only=True)

    class Meta:
        model = User
        fields = ["username", "password", "tokens"]

    def validate(self, attrs):
        username = attrs.get('username', '')
        password = attrs.get('password', '')

        if not username:
            raise ParseError("username must be provided")
        if not password:
            raise ParseError("password must be provided")
            
        user = authenticate(username=username, password=password)
        
        if not user:
            raise AuthenticationFailed("Invalid credintials, Please try again")

        
        return {
            "username": user.username,
            "tokens" : user.tokens()
        }

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')

from django.contrib.auth import password_validation
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

class ChangePasswordSerializer(serializers.ModelSerializer):

    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_new_password = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ("old_password", "new_password", "confirm_new_password")

    def validate(self, attrs):
        if attrs["confirm_new_password"] != attrs["new_password"]:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )
        return attrs

    def validate_old_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                {"old_password": "Old password is not correct"}
            )
        return value

class RequestResetPasswordSerializer(serializers.ModelSerializer):
    email = serializers.CharField(max_length=500, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['email']

    def validate(self, attrs):
        email = attrs['email']
        
        if not email:
            raise ParseError("Email must be provided!")
        user = User.objects.filter(email=email)
        if not user:
            raise NotFound("This email address is not registered")

        return super().validate(attrs)

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['name', 'username', 'email','user_type']

class RegisterUserSerializer(serializers.ModelSerializer):

    email = serializers.EmailField(max_length=225, min_length=8)
    name = serializers.CharField(max_length=155, min_length=8)
    username = serializers.CharField(max_length=155, min_length=8)

    class Meta:
        model = User
        fields = ["name", "username", "email",]


    def validate(self, attrs):
        name = attrs['name']
        username = attrs['username']
        email = attrs['email']

        if not name:
            raise serializers.ValidationError(
                {'name': 'name can not be empty.'}
            )
        if not username:
            raise serializers.ValidationError(
                {'username': 'name can not be empty.'}
            )
        if not email:
            raise serializers.ValidationError(
                {'email':'email can not be empty.'}
            )
        
        if User.objects.filter(email=attrs["email"]):
            raise serializers.ValidationError(
                {"email_duplication": "This email already exists"}
            )

        if User.objects.filter(username=attrs["username"]):
            raise serializers.ValidationError(
                {"username_duplication": "This username already exists"}
            )
            
        password = generate_password()
        attrs['password'] = password

        attrs['user_type'] = self.context['request'].user.user_type
        
        return attrs

    def create(self, validated_data):

        user =  User.objects.create_user(
            name=validated_data["name"],
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
        )
        if validated_data['user_type'] == 'admin':
            user.user_type = 'employee'
            user.save()
        elif validated_data['user_type'] == 'employee':
            user.user_type = 'client'
            user.save()

        return user