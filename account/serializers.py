#Django RestFramework Imports
from rest_framework import serializers

#Django Imports
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator

#Local Imports
from account.models import User
from account.utils import get_user_by_email

class UserRegistrationSerializer(serializers.ModelSerializer):
  password_confirmation = serializers.CharField(style={
    'input_type': 'password'
  }, write_only=True)
  
  class Meta:
    model = User
    fields = ['name', 'email', 'password', 'password_confirmation', 'is_admin']
    extra_kwargs = {
      'password': { 'write_only': True }
    }

  def validate(self, attrs):
    password = attrs.get('password')
    password_confirmation = attrs.get('password_confirmation')
    if password != password_confirmation:
      raise serializers.ValidationError("Password and confirmation password doesn't match")
    return attrs

  def create(self, validated_data):
    is_admin = validated_data.pop('is_admin', False)  # Default to False if not provided
    user = User.objects.create_user(**validated_data)
    user.is_admin = is_admin  # Set is_admin field
    user.save()  # Save the user with updated field
    return user

class UserLoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = User
    fields = ['email', 'password']


class UserProfileSerializer(serializers.ModelSerializer):
  class Meta:
    model = User
    fields = ['id', 'name', 'email', 'is_admin', 'avatar']

class UserChangePasswordSerializer(serializers.Serializer):
  old_password = serializers.CharField(max_length=255)
  new_password = serializers.CharField(max_length=255)
  new_password_confirmation = serializers.CharField(max_length=255)

  def validate(self, attrs):
    old_password = attrs.get('old_password')
    new_password = attrs.get('new_password')
    new_password_confirmation = attrs.get('new_password_confirmation')
    user = self.context.get('request').user
    if not user.check_password(old_password):
      raise serializers.ValidationError("Please enter correct old password")
    if new_password!= new_password_confirmation:
      raise serializers.ValidationError("Password and confirmation password doesn't match")
    return attrs


class UserPasswordResetSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255)
  password_confirmation = serializers.CharField(max_length=255)

  def validate(self, attrs):
    self.validate_password_match(attrs)
    user = self.get_user_from_token()
    self.reset_user_password(user, attrs.get('password'))
    return attrs

  def validate_password_match(self, attrs):
    password = attrs.get('password')
    password_confirmation = attrs.get('password_confirmation')
    if password!= password_confirmation:
      raise serializers.ValidationError("Password and confirmation password doesn't match")

  def get_user_from_token(self):
    uuid = self.context.get('uuid')
    token = self.context.get('token')
    id = smart_str(urlsafe_base64_decode(uuid))
    try:
      user = User.objects.get(id=id)
    except User.DoesNotExist:
      raise serializers.ValidationError("User doesn't exist")

    if not PasswordResetTokenGenerator().check_token(user, token):
      raise serializers.ValidationError("Token is not valid")
    return user

  def reset_user_password(self, user, password):
    user.set_password(password)
    user.save()
    

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'name', 'email', 'is_admin', 'avatar')
        read_only_fields = ('id', 'is_admin')

class UserProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('name', 'email', 'avatar')
    
