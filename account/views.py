#Django Imports
from django.shortcuts import render
from django.contrib.auth import authenticate

#Rest Framework Imports
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny

#Rest Framework Simple JWT Imports
from rest_framework_simplejwt.authentication import JWTAuthentication

#Local Imports
from account.serializers import (
  UserRegistrationSerializer,
  UserLoginSerializer,
  UserProfileSerializer,
  UserChangePasswordSerializer,
  UserPasswordResetSerializer,
  UserProfileUpdateSerializer
)
from account.renderers import UserRenderer
from account.utils import send_otp_email, verify_otp, get_tokens_for_user, is_valid_email
from account.models import User, PendingUser



# class UserRegistrationView(APIView):
#   renderer_classes = (UserRenderer,)
#   def post(self, request):
#     serializer = UserRegistrationSerializer(data=request.data)
#     if serializer.is_valid():
#       user = serializer.save()
#       tokens = get_tokens_for_user(user)
#       return Response({'success': True, 'tokens': tokens}, status=status.HTTP_200_OK)
#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class UserRegistrationView(APIView):
#     renderer_classes = (UserRenderer,)

#     def post(self, request):
#         serializer = UserRegistrationSerializer(data=request.data)
#         if serializer.is_valid():
#             user = serializer.save(is_active=False)  # User is inactive until OTP is verified
#             send_otp_email(user)  # Send OTP
#             return Response({'success': True, 'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

       

# class VerifyOTPView(APIView):
#     def post(self, request):
#         email = request.data.get("email")
#         otp = request.data.get("otp")

#         user = User.objects.filter(email=email).first()
#         if not user:
#             return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

#         otp_status = verify_otp(user, otp)

#         if otp_status == "expired":
#             return Response({"error": "Your OTP has expired. Please request a new one."}, status=status.HTTP_400_BAD_REQUEST)
#         elif otp_status == "invalid":
#             return Response({"error": "Invalid OTP. Please try again."}, status=status.HTTP_400_BAD_REQUEST)

#         # OTP is valid, return tokens
#         tokens = get_tokens_for_user(user)
#         return Response({
#             "success": True,
#             "message": "OTP verified, account activated.",
#             "tokens": tokens
#         }, status=status.HTTP_200_OK)

class UserRegistrationView(APIView):
    def post(self, request):
        """Register user and store data in PendingUser until OTP is verified."""
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            name = serializer.validated_data['name']
            password = serializer.validated_data['password']

            # Check if email is real using MailboxLayer
            if not is_valid_email(email):
                 return Response({"error": "Invalid or non-existent email address."}, status=status.HTTP_400_BAD_REQUEST)
            # Delete expired PendingUser records
            PendingUser.delete_expired_users()

            # Check if email already exists in PendingUser or User
            if PendingUser.objects.filter(email=email).exists() or User.objects.filter(email=email).exists():
                return Response({"error": "Email is already registered."}, status=status.HTTP_400_BAD_REQUEST)

            # Create a pending user
            pending_user = PendingUser.create_user_with_otp(email, name, password)
            
            # Send OTP email
            send_otp_email(pending_user)

            return Response(
                {'success': True, 'message': 'OTP sent to your email.'}, 
                status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    """Verify OTP and move user from PendingUser to User model"""

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")

        try:
            pending_user = PendingUser.objects.get(email=email)
        except PendingUser.DoesNotExist:
            return Response({"error": "Invalid email or OTP."}, status=status.HTTP_400_BAD_REQUEST)

        # Verify OTP
        if not pending_user.is_otp_valid():
            pending_user.delete()  # Remove expired user
            return Response({"error": "OTP has expired. Please register again."}, status=status.HTTP_400_BAD_REQUEST)

        if pending_user.otp != otp:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        # OTP is valid -> Move user to User model
        user = User(
            email=pending_user.email,
            name=pending_user.name,
            is_active=True
        )
        user.set_password(pending_user.password)  # Ensure secure password storage
        user.save()
         # Delete PendingUser entry after successful verification
        pending_user.delete()
        #  OTP is valid, return tokens
        tokens = get_tokens_for_user(user)
        return Response({
            "success": True,
            "message": "OTP verified, account activated.",
            "tokens": tokens
        }, status=status.HTTP_200_OK)



        # return Response({"success": True, "message": "Account verified successfully!"}, status=status.HTTP_200_OK)


  

class ResendOTPView(APIView):
    """Resends a new OTP if the previous one expired or was lost."""

    def post(self, request):
        email = request.data.get("email")

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Generate and send new OTP
        send_otp_email(user)

        return Response({"success": True, "message": "A new OTP has been sent to your email."}, status=status.HTTP_200_OK)


class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        user = User.objects.filter(email=email).first()

        if not user:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        send_otp_email(user)  # Send OTP to user
        return Response({"success": True, "message": "OTP sent to your email."}, status=status.HTTP_200_OK)


class VerifyForgotPasswordOTPView(APIView):
    
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        print(f"Received email: {email}, OTP: {otp}")  # Debugging
       
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        otp_status = verify_otp(user, otp)
        print(f"OTP verification result: {otp_status}")  # Debugging
        if otp_status == "expired":
            return Response({"error": "Your OTP has expired. Please request a new one."}, status=status.HTTP_400_BAD_REQUEST)
        elif otp_status == "invalid":
            return Response({"error": "Invalid OTP. Please try again."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"success": True, "message": "OTP verified. You can now reset your password."}, status=status.HTTP_200_OK)

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        new_password = request.data.get("new_password")

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        user.set_password(new_password)
        user.save()
        return Response({"success": True, "message": "Password reset successfully. You can now log in."}, status=status.HTTP_200_OK)
    

class UserLoginView(APIView):
  renderer_classes = (UserRenderer,)
  def post(self, request):
    serializer = UserLoginSerializer(data=request.data)
    if serializer.is_valid():
      email = serializer.data.get('email')
      password = serializer.data.get('password')
      user = authenticate(request, email=email, password=password)
      if user is not None:
        tokens = get_tokens_for_user(user)
        return Response({'success': True, 'data': {
          "email": user.email
        }, 'tokens': tokens}, status=status.HTTP_200_OK)
      else:
        response = {
          'errors': {
            'non_field_errors': 'Username or password is invalid'
          }
        }
        return Response(response, status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
  renderer_classes = (UserRenderer,)
  authentication_classes = [JWTAuthentication]
  permission_classes = [IsAuthenticated]

  def get(self, request):
    user = request.user
    serializer = UserProfileSerializer(user)
    return Response({
      'success': True, 
      'data': {
        **serializer.data,
        'avatar': request.build_absolute_uri(user.avatar.url) if user.avatar else None
      }
    }, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
  renderer_classes = (UserRenderer,)
  authentication_classes = [JWTAuthentication]
  permission_classes = [IsAuthenticated]

  def post(self, request):
    serializer = UserChangePasswordSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
      self.update_user_password(request.user, serializer.data.get('new_password'))
      return Response({'success': True}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

  def update_user_password(self, user, password):
    user.set_password(password)
    user.save()

class UserUpdateView(APIView):
  renderer_classes = (UserRenderer,)
  authentication_classes = [JWTAuthentication]
  permission_classes = [IsAuthenticated]

  def put(self, request):
    user = request.user
    serializer = UserProfileSerializer(user, data=request.data, partial=True)
    if serializer.is_valid():
      serializer.save()
      return Response({'success': True, 'data': serializer.data}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateProfileView(APIView):
    renderer_classes = (UserRenderer,)
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        user = request.user
        serializer = UserProfileUpdateSerializer(user, data=request.data, partial=True)
        
        if serializer.is_valid():
            # Handle avatar file upload
            if 'avatar' in request.FILES:
                # Delete old avatar if exists
                if user.avatar:
                    user.avatar.delete(save=False)
                user.avatar = request.FILES['avatar']
            
            serializer.save()
            return Response({
                'success': True,
                'data': {
                    **serializer.data,
                    'avatar': request.build_absolute_uri(user.avatar.url) if user.avatar else None
                }
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

