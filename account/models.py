# Django Imports
from django.db import models
import random
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.timezone import now
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth.hashers import make_password
#Local Imports
from account.managers import UserManager

class User(AbstractBaseUser, PermissionsMixin):
  email = models.EmailField(
    verbose_name="Email",
    max_length=255,
    unique=True,
  )
  name = models.CharField(max_length=100)
  is_active = models.BooleanField(default=True)
  is_admin = models.BooleanField(default=False)
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)
  avatar = models.ImageField(
    upload_to='avatars/',
    null=True,
    blank=True,
    help_text='User profile picture'
  )

  # otp = models.CharField(max_length=6, blank=True, null=True)  # Store OTP
  # otp_expires_at = models.DateTimeField(null=True, blank=True)  # OTP Expiry Time

  objects = UserManager()

  USERNAME_FIELD = "email"
  REQUIRED_FIELDS = ["name"]

  def __str__(self):
    return self.email

  def is_otp_valid(self):
      """Check if OTP is still valid."""
      return self.otp and self.otp_expires_at and self.otp_expires_at > now()

  def has_perm(self, perm, obj=None):
    "Does the user have a specific permission?"
    # Simplest possible answer: Yes, always
    return True

  def has_module_perms(self, app_label):
    "Does the user have permissions to view the app `app_label`?"
    # Simplest possible answer: Yes, always
    return True

  @property
  def is_staff(self):
    "Is the user a member of staff?"
    # Simplest possible answer: All admins are staff
    return self.is_admin




class PendingUser(models.Model):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255)
    password = models.CharField(max_length=255)  # Store the hashed password
    otp = models.CharField(max_length=6)  # OTP Code
    created_at = models.DateTimeField(auto_now_add=True)  # Store OTP creation time

    def is_otp_valid(self):
        """Check if OTP is still valid (expires after 10 minutes)."""
        expiry_time = self.created_at + timedelta(minutes=10)
        return timezone.now() <= expiry_time

    @classmethod
    def delete_expired_users(cls):
        """Delete users whose OTP has expired."""
        expiry_time = timezone.now() - timedelta(minutes=5)
        cls.objects.filter(created_at__lt=expiry_time).delete()

    @classmethod
    def create_user_with_otp(cls, email, name, password):
        """Create a pending user and generate an OTP."""
        from django.contrib.auth.hashers import make_password
        import random

        otp = str(random.randint(100000, 999999))  # Generate a 6-digit OTP
        hashed_password = make_password(password)  # Hash password before saving

        return cls.objects.create(email=email, name=name, password=hashed_password, otp=otp)

    
