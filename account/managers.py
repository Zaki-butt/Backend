# Django Imports
from django.contrib.auth.models import BaseUserManager

class UserManager(BaseUserManager):
  # def create_user(self, email, name, password=None, password_confirmation=None):
  #   """
  #   Creates and saves a User with the given email, name and password.
  #   """
  #   if not email:
  #     raise ValueError("Users must have an email address")

  #   user = self.model(
  #     email=self.normalize_email(email),
  #     name=name,
  #   )

  #   user.set_password(password)
  #   user.save(using=self._db)
  #   return user

  def create_user(self, email, name, password=None, password_confirmation=None,**extra_fields):
    """
    Creates and saves a User with the given email, name, and password.
    """
    if not email:
        raise ValueError("Users must have an email address")

    extra_fields.setdefault("is_active", True)  # Default to True if not provided

    user = self.model(
        email=self.normalize_email(email),
        name=name,
        **extra_fields  # Allow extra fields like is_active
    )

    user.set_password(password)
    user.save(using=self._db)
    return user


  def create_superuser(self, email, name, password=None):
    """
    Creates and saves a superuser with the given email, name and password.
    """
    user = self.create_user(
      email,
      password=password,
      name=name,
    )
    user.is_admin = True
    user.save(using=self._db)
    return user

