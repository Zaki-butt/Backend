#Django Imports
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

#Local Imports
from account.models import User

class UserAdmin(BaseUserAdmin):
  list_display = ["id", "name", "email", "is_admin"]
  list_filter = ["is_admin"]
  fieldsets = [
      ("Credentials", {"fields": ["email", "password"]}),
      ("Personal info", {"fields": ["name"]}),
      ("Permissions", {"fields": ["is_admin"]}),
  ]
  add_fieldsets = [
    (
      None,
      {
        "classes": ["wide"],
        "fields": ["email", "name", "password1", "password2"],
      },
    ),
  ]
  search_fields = ["id", "name", "email"]
  ordering = ["id", "name", "email"]
  filter_horizontal = []



admin.site.register(User, UserAdmin)
  
