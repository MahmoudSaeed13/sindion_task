from django.contrib import admin
from users.models import User
from django.utils.translation import gettext_lazy as _    

# Register your models here.


class UserAdmin(admin.ModelAdmin):
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("username", "name", "email", "password1", "password2"),
            },
        ),
    )
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (_("Personal info"), {"fields": ("name", "email")}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                    'user_type'
                ),
            },
        ),
        (_("Important dates"), {"fields": ("last_login",)}),
    )
    list_display = ("username", "name", "email", "is_superuser", 'user_type')
    search_fields = ["name"]

admin.site.register(User, UserAdmin)