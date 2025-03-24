from django.contrib import admin
from .models import User

class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'is_verified')
    list_filter = ('is_verified',)
    search_fields = ('username', 'email')
    actions = ['verify_users', 'unverify_users']

    def verify_users(self, request, queryset):
        queryset.update(is_verified=True)
        self.message_user(request, "Selected users have been verified.")

    def unverify_users(self, request, queryset):
        queryset.update(is_verified=False)
        self.message_user(request, "Selected users have been unverified.")

    verify_users.short_description = "Mark selected users as verified"
    unverify_users.short_description = "Mark selected users as unverified"

admin.site.register(User, UserAdmin)
