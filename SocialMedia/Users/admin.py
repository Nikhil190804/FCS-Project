from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.models import Group



class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'is_active', 'is_staff')
    search_fields = ('username', 'email')
    actions = ['reject_users', 'verify_users']
    def has_add_permission(self, request):
        return False

    def reject_users(self, request, queryset):
        queryset.update(is_active=False)
    reject_users.short_description = "Reject selected users"

    def verify_users(self, request, queryset):
        queryset.update(is_active=True)
    verify_users.short_description = "Verify selected users"

admin.site.unregister(User)
admin.site.register(User, UserAdmin)
admin.site.unregister(Group)
