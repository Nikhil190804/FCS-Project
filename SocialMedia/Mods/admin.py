
from django.contrib import admin
from .models import Ban, Suspension
from django.contrib import admin
from django.utils.html import format_html
from django.utils.timezone import now
from django import forms
from django.core.exceptions import ValidationError
from .models import ReportUser, Ban, Suspension
from django.urls import reverse

@admin.register(Ban)
class BanAdmin(admin.ModelAdmin):
    list_display = ("user", "banned_at", "reason")
    search_fields = ("user__username",)

@admin.register(Suspension)
class SuspensionAdmin(admin.ModelAdmin):
    list_display = ("user", "suspended_at", "duration", "reason", "is_expired")
    search_fields = ("user__username",)




class SuspensionForm(forms.ModelForm):
    duration = forms.DurationField(
        help_text="Enter duration as '7 days' or '3 hours'.",
        required=True
    )

    class Meta:
        model = Suspension
        fields = ['duration']


class ReportUserAdmin(admin.ModelAdmin):
    list_display = ('user_reported', 'reported_by', 'created_at', 'is_seen_by_admin', 'user_actions')
    list_filter = ('is_seen_by_admin',)
    search_fields = ('user_reported__username', 'reported_by__username', 'complaint')

    def user_actions(self, obj):
        return format_html(
            '<a class="button" style="color: white; background: red; padding: 5px 10px; border-radius: 5px; text-decoration: none;" href="ban/{}/">Ban</a> '
            '<a class="button" style="color: white; background: orange; padding: 5px 10px; border-radius: 5px; text-decoration: none;" href="suspend/{}/">Suspend</a>',
            obj.user_reported.user_id, obj.user_reported.user_id
        )

    user_actions.short_description = 'Actions'

    def get_urls(self):
        from django.urls import path
        urls = super().get_urls()
        custom_urls = [
            path('ban/<int:user_id>/', self.admin_site.admin_view(self.ban_user), name='ban_user'),
            path('suspend/<int:user_id>/', self.admin_site.admin_view(self.suspend_user), name='suspend_user'),
        ]
        return custom_urls + urls

    def ban_user(self, request, user_id):
        """Ban the reported user"""
        from django.shortcuts import redirect, get_object_or_404
        from django.contrib import messages
        from .models import User, Ban

        user = get_object_or_404(User, user_id=user_id)

        if Ban.objects.filter(user=user).exists():
            messages.error(request, f"{user.username} is already banned!")
        else:
            Ban.objects.create(user=user, reason="Banned due to policy violation.")
            messages.success(request, f"{user.username} has been permanently banned.")
            ReportUser.objects.filter(user_reported=user).update(is_seen_by_admin=True)

        return redirect(reverse("admin:Mods_reportuser_changelist"))
    
    def suspend_user(self, request, user_id):
        """Suspend a user with an admin form"""
        from django.shortcuts import render, get_object_or_404, redirect
        from django.contrib import messages
        from .models import User, Suspension

        user = get_object_or_404(User, user_id=user_id)

        if request.method == "POST":
            form = SuspensionForm(request.POST)
            if form.is_valid():
                duration = form.cleaned_data["duration"]
                existing_suspension = Suspension.objects.filter(user=user).first()

                # Check if an existing suspension is still active
                if existing_suspension and not existing_suspension.is_expired():
                    messages.error(request, f"{user.username} is already suspended!")
                else:
                    # If expired, delete old suspension and create a new one
                    if existing_suspension:
                        existing_suspension.delete()
                        
                    Suspension.objects.create(user=user, reason="Violation reported.", duration=duration)
                    messages.success(request, f"{user.username} has been suspended for {duration}.")
                    ReportUser.objects.filter(user_reported=user).update(is_seen_by_admin=True)


                return redirect(reverse("admin:Mods_reportuser_changelist"))
        else:
            form = SuspensionForm()

        return render(request, "Mods/suspend_user.html", {"form": form, "user": user})


    
admin.site.register(ReportUser, ReportUserAdmin)

