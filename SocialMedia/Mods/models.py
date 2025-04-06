from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError
from Users.models import User

class Ban(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="ban")
    reason = models.TextField()
    banned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} is permanently banned"


class Suspension(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="suspension")
    reason = models.TextField()
    suspended_at = models.DateTimeField(auto_now_add=True)
    duration = models.DurationField(help_text="Duration of suspension (e.g., 7 days, 3 hours)")

    def is_expired(self):
        return timezone.now() >= self.suspended_at + self.duration

    def extend_suspension(self, extra_duration):
        if extra_duration.total_seconds() <= 0:
            raise ValidationError("Extension duration must be positive.")
        
        self.duration += extra_duration
        self.save()

    def __str__(self):
        return f"{self.user.username} is suspended until {self.suspended_at + self.duration}"


class ReportUser(models.Model):
    user_reported = models.ForeignKey(User, on_delete=models.CASCADE, related_name="reports_received")
    reported_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="reports_sent")
    complaint = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_seen_by_admin = models.BooleanField(default=False)

    def __str__(self):
        return f"Report against {self.user_reported.username} by {self.reported_by.username}"
    