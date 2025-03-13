from django.db import models

class User(models.Model):
    user_id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, unique=True)
    password_hash = models.CharField(max_length=512)
    profile_picture = models.ImageField(upload_to='profile_pictures/',blank=False, null=False)
    verfication_document = models.FileField(upload_to='verfication_documents/', blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Hello I am {self.username}"
    


class Friendship(models.Model):
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('declined', 'Declined'),
    ]

    from_user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='sent_requests')
    to_user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='received_requests')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    from_user_blocked = models.BooleanField(default=False)  
    to_user_blocked = models.BooleanField(default=False)    

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['from_user', 'to_user'], name='unique_friendship')
        ]

    def __str__(self):
        return f"{self.from_user.username} -> {self.to_user.username} ({self.status})"

    def block_user(self, blocker):
        if blocker == self.from_user:
            self.from_user_blocked = True
        elif blocker == self.to_user:
            self.to_user_blocked = True
        self.save()

    def unblock_user(self, unblocker):
        if unblocker == self.from_user:
            self.from_user_blocked = False
        elif unblocker == self.to_user:
            self.to_user_blocked = False
        self.save()