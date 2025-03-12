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