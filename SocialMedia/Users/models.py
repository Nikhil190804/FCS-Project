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
    public_key = models.TextField() 


    
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



class OnetoOneConversation(models.Model):
    friendship = models.OneToOneField(
        'Friendship', on_delete=models.CASCADE, related_name='conversation'
    )
    user_a = models.ForeignKey('User', on_delete=models.CASCADE, related_name='conversation_a')
    user_b = models.ForeignKey('User', on_delete=models.CASCADE, related_name='conversation_b')

    encrypted_aes_key_for_user_a = models.BinaryField()
    encrypted_aes_key_for_user_b = models.BinaryField()  

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user_a', 'user_b'], name='unique_onetoone_conversation')
        ]

    def __str__(self):
        return f"Conversation: {self.user_a.username} ↔ {self.user_b.username}"




class OnetoOneMessage(models.Model):
    conversation = models.ForeignKey('OnetoOneConversation', on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey('User', on_delete=models.CASCADE, related_name='sent_onetoone_messages')
    receiver = models.ForeignKey('User', on_delete=models.CASCADE, related_name='received_onetoone_messages')
    encrypted_message_content = models.BinaryField()  
    encryption_iv = models.BinaryField(default=1)  
    document = models.FileField(upload_to='one_to_one_documents/', blank=True, null=True)
    is_document_present = models.BooleanField(default=False)

    sent_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False) 

    def __str__(self):
        return f"Message from {self.sender.username} to {self.receiver.username}"
    

class Group(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    group_profile_picture = models.ImageField(upload_to='group_profile_pictures/',blank=False, null=False)
    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name="admin_groups")
    created_at = models.DateTimeField(auto_now_add=True)
    aes_key_encrypted_by_admin = models.BinaryField()  

    def __str__(self):
        return self.name


class GroupMember(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="group_members")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="group_memberships")
    aes_key_encrypted = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('group', 'user')

    def __str__(self):
        return f"{self.user.username} is a part of {self.group}"



class GroupMessages(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="group_messages")
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_group_messages")
    encrypted_message_content = models.BinaryField()  
    sent_at = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return f"Message from {self.sender.username}"
    