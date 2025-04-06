from django.contrib import admin
from .models import User,Friendship,OnetoOneConversation,OnetoOneMessage,OneToOneAttachment
from .models import Group,GroupMember,GroupMessages,GroupAttachment


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


@admin.register(Friendship)
class FriendshipAdmin(admin.ModelAdmin):
    list_display = ("id", "from_user", "to_user", "status", "created_at")
    list_filter = ("status",)
    search_fields = ("from_user__username", "to_user__username")
    ordering = ("-created_at",)



@admin.register(OnetoOneConversation)
class OnetoOneConversationAdmin(admin.ModelAdmin):
    list_display = ("id", "user_a", "user_b", "created_at")
    search_fields = ("user_a__username", "user_b__username")
    ordering = ("-created_at",)



@admin.register(OnetoOneMessage)
class OnetoOneMessageAdmin(admin.ModelAdmin):
    list_display = ("id", "conversation", "sender", "receiver", "is_read", "sent_at")
    search_fields = ("sender__username", "receiver__username")
    ordering = ("-sent_at",)



@admin.register(OneToOneAttachment)
class OneToOneAttachmentAdmin(admin.ModelAdmin):
    list_display = ("id", "conversation", "message", "file", "uploaded_at")



@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "admin", "created_at")
    search_fields = ("name", "admin__username")
    ordering = ("-created_at",)


@admin.register(GroupMember)
class GroupMemberAdmin(admin.ModelAdmin):
    list_display = ("id", "group", "user", "created_at", "unread_count")
    search_fields = ("user__username", "group__name")
    ordering = ("-created_at",)



@admin.register(GroupMessages)
class GroupMessagesAdmin(admin.ModelAdmin):
    list_display = ("id", "group", "sender", "is_message_present", "is_attachment_present", "sent_at")
    search_fields = ("sender__username",)
    ordering = ("-sent_at",)



@admin.register(GroupAttachment)
class GroupAttachmentAdmin(admin.ModelAdmin):
    list_display = ("id", "group", "message", "file", "uploaded_at")


admin.site.register(User, UserAdmin)


