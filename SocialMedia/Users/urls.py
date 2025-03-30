"""
URL configuration for SocialMedia project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.urls import path
from django.contrib import admin
from Users.views import verify_users, change_verification_status 
import Users.views as views 
urlpatterns = [
    path('signup/',views.handle_signup_request,name="signup"),
    path('login/',views.handle_login_request,name="login"),
    path('otp/',views.otp,name="otp"),
    path('create_profile/',views.create_profile,name="create_profile"),
    path('home/',views.home,name="home"),
    path('search_users/',views.search_users,name="search_users"),
    path('show_friend_requests/',views.show_friend_requests,name="show_friend_requests"),
    path('settings/',views.settings,name="settings"),
    path('change_password/',views.change_password,name="change_password"),
    path('change_bio/',views.change_bio,name="change_bio"),
    path('change_profile_picture/',views.change_profile_picture,name="change_profile_picture"),
    path('messages/',views.messages,name="messages"),
    path('start_conversation/',views.start_conversation,name="start_conversation"),
    path('send_one_to_one_message/<int:reciever_id>/',views.send_one_to_one_message, name='send_one_to_one_message'),
    path('one_to_one_attachment/<int:conversation_id>/<int:message_id>/<int:attachment_id>/', views.one_to_one_attachment, name='one_to_one_attachment'),
    path('block_user/<int:user_id>/',views.block_user, name='block_user'),
    path('view_blocked_users/',views.view_blocked_users,name="view_blocked_users"),
    path('unblock_user/<int:user_id>/',views.unblock_user,name="unblock_user"),
    path('show_groups/',views.show_groups,name="show_groups"),
    path('create_group/',views.create_group,name="create_group"),
    path('send_group_message/<int:group_id>/',views.send_group_message,name="send_group_message"),
    path('view_group/<int:group_id>/',views.view_group,name="view_group"),
    path('group_attachment/<int:group_id>/<int:message_id>/<int:attachment_id>/', views.group_attachment, name='group_attachment'),





    path("admin/verify_users/", verify_users, name="verify_users"),
    path("admin/verify/<int:user_id>/<str:status>/", change_verification_status, name="change_verification_status"),
    path('admin/', admin.site.urls),
    path('profile/', views.profile, name="profile"),

]
