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

from django.urls import path, include
from . import views
from .views import reject_user, verify_user
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
    path('messages/',views.messages,name="messages"),
    path('start_conversation/',views.start_conversation,name="start_conversation"),
    

    
    

    path('reject/<int:user_id>/', reject_user, name='reject_user'),
    path('verify/<int:user_id>/', verify_user, name='verify_user'),
]
