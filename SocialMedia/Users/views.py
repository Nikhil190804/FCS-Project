from django.shortcuts import render
from django.http import HttpResponse
from .models import User
from django.contrib.auth.hashers import make_password, check_password
# Create your views here.
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib import messages


def validate_user(username,password):
    user = User.objects.get(username=username)  
    if check_password(password, user.password_hash):  
        return True
    else:
        return False

@staff_member_required
def reject_user(request, user_id):
    user = User.objects.get(id=user_id)
    user.is_active = False
    user.save()
    messages.success(request, "User rejected successfully.")
    return render('/admin/auth/user/')
  
@staff_member_required
def verify_user(request, user_id):
    user = User.objects.get(id=user_id)
    user.is_active = True
    user.save()
    messages.success(request, "User verified successfully.")
    return render('/admin/auth/user/')
  
def handle_signup_request(request):
    if(request.method == "POST"):
        username = request.POST.get("username")
        email = request.POST.get("email")
        phone_number = request.POST.get("phone_number")
        password = request.POST.get("password")
        bio = request.POST.get("bio", "")  
        profile_picture = request.FILES.get("profile_picture")
        hashed_password = make_password(password)

        user = User(
            username=username,
            email=email,
            phone_number=phone_number,
            password_hash=hashed_password,
            bio=bio,
            profile_picture=profile_picture
        )
        user.save()
        return HttpResponse("User saved")
        
    else:
        return render(request,"Users/sign-up.html")
    


def handle_login_request(request):
    if(request.method == "POST"):
        username = request.POST.get("username")
        password = request.POST.get("password")

        try:
            is_present = validate_user(username,password)
            if(is_present == True):
                print("bdia bhai")
                return HttpResponse("User saved")
            else:
                print("wrong password")
                return HttpResponse("User saved")

        except User.DoesNotExist:
            print("user not found")
            return HttpResponse("User saved")

    else:
        return render(request,"Users/login.html")
