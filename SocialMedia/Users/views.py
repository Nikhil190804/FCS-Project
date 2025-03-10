from django.shortcuts import render
from django.http import HttpResponse
from .models import User
from django.shortcuts import redirect
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
import secrets

# Create your views here.
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib import messages


def validate_user(username,password):
    user = User.objects.get(username=username)  
    if check_password(password, user.password_hash):  
        return True
    else:
        return False


def validate_email(email):
    try:
        email_validator = EmailValidator()
        email_validator(email)
        return True
    except ValidationError:
        return False



def otp(request):
    if(request.method == "POST"):
        user_data = request.session.get("pending_user")
        entered_otp = request.POST.get("otp")
        print(user_data)
        print(entered_otp)
        otp_hashed = user_data["otp_hashed"]
        if check_password(entered_otp, otp_hashed):  
            return HttpResponse("coolll")
        else:
            return render(request,"Users/otp.html",{"error":"Invalid OTP!!!"})
    else:
        return render(request,"Users/otp.html")


def generate_hashed_otp(length):
    OTP=""
    for i in range(length):
        OTP+=str(secrets.randbelow(10))
    print(OTP)

    hashed_otp = make_password(OTP)
    return hashed_otp
  

def handle_signup_request(request):
    if(request.method == "POST"):
        username = request.POST.get("username")
        email = request.POST.get("email")
        phone_number = request.POST.get("phone_number")
        password = request.POST.get("password")
        hashed_password = make_password(password)

        isEmailValid = validate_email(email)
        if(isEmailValid==True):
            otp_hashed = generate_hashed_otp(5)
            user_data = {
                "username": username,
                "email": email,
                "phone_number": phone_number,
                "hashed_password":hashed_password,
                "otp_hashed":otp_hashed,
            }
            request.session["pending_user"] = user_data
            return redirect("Users:otp")
        else:
            return render(request,"Users/sign-up.html",{"error": "Invalid email format!"})

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
