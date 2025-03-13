from django.shortcuts import render
from django.http import HttpResponse
from .models import User
from .models import Friendship
from django.shortcuts import redirect
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
import secrets
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail
from django.contrib import messages

# Create your views here.
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib import messages


def validate_user(username,password):
    try:
        user = User.objects.get(username=username)  
        if check_password(password, user.password_hash):  
            return True,user
        return False ,None
    except ObjectDoesNotExist:  
        return False,None


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
        otp = user_data["otp"]
        if entered_otp==otp:  
            return redirect("Users:create_profile")
        else:
            return render(request,"Users/otp.html",{"error":"Invalid OTP!!!"})
    else:
        return render(request,"Users/otp.html")


def generate_otp(length):
    OTP=""
    for i in range(length):
        OTP+=str(secrets.randbelow(10))
    print(OTP)
    return OTP
  

def send_otp_mail(OTP,email):
    subject = "Your OTP Code For SocialMedia"
    message = f"Your OTP code is: {OTP}"
    from_email = "the404s.fcs@gmail.com"
    recipient_list = [email]

    try:
        send_mail(subject, message, from_email, recipient_list)
        return True,None
    except Exception as e:
        return False,str(e)

def handle_signup_request(request):
    if(request.method == "POST"):
        username = request.POST.get("username")
        email = request.POST.get("email")
        phone_number = request.POST.get("phone_number")
        password = request.POST.get("password")
        hashed_password = make_password(password)

        isEmailValid = validate_email(email)
        if(isEmailValid==True):
            otp = generate_otp(5)
            user_data = {
                "username": username,
                "email": email,
                "phone_number": phone_number,
                "hashed_password":hashed_password,
                "otp":otp,
            }
            request.session["pending_user"] = user_data
            isOTPMailSent,message = send_otp_mail(otp,email)
            if(isOTPMailSent==True):
                return redirect("Users:otp")
            else:
                print(message)
                return HttpResponse("L lg gye dost!")
            
        else:
            return render(request,"Users/sign-up.html",{"error": "Invalid email format!"})

    else:
        return render(request,"Users/sign-up.html")
    


def handle_login_request(request):
    if(request.method == "POST"):
        username = request.POST.get("username")
        password = request.POST.get("password")

        try:
            is_present,user = validate_user(username,password)
            if(is_present == True):
                print("bdia bhai")
                request.session["current_user"] = user.user_id
                return redirect("Users:home")
            else:
                print("wrong password")
                return HttpResponse("wrong password")

        except User.DoesNotExist:
            print("user not found")
            return HttpResponse("not found")

    else:
        return render(request,"Users/login.html")
      

def create_profile(request):
    if(request.method == "POST"):
        user_data = request.session.get("pending_user")
        bio = request.POST.get("bio")
        profile_picture = request.FILES.get('profile_picture')  
        verification_doc = request.FILES.get('verification_doc')

        username = user_data.get("username")
        email = user_data.get("email")
        phone_number = user_data.get("phone_number")
        hashed_password = user_data.get("hashed_password")

        user = User.objects.create(
            username=username,
            email=email,
            phone_number=phone_number,
            password_hash=hashed_password,
            profile_picture=profile_picture,
            bio=bio
        )

        if verification_doc:
            user.verfication_document = verification_doc

        user.save()
        request.session.pop("pending_user", None)
        request.session["current_user"] = user.user_id
        return redirect("Users:home")
        
    else:
        return render(request,"Users/confirm-sign-up.html")

def home(request):
    user_id=request.session["current_user"]
    user = User.objects.get(user_id=user_id)  
    context = {
        "user_name": user.username, 
    }
    return render(request,"Users/home.html",context)


def search_users(request):
    current_user_id = request.session.get("current_user")
    if(request.method == "POST"):
        to_user_id = request.POST.get("to_user_id")
        print(current_user_id)
        print(to_user_id)
        friend_request =  Friendship.objects.create( 
            from_user = User.objects.get(user_id=current_user_id),
            to_user = User.objects.get(user_id=to_user_id),
        )
        friend_request.save()
        messages.success(request, "Request Sent!")
        return redirect("Users:search_users")

    
    if(request.method == "GET"):
        search_parameter = request.GET.get('query', None)
        if(search_parameter !=None):
            search_results = User.objects.filter(username__icontains=search_parameter).exclude(user_id=current_user_id)
        else:
            search_results=None

        return render(request, 'Users/search_users.html', {'search_results': search_results})
   

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
