from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.http import FileResponse, HttpResponseForbidden, Http404
from .models import User
from .models import Friendship
from .models import *
from django.shortcuts import redirect
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
import secrets
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail
from django.contrib import messages as mem
from django.db.models import Q,Count
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import json
from django.shortcuts import  get_object_or_404
# Create your views here.
from django.contrib.admin.views.decorators import staff_member_required
import os
import django.conf as dj_conf
from Mods.models import ReportUser,Ban,Suspension
from django.contrib.auth import logout
from django.db import IntegrityError, DatabaseError, transaction



@staff_member_required
def verify_users(request):
    users = User.objects.filter(is_verified=False)  # Show only unverified users
    return render(request, "verify_users.html", {"users": users})

@staff_member_required
def change_verification_status(request, user_id, status):
    user = get_object_or_404(User, user_id=user_id)
    user.is_verified = (status == "verify")
    user.save()
    
    status_message = "verified" if user.is_verified else "unverified"
    mem.success(request, f"User {user.username} has been {status_message}.")
    return redirect("verify_users")














def check_for_ban_suspension(user_id):
    if Ban.objects.filter(user__user_id=user_id).exists():
        return True, "You are permanently banned!"
    
    suspension = Suspension.objects.filter(user__user_id=user_id).first()
    if suspension and not suspension.is_expired():
        return True, "You are suspended for some time!"

    return False, "You have full access." 



def check_for_friends(user_id, friend_id):
    friendship = Friendship.objects.filter(
        Q(from_user_id=user_id, to_user_id=friend_id) | 
        Q(from_user_id=friend_id, to_user_id=user_id),   
        status='accepted'  
    ).exists()

    return friendship



def generate_public_private_keys():
    KEY = RSA.generate(2048)
    private_key = KEY.export_key(pkcs=8)
    public_key = KEY.public_key().export_key(format="PEM")

    private_key_encoded = private_key.decode()
    public_key_encoded = public_key.decode()

    return public_key_encoded,private_key_encoded


def encrypt_aes_key(aes_key,public_key):
    public_key_decoded = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key_decoded,hashAlgo=SHA256)
    #aes_key_base64 = base64.b64encode(aes_key)  
    encrypted_aes_key = cipher.encrypt(aes_key)

    #encrypted_aes_key_encoded = base64.b64encode(encrypted_aes_key).decode()
    return encrypted_aes_key


def validate_user(username,password):
        user = User.objects.get(username=username)  
        if check_password(password, user.password_hash):  
            return True,user
        else:
            return False ,None  


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
        if((not user_data) or (not entered_otp)):
            CONTEXT = {
                    "heading":"Session Expired",
                    "message":"Your Session Has Expired!",
                    "button_url":"Home"
                }
            return render(request,"Socialmedia/error.html",CONTEXT)

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
    return OTP
  

def check_for_blocked_user(current_user_id, friend_id):
    try:
        friendship = Friendship.objects.get(
            models.Q(from_user_id=current_user_id, to_user_id=friend_id) |
            models.Q(from_user_id=friend_id, to_user_id=current_user_id)
        )
        
        if ((friendship.from_user_id == current_user_id and friendship.from_user_blocked) or (friendship.to_user_id == current_user_id and friendship.to_user_blocked)):
            return True
        return False
    except Friendship.DoesNotExist:
        return False  
    except Exception as e:
        return False


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
    if "current_user" in request.session:  
        return redirect("Users:home")
    if(request.method == "POST"):
        username = request.POST.get("username")
        email = request.POST.get("email")
        phone_number = request.POST.get("phone_number")
        password = request.POST.get("password")

        if not all([username, email, phone_number, password]):
            CONTEXT = {
                    "heading":"Error",
                    "message":"Valid Fields Not Found",
                    "button_url":"Home"
                }
            return render(request,"Socialmedia/error.html",CONTEXT)
        
        try:
            if len(username) > 30:
                CONTEXT = {
                    "heading":"Error",
                    "message":"Username cannot be longer than 30 characters.",
                    "button_url":"Home"
                }
                return render(request,"Socialmedia/error.html",CONTEXT)
        
            if len(password) > 30:
                CONTEXT = {
                    "heading":"Error",
                    "message":"Password cannot be longer than 30 characters.",
                    "button_url":"Home"
                }
                return render(request,"Socialmedia/error.html",CONTEXT)
                

            if not phone_number.isdigit():
                CONTEXT = {
                    "heading":"Error",
                    "message":"Phone number must contain only digits.",
                    "button_url":"Home"
                }
                return render(request,"Socialmedia/error.html",CONTEXT)

            if len(phone_number) > 12: 
                CONTEXT = {
                    "heading":"Error",
                    "message":"Phone number cannot be longer than 12 digits.",
                    "button_url":"Home"
                }
                return render(request,"Socialmedia/error.html",CONTEXT)
                
        except Exception as e:
            CONTEXT = {
                    "heading":"Error",
                    "message":"Wrong Fields In Request",
                    "button_url":"Home"
                }
            return render(request,"Socialmedia/error.html",CONTEXT)

        
        hashed_password = make_password(password)

        isEmailValid = validate_email(email)
        if(isEmailValid==True):
            otp = generate_otp(6)
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
                CONTEXT = {
                    "heading":"Error",
                    "message":"Failure In Sending Mail",
                    "button_url":"Home"
                }
                return render(request,"Socialmedia/error.html",CONTEXT)
            
        else:
            return render(request,"Users/sign-up.html",{"error": "Invalid email format!"})

    else:
        return render(request,"Users/sign-up.html")
    

def handle_login_request(request):
    if "current_user" in request.session:  
        return redirect("Users:home")

    if(request.method == "POST"):
        username = request.POST.get("username")
        password = request.POST.get("password")

        try:
            is_present,user = validate_user(username,password)
            if(is_present == True):
                is_ban_or_suspended,msg = check_for_ban_suspension(user.user_id)
                if(is_ban_or_suspended==True):
                    CONTEXT = {
                        "heading":"Error",
                        "message":msg,
                        "button_url":"Home"
                    }
                    return render(request,"Socialmedia/error.html",CONTEXT)
                else:
                    request.session["current_user"] = user.user_id
                    return redirect("Users:home")
            else:
                CONTEXT = {
                    "heading":"Error",
                    "message":"Wrong Password!",
                    "button_url":"Users:login"
                }
                return render(request,"Socialmedia/error.html",CONTEXT)

        except User.DoesNotExist:
            CONTEXT = {
                    "heading":"Error",
                    "message":"User With Given Username Does Not Exist!",
                    "button_url":"Users:login"
            }
            return render(request,"Socialmedia/error.html",CONTEXT)

    else:
        return render(request,"Users/login.html")
      

def handle_logout_request(request):
    logout(request)  
    request.session.flush()  
    return redirect("/")


def create_profile(request):
    if(request.method == "POST"):
        user_data = request.session.get("pending_user")
        bio = request.POST.get("bio")
        profile_picture = request.FILES.get('profile_picture')  
        verification_doc = request.FILES.get('verification_doc')

        if not profile_picture:
            request.session.flush()  
            CONTEXT = {
                    "heading":"Error",
                    "message":"Profile Picture Is Mandatory!",
                    "button_url":"Home"
            }
            return render(request,"Socialmedia/error.html",CONTEXT)

        username = user_data.get("username")
        email = user_data.get("email")
        phone_number = user_data.get("phone_number")
        hashed_password = user_data.get("hashed_password")

        if not all([username, email, phone_number, hashed_password]):
            request.session.flush()  
            CONTEXT = {
                    "heading":"Error",
                    "message":"Session Expired!",
                    "button_url":"Home"
            }
            return render(request,"Socialmedia/error.html",CONTEXT)

        public_key,private_key = generate_public_private_keys()
        try:
            with transaction.atomic():
                user = User.objects.create(
                    username=username,
                    email=email,
                    phone_number=phone_number,
                    password_hash=hashed_password,
                    profile_picture=profile_picture,
                    bio=bio,
                    public_key=public_key,
                )

                if verification_doc:
                    user.verfication_document = verification_doc

                user.save()
        except Exception as e:
            request.session.flush()  
            CONTEXT = {
                    "heading":"Error",
                    "message":"Username, Email, Phone Number Should Be Unique !",
                    "button_url":"Home"
            }
            return render(request,"Socialmedia/error.html",CONTEXT)

        
        request.session.pop("pending_user", None)
        request.session["current_user"] = user.user_id
        request.session["private_key"]=private_key
        return redirect("Users:home")
        
    else:
        return render(request,"Users/confirm-sign-up.html")


def home(request):
    user_id=request.session["current_user"]
    private_key = request.session.get("private_key")
    user = User.objects.get(user_id=user_id)
    if(not private_key):
        context = {
        "user_name": user.username, 
        }
        return render(request,"Users/home.html",context)
    else:
        context = {
            "user_name": user.username, 
            "private_key": private_key,
        }
        request.session.pop("private_key", None)
        return render(request,"Users/home.html",context)
    


def search_users(request):
    current_user_id = request.session.get("current_user")
    if(request.method == "POST"):
        to_user_id = request.POST.get("to_user_id")

        if not to_user_id:
            CONTEXT = {
                    "heading":"Error",
                    "message":"Recipient is required!",
                    "button_url":"Users:home"
            }
            return render(request,"Socialmedia/error.html",CONTEXT)
        
        try:
            to_user = User.objects.get(user_id=to_user_id)
            from_user = User.objects.get(user_id=current_user_id)
        except User.DoesNotExist:
            CONTEXT = {
                    "heading":"Error",
                    "message":"No Recipient Found With That Username !",
                    "button_url":"Users:home"
            }
            return render(request,"Socialmedia/error.html",CONTEXT)
        
        existing_request = Friendship.objects.filter(
            (Q(from_user=from_user, to_user=to_user) | Q(from_user=to_user, to_user=from_user))
        ).exists()

        if existing_request:
            CONTEXT = {
                    "heading":"Error",
                    "message":"Friend request already exists!",
                    "button_url":"Users:home"
            }
            return render(request,"Socialmedia/error.html",CONTEXT)
    
        with transaction.atomic():
            friend_request = Friendship.objects.create(from_user=from_user, to_user=to_user)
            friend_request.save()
        
        mem.success(request, "Request Sent!")
        return redirect("Users:search_users")

    
    if(request.method == "GET"):
        final_results = []
        search_parameter = request.GET.get('query', None)
        if(search_parameter !=None):
            friendships = Friendship.objects.filter(
                Q(from_user=current_user_id, status__in=['accepted', 'pending']) | 
                Q(to_user=current_user_id, status__in=['accepted', 'pending'])
            ).values('from_user', 'to_user')

            friend_ids = set()
            for friendship in friendships:
                if friendship['from_user'] == current_user_id:
                    friend_ids.add(friendship['to_user'])  
                else:
                    friend_ids.add(friendship['from_user'])

            banned_user_ids = set(Ban.objects.values_list('user_id', flat=True))

            
            active_suspended_user_ids = set(
                suspension.user_id
                for suspension in Suspension.objects.all()
                if not suspension.is_expired()
            )

            restricted_user_ids = banned_user_ids | active_suspended_user_ids
           
            search_results = User.objects.filter(
                Q(username__icontains=search_parameter) | Q(bio__icontains=search_parameter) 
            ).exclude(user_id=current_user_id).exclude(user_id__in=restricted_user_ids)

            

           
            for user in search_results:
                if(user.user_id in friend_ids):
                    user.is_friend=True
                else:
                    user.is_friend=False
                final_results.append(user)

                
        else:
            final_results=None
            search_results=None

        return render(request, 'Users/search_users.html', {'search_results': final_results})
   

def show_friend_requests(request):
    if(request.method == "POST"):
        friends_id = request.POST.get("request_id")
        action = request.POST.get("action")

        if ((not friends_id) or (not action)):
            CONTEXT = {
                    "heading":"Error",
                    "message":"No Friend Selected or No Action Selected !",
                    "button_url":"Users:home"
            }
            return render(request,"Socialmedia/error.html",CONTEXT)
        try:
            friend_request = Friendship.objects.get(id=friends_id)
            if(action=="accept"):
                friend_request.status = "accepted"
                AES_KEY = get_random_bytes(32)
                public_key_user_a = friend_request.from_user.public_key
                public_key_user_b = friend_request.to_user.public_key
                aes_key_for_user_a = encrypt_aes_key(AES_KEY,public_key_user_a)
                aes_key_for_user_b = encrypt_aes_key(AES_KEY,public_key_user_b)
                conversation = OnetoOneConversation.objects.create(
                    friendship=friend_request,
                    user_a=friend_request.from_user,
                    user_b=friend_request.to_user,
                    encrypted_aes_key_for_user_a=aes_key_for_user_a,
                    encrypted_aes_key_for_user_b=aes_key_for_user_b,
                )
                conversation.save()
                
            else:
                friend_request.status = "declined"
            friend_request.save()
            mem.success(request, "Friend Request Accepted !")
           
            return redirect("Users:home")
        
        except Exception as e:
            CONTEXT = {
                    "heading":"Error",
                    "message":"No Valid Friend Request Found !",
                    "button_url":"Users:home"
            }
            return render(request,"Socialmedia/error.html",CONTEXT)

        
        
    else:
        current_user_id = request.session.get("current_user")
        friend_requests = Friendship.objects.filter(to_user_id=current_user_id, status='pending')
        return render(request,'Users/friend_requests.html',{"friend_requests":friend_requests})
    

def settings(request):
        current_user_id = request.session.get("current_user")
        user = User.objects.get(user_id=current_user_id)
        return render(request,'Users/settings.html',{"user":user, "profile":True, "action":True})


def change_password(request):
    if(request.method=="POST"):
        current_user_id = request.session.get("current_user")
        user = User.objects.get(user_id=current_user_id)
        otp = request.session.get("otp")
        user_entered_password = request.POST.get("new_password")
        user_entered_otp = request.POST.get("otp")

        if not otp or not user_entered_password or not user_entered_otp:
            CONTEXT = {
                        "heading":"Error",  
                        "message":"OTP and new password are required!",
                        "button_url":"Users:home",
                    }
            return render(request, "Socialmedia/error.html", CONTEXT,status=404)
            
        if not user_entered_otp.isdigit() or len(user_entered_otp) != 6:
            CONTEXT = {
                        "heading":"Error",  
                        "message":"Invalid OTP format!",
                        "button_url":"Users:home",
                    }
            return render(request, "Socialmedia/error.html", CONTEXT,status=404)
        
        if len(user_entered_password) > 30:
            CONTEXT = {
                        "heading":"Error",  
                        "message":"Password cannot exceed 30 characters!",
                        "button_url":"Users:home",
                    }
            return render(request, "Socialmedia/error.html", CONTEXT,status=404)
         

        if(otp==user_entered_otp):
            hashed_password = make_password(user_entered_password)
            user.password_hash=hashed_password
            user.save()
            request.session.pop("otp", None)
            return render(request,'Users/settings.html',{ "profile":False, "action":False, "otp":False,"message":"Password Updated !"})

        else:
            return render(request,'Users/settings.html',{ "profile":False, "action":False, "otp":False,"message":"Wrong OTP!"})



    else:

        current_user_id = request.session.get("current_user")
        user = User.objects.get(user_id=current_user_id)
        otp = generate_otp(6)
        isOTPMailSent,message = send_otp_mail(otp,user.email)
        if(isOTPMailSent==True):
            request.session["otp"] = otp
            return render(request,'Users/settings.html',{ "profile":False, "action":False, "otp":True})
        else:
            CONTEXT = {
                    "heading":"Error",
                    "message":"Failed To Send Mail !",
                    "button_url":"Home"
            }
            return render(request,"Socialmedia/error.html",CONTEXT)



def change_bio(request):
    if(request.method == "POST"):
        current_user_id = request.session.get("current_user")
        user = User.objects.get(user_id=current_user_id)
        new_bio = request.POST.get("bio", None)
        if(new_bio is not None):
            user.bio=new_bio
            user.save()
            return render(request,"Users/change_profile.html",{"message":"Bio Updated Successfully !"})
        else: 
            mem.success(request,"New Bio is Empty!")
            return render(request,"Users/change_profile.html",{"message":"New Bio is Empty!"})
    else:
        return render(request,"Users/change_profile.html",{"bio":True})


def change_profile_picture(request):
    if(request.method == "POST"):
        current_user_id = request.session.get("current_user")
        user = User.objects.get(user_id=current_user_id)
        try:
            if ("profile_picture" in request.FILES):
                if user.profile_picture:  
                    old_picture_path = os.path.join(dj_conf.settings.MEDIA_ROOT, str(user.profile_picture))
                    print(old_picture_path)
                    if os.path.exists(old_picture_path):
                        os.remove(old_picture_path)
                new_picture = request.FILES["profile_picture"]
                user.profile_picture = new_picture 
                user.save()
                return render(request,"Users/change_profile.html",{"message":"Profile Updated Successfully!"})
            else: 
                return render(request,"Users/change_profile.html",{"message":"Photo Not Uploaded or Backend Error!"})
        except Exception as e:
            CONTEXT = {
                        "heading":"Error",  
                        "message":"Backend Error !",
                        "button_url":"Users:home",
                    }
            return render(request, "Socialmedia/error.html", CONTEXT,status=404)
        
     
    else:
        return render(request,"Users/change_profile.html",{"profile_picture":True})



def messages(request):
    all_unread_messages = []
    current_user_id = request.session.get("current_user")
    current_user = User.objects.get(pk=current_user_id)

    conversations = OnetoOneConversation.objects.filter(
        Q(user_a=current_user) | Q(user_b=current_user)
    )

    for conversation in conversations:
        friendship = conversation.friendship
        friend = None
        if(friendship.from_user == current_user):
            friend=friendship.to_user
        else:
            friend=friendship.from_user

        isBlocked = check_for_blocked_user(current_user_id,friend.user_id)
        is_ban_or_suspend,msg = check_for_ban_suspension(friend.user_id)
        if(isBlocked or is_ban_or_suspend):
            continue
        else:
            # case 1 they have never talked , hence no entry in one to one message
            if not OnetoOneMessage.objects.filter(conversation=conversation).exists():
                continue

            # case 2 , when they have talked 
            unread_count = (
                OnetoOneMessage.objects
                .filter(conversation=conversation, receiver=current_user, is_read=False)
                .count()
            )

            data_dict = {}
            data_dict["sender"]=friend
            data_dict["unread_count"]=unread_count
            all_unread_messages.append(data_dict)

    if(all_unread_messages==[]):
        return render(request,'Users/messages.html',{ "message_data":False})
    else:
        return render(request,'Users/messages.html',{ "message_data":all_unread_messages})



def start_conversation(request):
    current_user_id = request.session.get("current_user")
    user = User.objects.get(pk=current_user_id)
    friends = OnetoOneConversation.objects.filter(
            Q(user_a=user) | Q(user_b=user)
    )
    friends_data=[]
    for friend in friends:
        if(friend.user_a==user):
            isBlocked = check_for_blocked_user(user.user_id,friend.user_b.user_id)
            is_ban_or_suspend,msg = check_for_ban_suspension(friend.user_b.user_id)
            if(isBlocked or is_ban_or_suspend):
                continue
            else:
                friends_data.append(friend.user_b)
        else:
            isBlocked = check_for_blocked_user(user.user_id,friend.user_a.user_id)
            is_ban_or_suspend,msg = check_for_ban_suspension(friend.user_a.user_id)
            if(isBlocked or is_ban_or_suspend):
                continue
            else:
                friends_data.append(friend.user_a)

    return render(request,"Users/friends.html",{"friends_data":friends_data})



def send_one_to_one_message(request,reciever_id):
    current_user_id = request.session.get("current_user")

    if not reciever_id:
        CONTEXT = {
                        "heading":"Error",  
                        "message":"Receiver ID is required!",
                        "button_url":"Users:home",
                    }
        return render(request, "Socialmedia/error.html", CONTEXT,status=404)
       
    if not User.objects.filter(user_id=reciever_id).exists():
        CONTEXT = {
                        "heading":"Error",  
                        "message":"Receiver not found!",
                        "button_url":"Users:home",
                    }
        return render(request, "Socialmedia/error.html", CONTEXT,status=404)
        

    isBlocked_or_valid = check_for_blocked_user(current_user_id,reciever_id)
    is_ban_or_suspend_1,msg_1 = check_for_ban_suspension(reciever_id)
    is_ban_or_suspend_2,msg_2 = check_for_ban_suspension(current_user_id)

    if(isBlocked_or_valid):
        mem.error(request,"Wrong FriendID or Friend has been blocked!!")
        return redirect("Users:home")
    
    if(is_ban_or_suspend_1):
        mem.error(request,"Friend has been banned or suspended!!")
        return redirect("Users:home")
    
    if(is_ban_or_suspend_2):
        mem.error(request,msg_2)
        return redirect("Home")
    
    if(request.method=="POST"):
        current_user_id = request.session.get("current_user")
        sender_id = current_user_id
        sender = User.objects.get(pk=current_user_id)
        reciever = User.objects.get(pk=reciever_id)
        conversation = OnetoOneConversation.objects.filter(
            Q(user_a=sender_id,user_b=reciever_id) | Q(user_a=reciever_id,user_b=sender_id)
        ).first()

        if(conversation):
            encrypted_msg_data = request.POST.get('encrypted_msg')
            file = request.FILES.get('file')
            is_message = False
            is_attachment = False
            if(encrypted_msg_data):
                encrypted_msg_data=json.loads(encrypted_msg_data)
                message_encrypted = base64.b64decode(encrypted_msg_data)   
                is_message=True
            if(file):
                is_attachment=True

            if(is_message):
                new_message = OnetoOneMessage.objects.create(
                    conversation=conversation,
                    sender=sender,
                    receiver=reciever,
                    encrypted_message_content=message_encrypted,
                    is_message_present=True
                )
                if(is_attachment):
                    attachment = OneToOneAttachment.objects.create(
                        conversation=conversation,
                        message=new_message,
                        file=file,
                    )
                    attachment.save()
                    new_message.attachment=attachment
                    new_message.is_attachment_present=True
                new_message.save()
            else:
                new_message = OnetoOneMessage.objects.create(
                    conversation=conversation,
                    sender=sender,
                    receiver=reciever,
                    is_message_present=False,
                )
                attachment = OneToOneAttachment.objects.create(
                        conversation=conversation,
                        message=new_message,
                        file=file,
                    )
                attachment.save()
                new_message.is_attachment_present=True
                new_message.attachment=attachment
                new_message.save()

            return HttpResponse("done",status=200)
        
        else:
            CONTEXT = {
                        "heading":"Error",  
                        "message":"Not your friend!",
                        "button_url":"Users:home",
                    }
            return render(request, "Socialmedia/error.html", CONTEXT,status=403)

    else:

        current_user_id = request.session.get("current_user")
        sender_id = current_user_id
        current_user = User.objects.get(pk=current_user_id)
        reciever = User.objects.get(pk=reciever_id)
        conversation = OnetoOneConversation.objects.filter(
            Q(user_a=sender_id,user_b=reciever_id) | Q(user_a=reciever_id,user_b=sender_id)
        ).first()

        if(conversation):
            old_messages = []
            aes_current_user_version = None
            current_user_public_key = current_user.public_key
            if(conversation.user_a==current_user):
                aes_current_user_version=conversation.encrypted_aes_key_for_user_a
            else:
                aes_current_user_version=conversation.encrypted_aes_key_for_user_b
            base64_aes_key = base64.b64encode(aes_current_user_version).decode()
            messages = OnetoOneMessage.objects.filter(conversation=conversation).order_by("sent_at")
            for message in messages:
                encrypted_msg_base64 = base64.b64encode(message.encrypted_message_content).decode('utf-8')
                temp_msg = {}
                if(message.sender!=current_user):
                    message.mark_as_read()
                temp_msg["sender"]=message.sender
                temp_msg["reciever"]=message.receiver
                temp_msg["time"]=message.sent_at
                temp_msg["read"]=message.is_read
                temp_msg["conversation_id"]=conversation.id
                temp_msg["id"]=message.id
                
                if(message.is_message_present):
                    temp_msg["message_encrypted"]=encrypted_msg_base64
                    temp_msg["is_message_present"]=True

                if(message.is_attachment_present):
                    temp_msg["attachment"]=message.attachment
                    temp_msg["is_attachment_present"]=True


                old_messages.append(temp_msg)

            CONTEXT = {}
            CONTEXT["friend"]=reciever
            CONTEXT["messages"]=old_messages
            CONTEXT["user"]=current_user
            CONTEXT["USER_PUBLIC_KEY"]=current_user_public_key
            CONTEXT["AES_KEY_ENCRYPTED"]=base64_aes_key
            CONTEXT["USERNAME"]=current_user.username

            
            return render(request,"Users/one_to_one_message.html",CONTEXT )

        else:
            CONTEXT = {
                        "heading":"Error",  
                        "message":"Wrong Chats !",
                        "button_url":"Users:home",
                    }
            return render(request, "Socialmedia/error.html", CONTEXT,status=404)

        

def one_to_one_attachment(request, conversation_id, message_id, attachment_id):
    current_user_id = request.session.get("current_user")

    if not (str(conversation_id).isdigit() and str(message_id).isdigit() and str(attachment_id).isdigit()):
        CONTEXT = {
                        "heading":"Error",  
                        "message":"Invalid IDs! They must be numeric.",
                        "button_url":"Users:home",
                    }
        return render(request, "Socialmedia/error.html", CONTEXT,status=404)

    conversation = OnetoOneConversation.objects.filter(id=conversation_id).first()
    if not conversation:
        CONTEXT = {
                        "heading":"Error",  
                        "message":"Conversation not found",
                        "button_url":"Users:home",
                    }
        return render(request, "Socialmedia/error.html", CONTEXT,status=404)
    
    if current_user_id not in [conversation.user_a.user_id, conversation.user_b.user_id]:
        CONTEXT = {
                        "heading":"Error",  
                        "message":"You are not authorized to access this conversation.",
                        "button_url":"Users:home",
                    }
        return render(request, "Socialmedia/error.html", CONTEXT,status=404)
    
    is_ban_or_suspend_1,msg = check_for_ban_suspension(conversation.user_a.user_id)
    is_ban_or_suspend_2,msg = check_for_ban_suspension(conversation.user_b.user_id)

    if(is_ban_or_suspend_1 or is_ban_or_suspend_2):
        CONTEXT = {
                        "heading":"Error",  
                        "message":"You are not authorized to access this conversation, as the sender/reciever is banned or suspended!",
                        "button_url":"Users:home",
                    }
        return render(request, "Socialmedia/error.html", CONTEXT,status=404)


    
    attachment = OneToOneAttachment.objects.filter(
            id=attachment_id, message_id=message_id, conversation_id=conversation_id
        ).first()
    
    if not attachment:
        CONTEXT = {
                        "heading":"Error",  
                        "message":"Attachment not found",
                        "button_url":"Users:home",
                    }
        return render(request, "Socialmedia/error.html", CONTEXT,status=404)
    
    return FileResponse(attachment.file, as_attachment=False)
    


def block_user(request,user_id):
    current_user_id = request.session.get("current_user")

    current_user = get_object_or_404(User,pk=current_user_id)
    target_user = get_object_or_404(User, pk=user_id)

    friendship = Friendship.objects.filter(
        Q(from_user=current_user, to_user=target_user) |
        Q(from_user=target_user, to_user=current_user)
    ).first()


    if(friendship):
        friendship.block_user(current_user)
        mem.success(request, f"{target_user.username} Blocked!")
        return redirect("Users:home")


    else:
        mem.error(request, "Friendship not found.")
        return redirect("Users:home")
        

def view_blocked_users(request):
    current_user_id = request.session.get("current_user")
    current_user = get_object_or_404(User,pk=current_user_id)

    friendships = Friendship.objects.filter(from_user=current_user) | Friendship.objects.filter(to_user=current_user)

    blocked_users = []
    for friendship in friendships:
        if friendship.from_user == current_user and friendship.from_user_blocked:
            blocked_users.append(friendship.to_user)
        elif friendship.to_user == current_user and friendship.to_user_blocked:
            blocked_users.append(friendship.from_user)

    if(blocked_users==[]):
        return render(request,"Users/show_blocked_users.html")
    
    CONTEXT = {"blocked_users":blocked_users}
    return render(request,"Users/show_blocked_users.html",CONTEXT)

    
def unblock_user(request,user_id):
    current_user_id = request.session.get("current_user")

    current_user = get_object_or_404(User,pk=current_user_id)
    target_user = get_object_or_404(User, pk=user_id)

    friendship = Friendship.objects.filter(
        Q(from_user=current_user, to_user=target_user) |
        Q(from_user=target_user, to_user=current_user)
    ).first()

    if not friendship:
        #return HttpResponse("h")
        mem.error(request, "You are not friends with this user.")
        return redirect("Users:view_blocked_users")
    
    if ((friendship.from_user == current_user and not friendship.from_user_blocked) or (friendship.to_user == current_user and not friendship.to_user_blocked)):
        mem.error(request, "This user is not blocked.")
        #return HttpResponse("h")
        return redirect("Users:view_blocked_users")

    friendship.unblock_user(current_user)

    mem.success(request, f"You have successfully unblocked {target_user.username}.")
    
    return redirect("Users:view_blocked_users")



def report_user(request,user_id):
    current_user_id = request.session.get("current_user")

    current_user = get_object_or_404(User,pk=current_user_id)
    target_user = get_object_or_404(User, pk=user_id)

    report_text = request.POST.get("report_text")
    block_user = request.POST.get("block_user")

    if not report_text:
        CONTEXT = {
                        "heading":"Error",  
                        "message":"Report Can't Be Empty !",
                        "button_url":"Users:home",
                    }
        return render(request, "Socialmedia/error.html", CONTEXT,status=404)

    friendship = Friendship.objects.filter(
        Q(from_user=current_user, to_user=target_user) |
        Q(from_user=target_user, to_user=current_user)
    ).first()


    if(friendship):
        report_request = ReportUser.objects.create(
            user_reported=target_user,
            reported_by=current_user,
            complaint=report_text,
        )

        if(block_user):
            friendship.block_user(current_user)
            mem.success(request, f"{target_user.username} Reported & Blocked!")
            return redirect("Users:home")
        
        report_request.save()
        mem.success(request, f"{target_user.username} Reported!")
        return redirect("Users:home")

    else:
        mem.error(request, "Friendship not found.")
        return redirect("Users:home")



def show_groups(request):
    current_user_id = request.session.get("current_user")
    user = User.objects.get(pk=current_user_id)
    if(user.is_verified==True):
        user_joined_groups = GroupMember.objects.filter(user=user)
        return render(request,"Users/show_groups.html",{"groups":user_joined_groups})

    else:
        return HttpResponse("You are not verified yet!")



def create_group(request):
    if(request.method == "POST"):
        current_user_id = request.session.get("current_user")
        user = User.objects.get(pk=current_user_id)
        group_name = request.POST.get("group_name")
        description = request.POST.get("description", "")
        group_pic = request.FILES.get("group_pic")
        selected_members = request.POST.getlist("members")

        if not group_name:
            CONTEXT = {
                        "heading":"Error",  
                        "message":"Group name is required!",
                        "button_url":"Users:home",
                    }
            return render(request, "Socialmedia/error.html", CONTEXT,status=400)

        if not selected_members:
            CONTEXT = {
                        "heading":"Error",  
                        "message":"At least one member must be selected!",
                        "button_url":"Users:home",
                    }
            return render(request, "Socialmedia/error.html", CONTEXT,status=400)
        
        if not group_pic:
            CONTEXT = {
                        "heading":"Error",  
                        "message":"Group picture is required!",
                        "button_url":"Users:home",
                    }
            return render(request, "Socialmedia/error.html", CONTEXT,status=400)

        AES_KEY = get_random_bytes(32)
        public_key_admin = user.public_key
        aes_key_encrypted = encrypt_aes_key(AES_KEY,public_key_admin)


        try:
            with transaction.atomic():
                new_group = Group.objects.create(
                    name=group_name,
                    description=description,
                    group_profile_picture=group_pic,
                    admin=user,
                    aes_key_encrypted_by_admin=aes_key_encrypted,
                )
                new_group.save()

                admin_as_a_member = GroupMember.objects.create(
                        group=new_group,
                        user=user,
                        aes_key_encrypted=aes_key_encrypted,
                    )
                admin_as_a_member.save()


                for member in selected_members:
                    new_group_member = User.objects.get(pk=member)
                    isfriend = check_for_friends(current_user_id,new_group_member.user_id)
                    is_ban_or_suspend,msg = check_for_ban_suspension(new_group_member.user_id)
                    if(isfriend == False):
                        raise ValueError("Added Group Members contain Users who are not your friends!")
                        
                    
                    if(is_ban_or_suspend):
                        raise ValueError("Added Group Members contain Users who are banned or suspended!")

                    
                    new_member_public_key = new_group_member.public_key
                    aes_key_encrypted_for_group_member = encrypt_aes_key(AES_KEY,new_member_public_key)
                    new_member = GroupMember.objects.create(
                        group=new_group,
                        user=new_group_member,
                        aes_key_encrypted=aes_key_encrypted_for_group_member,
                    )
                    new_member.save()
                return redirect("Users:show_groups")

        except ValueError as ve:
            CONTEXT = {
                "message": str(ve),
                "button_url": "Users:home"
            }
            return render(request, "Socialmedia/error.html", CONTEXT)
        
        except Exception as e:
            CONTEXT = {
                "message": "Backend Error!",
                "button_url": "Users:home"
            }
            return render(request, "Socialmedia/error.html", CONTEXT)


        
    else:
        current_user_id = request.session.get("current_user")
        user = User.objects.get(pk=current_user_id)
        friends = OnetoOneConversation.objects.filter(
                Q(user_a=user) | Q(user_b=user)
        )
        friends_data=[]
        for friend in friends:
            if(friend.user_a==user):
                isBlocked = check_for_blocked_user(user.user_id,friend.user_b.user_id)
                is_ban_or_suspend,msg = check_for_ban_suspension(friend.user_b.user_id)
                if(isBlocked or is_ban_or_suspend):
                    continue
                else:
                    friends_data.append(friend.user_b)
            else:
                isBlocked = check_for_blocked_user(user.user_id,friend.user_a.user_id)
                is_ban_or_suspend,msg = check_for_ban_suspension(friend.user_a.user_id)
                if(isBlocked or is_ban_or_suspend):
                    continue
                else:
                    friends_data.append(friend.user_a)
        return render(request,"Users/create_group.html",{"friends":friends_data})



def send_group_message(request,group_id):
    if(request.method == "POST"):
        current_user_id = request.session.get("current_user")
        user = User.objects.get(pk=current_user_id)
        group = get_object_or_404(Group, pk=group_id)
        user_joined_groups = GroupMember.objects.filter(user=user,group=group)
        all_members_in_this_group=GroupMember.objects.filter(group=group)
        if(user_joined_groups.exists()):
            encrypted_msg_data = request.POST.get('encrypted_msg')
            file = request.FILES.get('file')

            if( (not encrypted_msg_data) and (not file)):
                CONTEXT = {
                        "heading":"Error",  
                        "message":"Either an encrypted message or a file must be provided!",
                        "button_url":"Users:home",
                    }
                return render(request, "Socialmedia/error.html", CONTEXT,status=400)
                
            is_message = False
            is_attachment = False
            if(encrypted_msg_data):
                encrypted_msg_data=json.loads(encrypted_msg_data)
                message_encrypted = base64.b64decode(encrypted_msg_data)   
                is_message=True
            if(file):
                is_attachment=True
            
            if(is_message):
                new_grp_message = GroupMessages.objects.create(
                    group=group,
                    sender=user,
                    encrypted_message_content=message_encrypted,
                    is_message_present=True
                )
                if(is_attachment):
                    attachment = GroupAttachment.objects.create(
                        group=group,
                        message=new_grp_message,
                        file=file,
                    )
                    attachment.save()
                    new_grp_message.attachment=attachment
                    new_grp_message.is_attachment_present=True
                for member in all_members_in_this_group:
                    member.increase_unread_count()
                new_grp_message.save()
            else:
                new_group_message = GroupMessages.objects.create(
                    group=group,
                    sender=user,
                    is_message_present=False,
                )
                attachment = GroupAttachment.objects.create(
                        group=group,
                        message=new_group_message,
                        file=file,
                    )
                attachment.save()
                new_group_message.is_attachment_present=True
                new_group_message.attachment=attachment
                for member in all_members_in_this_group:
                    member.increase_unread_count()
                new_group_message.save()

            return HttpResponse("done",status=200)
        else:
            return HttpResponse("Not allowed",status=403)

    else:

        current_user_id = request.session.get("current_user")
        user = User.objects.get(pk=current_user_id)
        group = get_object_or_404(Group, pk=group_id)
        user_joined_groups = GroupMember.objects.filter(user=user,group=group)
        if(user_joined_groups.exists()):
            old_messages = []
            user_public_key = user.public_key
            user_grp=user_joined_groups.first()
            aes_key_for_user = user_grp.aes_key_encrypted
            base64_aes_key = base64.b64encode(aes_key_for_user).decode()
            group_messages = GroupMessages.objects.filter(group=group)
            user_joined_groups[0].make_unread_zero()
            
            for message in group_messages:
                encrypted_msg_base64 = base64.b64encode(message.encrypted_message_content).decode('utf-8')
                temp_msg = {}
                temp_msg["sender"]=message.sender
                temp_msg["time"]=message.sent_at
                temp_msg["id"]=message.id

                if(message.is_message_present):
                    temp_msg["message_encrypted"]=encrypted_msg_base64
                    temp_msg["is_message_present"]=True

                if(message.is_attachment_present):
                    temp_msg["attachment"]=message.attachment
                    temp_msg["is_attachment_present"]=True
                old_messages.append(temp_msg)

            CONTEXT = {}
            CONTEXT["messages"]=old_messages
            CONTEXT["user"]=user
            CONTEXT["USER_PUBLIC_KEY"]=user_public_key
            CONTEXT["AES_KEY_ENCRYPTED"]=base64_aes_key
            CONTEXT["group"]=group
            CONTEXT["USERNAME"]=user.username
            return render(request,"Users/group_message.html",CONTEXT)
        else:
            CONTEXT = {
                        "heading":"Error",  
                        "message":"Wrong Group Access!!!",
                        "button_url":"Users:home",
                    }
            return render(request, "Socialmedia/error.html", CONTEXT,status=400)
    

def view_group(request,group_id):
    current_user_id = request.session.get("current_user")
    user = User.objects.get(pk=current_user_id)
    group = get_object_or_404(Group, pk=group_id)

    user_joined_groups = GroupMember.objects.filter(user=user,group=group)
    if(user_joined_groups.exists()):
        
        all_group_members = GroupMember.objects.filter(group_id=group_id)
        group_members=[]
        for member in all_group_members:
            is_ban_or_suspend,msg = check_for_ban_suspension(member.user.user_id)
            if(is_ban_or_suspend):
                continue
            if(member.user==user):
                member.to_show=False
            else:
                is_friend = Friendship.objects.filter(
                    (Q(from_user=user, to_user=member.user) | Q(from_user=member.user, to_user=user)) &
                    Q(status__in=["accepted", "pending"])
                ).exists()

                if(is_friend):
                    member.to_show=False
                else:
                    member.to_show=True
            group_members.append(member)

            
        CONTEXT = {}
        CONTEXT["group"]=group
        CONTEXT["group_members"]=group_members

        return render(request,"Users/view_group.html",CONTEXT)
    else:
        CONTEXT = {
            "message":"You are Not A Part Of This Group!",
            "button_url":"Users:home"
        }
        return render(request,"Socialmedia/error.html",CONTEXT)

    
def group_attachment(request, group_id, message_id, attachment_id):
    current_user_id = request.session.get("current_user")
    if not (str(group_id).isdigit() and str(message_id).isdigit() and str(attachment_id).isdigit()):
        CONTEXT = {
            "message":"Invalid ID format. IDs must be numeric.",
            "button_url":"Users:home"
        }
        return render(request,"Socialmedia/error.html",CONTEXT)
        
    group_member = GroupMember.objects.filter(group=group_id,user=current_user_id).first()
    if not group_member:
        CONTEXT = {
            "message":"You are not authorized to access this conversation !",
            "button_url":"Users:home"
        }
        return render(request,"Socialmedia/error.html",CONTEXT)
   
    
    attachment = GroupAttachment.objects.filter(
            id=attachment_id, message_id=message_id, group=group_id
        ).first()
    
    if not attachment:
        CONTEXT = {
            "message":"Attachment Doesn't Exist !",
            "button_url":"Users:home"
        }
        return render(request,"Socialmedia/error.html",CONTEXT)
    
    return FileResponse(attachment.file, as_attachment=False)


