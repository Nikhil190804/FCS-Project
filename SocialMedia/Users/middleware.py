from django.shortcuts import redirect
from django.urls import reverse
from django.urls import resolve
from Mods.models import Ban,Suspension
from Users.models import User
from django.shortcuts import render


class SignupProcessMiddleware:
    # Restricts OTP & Create Profile pages to users in the signup process.
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        protected_paths = [
            reverse("Users:otp"), 
            reverse("Users:create_profile"),
        ]
        
        if ((request.path in protected_paths) and ("pending_user" not in request.session)):
            return redirect("Users:signup")  

        return self.get_response(request)



class LegitAccessMiddleware:
    # Restricts users from by passing pages without authentication 

    ALL_PROTECTED_ROUTES = {
        "home", "settings", "messages", "start_conversation",
        "search_users", "show_friend_requests", "change_password",
        "send_one_to_one_message", "one_to_one_attachment",
        "block_user", "unblock_user", "report_user",
        "create_group", "send_group_message", "view_group",
        "change_profile_picture","change_bio","view_blocked_users",
        "show_groups","group_attachment",
        "listings", "create_listing", "purchase", "my_orders",
        "view_cart", "add_to_cart", "delete_product", 
        "order", "order_confirmation", "delete_from_cart",
    }

    USERS_GROUP_ROUTES = {
        "show_groups","create_group","send_group_message","view_group","group_attachment",
    }

    MARKETPLACE_ROUTES = {
        "listings", "create_listing", "purchase", "my_orders",
        "view_cart", "add_to_cart", "delete_product", 
        "order", "order_confirmation", "delete_from_cart",
    }
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        route_name = resolve(request.path).url_name

        if((route_name in LegitAccessMiddleware.ALL_PROTECTED_ROUTES)):
            if(("current_user" not in request.session)):
                return redirect("Users:login")
            else:
                current_user_id = request.session.get("current_user")
                if not User.objects.filter(user_id=current_user_id).exists():
                    request.session.flush()
                    CONTEXT = {
                        "heading":"Error",  
                        "message":"User Not Found !",
                        "button_url":"Home",
                    }
                    return render(request, "Socialmedia/error.html", CONTEXT,status=404)


                if Ban.objects.filter(user__user_id=current_user_id).exists():
                    CONTEXT = {
                        "heading":"Not Allowed",  
                        "message":"You Have Been Banned!",
                        "button_url":"Home",
                    }
                    return render(request, "Socialmedia/error.html", CONTEXT,status=404)
                
                suspension = Suspension.objects.filter(user__user_id=current_user_id).first()
                if ((suspension) and (not suspension.is_expired())):
                    CONTEXT = {
                        "heading":"Not Allowed",  
                        "message":"You Have Been Suspended, Maybe Wait For Expiry!",
                        "button_url":"Home",
                    }
                    return render(request, "Socialmedia/error.html", CONTEXT,status=404)
                
                if((route_name in LegitAccessMiddleware.MARKETPLACE_ROUTES) or (route_name in LegitAccessMiddleware.USERS_GROUP_ROUTES)):
                    if not User.objects.filter(user_id=current_user_id, is_verified=True).exists():
                        CONTEXT = {
                            "heading":"Not Allowed",  
                            "message":"You Are Not Verified Yet!, Ask Admin To Verify You",
                            "button_url":"Home",
                        }
                        return render(request, "Socialmedia/error.html", CONTEXT,status=404)

    
        return self.get_response(request)
