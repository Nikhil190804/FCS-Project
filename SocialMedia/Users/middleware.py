from django.shortcuts import redirect
from django.urls import reverse

class AuthenticationMiddleware:
    # Middleware to have authentication on protected routes.
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        protected_paths = [
            reverse("Users:home"), 
            reverse("Users:settings"),
            reverse("Users:messages"),
            reverse("Users:start_conversation"),
            reverse("Users:search_users"),
            reverse("Users:show_friend_requests"),
            reverse("Users:change_password"),
        ]


        if ((request.path in protected_paths ) and ("current_user" not in request.session)):
            return redirect("Users:login")  

        return self.get_response(request)




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
            print("aa gya , chl bhag loged in user")
            return redirect("Users:signup")  

        return self.get_response(request)
