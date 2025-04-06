from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth.hashers import make_password, check_password
# Create your views here.

def home(request):
    return render(request, "Socialmedia/Home.html")


def error_404_page_not_found(request, exception):
    CONTEXT = {
        "heading":"PAGE NOT FOUND",  
        "message":"404 PAGE NOT FOUND!",
        "button_url":"Home",
    }
    
    return render(request, "Socialmedia/error.html", CONTEXT,status=404)

