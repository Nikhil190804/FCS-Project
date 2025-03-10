from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth.hashers import make_password, check_password
# Create your views here.

def home(request):
    return render(request, "Socialmedia/Home.html")




