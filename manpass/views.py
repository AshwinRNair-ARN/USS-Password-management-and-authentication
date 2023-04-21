from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.hashers import make_password
from .forms import RegisterForm
from datetime import datetime
from django.core.mail import send_mail
from django.http import  HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
import pyotp

@login_required(login_url="/login") 
def home(request):
    if request.user.is_authenticated:
        print("User is authenticated") 
        pass
    else:
        return redirect("/login")

def sign_up(request):
    if request.method == 'POST':
        user_form = RegisterForm(request.POST)  

        if user_form.is_valid():
            user = user_form.save(commit=False) # commit=False tells Django that "Don't send this to database yet. I have more things I want to do with it."
            user.is_active = False              # Deactivate account till it is confirmed
            # get username and password and hash it and store it in database
            username = user_form.cleaned_data.get('username')   
            password = user_form.cleaned_data.get('password1')
            hashed_pwd = make_password(password) # hash password
            user.username = username
            user.password = hashed_pwd
            user.save()
            user.refresh_from_db()  # user is not saved yet, so refresh it from database

            request.session['otp_user_id'] = user.id
            x = datetime.now()
            random = pyotp.random_base32()
            hotpp = pyotp.HOTP(random)
            one_time_password = hotpp.at(x.microsecond)
            message = '\nThe 6 digit OTP is: ' + str(
            one_time_password) + '\n\nThis is a system-generated response for your OTP. Please do not reply to this email.'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [user.email]
            subject = 'Validating OTP'
            send_mail(subject, message, email_from, recipient_list)
            request.session["random"] = random
            request.session["x_value"] = x.isoformat()
            return redirect("/otp")      
        else:
            print(user_form.errors)

    else:
        user_form = RegisterForm()

    return render(request, 'registration/sign_up.html', {"user_form": user_form})

def otp(request):
    if request.user.is_authenticated:
        return HttpResponse("<h1>Error</h1><p>Bad Requestttt</p>")

    if 'otp_user_id' not in request.session.keys():
        return HttpResponse("<h1>Error</h1><p>Bad Request</p>")

    if request.method == "GET":
        user = User.objects.get(id=request.session['otp_user_id'])
        args = {"email": user.email}
        return render(request, "registration/otp.html", args)
    
    elif request.method == "POST":
        user = User.objects.get(id=request.session['otp_user_id'])
        request.session.pop('otp_user_id') 
        x_iso= request.session["x_value"]
        x = datetime.fromisoformat(x_iso)
        random = request.session["random"]
        hotpp = pyotp.HOTP(random)
        one_time_password = hotpp.at(x.microsecond)
        request.session.pop("x_value")
        request.session.pop("random")
        post_datetime = datetime.now()
        diff = post_datetime - x
        sec = diff.total_seconds()
        if (request.POST['otp'] == one_time_password) and (sec < 120):
            #login(request, user)
            user.is_active = True
            user.save()
            return HttpResponse("<h1>Success</h1><p>OTP verified successfully. </p> <p> Click <a href='\home'>here</a> to go to home page.</p>")
        else:
            # delete the user and profile from the database
            user.delete()
            return HttpResponse(f"<h1>Error</h1><p> The OTP was wrong or has been expired </p><p><a href='{'/sign-up'}'>Try again</a></p>")
    else:
        return HttpResponse("<h1>Error</h1><p>Bad Request</p>")
    
