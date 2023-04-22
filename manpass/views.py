from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.hashers import make_password
from .forms import RegisterForm
from .models import Location
from datetime import datetime
from django.core.mail import send_mail
from django.http import  HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.views.generic import CreateView
from django.contrib import messages
from django.contrib.auth.hashers import check_password
from .encryption import *
import random
import string
import pyotp
import re

@login_required(login_url="/login") 
def home(request):
    if request.user.is_authenticated:
        user = request.user
        location = Location.objects.filter(author = user)
        context = {
            'location': location
        }
        return render(request, "main/home.html", context)
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
    
class LocationCreateView(CreateView): 
    template_name = "main/website_details_form.html"
    model = Location    
    fields = [
        'website_name',
        'website_link',
        'website_username',
        'website_password',
        'website_notes',
        'master_password',
    ]

    def form_valid(self, form):
        if form.is_valid():
            user = self.request.user
            form.instance.author = user

            form_master_password = form.instance.master_password
            # the field titled "master_password" in Location model 

            user_password = self.request.user.password
            # hashed master password in database 

            if not check_password(form_master_password, user_password):
                messages.error(self.request, "Error: Invalid link.")
                return redirect("create")
            else: 
                website_password = form.instance.website_password

                form.instance.website_password = encrypt(form_master_password.encode(), website_password.encode())

                form.instance.website_password = encrypt(form_master_password.encode(), form.instance.website_password.encode())

                form.instance.master_password = '' # to remove the master password from the database
                
                return super().form_valid(form)
        else:
            messages.error(self.request, "Error")
            messages.add_message(self.request, messages.ERROR, 'Error')  


def view(request, pk):
    user = request.user
    try:
        location = Location.objects.get(id=pk, author=user)
    except Location.DoesNotExist:
        messages.error(request, "Invalid link.")
        return redirect("home")

    if request.method == "POST":
        user_password = location.website_password
        password = request.POST.get("password_field")
        decrypted = decrypt(password.encode(), user_password)
        if decrypted is not None:
            decrypted = decrypt(password.encode(), decrypted)
            context = {
                'location': location,
                'decrypted': decrypted,
                'confirmed': True,
            }
            return render(request, "main/detail_view.html", context)
        else:
            messages.error(request, "Incorrect password!")
    
    context = {
        'location': location,
    }
    return render(request, "main/detail_view.html", context)

#creating a view for generating a password according to user requirements
@login_required(login_url="/login")
def generate_password(request):
    if request.method == "POST":
        password_length = int(request.POST['password_length'])
        include_uppercase = request.POST.get('include_uppercase') == 'on'
        include_lowercase = request.POST.get('include_lowercase') == 'on'
        include_numbers = request.POST.get('include_numbers') == 'on'
        include_special = request.POST.get('include_special') == 'on'
        
        #check if password length is between 4 and 50 else generate a error message and return it to html page
        if(password_length < 4 or password_length > 50):
            error = "Password length should be between 4 and 50"
            return render(request, 'main/generate_password.html', {'error': error})
        
        if not (include_uppercase or include_lowercase or include_numbers or include_special):
            error = "Please select at least one checkbox"
            return render(request, 'main/generate_password.html', {'error': error})
        
        character_set = ''
        if include_uppercase:
            character_set += string.ascii_uppercase
        if include_lowercase:
            character_set += string.ascii_lowercase
        if include_numbers:
            character_set += string.digits
        if include_special:
            character_set += string.punctuation
        
        while True:
            password = ''.join(random.choice(character_set) for i in range(password_length))
            if (include_uppercase and not re.search('[A-Z]', password)):
                continue
            if (include_lowercase and not re.search('[a-z]', password)):
                continue
            if (include_numbers and not re.search('[0-9]', password)):
                continue
            if (include_special and not re.search('[!@#$%^&*()_+{}|:"<>?`~\[\]\\;\',./-]', password)):
                continue
            break
            
        context = {
            'password': password,
            'include_uppercase': include_uppercase,
            'include_lowercase': include_lowercase,
            'include_numbers': include_numbers,
            'include_special': include_special,
            'password_length': password_length
        }
        return render(request, 'main/generate_password.html', context)
    
    return render(request, 'main/generate_password.html', {'password_length': 12, 'include_uppercase': False, 'include_lowercase': False, 'include_numbers': False, 'include_special': False})



    
