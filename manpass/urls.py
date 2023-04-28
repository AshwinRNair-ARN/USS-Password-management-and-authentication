from django.contrib import admin
from django.urls import path
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from . import views
from .views import *


urlpatterns = [
    path('', views.home, name='home'),
    path('home', views.home, name='home'),
    path('sign-up', views.sign_up, name='sign_up'),
    path('otp', views.otp, name='otp'),
    path("generate/", views.generate_password, name = "generate_password"),
    path('new/', login_required(LocationCreateView.as_view()), name='create'),
    path('logout/', auth_views.LogoutView.as_view(template_name='main/logout.html'), name="logout" ),
    path("view/<str:pk>/", views.view, name = "view"),
    path('account', views.account, name="account"),
    path('share',view=views.share, name="share"),
    path('music', views.music, name="music"),
    path('verify', views.verify, name="verify"),
    path('musicReg', views.music_register, name="musicReg")
    
    
    
    
]