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
    path('new/', login_required(LocationCreateView.as_view()), name='create'),
    path("view/<str:pk>/", views.view, name = "view"),
    path("generate/", views.generate_password, name = "generate_password"),
]