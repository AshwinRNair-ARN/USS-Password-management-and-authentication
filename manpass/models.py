from django.db import models
from django.contrib.auth.models import User
from django.urls import reverse
# Create your models here.

class Location(models.Model):
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    
    website_name = models.CharField(max_length=50)
    website_link = models.URLField(max_length=200, null=False) 
    website_username = models.CharField(max_length=50)
    website_password = models.CharField(max_length=500,null=False )
    website_notes = models.CharField( max_length=200, null=False)
    master_password = models.CharField(max_length=200,null=False )

    created = models.DateTimeField( auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.website_name

    def get_absolute_url(self):
        return reverse("home") 
    

class SharedPassword(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='shared_passwords')
    location = models.ForeignKey(Location, on_delete=models.CASCADE, related_name='shared_passwords')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_passwords')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('owner', 'location', 'receiver')

    
