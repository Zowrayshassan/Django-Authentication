from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractUser

class MyUser(AbstractUser):
    name=models.CharField(max_length=100)
    email=models.CharField(max_length=254,unique=True)
    password = models.CharField(max_length=50)
    username=None
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS=[]

