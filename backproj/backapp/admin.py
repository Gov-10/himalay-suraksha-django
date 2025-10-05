from django.contrib import admin
from .models import HimUser, PhoneOTP, Alert
# Register your models here.
admin.site.register(HimUser)
admin.site.register(PhoneOTP) 
admin.site.register(Alert)