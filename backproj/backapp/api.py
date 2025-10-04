from ninja import NinjaAPI
from .schema import SignupSchema, TokenSchema, LoginSchema
from .models import HimUser, PhoneOTP
from ninja.errors import ValidationError
from django.views.decorators.csrf import csrf_exempt
import requests
import random
from django.conf import settings
from ninja.security import HttpBearer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from ninja.security import HttpBearer
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import authenticate
from rest_framework_simplejwt.exceptions import TokenError
api = NinjaAPI(title="Himalay Suraksha API", version="1.0.0")
def generate_otp():
    return str(random.randint(100000, 999999))

def send_sms(mobile, otp):
    url = "https://api.msg91.com/api/v5/otp"
    payload = {
        "authkey": settings.MSG91_AUTH_KEY,
        "template_id": settings.MSG91_TEMPLATE_ID,
        "mobile": str(mobile),
        "otp": otp
    }
    headers = {"content-type": "application/json"}
    r = requests.post(url, json=payload, headers=headers)
    return r.json()

def verify_recaptcha(token: str) -> bool:
    url = "https://www.google.com/recaptcha/api/siteverify"
    payload = {"secret": settings.RECAPTCHA_PRIVATE_KEY, "response": token}
    r = requests.post(url, data=payload)
    result = r.json()

    if not result.get("success", False):
        return False

    # Handle v3 keys (score exists)
    if "score" in result:
        return result["score"] >= 0.5

    # For v2, success = True is enough
    return True

@csrf_exempt
@api.post("/verify-otp")
def verify_otp(request, mobile_no: str, otp: str):
    try:
        phone_otp = PhoneOTP.objects.get(mobile_no=mobile_no)
    except PhoneOTP.DoesNotExist:
        return {"error": "No OTP found for this number."}

    if phone_otp.otp == otp:
        user = HimUser.objects.get(mobile_no=mobile_no)
        user.is_active = True
        user.save()
        phone_otp.delete()
        return {"message": "OTP verified, account activated!"}
    else:
        return {"error": "Invalid OTP"}

@csrf_exempt
@api.post("/signup")
def signup(request, data:SignupSchema):
    if not verify_recaptcha(data.recaptcha_token):
        return api.create_response(request, {"error": "Invalid reCAPTCHA"}, status=400)
    if HimUser.objects.filter(username=data.username).exists():
        raise ValidationError([{"loc": ["username"], "msg": "Username already exists"}])
    if HimUser.objects.filter(email=data.email).exists():
        raise ValidationError([{"loc": ["email"], "msg": "Email already exists"}])
    if HimUser.objects.filter(mobile_no=data.mobile_no).exists():
        raise ValidationError([{"loc": ["mobile_no"], "msg": "Mobile number already exists"}])
    if data.password1 != data.password2:
        return api.create_response(request, {"error": "Passwords do not match"}, status=400)
    user = HimUser.objects.create_user(
        username=data.username,
        email=data.email,
        password=data.password1,
        mobile_no=data.mobile_no, 
        location=data.location,
        is_active=False
    )
    user.save()
    otp = generate_otp()
    PhoneOTP.objects.update_or_create(mobile_no=user.mobile_no, defaults={"otp": otp})    
    resp = send_sms(user.mobile_no, otp)
    return {"message": "User created successfully. OTP sent to your mobile.", "sms_resp": resp}

@csrf_exempt
@api.post("/refresh")
def refresh(request):
    view = TokenRefreshView.as_view()
    return view(request._request)

@csrf_exempt
@api.post("/login", response=TokenSchema)
def login(request, data: LoginSchema):
    if not verify_recaptcha(data.recaptcha_token):
        return api.create_response(request, {"error": "reCAPTCHA failed"}, status=400)

    user = authenticate(username=data.username, password=data.password)
    if user is None:
        return api.create_response(request, {"error": "Invalid credentials"}, status=401)

    if not user.is_active:
        return api.create_response(request, {"error": "Please verify your mobile number first"}, status=403)

    refresh = RefreshToken.for_user(user)
    return {"access": str(refresh.access_token), "refresh": str(refresh)}

class JWTAuth(HttpBearer):
    def authenticate(self, request, token):
        auth = JWTAuthentication()
        try:
            validated_token = auth.get_validated_token(token)
            user = auth.get_user(validated_token)
            return user
        except TokenError:
            return None

from django.contrib.auth import logout as django_logout
@csrf_exempt
@api.post("/logout")
def logout(request):
    django_logout(request)
    return {"message": "Logout handled on client side by deleting the token."}



