from ninja import NinjaAPI
from .schema import SignupSchema, TokenSchema, LoginSchema
from .models import HimUser, PhoneOTP, Alert
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
import json
import redis
from django.utils import timezone
api = NinjaAPI(title="Himalay Suraksha API", version="1.0.0")
redis_client = redis.StrictRedis(
    host="localhost", port=6379, db=0, decode_responses=True
)
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

@csrf_exempt
@api.get("/dashboard", auth=JWTAuth())
def get_profile(request):
    user = request.auth
    return {
        "username": user.username,
        "email": user.email,
        "mobile_no": str(user.mobile_no),
        "location": user.location
    }

@csrf_exempt
@api.get("/alerts", auth=JWTAuth())
def get_alerts(request):
    """
    Return active alerts for the logged-in user's location
    """
    user = request.auth
    alerts = []
    pattern = f"alert:{user.location}"
    alert_data = redis_client.get(pattern)
    if alert_data:
        alerts.append(json.loads(alert_data))
    return {
        "user": user.username,
        "location": user.location,
        "alerts": alerts,
        "count": len(alerts),
        "last_checked": timezone.now().isoformat()
    }

@csrf_exempt
@api.post("/notify")
def notify(request):
    """
    Store an alert pushed by Orkes/FastAPI AI into Redis,
    and also archive into DB for history.
    """
    data = request.data 
    city = data.get("city")
    if not city:
        return {"error": "City is required"}
    # Save in Redis with expiry (10 mins)
    key = f"alert:city:{city}"
    redis_client.setex(key, 600, json.dumps(data))  

    Alert.objects.create(
        city=city,
        risk_level=data.get("risk_level", "UNKNOWN"),
        hazard=data.get("hazard", "unknown"),
        reason=data.get("reason", "No reason provided")
    )

    return {"message": f"Alert stored for {city}", "alert": data}

@csrf_exempt
@api.get("/alerts/history", auth=JWTAuth())
def alert_history(request, limit: int = 10, days: int = 7):
    """
    Return alert history for the logged-in user's location.
    - limit: max number of alerts (default=10)
    - days: look back window (default=7 days)
    """
    user = request.auth
    since = timezone.now() - timezone.timedelta(days=days)
    alerts = Alert.objects.filter(
        city=user.location, created_at__gte=since
    ).order_by("-created_at")[:limit]
    alert_list = [
        {
            "city": alert.city,
            "risk_level": alert.risk_level,
            "hazard": alert.hazard,
            "reason": alert.reason,
            "created_at": alert.created_at.isoformat()
        }
        for alert in alerts
    ]
    return {
        "user": user.username,
        "location": user.location,
        "alerts": alert_list,
        "count": len(alert_list),
        "since": since.isoformat(),
        "limit": limit
    }

@csrf_exempt
@api.get("/alerts/active", auth=JWTAuth())
def get_active_alerts(request):
    """
    Return current active alerts for the logged-in user's location
    (from Redis).
    """
    user = request.auth
    alerts = []
    key = f"alert:city:{user.location}"
    alert_data = redis_client.get(key)
    if alert_data:
        alerts.append(json.loads(alert_data))
    return {
        "user": user.username,
        "location": user.location,
        "alerts": alerts,
        "count": len(alerts),
        "last_checked": timezone.now().isoformat()
    }
