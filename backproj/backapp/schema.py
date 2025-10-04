from ninja import Schema
from typing import List
from datetime import datetime
class SignupSchema(Schema):
    username : str
    password1: str
    password2 : str
    email :str
    mobile_no: str
    location: str
    recaptcha_token: str

class TokenSchema(Schema):
    access: str
    refresh :str

class LoginSchema(Schema):
    username: str
    password: str
    recaptcha_token: str

class RiskSchema(Schema):
    hazard_type: str
    risk_level: str
    reason: str

class NotifySchema(Schema):
    city: str
    risks: List[RiskSchema]

class AlertResponseSchema(Schema):
    city: str
    hazard_type: str
    risk_level: str
    reason: str
    created_at: datetime