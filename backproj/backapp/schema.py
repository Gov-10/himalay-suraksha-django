from ninja import Schema
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