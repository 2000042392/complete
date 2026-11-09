from pydantic import BaseModel, Field, EmailStr
class RegisterRequest(BaseModel):
    username: str=Field(min_length=3,max_length=40,pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    password: str=Field(min_length=12,max_length=128)
class LoginRequest(BaseModel):
    username: str
    password: str
class AccessRequest(BaseModel):
    device_posture: str="unknown"
