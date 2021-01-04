from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException

import connection
from bson import ObjectId
from json import dumps
from pydantic import BaseModel
from schematics.models import Model
from schematics.types import StringType, EmailType
from passlib.context import CryptContext

class SignUpUser(BaseModel):
    email: str
    firstname: str
    lastname: str
    password: str

class LoginUser(BaseModel):
    email: str
    password: str


class UserDB(Model):
    user_id = ObjectId()
    email = EmailType(required=True)
    firstname = StringType(required=True)
    lastname = StringType(required=True)
    password = StringType(required=True)

class Settings(BaseModel):
    authjwt_secret_key: str = "simple secret"
    authjwt_access_token_expires: int = 3600

@AuthJWT.load_config
def get_config():
    return Settings()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI()

origins = [
    "https://localhost:8080",
    "http://localhost:8080",
    "localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# exception handler for authjwt
@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message })

# An instance of class UserDB
newuser = UserDB()

# funtion to create and assign values to the instanse of class User created
def create_user(email, firstname, lastname, password):
    newuser.user_id = ObjectId()
    newuser.email = email
    newuser.firstname = firstname
    newuser.lastname = lastname
    newuser.password = password
    return dict(newuser)

def email_exists(email):
    user_exist = True
    if connection.db.users.find(
        {'email': email}
    ).count() == 0:
        user_exist = False
    return user_exist

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def check_login_creds(email, password):
    if email_exists(email):
        activeuser = connection.db.users.find(
            {'email': email}
        )
        for actuser in activeuser:
            actuser = dict(actuser)
            if verify_password(password, actuser['password']):
                actuser['_id'] = str(actuser['_id'])    
                return actuser
        return False
    return False


# Our root endpoint
@app.get("/")
def index():
    return {"message": "Hello World"}

# Signup endpoint with the POST method
@app.post("/auth/signup")
def signup(user: SignUpUser):
    user_exists = False
    data = create_user(user.email, user.firstname, user.lastname, get_password_hash(user.password))

    # Covert data to dict so it can be easily inserted to MongoDB
    dict(data)

    # Checks if an email exists from the collection of users
    if connection.db.users.find(
        {'email': data['email']}
        ).count() > 0:
        user_exists = True
        print("User Exists")
        return {"message":"User Exists"}
    # If the email doesn't exist, create the user
    elif user_exists == False:
        connection.db.users.insert_one(data)
        return {"message":"User Created","email": data['email'], "firstname": data['firstname'], "lastname": data['lastname']}

# Login endpoint
@app.post("/auth/signin")
def login(user: LoginUser, Authorize: AuthJWT = Depends()):
    # Read email from database to validate if user exists and checks if password matches
    logger = check_login_creds(user.email, user.password)
    if bool(logger):
        access_token = Authorize.create_access_token(subject=user.email)
        return {
            "id": logger["_id"],
            "firstname": logger["firstname"],
            "lastname": logger["lastname"],
            "email": logger["email"],
            "accessToken": access_token
        }
    else:
        raise HTTPException(status_code=401, detail="Bad email or password")

@app.get("/auth/user")
def user(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    current_user = Authorize.get_jwt_subject()
    return {"email": current_user}

