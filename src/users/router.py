from typing import Annotated, Optional
from argon2 import PasswordHasher

from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status
)

from src.users.schemas import CreateUserRequest, UserResponse
from src.common.database import blocked_token_db, session_db, user_db
from src.common.custom_exception import CustomException

user_router = APIRouter(prefix="/users", tags=["users"])
router = user_router  # router 이름으로도 export
ph = PasswordHasher()

@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    # Check if email already exists
    if any(u.get("email") == request.email for u in user_db):
        raise CustomException(
            status_code=409,
            error_code="ERR_002",
            error_msg="EMAIL ALREADY EXISTS"
        )
    
    # Create new user
    new_user = {
        "user_id": len(user_db) + 1,
        "email": request.email,
        "hashed_password": ph.hash(request.password),
        "name": request.name,
        "phone_number": request.phone_number,
        "height": request.height,
        "bio": request.bio
    }
    
    user_db.append(new_user)
    
    # Return user info without password
    return UserResponse(
        user_id=new_user["user_id"],
        email=new_user["email"],
        name=new_user["name"],
        phone_number=new_user["phone_number"],
        height=new_user["height"],
        bio=new_user["bio"]
    )

@user_router.get("/me")
def get_user_info(
    sid: Optional[str] = Cookie(None),
    authorization: Optional[str] = Header(None)
) -> UserResponse:
    # Both session and token authentication not provided
    if not sid and not authorization:
        raise CustomException(
            status_code=401,
            error_code="ERR_009",
            error_msg="UNAUTHENTICATED"
        )
    
    # Session-based authentication
    if sid:
        if sid not in session_db:
            raise CustomException(
                status_code=401,
                error_code="ERR_009",
                error_msg="UNAUTHENTICATED"
            )
        user_id = session_db[sid]["user_id"]
    else:
        # Token-based authentication will be implemented later
        # For now, just return unauthorized
        raise CustomException(
            status_code=401,
            error_code="ERR_009",
            error_msg="UNAUTHENTICATED"
        )
    
    # Find user in database
    user = next((u for u in user_db if u["user_id"] == user_id), None)
    if not user:
        raise CustomException(
            status_code=404,
            error_code="ERR_004",
            error_msg="USER NOT FOUND"
        )
        
    return UserResponse(
        user_id=user["user_id"],
        email=user["email"],
        name=user["name"],
        phone_number=user["phone_number"],
        height=user["height"],
        bio=user["bio"]
    )