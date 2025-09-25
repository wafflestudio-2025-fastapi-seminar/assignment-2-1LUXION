from typing import Annotated, Optional
from argon2 import PasswordHasher

from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status
)
from jose import jwt, JWTError
from datetime import datetime

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
            error_code="ERR_005",
            error_message="EMAIL ALREADY EXISTS"
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
    # 인증 수단이 없는 경우
    if not sid and not authorization:
        raise CustomException(
            status_code=401,
            error_code="ERR_009",
            error_message="UNAUTHENTICATED"
        )
    # 세션 기반 인증
    if sid:
        session = session_db.get(sid)
        if not session:
            raise CustomException(
                status_code=401,
                error_code="ERR_006",
                error_message="INVALID SESSION"
            )
        # 세션 만료 검증
        if session["exp"] < datetime.utcnow():
            session_db.pop(sid, None)
            raise CustomException(
                status_code=401,
                error_code="ERR_006",
                error_message="INVALID SESSION"
            )
        user_id = session["user_id"]
    # 토큰 기반 인증
    else:
        if not authorization.startswith("Bearer "):
            raise CustomException(
                status_code=400,
                error_code="ERR_007",
                error_message="BAD AUTHORIZATION HEADER"
            )
        token = authorization.split(" ", 1)[1]
        from src.auth.router import SECRET_KEY, ALGORITHM, blocked_token_db
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError:
            raise CustomException(
                status_code=401,
                error_code="ERR_008",
                error_message="INVALID TOKEN"
            )
        if token in blocked_token_db:
            raise CustomException(
                status_code=401,
                error_code="ERR_008",
                error_message="INVALID TOKEN"
            )
        # 만료 검증 (jose가 exp 자동 검증)
        user_id = int(payload.get("sub"))
    # Find user in database
    user = next((u for u in user_db if u["user_id"] == user_id), None)
    if not user:
        raise CustomException(
            status_code=404,
            error_code="ERR_004",
            error_message="USER NOT FOUND"
        )
    return UserResponse(
        user_id=user["user_id"],
        email=user["email"],
        name=user["name"],
        phone_number=user["phone_number"],
        height=user["height"],
        bio=user["bio"]
    )