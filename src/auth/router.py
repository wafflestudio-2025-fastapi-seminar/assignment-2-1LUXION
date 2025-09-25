
from fastapi import APIRouter, HTTPException
from fastapi import Depends, Cookie
from jose import jwt
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from datetime import datetime, timedelta
import os

from src.auth.schemas import TokenRequest, TokenResponse
from src.common.database import blocked_token_db, session_db, user_db
from src.common.custom_exception import CustomException

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

# JWT 설정
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
ph = PasswordHasher()


def create_jwt_token(sub: str, expires_delta: timedelta):
	expire = datetime.utcnow() + expires_delta
	to_encode = {"sub": sub, "exp": int(expire.timestamp())}
	return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


@auth_router.post("/token", response_model=TokenResponse)
def issue_token(request: TokenRequest):
	# 사용자 조회
	user = next((u for u in user_db if u["email"] == request.email), None)
	if not user:
		raise CustomException(status_code=401, error_code="ERR_010", error_message="INVALID ACCOUNT")
	# 비밀번호 검증
	try:
		ph.verify(user["hashed_password"], request.password)
	except argon2_exceptions.VerifyMismatchError:
		raise CustomException(status_code=401, error_code="ERR_010", error_message="INVALID ACCOUNT")
	# 토큰 생성 (sub: user_id)
	access_token = create_jwt_token(str(user["user_id"]), timedelta(minutes=SHORT_SESSION_LIFESPAN))
	refresh_token = create_jwt_token(str(user["user_id"]), timedelta(minutes=LONG_SESSION_LIFESPAN))
	return TokenResponse(access_token=access_token, refresh_token=refresh_token)



from fastapi import Header, Response, status
from jose import JWTError

def extract_token_from_header(authorization: str | None):
	if not authorization:
		raise CustomException(status_code=401, error_code="ERR_009", error_message="UNAUTHENTICATED")
	if not authorization.startswith("Bearer "):
		raise CustomException(status_code=400, error_code="ERR_007", error_message="BAD AUTHORIZATION HEADER")
	return authorization.split(" ", 1)[1]

def decode_token(token: str, verify_exp: bool = True):
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": verify_exp})
		return payload
	except JWTError:
		raise CustomException(status_code=401, error_code="ERR_008", error_message="INVALID TOKEN")


@auth_router.post("/token/refresh")
def refresh_token(authorization: str = Header(None)):
	refresh_token = extract_token_from_header(authorization)
	if refresh_token in blocked_token_db:
		raise CustomException(status_code=401, error_code="ERR_008", error_message="INVALID TOKEN")
	payload = decode_token(refresh_token)
	user_id = payload.get("sub")
	if not user_id:
		raise CustomException(status_code=401, error_code="ERR_008", error_message="INVALID TOKEN")
	# 기존 refresh_token 블랙리스트 처리
	blocked_token_db[refresh_token] = payload.get("exp")
	# 새 토큰 발급
	access_token = create_jwt_token(str(user_id), timedelta(minutes=SHORT_SESSION_LIFESPAN))
	new_refresh_token = create_jwt_token(str(user_id), timedelta(minutes=LONG_SESSION_LIFESPAN))
	return {"access_token": access_token, "refresh_token": new_refresh_token}



@auth_router.delete("/token")
def delete_token(authorization: str = Header(None)):
	refresh_token = extract_token_from_header(authorization)
	try:
		payload = decode_token(refresh_token)
	except CustomException as e:
		if e.error_code == "ERR_008":
			raise
		raise CustomException(status_code=401, error_code="ERR_009", error_message="UNAUTHENTICATED")
	# 블랙리스트 처리
	blocked_token_db[refresh_token] = payload.get("exp")
	return Response(status_code=status.HTTP_204_NO_CONTENT)



import secrets
from fastapi import Request

@auth_router.post("/session")
def create_session(request: TokenRequest, response: Response):
	# 사용자 조회
	user = next((u for u in user_db if u["email"] == request.email), None)
	if not user:
		raise CustomException(status_code=401, error_code="ERR_010", error_message="INVALID ACCOUNT")
	# 비밀번호 검증
	try:
		ph.verify(user["hashed_password"], request.password)
	except argon2_exceptions.VerifyMismatchError:
		raise CustomException(status_code=401, error_code="ERR_010", error_message="INVALID ACCOUNT")
	# 세션 생성
	sid = secrets.token_urlsafe(32)
	expire = datetime.utcnow() + timedelta(minutes=LONG_SESSION_LIFESPAN)
	session_db[sid] = {"user_id": user["user_id"], "exp": expire}
	response.set_cookie(key="sid", value=sid, httponly=True, max_age=LONG_SESSION_LIFESPAN*60)
	return {"message": "session created"}

@auth_router.delete("/session")
def delete_session(request: Request, response: Response):
	sid = request.cookies.get("sid")
	if sid:
		# 세션 삭제
		session_db.pop(sid, None)
		# 쿠키 만료
		response.delete_cookie("sid")
	response.status_code = 204
	return