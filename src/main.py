
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from src.common.custom_exception import CustomException

from tests.util import get_all_src_py_files_hash
from src.api import api_router
from src.users.router import user_router

app = FastAPI()

# Include routers
app.include_router(api_router)


# CustomException 핸들러
@app.exception_handler(CustomException)
def handle_custom_exception(request: Request, exc: CustomException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error_code": exc.error_code,
            "error_msg": exc.error_message
        }
    )

# HTTPException 핸들러 (Pydantic validator 등에서 발생)
@app.exception_handler(HTTPException)
def handle_http_exception(request: Request, exc: HTTPException):
    # detail이 dict면 error_code, error_msg 추출
    if isinstance(exc.detail, dict) and "error_code" in exc.detail and "error_msg" in exc.detail:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error_code": exc.detail["error_code"],
                "error_msg": exc.detail["error_msg"]
            }
        )
    # 그 외는 422, ERR_001, MISSING VALUE
    return JSONResponse(
        status_code=422,
        content={
            "error_code": "ERR_001",
            "error_msg": "MISSING VALUE"
        }
    )

# RequestValidationError 핸들러
@app.exception_handler(RequestValidationError)
def handle_request_validation_error(request, exc):
    return JSONResponse(
        status_code=422,
        content={
            "error_code": "ERR_001",
            "error_msg": "MISSING VALUE"
        }
    )

@app.get("/health")
def health_check():
    # 서버 정상 배포 여부를 확인하기 위한 엔드포인트입니다.
    # 본 코드는 수정하지 말아주세요!
    hash = get_all_src_py_files_hash()
    return {
        "status": "ok",
        "hash": hash
    }