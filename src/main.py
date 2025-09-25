from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from tests.util import get_all_src_py_files_hash
from src.api import api_router
from src.users.router import user_router

app = FastAPI()

# Include routers
app.include_router(api_router)

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