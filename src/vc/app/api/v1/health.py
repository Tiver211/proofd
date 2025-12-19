from fastapi import APIRouter

router = APIRouter(
    prefix="/health",
    tags=["Service"]
)

@router.get(
    "",
    summary="Проверка доступности VC",
    description="Используется для мониторинга и проверки работоспособности сервиса"
)
async def health():
    return {"status": "ok"}