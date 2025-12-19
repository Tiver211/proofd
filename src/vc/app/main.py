from fastapi import FastAPI
from app.api import router

app = FastAPI(
    title="Distributed Verification System",
    description="Authority Center & Verification Center API",
    version="0.1.0",
)

app.include_router(router)
