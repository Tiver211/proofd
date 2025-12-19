import base64
import os


class Config:
    DATABASE_URL: str = os.getenv("DATABASE_URL")
    DB_ECHO: bool = False

