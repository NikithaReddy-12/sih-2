import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseModel):
    APP_NAME: str = 'PREDICT-X Backend'
    API_PORT: int = int(os.getenv('API_PORT', '8000'))
    ALLOWED_ORIGINS: list[str] = [
        'http://localhost:5173',
        'http://127.0.0.1:5173'
    ]

settings = Settings()
