from fastapi import APIRouter

from ml.forecast import model_info

router = APIRouter(tags=['Health'])

@router.get('/health')
def get_health():
    return model_info()
