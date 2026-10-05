import sys
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Ensure backend root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from config import settings
from api.routes import health, forecast

app = FastAPI(
    title='PREDICT-X AI Attack Forecasting API',
    description='AI-Based Network Attack Forecasting from Network Traffic Data',
    version='1.0.0',
    docs_url='/docs',
    redoc_url='/redoc'
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

# Register routers
app.include_router(health.router)
app.include_router(forecast.router)

@app.get('/')
def root():
    return {
        'message': 'PREDICT-X Backend API is operational',
        'docs': '/docs',
        'health': '/health',
        'forecast_status': '/api/forecast/status'
    }

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', host='127.0.0.1', port=settings.API_PORT, reload=True)
