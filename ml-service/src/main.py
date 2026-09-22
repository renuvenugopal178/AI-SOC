from fastapi import FastAPI
from src.api.schemas import AnomalyResponse, SecurityEventFeatures
from src.models.anomaly_model import AnomalyModel

app = FastAPI(title="AI-SOC ML Service")
model = AnomalyModel()


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "AI-SOC ML Service",
    }


@app.post("/predict", response_model=AnomalyResponse)
def predict_anomaly(event: SecurityEventFeatures) -> AnomalyResponse:
    return model.predict(event.model_dump())


@app.get("/")
def root():
    return {
        "message": "AI-SOC ML Service",
    }
