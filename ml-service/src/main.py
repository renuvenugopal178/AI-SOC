from fastapi import FastAPI

app = FastAPI(title="AI-SOC ML Service")


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "AI-SOC ML Service",
    }


@app.get("/")
def root():
    return {
        "message": "AI-SOC ML Service",
    }
