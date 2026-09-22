# AI-SOC ML Service

This FastAPI service provides an AI-assistance signal for the SOC pipeline. It is deliberately separate from rule detection: the Node backend continues ingesting events and producing rule-based alerts when this service is unavailable.

## Run

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn src.main:app --host 0.0.0.0 --port 8001
```

## API

`GET /health` returns service status.

`POST /predict` accepts SecurityEvent-derived features:

```json
{
  "event_type": "LOGIN_SUCCESS",
  "severity": "MEDIUM",
  "source_port": 49152,
  "destination_port": 443,
  "protocol": "TCP",
  "action": "authenticate",
  "message": "login completed",
  "event_frequency": 1
}
```

The response contains `is_anomaly`, `anomaly_score` in the range `[0, 1]`, `model_version`, and the extracted feature values.

## Model and features

The service uses scikit-learn `IsolationForest` with a fixed random seed. It is an unsupervised prototype trained on a small local development baseline representing ordinary login and network telemetry. It does not claim to be trained on real enterprise data.

Features are meaningful numerical representations of the event:

- normalized source and destination ports
- severity encoding from LOW through CRITICAL
- deterministic semantic encodings for common event types and protocols
- login-failure indicator
- privileged or suspicious activity indicator from action/message text
- normalized event frequency

The returned score combines the Isolation Forest decision signal with transparent feature-deviation signals. Scores at or above `0.65` are classified as anomalies by the service. The backend may use `ML_ANOMALY_THRESHOLD` to choose its alert threshold.

## Limitations

This is an anomaly-assistance prototype, not a production-trained detection model. The baseline is small and static, categorical mappings are intentionally limited, and event frequency is supplied by the caller. Scores require calibration against representative local telemetry before operational use. The backend treats the service as optional and never lets an ML timeout block ingestion or existing rule detection.
