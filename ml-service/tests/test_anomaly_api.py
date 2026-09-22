from fastapi.testclient import TestClient

from src.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_normal_event_scoring():
    response = client.post("/predict", json={"event_type": "LOGIN_SUCCESS", "severity": "LOW", "destination_port": 443})
    assert response.status_code == 200
    assert response.json()["is_anomaly"] is False


def test_anomalous_event_scoring():
    response = client.post("/predict", json={
        "event_type": "UNAUTHORIZED_ACCESS",
        "severity": "CRITICAL",
        "source_port": 65535,
        "destination_port": 1,
        "protocol": "UNKNOWN",
        "action": "PRIVILEGED ADMIN SUDO",
        "event_frequency": 100,
    })
    assert response.status_code == 200
    assert response.json()["is_anomaly"] is True
    assert response.json()["anomaly_score"] >= 0.65


def test_invalid_input():
    response = client.post("/predict", json={"event_type": "", "severity": "INVALID"})
    assert response.status_code == 422


def test_response_structure():
    response = client.post("/predict", json={"event_type": "PORT_SCAN", "severity": "HIGH"})
    body = response.json()
    assert {"is_anomaly", "anomaly_score", "model_version", "features"} <= body.keys()
    assert 0 <= body["anomaly_score"] <= 1
