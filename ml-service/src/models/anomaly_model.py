from typing import Any

from sklearn.ensemble import IsolationForest

from src.preprocessing.features import _stable_encoding, extract_features

MODEL_VERSION = "isolation-forest-local-v1"


def _local_baseline() -> list[list[float]]:
    baseline: list[list[float]] = []
    for index in range(40):
        baseline.append([
            0.0,
            80 / 65535 if index % 4 else 443 / 65535,
            0.25 if index % 3 else 0.5,
            _stable_encoding("LOGIN_SUCCESS") + (index % 3 - 1) / 100,
            _stable_encoding("TCP") + (index % 3 - 1) / 100,
            0.0,
            0.0,
            0.05 + (index % 4) / 100,
        ])
    return baseline


class AnomalyModel:
    def __init__(self) -> None:
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
        )
        self.model.fit(_local_baseline())

    def predict(self, event: dict[str, Any]) -> dict[str, Any]:
        features = extract_features(event)
        decision = float(self.model.decision_function([features])[0])
        isolation_score = max(0.0, min(1.0, 0.5 - decision))
        behavioral_deviation = sum([
            features[0] > 0.2,
            features[1] < 0.001,
            features[2] > 0.75,
            features[3] >= 0.8,
            features[4] >= 0.6,
            features[6] > 0,
            features[7] > 0.5,
        ]) / 7
        anomaly_score = max(0.0, min(1.0, 0.4 * isolation_score + 0.6 * behavioral_deviation))
        return {
            "is_anomaly": bool(anomaly_score >= 0.65),
            "anomaly_score": round(anomaly_score, 6),
            "model_version": MODEL_VERSION,
            "features": dict(zip(
                [
                    "source_port", "destination_port", "severity", "event_type_encoding",
                    "protocol_encoding", "login_failure", "privileged_activity", "event_frequency",
                ],
                features,
            )),
        }
