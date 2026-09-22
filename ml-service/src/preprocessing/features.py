import hashlib
from typing import Any

SEVERITY_VALUES = {"LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.75, "CRITICAL": 1.0}
EVENT_TYPE_VALUES = {
    "LOGIN_SUCCESS": 0.1,
    "HEARTBEAT": 0.1,
    "DNS_QUERY": 0.2,
    "HTTP_REQUEST": 0.2,
    "LOGIN_FAILED": 0.6,
    "PORT_SCAN": 0.8,
    "UNAUTHORIZED_ACCESS": 1.0,
}
PROTOCOL_VALUES = {"TCP": 0.1, "UDP": 0.2, "HTTP": 0.3, "HTTPS": 0.3}
FEATURE_NAMES = [
    "source_port",
    "destination_port",
    "severity",
    "event_type_encoding",
    "protocol_encoding",
    "login_failure",
    "privileged_activity",
    "event_frequency",
]


def _stable_encoding(value: str | None) -> float:
    if not value:
        return 0.0
    digest = hashlib.sha256(value.strip().upper().encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") / 2**32


def extract_features(event: dict[str, Any]) -> list[float]:
    source_port = float(event.get("source_port") or 0) / 65535
    destination_port = float(event.get("destination_port") or 0) / 65535
    event_type = str(event.get("event_type") or "").upper()
    action = str(event.get("action") or "").upper()
    message = str(event.get("message") or "").upper()
    suspicious_text = f"{action} {message}"

    return [
        source_port,
        destination_port,
        SEVERITY_VALUES.get(str(event.get("severity") or "MEDIUM").upper(), 0.5),
        EVENT_TYPE_VALUES.get(event_type, 0.7),
        PROTOCOL_VALUES.get(str(event.get("protocol") or "").upper(), 0.7 if event.get("protocol") else 0.0),
        float(event_type == "LOGIN_FAILED"),
        float(any(term in suspicious_text for term in ("PRIVILEGED", "SUDO", "ADMIN", "UNAUTHORIZED"))),
        max(0.0, min(1.0, float(event.get("event_frequency") or 1) / 20)),
    ]
