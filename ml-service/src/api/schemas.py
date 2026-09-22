from typing import Optional

from pydantic import BaseModel, Field


class SecurityEventFeatures(BaseModel):
    source_port: Optional[int] = Field(default=None, ge=1, le=65535)
    destination_port: Optional[int] = Field(default=None, ge=1, le=65535)
    severity: str = Field(default="MEDIUM", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    event_type: str = Field(min_length=1, max_length=128)
    protocol: Optional[str] = Field(default=None, max_length=32)
    action: Optional[str] = Field(default=None, max_length=128)
    message: Optional[str] = Field(default=None, max_length=4000)
    event_frequency: Optional[int] = Field(default=1, ge=1, le=100000)


class AnomalyResponse(BaseModel):
    is_anomaly: bool
    anomaly_score: float
    model_version: str
    features: dict[str, float]
