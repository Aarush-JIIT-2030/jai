"""Stable serialisable contracts shared by the agents."""
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

BenchmarkClass = Literal["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]
AgentStatus = Literal["success", "error", "not_ready"]
PolicyAction = Literal["ALLOW", "BLOCK", "REVIEW"]

@dataclass
class ThreatDetectionResult:
    predicted_class: BenchmarkClass | None
    confidence: float | None
    status: AgentStatus = "success"
    model_version: str | None = None
    message: str | None = None

@dataclass
class AnomalyDetectionResult:
    anomaly_score: float | None
    is_anomaly: bool | None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    status: AgentStatus = "success"
    message: str | None = None

@dataclass
class FusionResult:
    final_class: BenchmarkClass | None
    evidence_status: Literal["AGREE", "DISAGREE", "INCOMPLETE"]
    action: PolicyAction
    rationale: list[str] = field(default_factory=list)
    threat_detection: ThreatDetectionResult | None = None
    anomaly_detection: AnomalyDetectionResult | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
