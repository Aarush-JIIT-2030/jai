"""Top-level orchestration entry point."""
from typing import Any
from cybersentinel.contracts import FusionResult

class CyberSentinelPipeline:
    def __init__(self, threat_agent: Any, anomaly_agent: Any, fusion_agent: Any):
        self.threat_agent = threat_agent
        self.anomaly_agent = anomaly_agent
        self.fusion_agent = fusion_agent

    def analyze(self, flow: dict[str, Any]) -> FusionResult:
        threat_result = self.threat_agent.predict(flow)
        anomaly_result = self.anomaly_agent.score(flow)
        return self.fusion_agent.fuse(threat_result, anomaly_result)
