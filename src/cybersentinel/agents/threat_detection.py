"""Supervised five-class threat detection agent."""
class ThreatDetectionAgent:
    def fit(self, features, labels) -> "ThreatDetectionAgent":
        raise NotImplementedError("Implement classifier and train-only preprocessing.")
    def predict(self, flow: dict):
        raise NotImplementedError("Return ThreatDetectionResult with class and confidence.")
