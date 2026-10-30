"""Independent anomaly detection agent."""
class AnomalyDetectionAgent:
    def fit(self, benign_training_features) -> "AnomalyDetectionAgent":
        raise NotImplementedError("Fit detector using permitted training data only.")
    def score(self, flow: dict):
        raise NotImplementedError("Return anomaly score and supporting feature evidence.")
