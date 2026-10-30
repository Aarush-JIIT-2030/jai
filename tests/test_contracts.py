from cybersentinel.contracts import AnomalyDetectionResult, FusionResult, ThreatDetectionResult

def test_fusion_result_serialises_to_dict():
    result = FusionResult(
        final_class="BENIGN",
        evidence_status="AGREE",
        action="ALLOW",
        rationale=["Both agents indicate normal activity."],
        threat_detection=ThreatDetectionResult("BENIGN", 0.98),
        anomaly_detection=AnomalyDetectionResult(-0.2, False, []),
    )
    payload = result.to_dict()
    assert payload["final_class"] == "BENIGN"
    assert payload["action"] == "ALLOW"
    assert payload["threat_detection"]["confidence"] == 0.98
