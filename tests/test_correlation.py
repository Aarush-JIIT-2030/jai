from cybersentinel.agents.correlation import TemporalCorrelationAgent


def test_endpoint_extraction():
    agent = TemporalCorrelationAgent()
    flow = {
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.1",
        "Destination Port": 80,
    }
    src, dst, port = agent.extract_endpoints(flow)
    assert src == "192.168.1.100"
    assert dst == "10.0.0.1"
    assert port == 80


def test_synthetic_endpoint_fallback():
    agent = TemporalCorrelationAgent()
    flow = {
        "Destination Port": 443,
        "Flow Duration": 50000,
        "Total Fwd Packets": 10,
    }
    src, dst, port = agent.extract_endpoints(flow)
    assert src.startswith("192.168.1.")
    assert dst == "10.0.0.1"
    assert port == 443


def test_port_scan_correlation():
    agent = TemporalCorrelationAgent(window_size=50)
    src_ip = "192.168.1.50"

    # Simulate single source scanning 6 different ports
    result = None
    for i, port in enumerate([21, 22, 80, 443, 8080, 3389]):
        flow = {
            "source_ip": src_ip,
            "destination_ip": "10.0.0.5",
            "Destination Port": port,
        }
        result = agent.correlate(record_id=f"rec-{i}", flow=flow)

    assert result is not None
    assert result.correlated is True
    assert result.attack_type == "PORT_SCAN"
    assert result.group_id is not None
    assert "probed" in result.evidence[0]


def test_brute_force_correlation():
    agent = TemporalCorrelationAgent(window_size=50)
    src_ip = "192.168.1.75"

    result = None
    for i in range(5):
        flow = {
            "source_ip": src_ip,
            "destination_ip": "10.0.0.10",
            "Destination Port": 22,
        }
        result = agent.correlate(record_id=f"rec-{i}", flow=flow, threat_class="BRUTE_FORCE")

    assert result is not None
    assert result.correlated is True
    assert result.attack_type == "BRUTE_FORCE"
    assert "rapid auth" in result.evidence[0]
