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


def test_tcp_stack_fingerprint_identity_is_stable():
    agent = TemporalCorrelationAgent()
    first = {
        "Init_Win_bytes_forward": 64240,
        "min_seg_size_forward": 20,
        "Fwd Header Length": 40,
        "Destination Port": 443,
        "Flow Duration": 50000,
    }
    second = {
        "Init_Win_bytes_forward": 64240,
        "min_seg_size_forward": 20,
        "Fwd Header Length": 40,
        "Destination Port": 22,
        "Flow Duration": 10,
    }
    src1, dst1, port1 = agent.extract_endpoints(first)
    src2, dst2, port2 = agent.extract_endpoints(second)
    assert src1 == src2
    assert src1.startswith("10.")
    assert dst1 == dst2 == ""
    assert port1 == 443
    assert port2 == 22


def test_missing_source_identity_fails_closed():
    agent = TemporalCorrelationAgent()
    flow = {"Destination Port": 443, "Flow Duration": 50000, "Total Fwd Packets": 10}
    src, dst, port = agent.extract_endpoints(flow)
    assert src == ""
    assert dst == ""
    assert port == 443
    result = agent.correlate("rec-unknown", flow, threat_class="DOS")
    assert result.correlated is False
    assert result.status == "not_ready"


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

