# CyberSentinel API Reference

## Base URL
`/api` (Vercel Serverless Functions)

## Endpoints

### 1. `GET /api/health`
Checks API status and verified model availability.

**Response (200 OK):**
```json
{
  "status": "ok",
  "service": "CyberSentinel API",
  "version": "0.2.0",
  "mode": "offline-replay",
  "model_ready": true,
  "agents": {
    "agent_1_threat_detection": true,
    "agent_2_anomaly_detection": true,
    "agent_3_evidence_fusion": true
  },
  "message": "Both model artifacts loaded."
}
```

### 2. `GET /api/models/status`
Returns metadata about loaded models, feature counts, and thresholds.

### 3. `POST /api/analyze`
Analyzes a single network flow record.

**Request:**
```json
{
  "flow": {
    "Destination Port": 80,
    "Flow Duration": 1500,
    "Total Fwd Packets": 120,
    "Flow Packets/s": 80000,
    "SYN Flag Count": 120
  }
}
```

**Response (200 OK):**
```json
{
  "final_class": "DOS",
  "evidence_status": "AGREE",
  "action": "BLOCK",
  "agent_agreement": "ATTACK_CONFIRMED",
  "confidence": 0.995,
  "rationale": [
    "Classifier predicts an attack and anomaly detector independently flags the flow.",
    "Classifier confidence: 0.9950.",
    "Anomaly detector flag: True.",
    "Policy action is simulated only; no firewall or live network control is performed."
  ],
  "latency_ms": 1.42
}
```

### 4. `POST /api/analyze/batch`
Replays a batch of network flows (up to 1,000 flows per request).

**Response (200 OK):**
```json
{
  "total_analyzed": 1000,
  "actions": {
    "ALLOW": 520,
    "BLOCK": 410,
    "REVIEW": 70
  },
  "results": [...]
}
```
