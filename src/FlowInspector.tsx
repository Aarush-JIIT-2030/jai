import { useState } from "react";
import { Activity, ArrowRight, Cpu, LockKeyhole, Network, Sparkles } from "lucide-react";

type FlowResult = {
  final_class: string | null;
  evidence_status: string;
  action: string;
  rationale: string[];
  threat_detection?: unknown;
  anomaly_detection?: unknown;
  latency_ms?: number;
};

const PRESETS: { name: string; flow: Record<string, number> }[] = [
  {
    name: "Normal Benign Traffic",
    flow: {
      "Destination Port": 443,
      "Flow Duration": 120000,
      "Total Fwd Packets": 12,
      "Total Backward Packets": 15,
      "Total Length of Fwd Packets": 1500,
      "Total Length of Bwd Packets": 4200,
      "Flow Bytes/s": 47500,
      "Flow Packets/s": 225,
      "Flow IAT Mean": 4500,
      "FIN Flag Count": 1,
      "SYN Flag Count": 1,
      "RST Flag Count": 0,
      "PSH Flag Count": 4,
      "ACK Flag Count": 26
    }
  },
  {
    name: "DoS SYN Flood",
    flow: {
      "Destination Port": 80,
      "Flow Duration": 1500,
      "Total Fwd Packets": 120,
      "Total Backward Packets": 0,
      "Total Length of Fwd Packets": 7200,
      "Total Length of Bwd Packets": 0,
      "Flow Bytes/s": 4800000,
      "Flow Packets/s": 80000,
      "Flow IAT Mean": 12.5,
      "SYN Flag Count": 120,
      "RST Flag Count": 0,
      "ACK Flag Count": 0
    }
  },
  {
    name: "Port Sweep Scan",
    flow: {
      "Destination Port": 445,
      "Flow Duration": 250,
      "Total Fwd Packets": 2,
      "Total Backward Packets": 0,
      "Total Length of Fwd Packets": 0,
      "Total Length of Bwd Packets": 0,
      "Flow Packets/s": 8000,
      "SYN Flag Count": 2,
      "ACK Flag Count": 0
    }
  },
  {
    name: "Brute Force SSH",
    flow: {
      "Destination Port": 22,
      "Flow Duration": 950000,
      "Total Fwd Packets": 35,
      "Total Backward Packets": 32,
      "Total Length of Fwd Packets": 3200,
      "Total Length of Bwd Packets": 3800,
      "Flow Packets/s": 70,
      "PSH Flag Count": 15,
      "ACK Flag Count": 66
    }
  },
  {
    name: "Zero-Day Anomaly",
    flow: {
      "Destination Port": 8088,
      "Flow Duration": 89000000,
      "Total Fwd Packets": 9500,
      "Total Backward Packets": 12,
      "Total Length of Fwd Packets": 1250000,
      "Total Length of Bwd Packets": 480,
      "Flow Packets/s": 106,
      "Flow Bytes/s": 14050,
      "FIN Flag Count": 12,
      "RST Flag Count": 85
    }
  }
];

export function FlowInspector({ modelReady }: { modelReady: boolean }) {
  const [flowJson, setFlowJson] = useState(JSON.stringify(PRESETS[0].flow, null, 2));
  const [result, setResult] = useState<FlowResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function analyze() {
    let flow: Record<string, unknown>;
    try {
      flow = JSON.parse(flowJson);
      if (!flow || Array.isArray(flow) || typeof flow !== "object" || !Object.keys(flow).length) {
        throw new Error("Enter a non-empty JSON object for one network flow.");
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Invalid JSON.");
      return;
    }
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ flow }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(String(payload?.detail?.message ?? payload?.detail ?? "Analysis request failed."));
      }
      setResult(payload as FlowResult);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The flow could not be analyzed.");
    } finally {
      setBusy(false);
    }
  }

  function loadPreset(preset: typeof PRESETS[number]) {
    setFlowJson(JSON.stringify(preset.flow, null, 2));
    setResult(null);
    setError("");
  }

  return <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
    <div className="panel-head">
      <div>
        <div className="panel-kicker">LOCAL MODEL INFERENCE</div>
        <h3>Single flow inspector</h3>
        <p>Analyze a real network-flow record. Presets represent verified challenge traffic distributions.</p>
      </div>
      <span className="panel-icon"><Network size={18}/></span>
    </div>

    <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
      <span style={{ fontSize: 11, color: "var(--muted)", alignSelf: "center", marginRight: 4, display: "flex", alignItems: "center", gap: 4 }}>
        <Sparkles size={13}/> Quick Presets:
      </span>
      {PRESETS.map((p) => (
        <button
          key={p.name}
          type="button"
          onClick={() => loadPreset(p)}
          className="text-btn"
          style={{
            fontSize: 11,
            padding: "4px 8px",
            background: "var(--panel2)",
            border: "1px solid var(--line)",
            borderRadius: 6,
            cursor: "pointer",
            color: "var(--text)"
          }}
        >
          {p.name}
        </button>
      ))}
    </div>

    <textarea
      aria-label="Network flow JSON"
      value={flowJson}
      onChange={event => setFlowJson(event.target.value)}
      spellCheck={false}
      style={{
        width: "100%",
        minHeight: 180,
        resize: "vertical",
        padding: 15,
        borderRadius: 9,
        border: "1px solid var(--line)",
        background: "var(--panel2)",
        color: "var(--text)",
        fontFamily: "monospace",
        fontSize: 12,
        lineHeight: 1.6
      }}
    />
    <div className="panel-foot">
      <span><LockKeyhole size={13}/> Offline replay only · No live firewall changes</span>
      <button className="primary-btn" disabled={!modelReady || busy} onClick={analyze}>
        {busy ? "Analyzing…" : "Analyze flow"} <ArrowRight size={14}/>
      </button>
    </div>
    {!modelReady && <div className="empty-inline">Inference is disabled until both trained model artifacts are installed and verified. The API remains fail-closed.</div>}
    {error && <div className="parse-warning" role="alert">{error}</div>}
    {result && <div className="dataset-loaded" style={{ marginTop: 18 }}>
      <div className="dataset-facts">
        <div><small>FINAL CLASS</small><b>{result.final_class ?? "Unconfirmed"}</b></div>
        <div><small>SIMULATED ACTION</small><b>{result.action}</b></div>
        <div><small>EVIDENCE</small><b>{result.evidence_status}</b></div>
        <div><small>LATENCY</small><b>{result.latency_ms == null ? "—" : result.latency_ms.toFixed(2) + " ms"}</b></div>
      </div>
      <b>Fusion rationale</b>
      <ul>{(result.rationale ?? []).map((line, index) => <li key={index}>{line}</li>)}</ul>
      <details style={{ marginTop: 10 }}>
        <summary style={{ cursor: "pointer", fontSize: 12, color: "var(--muted)" }}>Agent evidence payload</summary>
        <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", marginTop: 8, fontSize: 11, background: "var(--panel2)", padding: 10, borderRadius: 6 }}>
          {JSON.stringify({ threat_detection: result.threat_detection, anomaly_detection: result.anomaly_detection }, null, 2)}
        </pre>
      </details>
    </div>}
  </section>;
}

export function AgentReadiness({ health }: { health: { model_ready: boolean; agents?: Record<string, boolean> } | null }) {
  const agents = [
    ["Agent 1 · Threat detection", Boolean(health?.agents?.agent_1_threat_detection)],
    ["Agent 2 · Anomaly detection", Boolean(health?.agents?.agent_2_anomaly_detection)],
    ["Agent 3 · Evidence fusion", Boolean(health?.agents?.agent_3_evidence_fusion)],
  ];
  return <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
    <div className="panel-head">
      <div>
        <div className="panel-kicker">AGENT READINESS</div>
        <h3>Model and agent status</h3>
        <p>Readiness is reported by the API, not inferred from the UI.</p>
      </div>
      <span className="panel-icon"><Cpu size={18}/></span>
    </div>
    <div className="agent-list">
      {agents.map(([name, ready]) => (
        <div className="agent-row" key={String(name)}>
          <div className="agent-icon"><Cpu size={17}/></div>
          <div className="agent-copy">
            <b>{String(name)}</b>
            <span>{ready ? "Available & verified" : "Awaiting verified model artifact"}</span>
          </div>
          <span className={"agent-status " + (ready ? "ready" : "pending")}>
            {ready ? "Ready" : "Pending"}
          </span>
        </div>
      ))}
    </div>
    <div className="fusion-note" style={{ marginTop: 12 }}>
      Overall inference: <strong>{health?.model_ready ? "Operational (Models loaded)" : "Not ready — API fails closed"}</strong>.
    </div>
  </section>;
}



type AnomalyResult = {
  anomaly_score: number | null;
  is_anomaly: boolean | null;
  evidence: string[];
  status: string;
  message?: string | null;
};

export function Agent2Console({ ready }: { ready: boolean }) {
  const [flowJson, setFlowJson] = useState("{}");
  const [result, setResult] = useState<AnomalyResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function score() {
    let flow: Record<string, unknown>;
    try {
      flow = JSON.parse(flowJson);
      if (!flow || Array.isArray(flow) || typeof flow !== "object" || !Object.keys(flow).length) {
        throw new Error("Enter a non-empty JSON object for one network flow.");
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Invalid JSON.");
      return;
    }
    setBusy(true); setError(""); setResult(null);
    try {
      const response = await fetch("/api/agents/anomaly/score", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ flow }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(String(payload?.detail?.message ?? payload?.detail ?? "Agent 2 scoring failed."));
      setResult(payload as AnomalyResult);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Agent 2 could not score this flow.");
    } finally { setBusy(false); }
  }

  return <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
    <div className="panel-head">
      <div><div className="panel-kicker">AGENT 02 · INDEPENDENT ANOMALY DETECTION</div><h3>Use Agent 2</h3>
        <p>Score one network flow against the benign-only Isolation Forest baseline. This runs Agent 2 independently of Agent 1 and fusion.</p></div>
      <span className="panel-icon"><Activity size={18}/></span>
    </div>
    <textarea aria-label="Network flow JSON for Agent 2" value={flowJson} onChange={event => setFlowJson(event.target.value)}
      spellCheck={false} placeholder='{"Flow Duration": 1200, "Flow Packets/s": 15}'
      style={{ width: "100%", minHeight: 170, resize: "vertical", padding: 15, borderRadius: 9,
        border: "1px solid var(--line)", background: "var(--panel2)", color: "var(--text)",
        fontFamily: "monospace", fontSize: 12, lineHeight: 1.6 }} />
    <div className="panel-foot">
      <span><LockKeyhole size={13}/> Offline scoring only · No live network changes</span>
      <button className="primary-btn" disabled={!ready || busy} onClick={score}>
        {busy ? "Scoring…" : "Run Agent 2"} <ArrowRight size={14}/>
      </button>
    </div>
    {!ready && <div className="empty-inline">Agent 2 is not ready yet. Install the trained anomaly model at models/anomaly_detection/model.joblib and refresh API status.</div>}
    {error && <div className="parse-warning" role="alert">{error}</div>}
    {result && <div className="dataset-loaded" style={{ marginTop: 18 }}>
      <div className="dataset-facts">
        <div><small>ANOMALY RESULT</small><b>{result.is_anomaly ? "Anomaly flagged" : "Baseline-like"}</b></div>
        <div><small>ANOMALY SCORE</small><b>{result.anomaly_score == null ? "—" : result.anomaly_score.toFixed(5)}</b></div>
        <div><small>STATUS</small><b>{result.status}</b></div>
      </div>
      <b>Feature evidence</b>
      {result.evidence.length ? <ul>{result.evidence.map((item, index) => <li key={index}>{item.replaceAll("_", " ")}</li>)}</ul>
        : <div className="empty-inline">No out-of-range feature evidence was returned for this flow.</div>}
      <small className="muted">The anomaly score is interpreted against Agent 2's learned threshold; it is not a probability.</small>
    </div>}
  </section>;
}

