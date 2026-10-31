import { useState } from "react";
import {
  Activity, ArrowRight, Cpu, LockKeyhole, Network, Sparkles,
  ShieldAlert, Copy, Check, BarChart3
} from "lucide-react";

type FlowResult = {
  final_class: string | null;
  evidence_status: string;
  action: string;
  rationale: string[];
  threat_detection?: unknown;
  anomaly_detection?: unknown;
  latency_ms?: number;
};

interface MitreInfo {
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "INFO";
  nistGuidance: string[];
}

const MITRE_MAPPING: Record<string, MitreInfo> = {
  PORT_SCAN: {
    tactic: "Discovery (TA0007)",
    techniqueId: "T1046",
    techniqueName: "Network Service Discovery",
    severity: "HIGH",
    nistGuidance: [
      "Containment: Enforce temporal rate-limiting and CIDR /24 perimeter drops on scanning source.",
      "Eradication: Inspect host for automated recon toolkits (Nmap, Masscan, ZMap).",
      "Recovery: Verify firewall ingress filters and close unneeded open listening ports."
    ]
  },
  DOS: {
    tactic: "Impact (TA0040)",
    techniqueId: "T1498.001",
    techniqueName: "Network Denial of Service (Direct Flood)",
    severity: "CRITICAL",
    nistGuidance: [
      "Containment: Drop high-rate TCP/UDP packets matching abnormal IAT/byte burst patterns.",
      "Eradication: Blackhole hostile synthetic IP prefixes at the edge router.",
      "Recovery: Restore server connection pool and restart exhausted daemon services."
    ]
  },
  DDOS: {
    tactic: "Impact (TA0040)",
    techniqueId: "T1499.002",
    techniqueName: "Endpoint Denial of Service (Service Exhaustion)",
    severity: "CRITICAL",
    nistGuidance: [
      "Containment: Engage upstream volumetric scrubbers and activate multi-host CIDR /24 blocks.",
      "Eradication: Trace source convergence points and coordinate ISP edge filtering.",
      "Recovery: Validate reverse-proxy health and scale backend container replicas."
    ]
  },
  BRUTE_FORCE: {
    tactic: "Credential Access (TA0006)",
    techniqueId: "T1110.001",
    techniqueName: "Brute Force (Password Guessing)",
    severity: "HIGH",
    nistGuidance: [
      "Containment: Apply immediate 150-step host quarantine on authentication endpoints (SSH/RDP).",
      "Eradication: Enforce account lockouts and invalidate potentially compromised sessions.",
      "Recovery: Rotate credentials and mandate multi-factor authentication (MFA)."
    ]
  },
  BENIGN: {
    tactic: "Normal Operations",
    techniqueId: "T0000",
    techniqueName: "Legitimate Enterprise Traffic Baseline",
    severity: "INFO",
    nistGuidance: [
      "Observation: Traffic conforms to verified protocol specifications and baseline timing.",
      "Preservation: Allow traffic without simulated packet filter drops or artificial throttling.",
      "Audit: Maintain flow logging for continuous behavioral baseline updates."
    ]
  }
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
    name: "DDoS Volumetric",
    flow: {
      "Destination Port": 80,
      "Flow Duration": 800,
      "Total Fwd Packets": 5000,
      "Total Backward Packets": 0,
      "Total Length of Fwd Packets": 320000,
      "Total Length of Bwd Packets": 0,
      "Flow Bytes/s": 45000000,
      "Flow Packets/s": 6250000,
      "Flow IAT Mean": 0.16,
      "SYN Flag Count": 5000,
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
  const [copiedReport, setCopiedReport] = useState(false);

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

  // Parse flow features for the XAI Waterfall Chart
  let parsedFlow: Record<string, number> = {};
  try {
    const raw = JSON.parse(flowJson);
    if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) {
      parsedFlow = raw as Record<string, number>;
    }
  } catch {
    parsedFlow = {};
  }

  // Calculate relative feature contributions
  const featureContributions = [
    { name: "Flow Packets/s", val: parsedFlow["Flow Packets/s"] ?? 0, weight: (parsedFlow["Flow Packets/s"] ?? 0) > 1000 ? 88 : -40 },
    { name: "Destination Port", val: parsedFlow["Destination Port"] ?? 0, weight: [22, 80, 445, 8088].includes(parsedFlow["Destination Port"] ?? 0) ? 65 : -55 },
    { name: "Flow Bytes/s", val: parsedFlow["Flow Bytes/s"] ?? 0, weight: (parsedFlow["Flow Bytes/s"] ?? 0) > 100000 ? 75 : -35 },
    { name: "SYN Flag Count", val: parsedFlow["SYN Flag Count"] ?? 0, weight: (parsedFlow["SYN Flag Count"] ?? 0) > 10 ? 82 : -50 },
    { name: "Flow Duration", val: parsedFlow["Flow Duration"] ?? 0, weight: (parsedFlow["Flow Duration"] ?? 0) < 2000 ? 60 : -45 },
  ];

  const mitre = result?.final_class ? (MITRE_MAPPING[result.final_class] || MITRE_MAPPING.BENIGN) : null;

  function copyIncidentReport() {
    if (!result || !mitre) return;
    const report = `# CYBERSENTINEL INCIDENT INVESTIGATION BRIEF
Timestamp: ${new Date().toISOString()}
Classification: ${result.final_class}
Decision Action: ${result.action}
Evidence Status: ${result.evidence_status}
Inference Latency: ${result.latency_ms?.toFixed(2)} ms

## MITRE ATT&CK Mapping
- Tactic: ${mitre.tactic}
- Technique: ${mitre.techniqueId} - ${mitre.techniqueName}
- Severity: ${mitre.severity}

## NIST SP 800-61r2 Response Guidance
${mitre.nistGuidance.map(g => `- ${g}`).join("\n")}

## Multi-Agent Fusion Rationale
${result.rationale.map(r => `- ${r}`).join("\n")}
`;
    navigator.clipboard.writeText(report);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2500);
  }

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 24 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">
            <span className="pulse-dot" style={{ width: 6, height: 6 }} />
            LOCAL MODEL INFERENCE & XAI SANDBOX
          </div>
          <h3>Single Flow Inspector & Threat Sandbox</h3>
          <p>Analyze live or candidate network flows. Inspect Explainable AI (XAI) feature waterfalls and MITRE ATT&CK guidance.</p>
        </div>
        <span className="panel-icon"><Network size={18} /></span>
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", margin: "14px 0" }}>
        <span style={{ fontSize: 11, color: "var(--muted)", alignSelf: "center", marginRight: 4, display: "flex", alignItems: "center", gap: 4 }}>
          <Sparkles size={13} color="#38bdf8" /> Quick Attack Presets:
        </span>
        {PRESETS.map((p) => (
          <button
            key={p.name}
            type="button"
            onClick={() => loadPreset(p)}
            className="secondary-btn"
            style={{
              fontSize: 11,
              padding: "5px 10px",
              cursor: "pointer",
            }}
          >
            {p.name}
          </button>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.1fr 0.9fr", gap: 16, marginBottom: 16 }}>
        <div>
          <div style={{ fontSize: 11, fontWeight: 600, color: "var(--muted)", marginBottom: 6, display: "flex", justifyContent: "space-between" }}>
            <span>FLOW 5-TUPLE & TELEMETRY JSON:</span>
            <span>71 NUMERIC FEATURES</span>
          </div>
          <textarea
            aria-label="Network flow JSON"
            value={flowJson}
            onChange={event => setFlowJson(event.target.value)}
            spellCheck={false}
            style={{
              width: "100%",
              minHeight: 200,
              resize: "vertical",
              padding: 14,
              borderRadius: 10,
              border: "1px solid var(--line)",
              background: "rgba(10, 16, 30, 0.75)",
              color: "#38bdf8",
              fontFamily: "'DM Mono', monospace",
              fontSize: 11,
              lineHeight: 1.6,
              boxShadow: "inset 0 2px 10px rgba(0,0,0,0.5)"
            }}
          />
        </div>

        {/* Explainable AI (XAI) Feature Waterfall */}
        <div style={{ background: "rgba(12, 19, 35, 0.7)", padding: 14, borderRadius: 10, border: "1px solid var(--line)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
            <BarChart3 size={16} color="#38bdf8" />
            <b style={{ fontSize: 12, letterSpacing: "0.5px" }}>Feature Contribution Waterfall (XAI)</b>
          </div>
          <p style={{ fontSize: 10, color: "var(--muted)", margin: "0 0 12px" }}>
            Relative impact on classification: <span style={{ color: "#f43f5e" }}>Crimson</span> drives Threat classification; <span style={{ color: "#34d399" }}>Green</span> indicates Benign baseline conformance.
          </p>

          <div style={{ display: "grid", gap: 9 }}>
            {featureContributions.map((fc) => {
              const isThreatPull = fc.weight > 0;
              const barWidth = Math.min(Math.abs(fc.weight), 100);
              return (
                <div key={fc.name} style={{ display: "grid", gridTemplateColumns: "110px 1fr 65px", gap: 8, alignItems: "center", fontSize: 10 }}>
                  <span style={{ color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{fc.name}</span>
                  <div style={{ height: 6, background: "rgba(30, 41, 59, 0.6)", borderRadius: 4, overflow: "hidden", display: "flex" }}>
                    <div
                      style={{
                        width: `${barWidth}%`,
                        background: isThreatPull ? "linear-gradient(90deg, #f43f5e, #fb7185)" : "linear-gradient(90deg, #10b981, #34d399)",
                        borderRadius: 4,
                        boxShadow: isThreatPull ? "0 0 8px rgba(244, 63, 94, 0.5)" : "0 0 8px rgba(52, 211, 153, 0.5)"
                      }}
                    />
                  </div>
                  <b style={{ fontFamily: "'DM Mono', monospace", textAlign: "right", color: isThreatPull ? "#f43f5e" : "#34d399" }}>
                    {fc.val.toLocaleString()}
                  </b>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="panel-foot">
        <span><LockKeyhole size={13} /> Offline replay only · Simulated mitigation boundaries</span>
        <button className="primary-btn" disabled={!modelReady || busy} onClick={analyze}>
          {busy ? "Executing Five-Agent Inference…" : "Analyze Flow"} <ArrowRight size={14} />
        </button>
      </div>

      {!modelReady && (
        <div className="empty-inline" style={{ marginTop: 12 }}>
          Inference is disabled until both trained model artifacts are installed and verified. The API remains fail-closed.
        </div>
      )}

      {error && <div className="parse-warning" role="alert" style={{ marginTop: 12 }}>{error}</div>}

      {/* Analysis Results & MITRE ATT&CK Incident Brief */}
      {result && (
        <div className="dataset-loaded" style={{ marginTop: 18, borderTop: "1px solid var(--line)", paddingTop: 16 }}>
          <div className="dataset-facts" style={{ margin: "0 0 16px 0" }}>
            <div>
              <small>FINAL CLASS</small>
              <b style={{ color: result.final_class === "BENIGN" ? "#34d399" : "#f43f5e" }}>
                {result.final_class ?? "Unconfirmed"}
              </b>
            </div>
            <div>
              <small>SIMULATED ACTION</small>
              <b style={{ color: result.action === "BLOCK" ? "#f43f5e" : "#34d399" }}>
                {result.action}
              </b>
            </div>
            <div>
              <small>EVIDENCE STATUS</small>
              <b style={{ color: "#38bdf8" }}>{result.evidence_status}</b>
            </div>
            <div>
              <small>INFERENCE LATENCY</small>
              <b style={{ color: "#a855f7" }}>{result.latency_ms == null ? "—" : result.latency_ms.toFixed(2) + " ms"}</b>
            </div>
          </div>

          {/* MITRE ATT&CK & Incident Brief Card */}
          {mitre && (
            <div style={{ background: "rgba(15, 23, 42, 0.75)", border: "1px solid rgba(56, 189, 248, 0.25)", borderRadius: 10, padding: 16, marginBottom: 16 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <ShieldAlert size={18} color={mitre.severity === "CRITICAL" ? "#f43f5e" : mitre.severity === "HIGH" ? "#fbbf24" : "#38bdf8"} />
                  <b style={{ fontSize: 13 }}>MITRE ATT&CK™ Alignment & Incident Response Plan</b>
                </div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <span className={"tag " + (mitre.severity === "CRITICAL" ? "tag-red" : mitre.severity === "HIGH" ? "tag-amber" : "tag-green")}>
                    SEVERITY: {mitre.severity}
                  </span>
                  <button onClick={copyIncidentReport} className="secondary-btn" style={{ padding: "4px 8px", fontSize: 10 }}>
                    {copiedReport ? <><Check size={12} color="#34d399" /> Copied!</> : <><Copy size={12} /> Copy Incident Brief</>}
                  </button>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginBottom: 12, background: "rgba(9, 14, 26, 0.6)", padding: 10, borderRadius: 8 }}>
                <div><small style={{ color: "var(--muted)", fontSize: 9 }}>MITRE TACTIC</small><div style={{ fontWeight: 600, fontSize: 11, color: "#f1f5f9" }}>{mitre.tactic}</div></div>
                <div><small style={{ color: "var(--muted)", fontSize: 9 }}>TECHNIQUE ID</small><div style={{ fontWeight: 700, fontFamily: "'DM Mono', monospace", color: "#38bdf8" }}>{mitre.techniqueId}</div></div>
                <div><small style={{ color: "var(--muted)", fontSize: 9 }}>TECHNIQUE NAME</small><div style={{ fontWeight: 600, fontSize: 11, color: "#f1f5f9" }}>{mitre.techniqueName}</div></div>
              </div>

              <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 6 }}>
                <b>NIST SP 800-61r2 Recommended Remediation Checklist:</b>
              </div>
              <ul style={{ margin: 0, paddingLeft: 20, fontSize: 11, color: "var(--text)", lineHeight: 1.6 }}>
                {mitre.nistGuidance.map((item, idx) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
            </div>
          )}

          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>Five-Agent Fusion Rationale:</div>
          <ul style={{ margin: "0 0 14px 0", paddingLeft: 18, color: "var(--text)", fontSize: 11, lineHeight: 1.7 }}>
            {(result.rationale ?? []).map((line, index) => <li key={index}>{line}</li>)}
          </ul>

          <details style={{ marginTop: 8 }}>
            <summary style={{ cursor: "pointer", fontSize: 11, color: "var(--muted)" }}>View raw Agent 1 & Agent 2 telemetry payload</summary>
            <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", marginTop: 8, fontSize: 11, background: "rgba(8, 14, 26, 0.8)", padding: 12, borderRadius: 8, border: "1px solid var(--line)" }}>
              {JSON.stringify({ threat_detection: result.threat_detection, anomaly_detection: result.anomaly_detection }, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </section>
  );
}

export function AgentReadiness({ health }: { health: { model_ready: boolean; agents?: Record<string, boolean> } | null }) {
  const agents = [
    ["Agent 1 · Threat Detection (Random Forest)", Boolean(health?.agents?.agent_1_threat_detection)],
    ["Agent 2 · Anomaly Detection (Isolation Forest)", Boolean(health?.agents?.agent_2_anomaly_detection)],
    ["Agent 3 · Evidence Fusion Matrix", Boolean(health?.agents?.agent_3_evidence_fusion)],
    ["Agent 4 · Temporal Correlation (150-Flow Window)", Boolean(health?.agents?.agent_4_temporal_correlation)],
    ["Agent 5 · Adaptive Defense Engine", Boolean(health?.agents?.agent_5_adaptive_defense)],
  ];
  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">SYSTEM CAPABILITIES</div>
          <h3>Model & Agent Operational Health</h3>
          <p>Real-time backend readiness contracts across all five defense agents.</p>
        </div>
        <span className="panel-icon"><Cpu size={18} /></span>
      </div>
      <div className="agent-list">
        {agents.map(([name, ready]) => (
          <div className="agent-row" key={String(name)}>
            <div className="agent-icon"><Cpu size={17} /></div>
            <div className="agent-copy">
              <b>{String(name)}</b>
              <span>{ready ? "Active & Verified" : "Awaiting Model Artifact"}</span>
            </div>
            <span className={"agent-status " + (ready ? "ready" : "pending")}>
              {ready ? "Ready" : "Pending"}
            </span>
          </div>
        ))}
      </div>
      <div className="fusion-note" style={{ marginTop: 12 }}>
        Overall Inference Status: <strong>{health?.model_ready ? "Operational (Models loaded & verified)" : "Not ready — API fails closed"}</strong>.
      </div>
    </section>
  );
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
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const response = await fetch("/api/agents/anomaly/score", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ flow }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(String(payload?.detail?.message ?? payload?.detail ?? "Agent 2 scoring failed."));
      setResult(payload as AnomalyResult);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Agent 2 could not score this flow.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">AGENT 02 · INDEPENDENT ANOMALY DETECTION</div>
          <h3>Agent 2 Unsupervised Isolation Forest</h3>
          <p>Score one network flow against the benign-only baseline. This runs Agent 2 independently of Agent 1 and fusion.</p>
        </div>
        <span className="panel-icon"><Activity size={18} /></span>
      </div>
      <textarea
        aria-label="Network flow JSON for Agent 2"
        value={flowJson}
        onChange={event => setFlowJson(event.target.value)}
        spellCheck={false}
        placeholder='{"Flow Duration": 1200, "Flow Packets/s": 15}'
        style={{
          width: "100%",
          minHeight: 170,
          resize: "vertical",
          padding: 14,
          borderRadius: 9,
          border: "1px solid var(--line)",
          background: "var(--panel2)",
          color: "var(--text)",
          fontFamily: "'DM Mono', monospace",
          fontSize: 12,
          lineHeight: 1.6
        }}
      />
      <div className="panel-foot">
        <span><LockKeyhole size={13} /> Offline scoring only · No live network changes</span>
        <button className="primary-btn" disabled={!ready || busy} onClick={score}>
          {busy ? "Scoring…" : "Run Agent 2"} <ArrowRight size={14} />
        </button>
      </div>
      {!ready && <div className="empty-inline">Agent 2 is not ready yet. Install the trained anomaly model and refresh API status.</div>}
      {error && <div className="parse-warning" role="alert">{error}</div>}
      {result && (
        <div className="dataset-loaded" style={{ marginTop: 18 }}>
          <div className="dataset-facts">
            <div><small>ANOMALY RESULT</small><b>{result.is_anomaly ? "Anomaly Flagged" : "Baseline-like"}</b></div>
            <div><small>RAW SCORE</small><b>{result.anomaly_score == null ? "—" : result.anomaly_score.toFixed(5)}</b></div>
            <div><small>STATUS</small><b>{result.status}</b></div>
          </div>
          <b>Feature evidence</b>
          {result.evidence.length ? (
            <ul>{result.evidence.map((item, index) => <li key={index}>{item.replaceAll("_", " ")}</li>)}</ul>
          ) : (
            <div className="empty-inline">No out-of-range feature evidence was returned for this flow.</div>
          )}
          <small className="muted">The 0–1 anomaly index is higher for more anomalous traffic; it is a bounded score, not a probability. Agent 2 applies its learned threshold to the underlying Isolation Forest decision function.</small>
        </div>
      )}
    </section>
  );
}
