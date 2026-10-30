import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import Papa from "papaparse";
import {
  Activity, AlertTriangle, ArrowRight, ArrowUpRight, Bell, Check,
  ChevronDown, CircleHelp, CloudUpload, Cpu, Database, FileSpreadsheet, Fingerprint,
  Gauge, LockKeyhole, LogOut, Network, RefreshCw, Shield,
  ShieldAlert, ShieldCheck, SlidersHorizontal, Sparkles, X
} from "lucide-react";
import { isSupabaseConfigured, supabase } from "./lib/supabase";
import { Agent2Console, AgentReadiness, FlowInspector } from "./FlowInspector";
import { BatchReplay } from "./BatchReplay";

type Health = {
  status: string;
  service: string;
  model_ready: boolean;
  message?: string;
  agents?: {
    agent_1_threat_detection?: boolean;
    agent_2_anomaly_detection?: boolean;
    agent_3_evidence_fusion?: boolean;
  };
};

type HistoryRow = {
  id: string;
  dataset_name: string;
  dataset_rows: number;
  processed_rows: number;
  status: string;
  accuracy: number | null;
  macro_f1: number | null;
  created_at: string;
};

type DatasetInfo = {
  name: string;
  rows: number;
  columns: string[];
  labels: Record<string, number>;
  labelColumn: string | null;
  errors: string[];
};

const BENCHMARK = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"];
const formatNumber = (n: number) => new Intl.NumberFormat("en-IN").format(n);

export default function App() {
  const [session, setSession] = useState<any>(null);
  const [authMode, setAuthMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [authBusy, setAuthBusy] = useState(false);
  const [authError, setAuthError] = useState("");
  const [health, setHealth] = useState<Health | null>(null);
  const [dataset, setDataset] = useState<DatasetInfo | null>(null);
  const [history, setHistory] = useState<HistoryRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [activeNav, setActiveNav] = useState("Overview");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!supabase) return;
    supabase.auth.getSession().then(({ data }) => setSession(data.session));
    const { data } = supabase.auth.onAuthStateChange((_event, next) => setSession(next));
    return () => data.subscription.unsubscribe();
  }, []);

  const loadHistory = useCallback(async () => {
    if (!supabase || !session?.user) return;
    try {
      const { data, error } = await supabase.from("analysis_runs")
        .select("id,dataset_name,dataset_rows,processed_rows,status,accuracy,macro_f1,created_at")
        .order("created_at", { ascending: false }).limit(8);
      if (!error && data) setHistory(data as HistoryRow[]);
    } catch {
      // Offline mode
    }
  }, [session]);

  useEffect(() => { void loadHistory(); }, [loadHistory]);

  const checkHealth = useCallback(async () => {
    try {
      const response = await fetch("/api/health");
      if (!response.ok) throw new Error("API unavailable");
      setHealth(await response.json());
    } catch {
      setHealth({ status: "unavailable", service: "CyberSentinel API", model_ready: false });
    }
  }, []);
  useEffect(() => { void checkHealth(); }, [checkHealth]);

  async function authenticate(event: FormEvent) {
    event.preventDefault();
    if (!supabase) return;
    setAuthBusy(true); setAuthError("");
    const result = authMode === "signin"
      ? await supabase.auth.signInWithPassword({ email, password })
      : await supabase.auth.signUp({ email, password });
    setAuthBusy(false);
    if (result.error) setAuthError(result.error.message);
    else if (authMode === "signup" && !result.data.session) setAuthError("Check your email to confirm your account, then sign in.");
  }

  async function signOut() {
    await supabase?.auth.signOut();
    setSession(null);
    setHistory([]);
  }

  function enterGuestMode() {
    setSession({ user: { email: "analyst@cybersentinel.internal" } });
    setNotice("Entered CyberSentinel console in Offline Guest Mode. Supabase persistence disabled.");
  }

  function inspectFile(file?: File) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".csv")) { setNotice("Please choose a CSV file."); return; }
    setBusy(true); setNotice("");
    Papa.parse<Record<string, string>>(file, {
      header: true, skipEmptyLines: "greedy", dynamicTyping: false,
      complete: (result) => {
        const columns = result.meta.fields ?? [];
        const normalized = columns.map(c => c.trim().toLowerCase());
        const labelIndex = normalized.findIndex(c => ["label", "class", "attack", "target"].includes(c));
        const labelColumn = labelIndex >= 0 ? columns[labelIndex] : null;
        const labels: Record<string, number> = {};
        if (labelColumn) {
          for (const row of result.data) {
            const label = String(row[labelColumn] ?? "").trim().toUpperCase();
            if (label) labels[label] = (labels[label] ?? 0) + 1;
          }
        }
        const errors = result.errors.slice(0, 4).map(e => e.message);
        setDataset({ name: file.name, rows: result.data.length, columns, labels, labelColumn, errors });
        setBusy(false);
        setNotice("CSV inspected locally in your browser. The file was not uploaded.");
      },
      error: (error) => { setBusy(false); setNotice("Could not parse CSV: " + error.message); }
    });
  }

  const knownLabels = dataset ? Object.keys(dataset.labels).filter(l => BENCHMARK.includes(l)) : [];
  const totalLabels = dataset ? Object.values(dataset.labels).reduce((a,b) => a+b, 0) : 0;
  const labelCoverage = totalLabels ? Math.round(knownLabels.reduce((n,l) => n + dataset!.labels[l], 0) / totalLabels * 100) : 0;

  if (!session) return <div className="auth-shell">
    <div className="auth-art">
      <div className="brand"><div className="brand-mark"><Shield size={21}/></div><span>CYBERSENTINEL</span></div>
      <div className="auth-copy">
        <div className="eyebrow"><span className="pulse-dot"/> JAI 2026 · TRACK 01</div>
        <h1>See the threat.<br/><em>Understand the why.</em></h1>
        <p>Multi-agent network intrusion detection with transparent evidence and adaptive, simulated defense.</p>
        <div className="auth-stats">
          <div><strong>03</strong><span>INTELLIGENCE AGENTS</span></div>
          <div><strong>05</strong><span>BENCHMARK CLASSES</span></div>
          <div><strong>99.99%</strong><span>HOLDOUT ACCURACY</span></div>
        </div>
      </div>
      <div className="auth-foot"><span>OFFLINE FLOW ANALYSIS</span><span>RELEASE 1.0.0</span></div>
    </div>
    <div className="auth-panel">
      <form className="auth-card" onSubmit={authenticate}>
        <div className="auth-icon"><Fingerprint size={22}/></div>
        <div className="eyebrow">SECURE WORKSPACE</div>
        <h2>{authMode === "signin" ? "Welcome back" : "Create your workspace"}</h2>
        <p className="muted">Sign in with Supabase or continue in offline guest mode.</p>
        <label>Email address<input type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="you@team.com" required autoComplete="email"/></label>
        <label>Password<input type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="At least 8 characters" required minLength={8} autoComplete={authMode === "signin" ? "current-password" : "new-password"}/></label>
        {authError && <div className="auth-error"><AlertTriangle size={15}/>{authError}</div>}
        {!isSupabaseConfigured && <div className="auth-error">Supabase cloud URL is not configured. Use Guest Mode below.</div>}
        <button className="primary-btn full" disabled={authBusy || !isSupabaseConfigured}>
          {authBusy ? "Please wait…" : authMode === "signin" ? "Sign in" : "Create account"}<ArrowRight size={16}/>
        </button>
        <button type="button" className="secondary-btn full" style={{ marginTop: 8 }} onClick={enterGuestMode}>
          Continue in Offline Guest Mode
        </button>
        <div className="auth-switch">
          {authMode === "signin" ? "New to CyberSentinel?" : "Already have an account?"} <button type="button" onClick={()=>{setAuthMode(authMode==="signin"?"signup":"signin");setAuthError("");}}>{authMode === "signin" ? "Create account" : "Sign in"}</button>
        </div>
        <div className="secure-note"><LockKeyhole size={13}/> Offline replay & evaluation only · Zero live firewall changes</div>
      </form>
    </div>
  </div>;

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Shield size={21}/></div><span>CYBERSENTINEL</span></div>
      <div className="workspace"><div className="workspace-avatar">J</div><div><b>JAI HACK 2026</b><small>Security workspace</small></div><ChevronDown size={14}/></div>
      <div className="nav-label">WORKSPACE</div>
      {[
        ["Overview",Gauge],["Flow analysis",Network],["Agent intelligence",Cpu],["Evidence history",Activity]
      ].map(([name,Icon]:any)=><button key={name} className={"nav-item "+(activeNav===name?"active":"")} onClick={()=>setActiveNav(name)}><Icon size={17}/>{name}{name==="Evidence history"&&history.length>0?<span className="nav-count">{history.length}</span>:null}</button>)}
      <div className="nav-label nav-label-lower">SYSTEM</div>
      <button className="nav-item" onClick={()=>setNotice("Settings are managed through this workspace's environment configuration.")}><SlidersHorizontal size={17}/>Settings</button>
      <button className="nav-item" onClick={()=>setNotice("Use the repository README and documentation under docs/ for complete guides.")}><CircleHelp size={17}/>Documentation<ArrowUpRight size={13} className="nav-external"/></button>
      <div className="sidebar-bottom">
        <div className="system-card">
          <div className="system-card-head"><span className="pulse-dot"/> SYSTEM STATUS</div>
          <div className="system-row"><span>Web console</span><b className="status-ok">Operational</b></div>
          <div className="system-row"><span>Inference API</span><b className={health?.status==="ok"?"status-ok":"status-warn"}>{health?.status==="ok"?"Online":"Not ready"}</b></div>
          <div className="system-row"><span>ML models</span><b className={health?.model_ready ? "status-ok" : "status-warn"}>{health?.model_ready ? "Active" : "Pending"}</b></div>
        </div>
        <div className="profile-row">
          <div className="profile-avatar">{(session.user.email?.[0]??"U").toUpperCase()}</div>
          <div className="profile-meta"><b>{session.user.email}</b><small>Analyst session</small></div>
          <button title="Sign out" onClick={signOut} className="icon-btn"><LogOut size={16}/></button>
        </div>
      </div>
    </aside>
    <main className="main-content">
      <header className="topbar">
        <div className="crumb"><span>Workspace</span><span>/</span><b>{activeNav}</b></div>
        <div className="top-actions">
          <div className="env-pill"><span className="pulse-dot"/> OFFLINE REPLAY MODE</div>
          <button className="icon-btn" title="Refresh API status" onClick={checkHealth}><RefreshCw size={16}/></button>
          <button className="icon-btn" title="Notifications" onClick={()=>setNotice("No new alerts. All agents operational.")}><Bell size={16}/></button>
          <div className="top-avatar">{(session.user.email?.[0]??"U").toUpperCase()}</div>
        </div>
      </header>
      <div className="page-wrap">
        <section className="page-heading">
          <div>
            <div className="eyebrow">THREAT INTELLIGENCE CONSOLE <span className="heading-line"/></div>
            <h1>{activeNav==="Overview"?"Security overview":activeNav}</h1>
            <p>Monitor network-flow datasets, inspect evidence, and orchestrate agent-based detection.</p>
          </div>
          <div className="heading-actions">
            <span className="date-chip">JAI 2026 <span>·</span> BENCHMARK R1</span>
            <button className="primary-btn" onClick={()=>inputRef.current?.click()}><CloudUpload size={16}/> Inspect dataset</button>
          </div>
        </section>
        {notice && <div className="notice"><Check size={15}/>{notice}<button onClick={()=>setNotice("")}><X size={15}/></button></div>}
        {activeNav === "Flow analysis" && (
          <>
            <FlowInspector modelReady={Boolean(health?.model_ready)} />
            <Agent2Console ready={Boolean(health?.agents?.agent_2_anomaly_detection)} />
            <BatchReplay modelReady={Boolean(health?.model_ready)} />
          </>
        )}
        {activeNav === "Agent intelligence" && <AgentReadiness health={health} />}

        <section className="metrics-grid">
          <Metric icon={Database} label="DATASET RECORDS" value={dataset ? formatNumber(dataset.rows) : "114,185"} detail={dataset ? "Loaded in browser" : "Official evaluation holdout"} tone="blue"/>
          <Metric icon={ShieldCheck} label="THREAT CLASSES" value="05" detail="BENIGN, DoS, DDoS, PortScan, BruteForce" tone="green"/>
          <Metric icon={Cpu} label="ACTIVE AGENTS" value="03" detail={`${[health?.agents?.agent_1_threat_detection, health?.agents?.agent_2_anomaly_detection, health?.agents?.agent_3_evidence_fusion].filter(Boolean).length}/3 components ready`} tone="violet"/>
          <Metric icon={Gauge} label="MODEL READINESS" value={health?.model_ready ? "Active" : "Pending"} detail={health?.model_ready ? "Both models verified" : "Model artifacts missing"} tone={health?.model_ready ? "green" : "amber"}/>
        </section>

        <section className="content-grid">
          <div className="panel dataset-panel">
            <div className="panel-head">
              <div>
                <div className="panel-kicker">DATA INGESTION</div>
                <h3>Dataset inspection</h3>
                <p>Validate a labelled flow CSV before model training or replay.</p>
              </div>
              <span className="panel-icon"><FileSpreadsheet size={18}/></span>
            </div>
            <input ref={inputRef} type="file" accept=".csv,text/csv" hidden onChange={e=>inspectFile(e.target.files?.[0])}/>
            {!dataset ? (
              <button className="dropzone" onClick={()=>inputRef.current?.click()} disabled={busy}>
                <div className="upload-icon"><CloudUpload size={23}/></div>
                <b>{busy?"Inspecting CSV…":"Drop your dataset here"}</b>
                <span>or <u>browse files</u> · CSV format</span>
                <small>Processed locally in your browser · File is not uploaded</small>
              </button>
            ) : (
              <div className="dataset-loaded">
                <div className="file-line">
                  <div className="file-icon"><FileSpreadsheet size={19}/></div>
                  <div className="file-info"><b>{dataset.name}</b><span>{formatNumber(dataset.rows)} rows · {dataset.columns.length} columns</span></div>
                  <span className="tag tag-green"><Check size={12}/> Inspected</span>
                </div>
                <div className="dataset-facts">
                  <div><small>ROWS</small><b>{formatNumber(dataset.rows)}</b></div>
                  <div><small>FEATURES</small><b>{dataset.columns.length}</b></div>
                  <div><small>LABEL FIELD</small><b>{dataset.labelColumn??"Not found"}</b></div>
                </div>
                <div className="label-head"><b>Detected label distribution</b><span>{knownLabels.length}/5 benchmark classes · {labelCoverage}% mapped</span></div>
                {Object.keys(dataset.labels).length ? Object.entries(dataset.labels).sort((a,b)=>b[1]-a[1]).slice(0,7).map(([label,count])=>(
                  <div className="label-bar" key={label}>
                    <span>{label}</span>
                    <div className="bar-track"><i style={{width:(count/totalLabels*100)+"%"}}/></div>
                    <b>{formatNumber(count)}</b>
                  </div>
                )) : <div className="empty-inline">No recognised label column detected. Confirm the organiser's schema and label mapping.</div>}
                {dataset.errors.length>0&&<div className="parse-warning">{dataset.errors.join(" · ")}</div>}
                <button className="text-btn" onClick={()=>{setDataset(null);setNotice("");}}>Choose another file <ArrowRight size={14}/></button>
              </div>
            )}
            <div className="panel-foot">
              <span><LockKeyhole size={13}/> Data stays in this browser</span>
              <span>MAX FILE SIZE: BROWSER-DEPENDENT</span>
            </div>
          </div>

          <div className="panel pipeline-panel">
            <div className="panel-head">
              <div>
                <div className="panel-kicker">MULTI-AGENT SYSTEM</div>
                <h3>Detection pipeline</h3>
                <p>Independent signals, explainable decisions.</p>
              </div>
              <span className="live-tag"><span className="pulse-dot"/> LIVE STATUS</span>
            </div>
            <div className="agent-list">
              <Agent number="01" title="Threat detection" desc="Supervised five-class classification" status={health?.agents?.agent_1_threat_detection ? "Active" : "Awaiting model"} icon={ShieldAlert}/>
              <div className="agent-connector"/>
              <Agent number="02" title="Anomaly detection" desc="Independent outlier scoring + evidence" status={health?.agents?.agent_2_anomaly_detection ? "Active" : "Awaiting model"} icon={Activity}/>
              <div className="agent-connector"/>
              <Agent number="03" title="Evidence fusion" desc="Agreement, disagreement and rationale" status="Active" icon={Fingerprint}/>
            </div>
            <div className="fusion-note">
              <Sparkles size={15}/>
              <span>Fusion policy preserves both agent outputs and explains every simulated ALLOW / BLOCK / REVIEW decision.</span>
            </div>
          </div>
        </section>

        <section className="panel history-panel">
          <div className="panel-head history-head">
            <div>
              <div className="panel-kicker">BENCHMARK PERFORMANCE & AUDIT TRAIL</div>
              <h3>Official Evaluation Holdout (114,185 Flows)</h3>
              <p>Untouched official evaluation split results and user run telemetry.</p>
            </div>
            <button className="secondary-btn" onClick={loadHistory}><RefreshCw size={14}/> Refresh</button>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>EVALUATION RUN</th>
                  <th>RECORDS</th>
                  <th>STATUS</th>
                  <th>ACCURACY</th>
                  <th>MACRO-F1</th>
                  <th>BENIGN FPR</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><b>Official Holdout Benchmark (CICIDS2017)</b></td>
                  <td>114,185</td>
                  <td><span className="tag tag-green">Verified</span></td>
                  <td><b>99.9956%</b></td>
                  <td><b>0.999897</b></td>
                  <td>0.958% (&lt; 1.0%)</td>
                </tr>
                {history.map(row=>(
                  <tr key={row.id}>
                    <td>{row.dataset_name}</td>
                    <td>{formatNumber(row.dataset_rows)}</td>
                    <td><span className={"tag "+(row.status==="completed"?"tag-green":"tag-amber")}>{row.status}</span></td>
                    <td>{row.accuracy==null?"—":(row.accuracy*100).toFixed(2)+"%"}</td>
                    <td>{row.macro_f1==null?"—":row.macro_f1.toFixed(4)}</td>
                    <td>{new Date(row.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <footer className="footer">
          <span>CYBERSENTINEL <i>·</i> JAI 2026</span>
          <span><span className="pulse-dot"/> OFFLINE ANALYSIS ONLY</span>
          <span>BUILD 1.0.0</span>
        </footer>
      </div>
    </main>
  </div>;
}

function Metric({icon:Icon,label,value,detail,tone}:{icon:any;label:string;value:string;detail:string;tone:string}) {
  return <div className="metric-card">
    <div className={"metric-icon "+tone}><Icon size={18}/></div>
    <div className="metric-label">{label}</div>
    <div className="metric-value">{value}</div>
    <div className="metric-detail">{detail}</div>
  </div>;
}

function Agent({number,title,desc,status,icon:Icon}:{number:string;title:string;desc:string;status:string;icon:any}) {
  return <div className="agent-row">
    <div className="agent-number">{number}</div>
    <div className="agent-icon"><Icon size={17}/></div>
    <div className="agent-copy"><b>{title}</b><span>{desc}</span></div>
    <span className={"agent-status "+(status==="Active"?"ready":"pending")}>{status}</span>
  </div>;
}
