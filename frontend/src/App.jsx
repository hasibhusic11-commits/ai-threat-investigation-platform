import { useEffect, useMemo, useState, useCallback } from "react";
import api from "./api";
import "./App.css";
import ThreatPulse from "./components/ThreatPulse";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";

const PIE_COLORS = ["#22c55e", "#facc15", "#f97316", "#ef4444"];

function ensureApiKey() {
  const existing = localStorage.getItem("backend_api_key");
  if (existing) return existing;

  const entered = window.prompt("Enter backend API key");
  if (entered) {
    localStorage.setItem("backend_api_key", entered);
    return entered;
  }
  return null;
}

function StatCard({ label, value, sublabel }) {
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value ?? 0}</div>
      <div className="stat-sublabel">{sublabel}</div>
    </div>
  );
}

function SectionCard({ title, subtitle, children }) {
  return (
    <section className="section-card">
      <div className="section-header">
        <h2>{title}</h2>
        {subtitle ? <p>{subtitle}</p> : null}
      </div>
      {children}
    </section>
  );
}

function ActionCard({ title, text, buttonText, onClick }) {
  return (
    <div className="action-card">
      <h3>{title}</h3>
      <p>{text}</p>
      <button className="action-btn" onClick={onClick}>
        {buttonText}
      </button>
    </div>
  );
}

export default function App() {
  const [summary, setSummary] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [cases, setCases] = useState([]);
  const [telemetry, setTelemetry] = useState([]);
  const [flows, setFlows] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const [activeView, setActiveView] = useState("dashboard");
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [traceInput, setTraceInput] = useState("");
  const [traceResults, setTraceResults] = useState([]);

  const [llmOutput, setLlmOutput] = useState(null);
  const [llmLoading, setLlmLoading] = useState(false);

  const [scanTarget, setScanTarget] = useState("");
  const [scanPorts, setScanPorts] = useState("");
  const [scanResults, setScanResults] = useState(null);
  const [scanLoading, setScanLoading] = useState(false);

  useEffect(() => {
    ensureApiKey();
  }, []);

  useEffect(() => {
    if ("scrollRestoration" in window.history) {
      window.history.scrollRestoration = "manual";
    }
  }, []);

  const loadData = useCallback(async () => {
    try {
      setError("");

      const [summaryRes, incidentsRes, casesRes, telemetryRes, flowsRes] =
        await Promise.all([
          api.get("/dashboard/summary"),
          api.get("/incidents"),
          api.get("/cases"),
          api.get("/telemetry/recent?limit=12"),
          api.get("/packets/flows"),
        ]);

      setSummary(summaryRes.data || null);
      setIncidents(incidentsRes.data?.incidents || []);
      setCases(casesRes.data?.cases || []);
      setTelemetry(telemetryRes.data?.events || []);
      setFlows(flowsRes.data?.flows || []);
    } catch (err) {
      console.error(err);
      setError(err?.response?.data?.detail || err?.message || "Network Error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      loadData();
    }, 15000);
    return () => clearInterval(interval);
  }, [loadData]);

  const severityData = useMemo(() => {
    return summary?.risk_distribution || [];
  }, [summary]);

  const visibleFlows = useMemo(() => {
    if (!traceInput.trim()) return traceResults.length ? traceResults : flows;
    return traceResults;
  }, [flows, traceInput, traceResults]);

  const recentAlerts = useMemo(() => {
    return telemetry
      .filter((e) =>
        ["alert", "dns", "authentication", "process", "flow"].includes(
          e.event_type
        )
      )
      .slice(0, 8);
  }, [telemetry]);

  const openIncident = (incident) => {
    setSelectedIncident(incident);
    setActiveView("incidents");
    setLlmOutput(null);
  };

  const runTrace = async () => {
    try {
      setError("");
      if (!traceInput.trim()) {
        setTraceResults(flows);
        setActiveView("packets");
        return;
      }

      const res = await api.get(`/packets/trace/${traceInput.trim()}`);
      setTraceResults(res.data?.flows || []);
      setActiveView("packets");
    } catch (err) {
      console.error(err);
      setError(err?.response?.data?.detail || err?.message || "Trace failed");
    }
  };

  const showAllFlows = () => {
    setTraceInput("");
    setTraceResults(flows);
  };

  const runLlmExplain = async () => {
    if (!selectedIncident?.incident_id) return;

    try {
      setLlmLoading(true);
      setError("");
      const res = await api.get(
        `/ai/explain/incident/${selectedIncident.incident_id}`
      );
      setLlmOutput(res.data);
      setActiveView("llm");
    } catch (err) {
      console.error(err);
      setError(
        err?.response?.data?.detail || err?.message || "LLM analysis failed"
      );
    } finally {
      setLlmLoading(false);
    }
  };

  const runScan = async () => {
    try {
      setScanLoading(true);
      setError("");

      const ports = scanPorts
        .split(",")
        .map((p) => parseInt(p.trim(), 10))
        .filter((p) => !Number.isNaN(p));

      const res = await api.post("/scan/ports", {
        target: scanTarget.trim(),
        ports: ports.length ? ports : null,
      });

      setScanResults(res.data);
      setActiveView("scanner");
    } catch (err) {
      console.error(err);
      setError(err?.response?.data?.detail || err?.message || "Port scan failed");
    } finally {
      setScanLoading(false);
    }
  };

  const quickScanIp = (ip) => {
    if (!ip) return;
    setScanTarget(ip);
    setActiveView("scanner");
  };

  const quickTraceIp = (ip) => {
    if (!ip) return;
    setTraceInput(ip);
    setActiveView("packets");
  };

  if (loading) {
    return <div className="loading-screen">Loading platform data...</div>;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-kicker">SOC Platform</div>
        <h1 className="brand-title">Threat Engine</h1>

        <div className="nav-list">
          {[
            ["dashboard", "Dashboard"],
            ["incidents", "Incidents"],
            ["cases", "Cases"],
            ["telemetry", "Telemetry"],
            ["packets", "Packet Tracer"],
            ["llm", "AI Analyst"],
            ["scanner", "Port Scanner"],
            ["status", "System Status"],
          ].map(([key, label]) => (
            <button
              key={key}
              className={`nav-button ${activeView === key ? "active" : ""}`}
              onClick={() => setActiveView(key)}
            >
              {label}
            </button>
          ))}
        </div>
      </aside>

      <main className="main-panel">
        <div className="topbar">
          <div>
            <div className="eyebrow">AI-Assisted Security Operations</div>
            <h2 className="hero-title">AI Threat Investigation Platform</h2>
          </div>
          <button className="refresh-btn" onClick={loadData}>
            Refresh Data
          </button>
        </div>

        {error ? <div className="error-banner">{error}</div> : null}

        {activeView === "dashboard" && (
          <>
            <SectionCard
              title="Mission Control"
              subtitle="A cyber-style command center for telemetry, incident response, and threat context"
            >
              <div className="dashboard-hero-grid">
                <div className="dashboard-hero-card">
                  <div className="hero-chip">CYBER THREAT COMMAND</div>
                  <h3 className="dashboard-hero-heading">
                    Real-time investigation, threat visibility, and analyst support in one platform.
                  </h3>
                  <p className="dashboard-hero-text">
                    Monitor suspicious activity, inspect incident chains, generate AI-guided notes,
                    run internal network scans, and manage investigations from a unified SOC dashboard.
                  </p>

                  <div className="dashboard-hero-badges">
                    <span>{summary?.total_incidents ?? 0} Incidents</span>
                    <span>{summary?.high_risk_incidents ?? 0} High Risk</span>
                    <span>{summary?.suspicious_ip_incidents ?? 0} Suspicious IPs</span>
                    <span>{summary?.case_summary?.open_cases ?? 0} Open Cases</span>
                  </div>

                  <div className="hero-live-panel">
                    <div className="hero-live-header">Live Incident Feed</div>

                    <div className="hero-live-list">
                      {(incidents || []).slice(0, 5).map((incident, i) => (
                        <div key={i} className="hero-live-item">
                          <div className="hero-live-title">
                            {incident.title || "Security Incident"}
                          </div>
                          <div className="hero-live-meta">
                            Incident ID: {incident.incident_id || "N/A"} | Hosts:{" "}
                            {(incident.hosts || []).join(", ") || "Unknown"} | Max Risk:{" "}
                            {incident.max_risk_score ?? 0}
                          </div>
                        </div>
                      ))}

                      {(!incidents || incidents.length === 0) && (
                        <div className="empty-state">No recent incidents detected</div>
                      )}
                    </div>
                  </div>
                </div>

                <ThreatPulse
                  incidents={incidents}
                  telemetry={telemetry}
                  summary={summary}
                />
              </div>
            </SectionCard>

            <SectionCard
              title="Overview"
              subtitle="High-level platform metrics"
            >
              <div className="stats-grid">
                <StatCard
                  label="Total Incidents"
                  value={summary?.total_incidents ?? 0}
                  sublabel="Correlated chains"
                />
                <StatCard
                  label="High Risk"
                  value={summary?.high_risk_incidents ?? 0}
                  sublabel="Risk score ≥ 50"
                />
                <StatCard
                  label="Suspicious IP Incidents"
                  value={summary?.suspicious_ip_incidents ?? 0}
                  sublabel="Threat intel hits"
                />
                <StatCard
                  label="Open Cases"
                  value={summary?.case_summary?.open_cases ?? 0}
                  sublabel="Analyst queue"
                />
              </div>
            </SectionCard>

            <SectionCard
              title="Quick Actions"
              subtitle="Fast access to core workflows"
            >
              <div className="action-grid">
                <ActionCard
                  title="Review Incidents"
                  text="Open the incident queue and inspect recent correlated chains."
                  buttonText="Open Incidents"
                  onClick={() => setActiveView("incidents")}
                />
                <ActionCard
                  title="Launch Packet Trace"
                  text="Jump straight into packet flow tracing for a source or destination IP."
                  buttonText="Open Tracer"
                  onClick={() => setActiveView("packets")}
                />
                <ActionCard
                  title="Run AI Analysis"
                  text="Use the AI analyst to produce investigation-ready notes."
                  buttonText="Open AI Analyst"
                  onClick={() => setActiveView("llm")}
                />
                <ActionCard
                  title="Run Port Scan"
                  text="Perform a bounded scan against a private/internal target you control."
                  buttonText="Open Scanner"
                  onClick={() => setActiveView("scanner")}
                />
              </div>
            </SectionCard>

            <SectionCard
              title="Recent Alert Activity"
              subtitle="Latest telemetry with one-click actions"
            >
              <div className="alert-strip">
                {recentAlerts.length === 0 ? (
                  <div className="empty-state">No recent alerts available.</div>
                ) : (
                  recentAlerts.map((event, idx) => (
                    <div key={idx} className="alert-row">
                      <div className="alert-left">
                        <div className="alert-title">
                          {event.event_type || "event"} — {event.host || "unknown host"}
                        </div>
                        <div className="alert-meta">
                          {event.timestamp || "N/A"} | {event.src_ip || "N/A"} →{" "}
                          {event.dest_ip || "N/A"} | user: {event.username || "N/A"}
                        </div>
                      </div>
                      <div className="alert-actions">
                        <button
                          className="action-btn secondary-btn"
                          onClick={() => quickTraceIp(event.src_ip)}
                        >
                          Trace Source
                        </button>
                        <button
                          className="action-btn secondary-btn"
                          onClick={() => quickScanIp(event.src_ip)}
                        >
                          Scan Source
                        </button>
                        <button
                          className="action-btn secondary-btn"
                          onClick={() => quickScanIp(event.dest_ip)}
                        >
                          Scan Dest
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </SectionCard>

            <SectionCard
              title="Analytics"
              subtitle="Risk and technique distribution"
            >
              <div className="content-grid">
                <div className="chart-wrap">
                  <h3 className="stack-title">Top MITRE Techniques</h3>
                  <ResponsiveContainer width="100%" height={280}>
                    <BarChart data={summary?.top_techniques || []}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.18)" />
                      <XAxis dataKey="technique" stroke="#9fb5d4" />
                      <YAxis stroke="#9fb5d4" />
                      <Tooltip />
                      <Bar dataKey="count" fill="#38bdf8" radius={[6, 6, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="chart-wrap">
                  <h3 className="stack-title">Risk Distribution</h3>
                  <ResponsiveContainer width="100%" height={280}>
                    <PieChart>
                      <Pie
                        data={severityData}
                        cx="50%"
                        cy="50%"
                        outerRadius={95}
                        dataKey="value"
                        nameKey="name"
                        label
                      >
                        {severityData.map((entry, index) => (
                          <Cell key={entry.name} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                        ))}
                      </Pie>
                      <Legend />
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </SectionCard>

            <SectionCard
              title="Operations Snapshot"
              subtitle="Latest incidents and active cases"
            >
              <div className="list-grid">
                <div className="stack-card">
                  <h3 className="stack-title">Latest Incidents</h3>
                  <div className="item-list">
                    {incidents.length === 0 ? (
                      <div className="empty-state">No incidents found.</div>
                    ) : (
                      incidents.slice(0, 5).map((incident) => (
                        <div key={incident.incident_id} className="item-card">
                          <h4>{incident.title}</h4>
                          <div className="item-meta">
                            Incident ID: {incident.incident_id}
                            <br />
                            Hosts: {(incident.hosts || []).join(", ") || "None"}
                            <br />
                            Max Risk: {incident.max_risk_score ?? 0}
                          </div>
                          <div className="item-actions">
                            <button className="action-btn" onClick={() => openIncident(incident)}>
                              Open
                            </button>
                            {(incident.suspicious_ips || [])[0] ? (
                              <button
                                className="action-btn secondary-btn"
                                onClick={() => quickTraceIp(incident.suspicious_ips[0])}
                              >
                                Trace IP
                              </button>
                            ) : null}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="stack-card">
                  <h3 className="stack-title">Open Cases</h3>
                  <div className="item-list">
                    {cases.length === 0 ? (
                      <div className="empty-state">No cases yet.</div>
                    ) : (
                      cases.slice(0, 5).map((item) => (
                        <div key={item.case_id} className="item-card">
                          <h4>{item.title}</h4>
                          <div className="item-meta">
                            Status: {item.status}
                            <br />
                            Priority: {item.priority}
                            <br />
                            Owner: {item.owner || "Unassigned"}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </SectionCard>
          </>
        )}

        {activeView === "incidents" && (
          <SectionCard title="Incidents" subtitle="Correlated attack chains and investigation context">
            <div className="list-grid incidents-grid">
              <div className="stack-card">
                <h3 className="stack-title">Incident Queue</h3>
                <div className="item-list">
                  {incidents.length === 0 ? (
                    <div className="empty-state">No incidents found.</div>
                  ) : (
                    incidents.map((incident) => (
                      <div key={incident.incident_id} className="item-card">
                        <h4>{incident.title}</h4>
                        <div className="item-meta">
                          Incident ID: {incident.incident_id}
                          <br />
                          Hosts: {(incident.hosts || []).join(", ") || "None"}
                          <br />
                          Users: {(incident.users || []).join(", ") || "None"}
                          <br />
                          Max Risk: {incident.max_risk_score ?? 0}
                        </div>
                        <div className="item-actions">
                          <button
                            className="action-btn"
                            onClick={() => setSelectedIncident(incident)}
                          >
                            Inspect
                          </button>
                          <button
                            className="action-btn secondary-btn"
                            onClick={() => {
                              setSelectedIncident(incident);
                              setTimeout(() => {
                                runLlmExplain();
                              }, 0);
                            }}
                          >
                            {llmLoading &&
                            selectedIncident?.incident_id === incident.incident_id
                              ? "Analyzing..."
                              : "AI Explain"}
                          </button>
                          {(incident.suspicious_ips || [])[0] ? (
                            <button
                              className="action-btn secondary-btn"
                              onClick={() => quickScanIp(incident.suspicious_ips[0])}
                            >
                              Scan IP
                            </button>
                          ) : null}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="detail-panel">
                <h3 className="stack-title">Incident Detail</h3>
                {!selectedIncident ? (
                  <div className="empty-state">Choose an incident from the queue.</div>
                ) : (
                  <>
                    <div className="item-meta">
                      <strong>{selectedIncident.title}</strong>
                      <br />
                      Incident ID: {selectedIncident.incident_id}
                      <br />
                      Hosts: {(selectedIncident.hosts || []).join(", ") || "None"}
                      <br />
                      Users: {(selectedIncident.users || []).join(", ") || "None"}
                      <br />
                      Suspicious IPs: {(selectedIncident.suspicious_ips || []).join(", ") || "None"}
                    </div>

                    <h4>Summary</h4>
                    <pre>{JSON.stringify(selectedIncident.summary, null, 2)}</pre>

                    <h4>Timeline</h4>
                    <pre>{JSON.stringify(selectedIncident.timeline, null, 2)}</pre>
                  </>
                )}
              </div>
            </div>
          </SectionCard>
        )}

        {activeView === "cases" && (
          <SectionCard title="Cases" subtitle="Analyst-tracked investigations">
            <div className="cases-wrap">
              <div className="item-list">
                {cases.length === 0 ? (
                  <div className="empty-state">No cases yet.</div>
                ) : (
                  cases.map((item) => (
                    <div key={item.case_id} className="item-card">
                      <h4>{item.title}</h4>
                      <div className="item-meta">
                        <span className="badge">Status: {item.status}</span>
                        <span className="badge">Priority: {item.priority}</span>
                        <span className="badge">Owner: {item.owner || "Unassigned"}</span>
                        <br />
                        Case ID: {item.case_id}
                        <br />
                        Incident ID: {item.incident_id}
                      </div>

                      {item.notes?.length ? (
                        <>
                          <h4 style={{ marginTop: 14 }}>Notes</h4>
                          <pre>{JSON.stringify(item.notes, null, 2)}</pre>
                        </>
                      ) : null}
                    </div>
                  ))
                )}
              </div>
            </div>
          </SectionCard>
        )}

        {activeView === "telemetry" && (
          <SectionCard title="Telemetry" subtitle="Latest ingested security events">
            <div className="telemetry-wrap">
              {telemetry.length === 0 ? (
                <div className="empty-state">No telemetry available.</div>
              ) : (
                <div className="detail-panel">
                  <table className="telemetry-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Type</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Host</th>
                        <th>User</th>
                      </tr>
                    </thead>
                    <tbody>
                      {telemetry.map((event, idx) => (
                        <tr key={idx}>
                          <td>{event.timestamp || "N/A"}</td>
                          <td>{event.event_type || "N/A"}</td>
                          <td>{event.src_ip || "N/A"}</td>
                          <td>{event.dest_ip || "N/A"}</td>
                          <td>{event.host || "N/A"}</td>
                          <td>{event.username || "N/A"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </SectionCard>
        )}

        {activeView === "packets" && (
          <SectionCard title="Packet Tracer" subtitle="Trace traffic flows for a source or destination IP">
            <div className="trace-row">
              <div className="trace-box">
                <div className="trace-controls">
                  <input
                    className="trace-input"
                    value={traceInput}
                    onChange={(e) => setTraceInput(e.target.value)}
                    placeholder="Enter IP address to trace, or leave blank to show all flows"
                  />
                  <button className="action-btn" onClick={runTrace}>
                    Trace
                  </button>
                  <button className="action-btn secondary-btn" onClick={showAllFlows}>
                    Show All
                  </button>
                </div>

                {visibleFlows.length === 0 ? (
                  <div className="empty-state">Run a trace to view packet flows.</div>
                ) : (
                  visibleFlows.slice(0, 60).map((flow, idx) => (
                    <div
                      key={`${flow.src_ip}-${flow.dest_ip}-${idx}`}
                      className="flow-card"
                    >
                      <div className="flow-main">
                        {flow.src_ip || "unknown"} → {flow.dest_ip || "unknown"}
                      </div>
                      <div className="flow-sub">
                        Protocol: {flow.proto || "UNKNOWN"} | Src Port:{" "}
                        {flow.src_port ?? "N/A"} | Dest Port: {flow.dest_port ?? "N/A"}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </SectionCard>
        )}

        {activeView === "llm" && (
          <SectionCard title="AI Analyst" subtitle="Structured incident notes and triage guidance">
            <div className="detail-grid">
              <div className="detail-panel">
                <h3 className="stack-title">Selected Incident</h3>
                {!selectedIncident ? (
                  <div className="empty-state">Select an incident from the Incidents view first.</div>
                ) : (
                  <>
                    <div className="item-meta">
                      <strong>{selectedIncident.title}</strong>
                      <br />
                      Incident ID: {selectedIncident.incident_id}
                      <br />
                      Max Risk: {selectedIncident.max_risk_score}
                      <br />
                      Hosts: {(selectedIncident.hosts || []).join(", ") || "None"}
                      <br />
                      Users: {(selectedIncident.users || []).join(", ") || "None"}
                    </div>
                    <div className="item-actions">
                      <button className="action-btn" onClick={runLlmExplain}>
                        {llmLoading ? "Analyzing..." : "Run AI Analysis"}
                      </button>
                    </div>
                  </>
                )}
              </div>

              <div className="detail-panel">
                <h3 className="stack-title">Analyst Output</h3>
                {!llmOutput ? (
                  <div className="empty-state">No AI analysis yet.</div>
                ) : (
                  <div className="item-meta">
                    <div style={{ marginBottom: 16 }}>
                      <strong>Executive Summary</strong>
                      <div style={{ marginTop: 8 }}>
                        {llmOutput.executive_summary || "N/A"}
                      </div>
                    </div>

                    <div style={{ marginBottom: 16 }}>
                      <strong>Attack Stage</strong>
                      <div style={{ marginTop: 8 }}>
                        {llmOutput.likely_attack_stage || "Unknown"} | Confidence:{" "}
                        {llmOutput.confidence ?? 0}%
                      </div>
                    </div>

                    <div style={{ marginBottom: 16 }}>
                      <strong>Analyst Notes</strong>
                      <ul>
                        {(llmOutput.analyst_notes || []).map((note, idx) => (
                          <li key={idx}>{note}</li>
                        ))}
                      </ul>
                    </div>

                    <div style={{ marginBottom: 16 }}>
                      <strong>Affected Assets</strong>
                      <div style={{ marginTop: 8 }}>
                        {(llmOutput.affected_assets || []).join(", ") || "None"}
                      </div>
                    </div>

                    <div style={{ marginBottom: 16 }}>
                      <strong>Affected Users</strong>
                      <div style={{ marginTop: 8 }}>
                        {(llmOutput.affected_users || []).join(", ") || "None"}
                      </div>
                    </div>

                    <div style={{ marginBottom: 16 }}>
                      <strong>Suspicious Indicators</strong>
                      <div style={{ marginTop: 8 }}>
                        {(llmOutput.suspicious_indicators || []).join(", ") || "None"}
                      </div>
                    </div>

                    <div style={{ marginBottom: 16 }}>
                      <strong>Top Risks</strong>
                      <ul>
                        {(llmOutput.top_risks || []).map((risk, idx) => (
                          <li key={idx}>{risk}</li>
                        ))}
                      </ul>
                    </div>

                    <div style={{ marginBottom: 16 }}>
                      <strong>Recommended Actions</strong>
                      <ul>
                        {(llmOutput.recommended_actions || []).map((action, idx) => (
                          <li key={idx}>{action}</li>
                        ))}
                      </ul>
                    </div>

                    <div style={{ marginBottom: 16 }}>
                      <strong>Containment Steps</strong>
                      <ul>
                        {(llmOutput.containment_steps || []).map((step, idx) => (
                          <li key={idx}>{step}</li>
                        ))}
                      </ul>
                    </div>

                    <div>
                      <strong>Mode</strong>
                      <div style={{ marginTop: 8 }}>{llmOutput.llm_mode || "unknown"}</div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </SectionCard>
        )}

        {activeView === "scanner" && (
          <SectionCard title="Port Scanner" subtitle="Defensive scanning for private/internal targets you control">
            <div className="trace-row">
              <div className="trace-box">
                <div className="trace-controls">
                  <input
                    className="trace-input"
                    value={scanTarget}
                    onChange={(e) => setScanTarget(e.target.value)}
                    placeholder="Target IP, e.g. 192.168.1.1"
                  />
                  <input
                    className="trace-input"
                    value={scanPorts}
                    onChange={(e) => setScanPorts(e.target.value)}
                    placeholder="Ports, e.g. 22,80,443"
                  />
                  <button className="action-btn" onClick={runScan}>
                    {scanLoading ? "Scanning..." : "Run Scan"}
                  </button>
                </div>

                {!scanResults ? (
                  <div className="empty-state">No scan run yet.</div>
                ) : (
                  <>
                    <div className="item-meta" style={{ marginBottom: 16 }}>
                      <strong>Target:</strong> {scanResults.target}
                      <br />
                      <strong>Open Ports Found:</strong>{" "}
                      {scanResults.open_ports?.length || 0}
                    </div>

                    {(scanResults.open_ports || []).length === 0 ? (
                      <div className="empty-state">No open ports found in the scanned set.</div>
                    ) : (
                      scanResults.open_ports.map((portObj) => (
                        <div key={portObj.port} className="flow-card">
                          <div className="flow-main">Port {portObj.port} is open</div>
                          <div className="flow-sub">
                            Banner: {portObj.banner || "No banner captured"}
                          </div>
                        </div>
                      ))
                    )}
                  </>
                )}
              </div>
            </div>
          </SectionCard>
        )}

        {activeView === "status" && (
          <SectionCard title="System Status" subtitle="Operational state of the platform">
            <div className="stats-grid">
              <StatCard label="Frontend" value="ONLINE" sublabel="React / Vite UI" />
              <StatCard label="FastAPI Backend" value="ONLINE" sublabel="API responding" />
              <StatCard
                label="Incident Objects"
                value={summary?.total_incidents ?? 0}
                sublabel="Correlated incidents"
              />
              <StatCard
                label="Open Cases"
                value={summary?.case_summary?.open_cases ?? 0}
                sublabel="Active investigations"
              />
            </div>
          </SectionCard>
        )}
      </main>
    </div>
  );
}
