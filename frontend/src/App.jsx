import { useEffect, useMemo, useState } from "react";
import api from "./api";
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

function getRiskLabel(score) {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

function RiskBadge({ score }) {
  const label = getRiskLabel(score ?? 0);
  return <span className={`risk-badge ${label}`}>{label.toUpperCase()}</span>;
}

function StatusPill({ status }) {
  return <span className={`status-pill ${status || "open"}`}>{status || "open"}</span>;
}

function Sidebar({ activeView, setActiveView }) {
  const items = [
    { key: "dashboard", label: "Dashboard" },
    { key: "incidents", label: "Incidents" },
    { key: "cases", label: "Cases" },
    { key: "search", label: "Search" },
    { key: "packet_tracer", label: "Packet Tracer" },
    { key: "status", label: "System Status" },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-tag">SOC PLATFORM</div>
        <h1>Threat Engine</h1>
      </div>

      <nav className="sidebar-nav">
        {items.map((item) => (
          <button
            key={item.key}
            className={`nav-btn ${activeView === item.key ? "active" : ""}`}
            onClick={() => setActiveView(item.key)}
          >
            {item.label}
          </button>
        ))}
      </nav>
    </aside>
  );
}

function Header({ onRefresh }) {
  return (
    <header className="header">
      <div>
        <div className="eyebrow">AI-ASSISTED SECURITY OPERATIONS</div>
        <h2>AI Threat Investigation Platform</h2>
      </div>
      <button onClick={onRefresh}>Refresh Data</button>
    </header>
  );
}

function SummaryCard({ title, value, sublabel }) {
  return (
    <div className="summary-card">
      <div className="summary-title">{title}</div>
      <div className="summary-value">{value}</div>
      {sublabel ? <div className="summary-sublabel">{sublabel}</div> : null}
    </div>
  );
}

function SectionTitle({ title, subtitle }) {
  return (
    <div className="section-title">
      <h3>{title}</h3>
      {subtitle ? <p>{subtitle}</p> : null}
    </div>
  );
}

function DashboardView({ summary, incidents, cases, telemetry, onSelectIncident, onSelectCase }) {
  const latestIncidents = incidents.slice(0, 5);
  const latestCases = cases.slice(0, 5);

  return (
    <div className="dashboard-stack">
      <div className="panel">
        <SectionTitle title="Overview" subtitle="High-level platform metrics" />
        <div className="summary-grid">
          <SummaryCard title="Total Incidents" value={summary?.total_incidents ?? "-"} sublabel="Correlated chains" />
          <SummaryCard title="High Risk" value={summary?.high_risk_incidents ?? "-"} sublabel="Risk score ≥ 50" />
          <SummaryCard title="Suspicious IP Incidents" value={summary?.suspicious_ip_incidents ?? "-"} sublabel="Threat intel hits" />
          <SummaryCard title="Open Cases" value={summary?.case_summary?.open_cases ?? "-"} sublabel="Analyst queue" />
        </div>
      </div>

      <div className="chart-grid">
        <div className="panel chart-panel">
          <SectionTitle title="Top MITRE Techniques" subtitle="Most frequent ATT&CK mappings" />
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={summary?.top_techniques || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="technique" stroke="#cbd5e1" />
                <YAxis stroke="#cbd5e1" />
                <Tooltip />
                <Bar dataKey="count" fill="#3b82f6" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel chart-panel">
          <SectionTitle title="Risk Distribution" subtitle="Incident severity spread" />
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={summary?.risk_distribution || []}
                  dataKey="value"
                  nameKey="name"
                  outerRadius={100}
                  innerRadius={55}
                >
                  {(summary?.risk_distribution || []).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel chart-panel">
          <SectionTitle title="Incidents by Host" subtitle="Hosts with the most incident activity" />
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={summary?.incidents_by_host || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="host" stroke="#cbd5e1" />
                <YAxis stroke="#cbd5e1" />
                <Tooltip />
                <Bar dataKey="count" fill="#14b8a6" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel chart-panel">
          <SectionTitle title="Live Telemetry" subtitle="Recent ingestion and sensor activity" />
          <div className="telemetry-status-grid">
            <div className="telemetry-stat">
              <span className="telemetry-label">Total Events</span>
              <span className="telemetry-value">{telemetry?.total_events ?? 0}</span>
            </div>
            <div className="telemetry-stat">
              <span className="telemetry-label">Last 5 Minutes</span>
              <span className="telemetry-value">{telemetry?.events_last_5_minutes ?? 0}</span>
            </div>
            <div className="telemetry-stat">
              <span className="telemetry-label">Suricata File</span>
              <span className={`telemetry-value ${telemetry?.suricata_eve_exists ? "ok" : "bad"}`}>
                {telemetry?.suricata_eve_exists ? "READY" : "MISSING"}
              </span>
            </div>
            <div className="telemetry-stat">
              <span className="telemetry-label">Latest Event</span>
              <span className="telemetry-small">
                {telemetry?.latest_event_timestamp || "No live events yet"}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="two-panel-grid">
        <div className="panel">
          <SectionTitle title="Latest Incidents" subtitle="Click an incident to inspect details" />
          <div className="table-list">
            {latestIncidents.map((incident) => (
              <div key={incident.incident_id} className="table-row clickable compact-row" onClick={() => onSelectIncident(incident.incident_id)}>
                <div>
                  <div className="row-title">{incident.title}</div>
                  <div className="row-subtitle">{incident.incident_id}</div>
                </div>
                <div>{incident.hosts?.join(", ") || "N/A"}</div>
                <div>{incident.event_count}</div>
                <div><RiskBadge score={incident.max_risk_score} /></div>
              </div>
            ))}
          </div>
        </div>

        <div className="panel">
          <SectionTitle title="Latest Cases" subtitle="Most recently created investigation cases" />
          <div className="table-list">
            {latestCases.map((c) => (
              <div key={c.case_id} className="table-row clickable compact-row" onClick={() => onSelectCase(c.case_id)}>
                <div>
                  <div className="row-title">{c.title}</div>
                  <div className="row-subtitle">{c.case_id}</div>
                </div>
                <div>{c.priority}</div>
                <div><StatusPill status={c.status} /></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function IncidentsView({ incidents, filters, setFilters, onSelectIncident, onCreateCase, selectedIncidentId }) {
  const filtered = incidents.filter((incident) => {
    const matchesHost =
      !filters.host || incident.hosts?.some((h) => h.toLowerCase().includes(filters.host.toLowerCase()));
    const matchesMinRisk = !filters.minRisk || (incident.max_risk_score ?? 0) >= Number(filters.minRisk);
    return matchesHost && matchesMinRisk;
  });

  return (
    <div className="panel">
      <SectionTitle title="Incidents" subtitle="Structured incident list for investigation" />

      <div className="filter-bar">
        <input
          type="text"
          placeholder="Filter by host"
          value={filters.host}
          onChange={(e) => setFilters((prev) => ({ ...prev, host: e.target.value }))}
        />
        <input
          type="number"
          placeholder="Min risk"
          value={filters.minRisk}
          onChange={(e) => setFilters((prev) => ({ ...prev, minRisk: e.target.value }))}
        />
      </div>

      <div className="table-header">
        <div>Incident</div>
        <div>Hosts</div>
        <div>Events</div>
        <div>Risk</div>
        <div>Actions</div>
      </div>

      <div className="table-list">
        {filtered.map((incident) => (
          <div
            key={incident.incident_id}
            className={`table-row ${selectedIncidentId === incident.incident_id ? "selected-row" : ""}`}
          >
            <div>
              <div className="row-title">{incident.title}</div>
              <div className="row-subtitle">{incident.incident_id}</div>
            </div>
            <div>{incident.hosts?.join(", ") || "N/A"}</div>
            <div>{incident.event_count}</div>
            <div><RiskBadge score={incident.max_risk_score} /></div>
            <div className="row-actions">
              <button className="secondary-btn" onClick={() => onSelectIncident(incident.incident_id)}>Open</button>
              <button onClick={() => onCreateCase(incident.incident_id)}>Case</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function CasesView({ cases, onSelectCase }) {
  return (
    <div className="panel">
      <SectionTitle title="Cases" subtitle="Case management and analyst workflow" />
      <div className="table-header">
        <div>Case</div>
        <div>Incident</div>
        <div>Priority</div>
        <div>Status</div>
      </div>

      <div className="table-list">
        {cases.map((c) => (
          <div key={c.case_id} className="table-row clickable" onClick={() => onSelectCase(c.case_id)}>
            <div>
              <div className="row-title">{c.title}</div>
              <div className="row-subtitle">{c.case_id}</div>
            </div>
            <div>{c.incident_id}</div>
            <div>{c.priority}</div>
            <div><StatusPill status={c.status} /></div>
          </div>
        ))}
      </div>
    </div>
  );
}

function CaseDetail({ selectedCase, onRefreshCases }) {
  const [noteText, setNoteText] = useState("");
  const [ownerText, setOwnerText] = useState("");

  if (!selectedCase) {
    return (
      <div className="panel detail-panel">
        <SectionTitle title="Case Detail" subtitle="Select a case to inspect and update it" />
        <div className="empty-state">No case selected.</div>
      </div>
    );
  }

  async function updateStatus(status) {
    await api.post(`/cases/${selectedCase.case_id}/status`, { status });
    onRefreshCases();
  }

  async function updateOwner() {
    await api.post(`/cases/${selectedCase.case_id}/owner`, { owner: ownerText || null });
    setOwnerText("");
    onRefreshCases();
  }

  async function updatePriority(priority) {
    await api.post(`/cases/${selectedCase.case_id}/priority`, { priority });
    onRefreshCases();
  }

  async function addNote() {
    if (!noteText.trim()) return;
    await api.post(`/cases/${selectedCase.case_id}/notes`, {
      note: noteText,
      author: "Hasib",
    });
    setNoteText("");
    onRefreshCases();
  }

  return (
    <div className="panel detail-panel">
      <SectionTitle title="Case Detail" subtitle="Update status, owner, priority, and notes" />

      <div className="detail-top">
        <div>
          <div className="detail-title">{selectedCase.title}</div>
          <div className="detail-subtitle">{selectedCase.case_id}</div>
        </div>
        <StatusPill status={selectedCase.status} />
      </div>

      <div className="detail-metrics">
        <div><strong>Incident:</strong> {selectedCase.incident_id}</div>
        <div><strong>Priority:</strong> {selectedCase.priority}</div>
        <div><strong>Owner:</strong> {selectedCase.owner || "Unassigned"}</div>
        <div><strong>Updated:</strong> {selectedCase.updated_at}</div>
      </div>

      <div className="detail-block">
        <div className="detail-block-title">Case Actions</div>
        <div className="detail-text-block">
          <div className="action-row">
            <button onClick={() => updateStatus("open")}>Open</button>
            <button onClick={() => updateStatus("triaged")}>Triaged</button>
            <button onClick={() => updateStatus("closed")}>Closed</button>
          </div>

          <div className="action-row">
            <button onClick={() => updatePriority("low")}>Low</button>
            <button onClick={() => updatePriority("medium")}>Medium</button>
            <button onClick={() => updatePriority("high")}>High</button>
            <button onClick={() => updatePriority("critical")}>Critical</button>
          </div>

          <div className="action-row">
            <input
              type="text"
              placeholder="Assign owner"
              value={ownerText}
              onChange={(e) => setOwnerText(e.target.value)}
            />
            <button onClick={updateOwner}>Assign</button>
          </div>
        </div>
      </div>

      <div className="detail-block">
        <div className="detail-block-title">Notes</div>
        <div className="detail-text-block">
          <div className="action-row">
            <input
              type="text"
              placeholder="Add case note"
              value={noteText}
              onChange={(e) => setNoteText(e.target.value)}
            />
            <button onClick={addNote}>Add Note</button>
          </div>

          <div className="note-list">
            {(selectedCase.notes || []).length === 0 ? (
              <div className="empty-note">No notes yet.</div>
            ) : (
              selectedCase.notes.map((note, idx) => (
                <div key={idx} className="note-card">
                  <div className="note-meta">
                    <strong>{note.author || "Unknown"}</strong> · {note.timestamp}
                  </div>
                  <div>{note.note}</div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function SearchView() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);

  async function runSearch() {
    if (!query.trim()) return;
    const response = await api.get("/search", { params: { query, limit: 8 } });
    setResults(response.data.results || []);
  }

  return (
    <div className="panel">
      <SectionTitle title="Threat Search" subtitle="Search security telemetry semantically" />
      <div className="search-toolbar">
        <input
          type="text"
          placeholder="Search events, hosts, behaviors, or MITRE techniques..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button onClick={runSearch}>Search</button>
      </div>

      <div className="table-header">
        <div>Event</div>
        <div>Host</div>
        <div>Vector Score</div>
        <div>Risk</div>
      </div>

      <div className="table-list">
        {results.map((r, idx) => (
          <div key={idx} className="table-row">
            <div>
              <div className="row-title">{r.payload?.event_text}</div>
              <div className="row-subtitle">{r.payload?.source}</div>
            </div>
            <div>{r.payload?.host || "N/A"}</div>
            <div>{r.score?.toFixed(4)}</div>
            <div><RiskBadge score={r.payload?.risk_score || 0} /></div>
          </div>
        ))}
      </div>
    </div>
  );
}

function PacketTracerView() {
  const [ip, setIp] = useState("");
  const [flows, setFlows] = useState([]);
  const [allFlows, setAllFlows] = useState([]);
  const [loading, setLoading] = useState(false);

  async function loadAllFlows() {
    setLoading(true);
    try {
      const response = await api.get("/packets/flows");
      setAllFlows(response.data.flows || []);
    } finally {
      setLoading(false);
    }
  }

  async function runTrace() {
    if (!ip.trim()) {
      await loadAllFlows();
      setFlows([]);
      return;
    }

    setLoading(true);
    try {
      const response = await api.get(`/packets/trace/${ip}`);
      setFlows(response.data.flows || []);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAllFlows();
    const interval = setInterval(loadAllFlows, 5000);
    return () => clearInterval(interval);
  }, []);

  const displayFlows = ip.trim() ? flows : allFlows;

  return (
    <div className="panel">
      <SectionTitle
        title="Packet Tracer"
        subtitle="Trace recorded network flows from ingested telemetry. Leave the field blank to view all flows."
      />

      <div className="search-toolbar">
        <input
          type="text"
          placeholder="Enter IP address to trace, or leave blank to show all flows"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
        />
        <button onClick={runTrace}>Trace</button>
        <button
          className="secondary-btn"
          onClick={() => {
            setIp("");
            setFlows([]);
            loadAllFlows();
          }}
        >
          Show All
        </button>
      </div>

      {loading ? (
        <div className="empty-state">Loading packet flows...</div>
      ) : displayFlows.length === 0 ? (
        <div className="empty-state">
          No flows found. Your platform needs real Suricata telemetry for this to populate.
        </div>
      ) : (
        <div className="trace-list">
          {displayFlows.map((flow, idx) => (
            <div key={idx} className="trace-card">
              <div className="trace-header">
                <div className="trace-title">
                  {flow.src_ip} → {flow.dest_ip}
                </div>
                <RiskBadge score={flow.max_risk_score || 0} />
              </div>

              <div className="trace-subtitle">
                {flow.event_count} related event{flow.event_count === 1 ? "" : "s"}
              </div>

              <div className="trace-timeline">
                {flow.timeline.map((event, i) => (
                  <div key={i} className="trace-event">
                    <div className="trace-time">{event.timestamp}</div>
                    <div className="trace-text">
                      <div className="trace-event-title">{event.event_text}</div>
                      <div className="trace-event-meta">
                        {event.source} · {event.host || "N/A"} · {event.event_type || "N/A"}
                      </div>
                    </div>
                    <div className="trace-risk">Risk {event.risk_score ?? 0}</div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function StatusView({ summary, telemetry, recentEvents }) {
  return (
    <div className="dashboard-stack">
      <div className="panel">
        <SectionTitle title="System Status" subtitle="Operational state of the platform" />

        <div className="status-grid">
          <div className="status-card">
            <div className="status-label">Frontend</div>
            <div className="status-value ok">ONLINE</div>
          </div>
          <div className="status-card">
            <div className="status-label">FastAPI Backend</div>
            <div className="status-value ok">ONLINE</div>
          </div>
          <div className="status-card">
            <div className="status-label">Incident Objects</div>
            <div className="status-value">{summary?.total_incidents ?? 0}</div>
          </div>
          <div className="status-card">
            <div className="status-label">Open Cases</div>
            <div className="status-value">{summary?.case_summary?.open_cases ?? 0}</div>
          </div>
        </div>
      </div>

      <div className="panel">
        <SectionTitle title="Live Telemetry Feed" subtitle="Most recent ingested events" />
        <div className="telemetry-feed">
          {recentEvents.map((event, idx) => (
            <div key={idx} className="feed-row">
              <div className="feed-time">{event.timestamp}</div>
              <div className="feed-main">
                <div className="row-title">{event.event_text}</div>
                <div className="row-subtitle">
                  {event.source} · {event.host || "N/A"} · {event.src_ip || "N/A"} → {event.dest_ip || "N/A"}
                </div>
              </div>
              <RiskBadge score={event.risk_score || 0} />
            </div>
          ))}
        </div>

        <div className="telemetry-status-grid">
          <div className="telemetry-stat">
            <span className="telemetry-label">Total Events</span>
            <span className="telemetry-value">{telemetry?.total_events ?? 0}</span>
          </div>
          <div className="telemetry-stat">
            <span className="telemetry-label">Events Last 5 Minutes</span>
            <span className="telemetry-value">{telemetry?.events_last_5_minutes ?? 0}</span>
          </div>
          <div className="telemetry-stat">
            <span className="telemetry-label">Suricata File</span>
            <span className={`telemetry-value ${telemetry?.suricata_eve_exists ? "ok" : "bad"}`}>
              {telemetry?.suricata_eve_exists ? "READY" : "MISSING"}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

function IncidentDetail({ incident }) {
  if (!incident) {
    return (
      <div className="panel detail-panel">
        <SectionTitle title="Incident Detail" subtitle="Select an incident from the list to inspect it" />
        <div className="empty-state">No incident selected.</div>
      </div>
    );
  }

  return (
    <div className="panel detail-panel">
      <SectionTitle title="Incident Detail" subtitle="Summary, context, and timeline" />

      <div className="detail-top">
        <div>
          <div className="detail-title">{incident.title}</div>
          <div className="detail-subtitle">{incident.incident_id}</div>
        </div>
        <RiskBadge score={incident.max_risk_score} />
      </div>

      <div className="detail-metrics">
        <div><strong>Hosts:</strong> {incident.hosts?.join(", ") || "N/A"}</div>
        <div><strong>Users:</strong> {incident.users?.join(", ") || "N/A"}</div>
        <div><strong>Events:</strong> {incident.event_count}</div>
        <div><strong>Suspicious IPs:</strong> {incident.suspicious_ips?.join(", ") || "None"}</div>
      </div>

      <div className="detail-block">
        <div className="detail-block-title">Summary</div>
        <div className="detail-text-block">
          <p><strong>Summary:</strong> {incident.summary?.summary}</p>
          <p><strong>Why Suspicious:</strong> {incident.summary?.why_suspicious}</p>
          <p><strong>Likely Progression:</strong> {incident.summary?.likely_progression}</p>
        </div>
      </div>

      <div className="detail-block">
        <div className="detail-block-title">Timeline</div>
        <div className="timeline-list">
          {(incident.timeline || []).map((event, idx) => (
            <div key={idx} className="timeline-row">
              <div className="timeline-time">{event.timestamp}</div>
              <div className="timeline-main">
                <div className="timeline-header-row">
                  <div className="timeline-type">{event.event_type}</div>
                  <RiskBadge score={event.risk_score} />
                </div>
                <div className="timeline-event-text">{event.event_text}</div>
                <div className="timeline-meta">
                  Host: {event.host || "N/A"} · User: {event.username || "N/A"} · Src: {event.src_ip || "N/A"} · Dst: {event.dest_ip || "N/A"}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function EmptyNotice({ message }) {
  return <div className="notice-banner">{message}</div>;
}

export default function App() {
    useEffect(() => {
    ensureApiKey();
  }, []); 
  const [activeView, setActiveView] = useState("dashboard");
  const [summary, setSummary] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [cases, setCases] = useState([]);
  const [telemetry, setTelemetry] = useState(null);
  const [recentEvents, setRecentEvents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [selectedCase, setSelectedCase] = useState(null);
  const [loading, setLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState("");
  const [filters, setFilters] = useState({ host: "", minRisk: "" });

  async function loadSummary() {
    const response = await api.get("/dashboard/summary");
    setSummary(response.data);
  }

  async function loadIncidents() {
    const response = await api.get("/incidents");
    setIncidents(response.data.incidents || []);
  }

  async function loadCases() {
    const response = await api.get("/cases");
    setCases(response.data.cases || []);
  }

  async function loadTelemetry() {
    const [statusResponse, recentResponse] = await Promise.all([
      api.get("/status/live"),
      api.get("/telemetry/recent", { params: { limit: 10 } }),
    ]);
    setTelemetry(statusResponse.data);
    setRecentEvents(recentResponse.data.events || []);
  }

  async function loadIncidentDetail(incidentId) {
    const response = await api.get(`/incidents/${incidentId}`);
    setSelectedIncident(response.data);
    setSelectedCase(null);
  }

  async function loadCaseDetail(caseId) {
    const response = await api.get(`/cases/${caseId}`);
    setSelectedCase(response.data);
    setSelectedIncident(null);
    setActiveView("cases");
  }

  async function createCase(incidentId) {
    await api.post("/cases", {
      incident_id: incidentId,
      priority: "high",
    });
    await loadCases();
  }

  async function loadAll() {
    setLoading(true);
    setErrorMessage("");

    try {
      await Promise.all([loadSummary(), loadIncidents(), loadCases(), loadTelemetry()]);
    } catch (err) {
      console.error(err);
      setErrorMessage(err?.message || "Could not load data from backend.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAll();
    const interval = setInterval(loadAll, 10000);
    return () => clearInterval(interval);
  }, []);

  const currentView = useMemo(() => {
    if (activeView === "dashboard") {
      return (
        <DashboardView
          summary={summary}
          incidents={incidents}
          cases={cases}
          telemetry={telemetry}
          onSelectIncident={loadIncidentDetail}
          onSelectCase={loadCaseDetail}
        />
      );
    }

    if (activeView === "incidents") {
      return (
        <IncidentsView
          incidents={incidents}
          filters={filters}
          setFilters={setFilters}
          onSelectIncident={loadIncidentDetail}
          onCreateCase={createCase}
          selectedIncidentId={selectedIncident?.incident_id}
        />
      );
    }

    if (activeView === "cases") {
      return <CasesView cases={cases} onSelectCase={loadCaseDetail} />;
    }

    if (activeView === "search") {
      return <SearchView />;
    }

    if (activeView === "packet_tracer") {
      return <PacketTracerView />;
    }

    if (activeView === "status") {
      return <StatusView summary={summary} telemetry={telemetry} recentEvents={recentEvents} />;
    }

    return null;
  }, [activeView, summary, incidents, cases, telemetry, recentEvents, selectedIncident, filters]);

  return (
    <div className="soc-layout">
      <Sidebar activeView={activeView} setActiveView={setActiveView} />

      <div className="main-shell">
        <Header onRefresh={loadAll} />

        <div className="content-shell">
          {errorMessage ? <EmptyNotice message={errorMessage} /> : null}

          {loading ? (
            <div className="loading-state">Loading platform data...</div>
          ) : (
            <div className="content-grid">
              <div className="primary-column">{currentView}</div>
              <div className="secondary-column">
                {activeView === "cases" ? (
                  <CaseDetail selectedCase={selectedCase} onRefreshCases={loadCases} />
                ) : (
                  <IncidentDetail incident={selectedIncident} />
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
