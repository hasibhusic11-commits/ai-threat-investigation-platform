import React, { useMemo } from "react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";

function buildPulseSeries(telemetry = []) {
  const buckets = Array.from({ length: 8 }, (_, i) => ({
    label: `T${i + 1}`,
    value: 0,
  }));

  telemetry.slice(0, 24).forEach((event, idx) => {
    const bucketIndex = idx % 8;
    const weight =
      event.event_type === "alert" ? 5 :
      event.event_type === "authentication" ? 3 :
      event.event_type === "dns" ? 2 :
      event.event_type === "flow" ? 2 : 1;
    buckets[bucketIndex].value += weight;
  });

  return buckets.map((b, idx) => ({
    ...b,
    value: b.value || (idx % 2 === 0 ? 1 : 2),
  }));
}

export default function ThreatPulse({ telemetry = [], summary = null }) {
  const pulseData = useMemo(() => buildPulseSeries(telemetry), [telemetry]);

  const openCases = summary?.case_summary?.open_cases ?? 0;
  const highRisk = summary?.high_risk_incidents ?? 0;
  const suspicious = summary?.suspicious_ip_incidents ?? 0;
  const recentEvents = telemetry.length;

  return (
    <div className="hero-card ops-pulse-card">
      <div className="pulse-topline">
        <div>
          <h3>Operations Pulse</h3>
          <p>Live SOC posture based on current platform telemetry</p>
        </div>
        <div className="pulse-status-pill">LIVE</div>
      </div>

      <div className="pulse-metrics-grid">
        <div className="pulse-metric">
          <span className="pulse-metric-label">Recent Events</span>
          <strong>{recentEvents}</strong>
        </div>
        <div className="pulse-metric">
          <span className="pulse-metric-label">High Risk</span>
          <strong>{highRisk}</strong>
        </div>
        <div className="pulse-metric">
          <span className="pulse-metric-label">Suspicious IPs</span>
          <strong>{suspicious}</strong>
        </div>
        <div className="pulse-metric">
          <span className="pulse-metric-label">Open Cases</span>
          <strong>{openCases}</strong>
        </div>
      </div>

      <div className="pulse-wrap">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={pulseData}>
            <defs>
              <linearGradient id="opsPulseFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.45} />
                <stop offset="100%" stopColor="#22d3ee" stopOpacity={0.03} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(125,211,252,0.08)" />
            <XAxis dataKey="label" stroke="#7dd3fc" />
            <YAxis stroke="#7dd3fc" />
            <Tooltip />
            <Area
              type="monotone"
              dataKey="value"
              stroke="#22d3ee"
              strokeWidth={3}
              fill="url(#opsPulseFill)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="pulse-notes">
        <div className="pulse-note">
          <span className="pulse-note-label">Current Priority</span>
          <span className="pulse-note-value">
            {highRisk > 0 ? "High-risk investigation queue active" : "No high-risk cluster detected"}
          </span>
        </div>
        <div className="pulse-note">
          <span className="pulse-note-label">Ingest State</span>
          <span className="pulse-note-value">
            {recentEvents > 0 ? "Telemetry stream present" : "No recent telemetry returned"}
          </span>
        </div>
      </div>
    </div>
  );
}
