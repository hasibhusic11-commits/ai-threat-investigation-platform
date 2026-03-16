import React, { useMemo } from "react";

const REGION_COLORS = {
  low: "#22c55e",
  medium: "#facc15",
  high: "#f97316",
  critical: "#ef4444",
};

function buildHotZones(summary, incidents) {
  const total = summary?.total_incidents || incidents.length || 1;
  const high = summary?.high_risk_incidents || 0;
  const suspicious = summary?.suspicious_ip_incidents || 0;

  const zones = [
    { name: "North America", x: 140, y: 110, score: 24 + total * 2 + suspicious * 3 },
    { name: "Western Europe", x: 315, y: 96, score: 20 + high * 4 + total * 1.5 },
    { name: "Eastern Europe", x: 365, y: 92, score: 24 + high * 4 + suspicious * 4 },
    { name: "Middle East", x: 390, y: 132, score: 18 + high * 3 + suspicious * 3 },
    { name: "South Asia", x: 455, y: 142, score: 18 + suspicious * 3 + total * 2 },
    { name: "East Asia", x: 540, y: 118, score: 18 + high * 3 + suspicious * 3 },
    { name: "South America", x: 205, y: 208, score: 14 + total * 1.5 + suspicious * 2 },
    { name: "Africa", x: 350, y: 185, score: 14 + total * 1.5 + high * 1.5 },
  ].map((z) => {
    const score = Math.min(95, Math.round(z.score));
    let level = "low";
    if (score >= 75) level = "critical";
    else if (score >= 55) level = "high";
    else if (score >= 35) level = "medium";
    return { ...z, score, level };
  });

  return zones;
}

export default function ThreatMap({ summary, incidents }) {
  const hotZones = useMemo(() => buildHotZones(summary, incidents), [summary, incidents]);

  return (
    <div className="map-card refined-map-card">
      <div className="map-header-row">
        <div>
          <h3 className="stack-title">Global Hot Zones</h3>
          <p className="map-subtitle">Risk-weighted view from current platform activity</p>
        </div>
        <div className="map-legend">
          <span><i className="legend-dot low" />Low</span>
          <span><i className="legend-dot medium" />Medium</span>
          <span><i className="legend-dot high" />High</span>
          <span><i className="legend-dot critical" />Critical</span>
        </div>
      </div>

      <div className="map-frame">
        <svg
          className="map-svg clean-map-svg"
          viewBox="0 0 640 320"
          preserveAspectRatio="xMidYMid meet"
          xmlns="http://www.w3.org/2000/svg"
        >
          <rect x="0" y="0" width="640" height="320" rx="20" fill="#051120" />

          <g stroke="rgba(96,165,250,0.09)" strokeWidth="1">
            {[...Array(13)].map((_, i) => (
              <line key={`v-${i}`} x1={i * 53} y1="0" x2={i * 53} y2="320" />
            ))}
            {[...Array(7)].map((_, i) => (
              <line key={`h-${i}`} x1="0" y1={i * 53} x2="640" y2={i * 53} />
            ))}
          </g>

          <g fill="rgba(56,189,248,0.16)" stroke="rgba(56,189,248,0.18)" strokeWidth="1.2">
            <path d="M70 96l34-18 54 4 22 18-5 18-26 10-24-8-14 10-34-6-8-16z" />
            <path d="M170 176l26-7 20 18 4 22-18 20-14 18-15-8 5-24-8-18z" />
            <path d="M280 88l28-18 52 3 20 15-5 15-22 8-7 15 8 14-16 10-24-5-16-20-17 3-14-14z" />
            <path d="M348 168l18-4 16 14 8 30-12 22-28-8-8-24z" />
            <path d="M430 86l32-16 56 4 34 18-8 18-26 7-18 10-15 3-22-10-22 2-11-14z" />
            <path d="M512 174l22 3 24 16-6 18-26 14-20-8-4-18z" />
            <path d="M548 258l26 7 16 14-8 16-24 5-14-8z" />
          </g>

          {hotZones.map((zone) => (
            <g key={zone.name}>
              <circle
                cx={zone.x}
                cy={zone.y}
                r="22"
                fill={REGION_COLORS[zone.level]}
                opacity="0.12"
              />
              <circle
                cx={zone.x}
                cy={zone.y}
                r="11"
                fill={REGION_COLORS[zone.level]}
                opacity="0.30"
              />
              <circle
                cx={zone.x}
                cy={zone.y}
                r="5"
                fill={REGION_COLORS[zone.level]}
              />
              <text
                x={zone.x + 10}
                y={zone.y - 8}
                fill="#dbeafe"
                fontSize="10"
                fontWeight="700"
              >
                {zone.name}
              </text>
            </g>
          ))}
        </svg>
      </div>

      <div className="map-zone-grid">
        {hotZones.map((zone) => (
          <div className="map-zone-chip" key={zone.name}>
            <span className={`zone-badge ${zone.level}`}>{zone.level.toUpperCase()}</span>
            <span className="zone-name">{zone.name}</span>
            <span className="zone-score">{zone.score}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
