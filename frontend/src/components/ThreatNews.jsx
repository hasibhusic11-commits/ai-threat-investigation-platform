import React, { useEffect, useState } from "react";
import api from "../api";

export default function ThreatNews() {
  const [news, setNews] = useState([]);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const loadNews = async () => {
      try {
        setFailed(false);
        const res = await api.get("/news/cyber");
        setNews(res.data?.articles || []);
      } catch (err) {
        console.error(err);
        setFailed(true);
      } finally {
        setLoading(false);
      }
    };

    loadNews();
  }, []);

  return (
    <div className="hotzone-card">
      <h3 className="stack-title">Cyber Threat News</h3>

      {loading ? <div className="empty-state">Loading cyber news…</div> : null}

      {!loading && failed ? (
        <div className="empty-state">
          Cyber news feed unavailable. Check backend API key and news endpoint.
        </div>
      ) : null}

      {!loading && !failed && news.length === 0 ? (
        <div className="empty-state">No major cyber stories returned in the last 24 hours.</div>
      ) : null}

      {!loading && !failed && news.length > 0 ? (
        <div className="item-list">
          {news.map((item, idx) => (
            <a
              key={idx}
              className="item-card news-card-link"
              href={item.url}
              target="_blank"
              rel="noreferrer"
            >
              <div className="badge">LIVE NEWS</div>
              <h4 style={{ marginTop: 10 }}>{item.title}</h4>
              <div className="item-meta" style={{ marginTop: 8 }}>
                {item.source || "Unknown source"} • {item.published_at || "Unknown time"}
              </div>
              <div className="item-meta" style={{ marginTop: 10 }}>
                {item.description || "No summary available."}
              </div>
            </a>
          ))}
        </div>
      ) : null}
    </div>
  );
}
