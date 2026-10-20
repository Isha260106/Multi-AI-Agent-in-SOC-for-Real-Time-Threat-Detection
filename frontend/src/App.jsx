import React, { useState, useEffect, useCallback, useMemo } from 'react';
import './App.css';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  Terminal,
  Cpu,
  Layers,
  Radio,
  Play,
  Pause,
  RefreshCw,
  Search,
  Filter,
  AlertTriangle,
  Info,
  Server,
  Database,
  Clock,
  ArrowUpRight,
  Eye,
  FileCode,
  Sliders,
  CheckCircle2,
  XCircle,
  Globe
} from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8000/api';

export default function App() {
  // Navigation
  const [activeTab, setActiveTab] = useState('stream'); // 'stream' | 'threats' | 'incidents' | 'agents' | 'analytics'

  // Polling & Controls
  const [isLive, setIsLive] = useState(true);
  const [pollIntervalMs, setPollIntervalMs] = useState(1500);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  // Data States
  const [overview, setOverview] = useState(null);
  const [events, setEvents] = useState([]);
  const [threats, setThreats] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [investigations, setInvestigations] = useState([]);
  const [agents, setAgents] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [intelData, setIntelData] = useState({ items: [], stats: {} });
  const [intelQueryInput, setIntelQueryInput] = useState('');
  const [intelQueryType, setIntelQueryType] = useState('ip');
  const [intelQueryProvider, setIntelQueryProvider] = useState('mock');
  const [intelQueryResult, setIntelQueryResult] = useState(null);
  const [intelQueryLoading, setIntelQueryLoading] = useState(false);

  // Filter States
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterCategory, setFilterCategory] = useState('ALL');
  const [filterPrediction, setFilterPrediction] = useState('ALL');

  // Selected Detail Modal / Drawer
  const [selectedEventId, setSelectedEventId] = useState(null);
  const [eventDetail, setEventDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Network / Connection status
  const [apiConnected, setApiConnected] = useState(true);
  const [errorMessage, setErrorMessage] = useState(null);

  // Fetch Overview and System Health
  const fetchOverviewData = useCallback(async () => {
    try {
      const [ovRes, agRes, anRes] = await Promise.all([
        fetch(`${API_BASE}/overview`),
        fetch(`${API_BASE}/agents/status`),
        fetch(`${API_BASE}/analytics`)
      ]);

      if (ovRes.ok) setOverview(await ovRes.json());
      if (agRes.ok) {
        const agData = await agRes.json();
        setAgents(agData.agents || []);
      }
      if (anRes.ok) setAnalytics(await anRes.json());
      setApiConnected(true);
      setErrorMessage(null);
    } catch (err) {
      setApiConnected(false);
      setErrorMessage('Backend API disconnected. Ensure dashboard_api.py is running.');
    }
  }, []);

  // Fetch Tab Specific Feeds
  const fetchTabFeed = useCallback(async () => {
    try {
      let params = new URLSearchParams();
      params.append('limit', '60');
      if (filterSeverity !== 'ALL') params.append('severity', filterSeverity);
      if (filterCategory !== 'ALL') params.append('category', filterCategory);
      if (filterPrediction !== 'ALL') params.append('prediction', filterPrediction);
      if (searchTerm.trim()) params.append('search', searchTerm.trim());

      if (activeTab === 'stream') {
        const res = await fetch(`${API_BASE}/events?${params.toString()}`);
        if (res.ok) setEvents(await res.json());
      } else if (activeTab === 'threats') {
        const res = await fetch(`${API_BASE}/threats?limit=50`);
        if (res.ok) setThreats(await res.json());
      } else if (activeTab === 'investigations') {
        const res = await fetch(`${API_BASE}/investigations?limit=50`);
        if (res.ok) setInvestigations(await res.json());
      } else if (activeTab === 'incidents') {
        const [incRes, alRes] = await Promise.all([
          fetch(`${API_BASE}/incidents?limit=50`),
          fetch(`${API_BASE}/alerts?limit=50`)
        ]);
        if (incRes.ok) setIncidents(await incRes.json());
        if (alRes.ok) setAlerts(await alRes.json());
      } else if (activeTab === 'intel') {
        const res = await fetch(`${API_BASE}/intel/cache?limit=50`);
        if (res.ok) setIntelData(await res.json());
      }
      setLastRefreshed(new Date());
    } catch (err) {
      console.warn('Feed fetch error:', err);
    }
  }, [activeTab, filterSeverity, filterCategory, filterPrediction, searchTerm]);

  // Master Refresh
  const handleRefresh = useCallback(() => {
    fetchOverviewData();
    fetchTabFeed();
  }, [fetchOverviewData, fetchTabFeed]);

  // Polling loop
  useEffect(() => {
    handleRefresh();
    if (!isLive) return;

    const timer = setInterval(() => {
      fetchOverviewData();
      fetchTabFeed();
    }, pollIntervalMs);

    return () => clearInterval(timer);
  }, [isLive, pollIntervalMs, handleRefresh, fetchOverviewData, fetchTabFeed]);

  // Fetch Event Detail on Selection
  useEffect(() => {
    if (!selectedEventId) {
      setEventDetail(null);
      return;
    }
    let cancelled = false;
    setDetailLoading(true);

    fetch(`${API_BASE}/events/${selectedEventId}`)
      .then(res => (res.ok ? res.json() : null))
      .then(data => {
        if (!cancelled) {
          setEventDetail(data);
          setDetailLoading(false);
        }
      })
      .catch(() => {
        if (!cancelled) setDetailLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [selectedEventId]);

  // Formatting helpers
  const getSeverityBadgeClass = (sev) => {
    switch ((sev || '').toUpperCase()) {
      case 'HIGH':
      case 'CRITICAL':
        return 'badge badge-high';
      case 'MEDIUM':
        return 'badge badge-medium';
      case 'LOW':
        return 'badge badge-low';
      default:
        return 'badge badge-info';
    }
  };

  const getCategoryBadge = (cat) => {
    switch (cat) {
      case 'Confirmed Attack':
        return <span className="badge badge-high">Confirmed Attack</span>;
      case 'Suspected Attack':
        return <span className="badge badge-high">Suspected Attack</span>;
      case 'Suspicious Anomaly':
        return <span className="badge badge-medium">Suspicious Anomaly</span>;
      case 'Benign':
        return <span className="badge badge-low">Benign</span>;
      default:
        return <span className="badge badge-info">{cat || 'Unknown'}</span>;
    }
  };

  return (
    <div className="dashboard-container">
      {/* Top Header */}
      <header className="dashboard-header glass-panel">
        <div className="brand-section">
          <div className="brand-icon">
            <ShieldAlert size={26} color="#00f0ff" />
          </div>
          <div>
            <h1 className="brand-title">MULTI-AGENT AI SOC PLATFORM</h1>
            <p className="brand-subtitle">
              <span className={`pulsing-dot ${apiConnected ? 'pulsing-dot-green' : 'pulsing-dot-red'}`} />
              {apiConnected ? 'TELEMETRY STREAM: CONNECTED' : 'DISCONNECTED'} | STAGE 9A UNIFIED THREAT ASSESSMENT
            </p>
          </div>
        </div>

        <div className="header-controls">
          <button
            className={`btn-cyber ${isLive ? 'active' : ''}`}
            onClick={() => setIsLive(!isLive)}
            title={isLive ? 'Pause auto-updates' : 'Resume auto-updates'}
          >
            {isLive ? <Pause size={15} /> : <Play size={15} />}
            {isLive ? 'STREAMING ACTIVE' : 'STREAM PAUSED'}
          </button>

          <button className="btn-cyber" onClick={handleRefresh} title="Manual Refresh">
            <RefreshCw size={15} />
            REFRESH
          </button>

          <span className="badge badge-cyan font-mono">
            POLL: 1.5s | {lastRefreshed.toLocaleTimeString()}
          </span>
        </div>
      </header>

      {/* Simulated Replay Notice */}
      <div className="sim-notice">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Info size={16} color="#60a5fa" />
          <span>
            <strong>MODE: SIMULATED DATASET REPLAY</strong> — Network flow records are continuously injected via
            inter-process queue to emulate real-time tap ingestion. Live packet capture (PCAP) is inactive.
          </span>
        </div>
        <span className="badge badge-info font-mono">NO FABRICATED SCORES</span>
      </div>

      {/* Metric Cards Row */}
      <section className="metrics-grid">
        <div className="metric-card glass-panel" style={{ '--accent-color': '#00f0ff' }}>
          <div className="metric-header">
            <span className="metric-label">Total Events</span>
            <Activity size={18} color="#00f0ff" />
          </div>
          <div className="metric-value">{overview ? overview.total_events.toLocaleString() : '—'}</div>
          <div className="metric-sub">Events ingested to soc.db</div>
        </div>

        <div className="metric-card glass-panel" style={{ '--accent-color': '#10b981' }}>
          <div className="metric-header">
            <span className="metric-label">Benign Traffic</span>
            <ShieldCheck size={18} color="#10b981" />
          </div>
          <div className="metric-value">{overview ? overview.benign_events.toLocaleString() : '—'}</div>
          <div className="metric-sub">Classified benign signatures</div>
        </div>

        <div className="metric-card glass-panel" style={{ '--accent-color': '#ef4444' }}>
          <div className="metric-header">
            <span className="metric-label">Threats Detected</span>
            <ShieldAlert size={18} color="#ef4444" />
          </div>
          <div className="metric-value">{overview ? overview.threat_events.toLocaleString() : '—'}</div>
          <div className="metric-sub">Supervised signature matches</div>
        </div>

        <div className="metric-card glass-panel" style={{ '--accent-color': '#f59e0b' }}>
          <div className="metric-header">
            <span className="metric-label">Anomalous Outliers</span>
            <Radio size={18} color="#f59e0b" />
          </div>
          <div className="metric-value">{overview ? overview.anomalous_events.toLocaleString() : '—'}</div>
          <div className="metric-sub">Statistical baseline deviations</div>
        </div>

        <div className="metric-card glass-panel" style={{ '--accent-color': '#ff2e63' }}>
          <div className="metric-header">
            <span className="metric-label">Critical Alerts</span>
            <AlertTriangle size={18} color="#ff2e63" />
          </div>
          <div className="metric-value">{overview ? overview.critical_alerts.toLocaleString() : '—'}</div>
          <div className="metric-sub">High severity alerts recorded</div>
        </div>

        <div className="metric-card glass-panel" style={{ '--accent-color': '#8b5cf6' }}>
          <div className="metric-header">
            <span className="metric-label">Correlated Incidents</span>
            <Layers size={18} color="#8b5cf6" />
          </div>
          <div className="metric-value">{overview ? overview.open_incidents.toLocaleString() : '—'}</div>
          <div className="metric-sub">Cross-agent syntheses</div>
        </div>
      </section>

      {/* Navigation Tabs */}
      <nav className="tabs-bar">
        <button
          className={`tab-btn ${activeTab === 'stream' ? 'active' : ''}`}
          onClick={() => setActiveTab('stream')}
        >
          <Activity size={17} /> Live Event Stream
        </button>
        <button
          className={`tab-btn ${activeTab === 'threats' ? 'active' : ''}`}
          onClick={() => setActiveTab('threats')}
        >
          <ShieldAlert size={17} /> Unified Threat Assessments
        </button>
        <button
          className={`tab-btn ${activeTab === 'investigations' ? 'active' : ''}`}
          onClick={() => setActiveTab('investigations')}
        >
          <FileCode size={17} /> Threat Investigations
        </button>
        <button
          className={`tab-btn ${activeTab === 'incidents' ? 'active' : ''}`}
          onClick={() => setActiveTab('incidents')}
        >
          <Layers size={17} /> Alerts & Incidents
        </button>
        <button
          className={`tab-btn ${activeTab === 'agents' ? 'active' : ''}`}
          onClick={() => setActiveTab('agents')}
        >
          <Cpu size={17} /> Agent Health Status
        </button>
        <button
          className={`tab-btn ${activeTab === 'analytics' ? 'active' : ''}`}
          onClick={() => setActiveTab('analytics')}
        >
          <Sliders size={17} /> Analytics & Latency
        </button>
        <button
          className={`tab-btn ${activeTab === 'intel' ? 'active' : ''}`}
          onClick={() => setActiveTab('intel')}
        >
          <Globe size={17} /> Threat Intelligence
        </button>
      </nav>

      {/* Filter and Search Bar (Active for Stream and Threat feeds) */}
      {(activeTab === 'stream' || activeTab === 'threats' || activeTab === 'investigations') && (
        <section className="filter-bar glass-panel">
          <div className="search-input-group">
            <Search size={16} color="#9aa8c2" />
            <input
              type="text"
              placeholder="Search by Event UUID, source, or keyword..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <select
              className="select-filter"
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
            >
              <option value="ALL">All Severities</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="INFORMATIONAL">INFORMATIONAL</option>
            </select>

            <select
              className="select-filter"
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
            >
              <option value="ALL">All Threat Categories</option>
              <option value="Confirmed Attack">Confirmed Attack</option>
              <option value="Suspected Attack">Suspected Attack</option>
              <option value="Suspicious Anomaly">Suspicious Anomaly</option>
              <option value="Benign">Benign</option>
              <option value="Unknown">Unknown</option>
            </select>

            <select
              className="select-filter"
              value={filterPrediction}
              onChange={(e) => setFilterPrediction(e.target.value)}
            >
              <option value="ALL">All Predictions</option>
              <option value="Infilteration">Attack (Infiltration)</option>
              <option value="Benign">Benign</option>
            </select>

            {(searchTerm || filterSeverity !== 'ALL' || filterCategory !== 'ALL' || filterPrediction !== 'ALL') && (
              <button
                className="btn-cyber"
                onClick={() => {
                  setSearchTerm('');
                  setFilterSeverity('ALL');
                  setFilterCategory('ALL');
                  setFilterPrediction('ALL');
                }}
              >
                Reset Filters
              </button>
            )}
          </div>
        </section>
      )}

      {/* Main Content Area */}
      {activeTab === 'stream' && (
        <main className="main-two-col">
          {/* Table Container */}
          <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontWeight: 600, fontSize: '0.95rem' }}>
                RECENT INGESTED EVENTS ({events.length})
              </span>
              <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Click row to inspect agent features
              </span>
            </div>

            <div className="table-container">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Event UUID</th>
                    <th>Source</th>
                    <th>Network Model</th>
                    <th>Anomaly Model</th>
                    <th>Threat Posture</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {events.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                        No events found matching current criteria. Start the replay producer or reset filters.
                      </td>
                    </tr>
                  ) : (
                    events.map((ev) => (
                      <tr
                        key={ev.event_id}
                        className={selectedEventId === ev.event_id ? 'selected' : ''}
                        onClick={() => setSelectedEventId(ev.event_id)}
                      >
                        <td className="font-mono">{ev.timestamp ? ev.timestamp.replace('T', ' ').slice(0, 19) : 'N/A'}</td>
                        <td className="font-mono" style={{ color: 'var(--cyber-cyan)' }}>
                          {ev.event_id.slice(0, 8)}...
                        </td>
                        <td>{ev.source || 'simulated_tap'}</td>
                        <td>
                          {ev.network_prediction ? (
                            <span className={ev.network_prediction.toLowerCase() === 'benign' ? 'badge badge-low' : 'badge badge-high'}>
                              {ev.network_prediction}
                            </span>
                          ) : (
                            <span className="badge badge-info">N/A</span>
                          )}
                        </td>
                        <td>
                          {ev.anomaly_prediction ? (
                            <span className={ev.anomaly_prediction.toLowerCase() === 'normal' ? 'badge badge-low' : 'badge badge-medium'}>
                              {ev.anomaly_prediction}
                            </span>
                          ) : (
                            <span className="badge badge-info">N/A</span>
                          )}
                        </td>
                        <td>{getCategoryBadge(ev.threat_category)}</td>
                        <td>
                          <span className={getSeverityBadgeClass(ev.threat_severity)}>
                            {ev.threat_severity || 'INFORMATIONAL'}
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Event Details Drawer */}
          <div className="glass-panel detail-panel">
            <div className="detail-header">
              <div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 600 }}>EVENT TELEMETRY INSPECTOR</h3>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  {selectedEventId ? selectedEventId : 'Select any event from the stream'}
                </p>
              </div>
              {selectedEventId && (
                <button
                  className="btn-cyber"
                  style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                  onClick={() => setSelectedEventId(null)}
                >
                  Close
                </button>
              )}
            </div>

            {!selectedEventId ? (
              <div style={{ padding: '40px 10px', textAlign: 'center', color: 'var(--text-muted)' }}>
                <Eye size={36} style={{ margin: '0 auto 12px auto', opacity: 0.4 }} />
                <p>Click on any flow record on the left to inspect raw features, agent confidences, and deterministic explanations.</p>
              </div>
            ) : detailLoading ? (
              <div style={{ padding: '40px 10px', textAlign: 'center' }}>
                <span className="pulsing-dot" /> Loading telemetry...
              </div>
            ) : eventDetail ? (
              <>
                {/* Threat Assessment Summary */}
                <div>
                  <h4 className="detail-section-title">UNIFIED THREAT POSTURE</h4>
                  {eventDetail.threat_assessment ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <div className="detail-row">
                        <span className="detail-key">Category</span>
                        <span>{getCategoryBadge(eventDetail.threat_assessment.category)}</span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-key">Assigned Severity</span>
                        <span className={getSeverityBadgeClass(eventDetail.threat_assessment.severity)}>
                          {eventDetail.threat_assessment.severity}
                        </span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-key">Decision Method</span>
                        <span className="detail-val">Stage 9A Policy Table</span>
                      </div>
                      <div className="explanation-box">
                        <strong>Explanation:</strong> {eventDetail.threat_assessment.explanation}
                      </div>
                    </div>
                  ) : (
                    <div className="explanation-box" style={{ color: 'var(--text-muted)' }}>
                      No Unified Threat Assessment recorded for this event yet.
                    </div>
                  )}
                </div>

                {/* Multi-Agent Threat Investigation Report (Stage 10) */}
                {eventDetail.threat_investigation && (
                  <div>
                    <h4 className="detail-section-title">STAGE 10 MULTI-AGENT INVESTIGATION</h4>
                    <div style={{ background: 'rgba(0, 240, 255, 0.05)', border: '1px solid rgba(0, 240, 255, 0.3)', borderRadius: '8px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <div className="detail-row">
                        <span className="detail-key">Investigation Status</span>
                        <span className={`badge ${eventDetail.threat_investigation.investigation_status === 'COMPLETED' ? 'badge-high' : 'badge-medium'}`}>
                          {eventDetail.threat_investigation.investigation_status}
                        </span>
                      </div>
                      <div className="explanation-box">
                        <strong>Investigator Summary:</strong> {eventDetail.threat_investigation.summary}
                      </div>

                      {eventDetail.threat_investigation.conflicting_signals && eventDetail.threat_investigation.conflicting_signals.length > 0 && (
                        <div style={{ background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.3)', borderRadius: '6px', padding: '8px', fontSize: '0.78rem', color: '#fcd34d' }}>
                          <strong>Conflicting Signals:</strong> {eventDetail.threat_investigation.conflicting_signals.join(' ')}
                        </div>
                      )}

                      {eventDetail.threat_investigation.recommended_next_steps && eventDetail.threat_investigation.recommended_next_steps.length > 0 && (
                        <div style={{ marginTop: '4px' }}>
                          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--cyber-green)' }}>RECOMMENDED ACTION:</span>
                          <ul style={{ paddingLeft: '18px', fontSize: '0.78rem', marginTop: '4px', color: '#cbd5e1' }}>
                            {eventDetail.threat_investigation.recommended_next_steps.map((st, i) => (
                              <li key={i}>{st}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {eventDetail.threat_investigation.findings_by_agent?.threat_intelligence && (
                        <div style={{ marginTop: '4px', background: 'rgba(56, 189, 248, 0.08)', border: '1px solid rgba(56, 189, 248, 0.25)', borderRadius: '6px', padding: '8px' }}>
                          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#38bdf8' }}>STAGE 11 THREAT INTEL FINDINGS:</span>
                          <ul style={{ paddingLeft: '18px', fontSize: '0.78rem', marginTop: '4px', color: '#e2e8f0' }}>
                            {eventDetail.threat_investigation.findings_by_agent.threat_intelligence.map((st, i) => (
                              <li key={i}>{st}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Individual Agent Outputs */}
                <div>
                  <h4 className="detail-section-title">AGENT PREDICTION BREAKDOWN</h4>
                  {eventDetail.alerts && eventDetail.alerts.length > 0 ? (
                    eventDetail.alerts.map((al, idx) => (
                      <div
                        key={idx}
                        style={{
                          background: 'rgba(0,0,0,0.25)',
                          borderRadius: '8px',
                          padding: '10px',
                          marginBottom: '8px',
                          border: '1px solid var(--border-subtle)'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                          <strong style={{ fontSize: '0.85rem' }}>{al.agent}</strong>
                          <span className={getSeverityBadgeClass(al.severity)}>{al.severity}</span>
                        </div>
                        <div className="detail-row">
                          <span className="detail-key">Prediction</span>
                          <span className="detail-val">{al.prediction}</span>
                        </div>
                        <div className="detail-row">
                          <span className="detail-key">Score / Confidence</span>
                          <span className="detail-val">
                            {al.confidence !== null && al.confidence !== undefined
                              ? al.agent.includes('Anomaly')
                                ? Number(al.confidence).toFixed(6)
                                : `${(Number(al.confidence) * 100).toFixed(2)}%`
                              : 'N/A'}
                          </span>
                        </div>
                        {al.processing_time_s && (
                          <div className="detail-row">
                            <span className="detail-key">Latency</span>
                            <span className="detail-val">{(al.processing_time_s * 1000).toFixed(1)} ms</span>
                          </div>
                        )}
                      </div>
                    ))
                  ) : (
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No alert rows recorded.</p>
                  )}
                </div>

                {/* Raw Event Network Features */}
                <div>
                  <h4 className="detail-section-title">EXTRACTED FLOW FEATURES (SAMPLE)</h4>
                  <div
                    style={{
                      maxHeight: '220px',
                      overflowY: 'auto',
                      background: '#070a0f',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '8px',
                      padding: '10px',
                      fontSize: '0.75rem',
                      fontFamily: 'var(--font-mono)'
                    }}
                  >
                    {eventDetail.event && eventDetail.event.features ? (
                      Object.entries(eventDetail.event.features).slice(0, 20).map(([k, v]) => (
                        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '2px 0' }}>
                          <span style={{ color: 'var(--text-secondary)' }}>{k}:</span>
                          <span style={{ color: '#38bdf8' }}>{String(v)}</span>
                        </div>
                      ))
                    ) : (
                      <span>No features available</span>
                    )}
                  </div>
                </div>
              </>
            ) : null}
          </div>
        </main>
      )}

      {/* Tab 2: Unified Threat Assessments */}
      {activeTab === 'threats' && (
        <section className="glass-panel" style={{ padding: '20px' }}>
          <h2 style={{ fontSize: '1.15rem', marginBottom: '14px', fontWeight: 600 }}>
            UNIFIED THREAT ASSESSMENTS (STAGE 9A)
          </h2>
          <div className="table-container">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Assessment ID</th>
                  <th>Event ID</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Network Pred</th>
                  <th>Anomaly Score</th>
                  <th>Explanation</th>
                </tr>
              </thead>
              <tbody>
                {threats.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                      No threat assessments recorded yet. Run the streaming demo or test runner to populate.
                    </td>
                  </tr>
                ) : (
                  threats.map((t) => (
                    <tr key={t.assessment_id}>
                      <td className="font-mono">{t.timestamp ? t.timestamp.replace('T', ' ').slice(0, 19) : 'N/A'}</td>
                      <td className="font-mono" style={{ color: 'var(--cyber-cyan)' }}>
                        {t.assessment_id.slice(0, 8)}...
                      </td>
                      <td className="font-mono">{t.event_id.slice(0, 8)}...</td>
                      <td>{getCategoryBadge(t.category)}</td>
                      <td><span className={getSeverityBadgeClass(t.severity)}>{t.severity}</span></td>
                      <td>{t.network_prediction || 'N/A'}</td>
                      <td className="font-mono">{t.anomaly_score !== null ? Number(t.anomaly_score).toFixed(4) : 'N/A'}</td>
                      <td style={{ maxWidth: '400px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={t.explanation}>
                        {t.explanation}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Tab 3: Threat Investigations (Stage 10) */}
      {activeTab === 'investigations' && (
        <section className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <h2 style={{ fontSize: '1.15rem', fontWeight: 600 }}>
              MULTI-AGENT THREAT INVESTIGATIONS (STAGE 10)
            </h2>
            <span className="badge badge-cyan font-mono">{investigations.length} Reports</span>
          </div>
          <div className="table-container">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Investigation ID</th>
                  <th>Event ID</th>
                  <th>Threat Posture</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Summary</th>
                  <th>Next Steps</th>
                </tr>
              </thead>
              <tbody>
                {investigations.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                      No investigations recorded yet. Run `python query_investigations.py --investigate &lt;EVENT_ID&gt;` or process live threats.
                    </td>
                  </tr>
                ) : (
                  investigations.map((inv) => (
                    <tr
                      key={inv.investigation_id}
                      onClick={() => {
                        setSelectedEventId(inv.event_id);
                        setActiveTab('stream');
                      }}
                      title="Click to inspect underlying event telemetry in stream"
                    >
                      <td className="font-mono">{inv.timestamp ? inv.timestamp.replace('T', ' ').slice(0, 19) : 'N/A'}</td>
                      <td className="font-mono" style={{ color: 'var(--cyber-cyan)' }}>
                        {inv.investigation_id.slice(0, 8)}...
                      </td>
                      <td className="font-mono">{inv.event_id.slice(0, 8)}...</td>
                      <td>{getCategoryBadge(inv.threat_category)}</td>
                      <td><span className={getSeverityBadgeClass(inv.severity)}>{inv.severity}</span></td>
                      <td>
                        <span className={`badge ${inv.investigation_status === 'COMPLETED' ? 'badge-high' : inv.investigation_status.includes('TIER2') ? 'badge-medium' : 'badge-low'}`}>
                          {inv.investigation_status}
                        </span>
                      </td>
                      <td style={{ maxWidth: '300px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={inv.summary}>
                        {inv.summary}
                      </td>
                      <td style={{ maxWidth: '280px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {Array.isArray(inv.recommended_next_steps) && inv.recommended_next_steps.length > 0
                          ? inv.recommended_next_steps[0]
                          : 'Standard monitoring'}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Tab 4: Alerts & Incidents */}
      {activeTab === 'incidents' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
          <section className="glass-panel" style={{ padding: '20px' }}>
            <h2 style={{ fontSize: '1.15rem', marginBottom: '14px', fontWeight: 600 }}>
              CORRELATED INCIDENTS ({incidents.length})
            </h2>
            <div className="table-container">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Incident ID</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Correlated Agents</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                        No correlated incidents recorded.
                      </td>
                    </tr>
                  ) : (
                    incidents.map((inc) => (
                      <tr key={inc.incident_id}>
                        <td className="font-mono">{inc.timestamp ? inc.timestamp.replace('T', ' ').slice(0, 19) : 'N/A'}</td>
                        <td className="font-mono" style={{ color: 'var(--cyber-cyan)' }}>{inc.incident_id.slice(0, 8)}...</td>
                        <td><span className={getSeverityBadgeClass(inc.severity)}>{inc.status}</span></td>
                        <td><span className={getSeverityBadgeClass(inc.severity)}>{inc.severity}</span></td>
                        <td>{Array.isArray(inc.correlated_agents) ? inc.correlated_agents.join(', ') : '2 Agents'}</td>
                        <td title={inc.correlation_reason} style={{ maxWidth: '200px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {inc.correlation_reason}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section className="glass-panel" style={{ padding: '20px' }}>
            <h2 style={{ fontSize: '1.15rem', marginBottom: '14px', fontWeight: 600 }}>
              RAW AGENT ALERTS ({alerts.length})
            </h2>
            <div className="table-container">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>Agent</th>
                    <th>Prediction</th>
                    <th>Severity</th>
                    <th>Score</th>
                    <th>Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.length === 0 ? (
                    <tr>
                      <td colSpan={5} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                        No raw alerts recorded.
                      </td>
                    </tr>
                  ) : (
                    alerts.map((al, idx) => (
                      <tr key={idx}>
                        <td>{al.agent}</td>
                        <td>{al.prediction}</td>
                        <td><span className={getSeverityBadgeClass(al.severity)}>{al.severity}</span></td>
                        <td className="font-mono">
                          {al.confidence !== null && al.confidence !== undefined
                            ? al.agent.includes('Anomaly')
                              ? Number(al.confidence).toFixed(4)
                              : `${(Number(al.confidence) * 100).toFixed(1)}%`
                            : 'N/A'}
                        </td>
                        <td className="font-mono">
                          {al.processing_time_s ? `${(al.processing_time_s * 1000).toFixed(1)} ms` : 'N/A'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}

      {/* Tab 4: Agent Health Status */}
      {activeTab === 'agents' && (
        <section className="glass-panel" style={{ padding: '22px' }}>
          <h2 style={{ fontSize: '1.15rem', marginBottom: '18px', fontWeight: 600 }}>
            PIPELINE AGENT TOPOLOGY & OPERATIONAL HEALTH
          </h2>

          <div className="agents-grid">
            {agents.map((ag) => (
              <div key={ag.id} className="agent-card glass-panel">
                <div className="agent-card-header">
                  <div>
                    <h3 className="agent-name">{ag.name}</h3>
                    <span className="agent-type">{ag.type}</span>
                  </div>
                  <span
                    className={`badge ${
                      ag.status === 'ACTIVE' || ag.status === 'ONLINE' || ag.status === 'READY'
                        ? 'badge-low'
                        : 'badge-high'
                    }`}
                  >
                    {ag.status}
                  </span>
                </div>

                <div className="detail-row">
                  <span className="detail-key">Model / Logic</span>
                  <span className="detail-val">{ag.model}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-key">Details</span>
                  <span className="detail-val" style={{ color: 'var(--text-secondary)' }}>
                    {ag.details}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Tab 5: Analytics & Latency */}
      {activeTab === 'analytics' && (
        <section className="analytics-grid">
          {/* Category Breakdown */}
          <div className="chart-card glass-panel">
            <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>THREAT CATEGORY DISTRIBUTION</h3>
            <div>
              {analytics && analytics.categories && Object.keys(analytics.categories).length > 0 ? (
                Object.entries(analytics.categories).map(([cat, cnt]) => {
                  const total = overview ? overview.total_assessments || 1 : 1;
                  const pct = Math.min(100, Math.round((cnt / total) * 100));
                  return (
                    <div key={cat} className="bar-item">
                      <div className="bar-label-row">
                        <span>{cat}</span>
                        <span className="font-mono">{cnt} ({pct}%)</span>
                      </div>
                      <div className="bar-track">
                        <div
                          className="bar-fill"
                          style={{
                            width: `${pct}%`,
                            background:
                              cat.includes('Attack') ? 'var(--cyber-red)' : cat.includes('Anomaly') ? 'var(--cyber-yellow)' : 'var(--cyber-green)'
                          }}
                        />
                      </div>
                    </div>
                  );
                })
              ) : (
                <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No category metrics recorded.</p>
              )}
            </div>
          </div>

          {/* Severity Breakdown */}
          <div className="chart-card glass-panel">
            <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>SEVERITY BREAKDOWN</h3>
            <div>
              {analytics && analytics.severities && Object.keys(analytics.severities).length > 0 ? (
                Object.entries(analytics.severities).map(([sev, cnt]) => {
                  const total = overview ? overview.total_alerts || overview.total_assessments || 1 : 1;
                  const pct = Math.min(100, Math.round((cnt / total) * 100));
                  return (
                    <div key={sev} className="bar-item">
                      <div className="bar-label-row">
                        <span>{sev}</span>
                        <span className="font-mono">{cnt} ({pct}%)</span>
                      </div>
                      <div className="bar-track">
                        <div
                          className="bar-fill"
                          style={{
                            width: `${pct}%`,
                            background:
                              sev === 'HIGH' ? 'var(--cyber-red)' : sev === 'MEDIUM' ? 'var(--cyber-yellow)' : 'var(--cyber-green)'
                          }}
                        />
                      </div>
                    </div>
                  );
                })
              ) : (
                <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No severity data recorded.</p>
              )}
            </div>
          </div>

          {/* Processing Latency Metrics */}
          <div className="chart-card glass-panel">
            <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>FLOW PROCESSING LATENCY</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '10px' }}>
              <div className="detail-row">
                <span className="detail-key">Average Inference Time</span>
                <span className="detail-val" style={{ color: 'var(--cyber-cyan)', fontSize: '1.1rem' }}>
                  {analytics && analytics.latency_stats.avg_ms !== null ? `${analytics.latency_stats.avg_ms} ms` : 'N/A'}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Minimum Latency</span>
                <span className="detail-val">
                  {analytics && analytics.latency_stats.min_ms !== null ? `${analytics.latency_stats.min_ms} ms` : 'N/A'}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Maximum Latency</span>
                <span className="detail-val">
                  {analytics && analytics.latency_stats.max_ms !== null ? `${analytics.latency_stats.max_ms} ms` : 'N/A'}
                </span>
              </div>
              <div className="explanation-box" style={{ marginTop: '10px' }}>
                Flow latency measures model inference and feature sanitization time per network event row before persistence.
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Tab 7: Threat Intelligence (Stage 11) */}
      {activeTab === 'intel' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Cache Stats Overview */}
          <div className="analytics-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
            <div className="stat-card glass-panel">
              <span className="stat-label">TOTAL CACHED LOOKUPS</span>
              <span className="stat-value font-mono" style={{ color: 'var(--cyber-cyan)' }}>
                {intelData.stats?.total_cached || 0}
              </span>
              <span className="stat-sub">SQLite Cached Indicators</span>
            </div>
            <div className="stat-card glass-panel">
              <span className="stat-label">REAL EXTERNAL LOOKUPS</span>
              <span className="stat-value font-mono" style={{ color: 'var(--cyber-green)' }}>
                {intelData.stats?.real_count || 0}
              </span>
              <span className="stat-sub">Live API queries</span>
            </div>
            <div className="stat-card glass-panel">
              <span className="stat-label">OFFLINE / DEMO FIXTURES</span>
              <span className="stat-value font-mono" style={{ color: 'var(--cyber-yellow)' }}>
                {intelData.stats?.mock_count || 0}
              </span>
              <span className="stat-sub">Simulated mock lookups</span>
            </div>
            <div className="stat-card glass-panel">
              <span className="stat-label">EXPIRED CACHE ENTRIES</span>
              <span className="stat-value font-mono" style={{ color: 'var(--text-muted)' }}>
                {intelData.stats?.expired_count || 0}
              </span>
              <span className="stat-sub">TTL Exceeded</span>
            </div>
          </div>

          {/* Interactive Indicator Lookup Tool */}
          <section className="glass-panel" style={{ padding: '20px' }}>
            <h3 style={{ fontSize: '1.05rem', marginBottom: '12px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Search size={18} color="var(--cyber-cyan)" /> OBSERVABLE INDICATOR LOOKUP CONSOLE
            </h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '14px' }}>
              Query IP addresses or port services against configured Threat Intelligence providers with automatic SQLite caching and TTL enforcement.
            </p>

            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '14px' }}>
              <input
                type="text"
                placeholder="Enter indicator (e.g., 198.51.100.1, 4444)..."
                value={intelQueryInput}
                onChange={(e) => setIntelQueryInput(e.target.value)}
                style={{
                  flex: 1,
                  minWidth: '240px',
                  background: 'rgba(0,0,0,0.4)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  color: '#fff',
                  fontSize: '0.88rem',
                  fontFamily: 'var(--font-mono)'
                }}
              />
              <select
                className="select-filter"
                value={intelQueryType}
                onChange={(e) => setIntelQueryType(e.target.value)}
              >
                <option value="ip">Indicator: IP Address</option>
                <option value="port">Indicator: Port Number</option>
              </select>
              <select
                className="select-filter"
                value={intelQueryProvider}
                onChange={(e) => setIntelQueryProvider(e.target.value)}
              >
                <option value="mock">Provider: Mock Fixtures (Offline)</option>
                <option value="abuseipdb">Provider: AbuseIPDB v2</option>
                <option value="virustotal">Provider: VirusTotal v3</option>
              </select>
              <button
                className="btn btn-secondary"
                disabled={!intelQueryInput.trim() || intelQueryLoading}
                onClick={async () => {
                  setIntelQueryLoading(true);
                  try {
                    const res = await fetch(
                      `${API_BASE}/intel/lookup?indicator=${encodeURIComponent(intelQueryInput.trim())}&type=${intelQueryType}&provider=${intelQueryProvider}`
                    );
                    if (res.ok) {
                      setIntelQueryResult(await res.json());
                      // Refresh cache list
                      const cacheRes = await fetch(`${API_BASE}/intel/cache?limit=50`);
                      if (cacheRes.ok) setIntelData(await cacheRes.json());
                    } else {
                      alert('Lookup failed: ' + (await res.text()));
                    }
                  } catch (err) {
                    alert('Lookup error: ' + err.message);
                  } finally {
                    setIntelQueryLoading(false);
                  }
                }}
              >
                {intelQueryLoading ? 'Querying...' : 'Query Threat Intel'}
              </button>
            </div>

            {/* Display Lookup Result */}
            {intelQueryResult && (
              <div style={{ background: 'rgba(15, 23, 42, 0.75)', border: '1px solid rgba(56, 189, 248, 0.3)', borderRadius: '8px', padding: '14px', marginTop: '10px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span className="font-mono" style={{ fontSize: '1rem', fontWeight: 600, color: '#fff' }}>
                      {intelQueryResult.indicator_type?.toUpperCase()}: {intelQueryResult.indicator_value}
                    </span>
                    <span className={`badge ${intelQueryResult.verdict === 'MALICIOUS' ? 'badge-high' : intelQueryResult.verdict === 'SUSPICIOUS' ? 'badge-medium' : intelQueryResult.verdict === 'NO_KNOWN_REPORTS' ? 'badge-low' : 'badge-info'}`}>
                      {intelQueryResult.verdict}
                    </span>
                    {intelQueryResult.is_mock && (
                      <span className="badge" style={{ background: 'rgba(234, 179, 8, 0.2)', color: '#facc15', border: '1px solid rgba(234, 179, 8, 0.4)' }}>
                        MOCK FIXTURE
                      </span>
                    )}
                    {intelQueryResult.cache_hit && (
                      <span className="badge badge-info">CACHE HIT</span>
                    )}
                  </div>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    Provider: {intelQueryResult.provider}
                  </span>
                </div>

                {intelQueryResult.reputation_score !== null && intelQueryResult.reputation_score !== undefined && (
                  <div className="detail-row" style={{ marginBottom: '4px' }}>
                    <span className="detail-key">Reputation / Confidence Score:</span>
                    <span className="detail-val font-mono">{intelQueryResult.reputation_score}</span>
                  </div>
                )}

                {intelQueryResult.evidence_links && intelQueryResult.evidence_links.length > 0 && (
                  <div className="detail-row" style={{ marginBottom: '4px' }}>
                    <span className="detail-key">Evidence Report Links:</span>
                    <span className="detail-val">
                      {intelQueryResult.evidence_links.map((link, i) => (
                        <a key={i} href={link} target="_blank" rel="noreferrer" style={{ color: '#38bdf8', textDecoration: 'underline', marginRight: '10px' }}>
                          {link}
                        </a>
                      ))}
                    </span>
                  </div>
                )}

                {intelQueryResult.limitations && intelQueryResult.limitations.length > 0 && (
                  <div style={{ marginTop: '8px', fontSize: '0.75rem', color: '#94a3b8' }}>
                    <strong>Disclaimers & Limitations:</strong>
                    <ul style={{ paddingLeft: '18px', marginTop: '2px' }}>
                      {intelQueryResult.limitations.map((lim, i) => (
                        <li key={i}>{lim}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </section>

          {/* Cached Intelligence Feed */}
          <section className="glass-panel" style={{ padding: '20px' }}>
            <h3 style={{ fontSize: '1.05rem', marginBottom: '12px', fontWeight: 600 }}>
              CACHED THREAT INTELLIGENCE FEED ({intelData.items?.length || 0})
            </h3>
            <div className="table-container">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Indicator Value</th>
                    <th>Provider</th>
                    <th>Verdict</th>
                    <th>Score</th>
                    <th>Mode</th>
                    <th>Last Checked</th>
                    <th>TTL Status</th>
                  </tr>
                </thead>
                <tbody>
                  {!intelData.items || intelData.items.length === 0 ? (
                    <tr>
                      <td colSpan={8} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                        No threat intelligence records cached in database.
                      </td>
                    </tr>
                  ) : (
                    intelData.items.map((row) => (
                      <tr key={row.id}>
                        <td className="font-mono">{row.indicator_type?.toUpperCase()}</td>
                        <td className="font-mono" style={{ color: 'var(--cyber-cyan)' }}>{row.indicator_value}</td>
                        <td>{row.provider}</td>
                        <td>
                          <span className={`badge ${row.verdict === 'MALICIOUS' ? 'badge-high' : row.verdict === 'SUSPICIOUS' ? 'badge-medium' : row.verdict === 'NO_KNOWN_REPORTS' ? 'badge-low' : 'badge-info'}`}>
                            {row.verdict}
                          </span>
                        </td>
                        <td className="font-mono">
                          {row.reputation_score !== null && row.reputation_score !== undefined ? row.reputation_score : 'N/A'}
                        </td>
                        <td>
                          {row.is_mock ? (
                            <span className="badge" style={{ background: 'rgba(234, 179, 8, 0.15)', color: '#facc15' }}>MOCK</span>
                          ) : (
                            <span className="badge badge-low">REAL</span>
                          )}
                        </td>
                        <td className="font-mono" style={{ fontSize: '0.78rem' }}>
                          {row.last_checked ? row.last_checked.replace('T', ' ').slice(0, 19) : 'N/A'}
                        </td>
                        <td>
                          {row.is_expired ? (
                            <span className="badge badge-high">EXPIRED</span>
                          ) : (
                            <span className="badge badge-low">ACTIVE</span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
