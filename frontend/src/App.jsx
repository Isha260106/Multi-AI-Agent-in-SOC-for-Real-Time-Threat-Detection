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
  Globe,
  ChevronRight,
  ExternalLink,
  Shield,
  Zap,
  Check,
  FileText,
  Sparkles,
  AlertOctagon,
  ArrowRight
} from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8000/api';

export default function App() {
  // Navigation Tabs: 'overview' | 'stream' | 'telemetry' | 'ai_playbooks' | 'intel_analytics'
  const [activeTab, setActiveTab] = useState('overview');

  // Polling & Controls
  const [isLive, setIsLive] = useState(true);
  const [pollIntervalMs, setPollIntervalMs] = useState(2000);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  // Core Data States
  const [overview, setOverview] = useState(null);
  const [events, setEvents] = useState([]);
  const [threats, setThreats] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [investigations, setInvestigations] = useState([]);
  const [agents, setAgents] = useState([]);
  const [analytics, setAnalytics] = useState(null);

  // Threat Intel States
  const [intelData, setIntelData] = useState({ items: [], stats: {} });
  const [intelQueryInput, setIntelQueryInput] = useState('');
  const [intelQueryType, setIntelQueryType] = useState('ip');
  const [intelQueryProvider, setIntelQueryProvider] = useState('mock');
  const [intelQueryResult, setIntelQueryResult] = useState(null);
  const [intelQueryLoading, setIntelQueryLoading] = useState(false);

  // Response Playbooks States
  const [playbooks, setPlaybooks] = useState([]);
  const [playbookStats, setPlaybookStats] = useState({});
  const [approvingId, setApprovingId] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [approvalSuccessMsg, setApprovalSuccessMsg] = useState(null);

  // Filter States (For Live Flow Stream)
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterCategory, setFilterCategory] = useState('ALL');
  const [filterPrediction, setFilterPrediction] = useState('ALL');

  // Selected Detail Modal / Drawer
  const [selectedEventId, setSelectedEventId] = useState(null);
  const [eventDetail, setEventDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [inspectorSubTab, setInspectorSubTab] = useState('posture'); // 'posture' | 'ai' | 'playbook' | 'features'

  // Network / Connection Status
  const [apiConnected, setApiConnected] = useState(true);
  const [errorMessage, setErrorMessage] = useState(null);

  // Telemetry & Victim VM States
  const [sensorStatus, setSensorStatus] = useState(null);
  const [systemLogs, setSystemLogs] = useState([]);
  const [systemLogStats, setSystemLogStats] = useState({});
  const [isUpdatingMode, setIsUpdatingMode] = useState(false);

  // Fetch High-Level Overview and System Health
  const fetchOverviewData = useCallback(async () => {
    try {
      const [ovRes, agRes, anRes, snRes] = await Promise.all([
        fetch(`${API_BASE}/overview`),
        fetch(`${API_BASE}/agents/status`),
        fetch(`${API_BASE}/analytics`),
        fetch(`${API_BASE}/sensor/status`)
      ]);

      if (ovRes.ok) setOverview(await ovRes.json());
      if (agRes.ok) {
        const agData = await agRes.json();
        setAgents(agData.agents || []);
      }
      if (anRes.ok) setAnalytics(await anRes.json());
      if (snRes.ok) setSensorStatus(await snRes.json());
      setApiConnected(true);
      setErrorMessage(null);
    } catch (err) {
      setApiConnected(false);
      setErrorMessage('Backend API disconnected. Ensure dashboard_api.py is running on port 8000.');
    }
  }, []);

  // Fetch Workspace Specific Feeds
  const fetchWorkspaceFeed = useCallback(async () => {
    try {
      let params = new URLSearchParams();
      params.append('limit', '60');
      if (filterSeverity !== 'ALL') params.append('severity', filterSeverity);
      if (filterCategory !== 'ALL') params.append('category', filterCategory);
      if (filterPrediction !== 'ALL') params.append('prediction', filterPrediction);
      if (searchTerm.trim()) params.append('search', searchTerm.trim());

      if (activeTab === 'overview') {
        const [incRes, thRes, alRes] = await Promise.all([
          fetch(`${API_BASE}/incidents?limit=20`),
          fetch(`${API_BASE}/threats?limit=20`),
          fetch(`${API_BASE}/alerts?limit=20`)
        ]);
        if (incRes.ok) setIncidents(await incRes.json());
        if (thRes.ok) setThreats(await thRes.json());
        if (alRes.ok) setAlerts(await alRes.json());
      } else if (activeTab === 'stream') {
        const res = await fetch(`${API_BASE}/events?${params.toString()}`);
        if (res.ok) setEvents(await res.json());
      } else if (activeTab === 'telemetry') {
        const [snRes, lgRes] = await Promise.all([
          fetch(`${API_BASE}/sensor/status`),
          fetch(`${API_BASE}/logs?limit=60`)
        ]);
        if (snRes.ok) setSensorStatus(await snRes.json());
        if (lgRes.ok) {
          const lgData = await lgRes.json();
          setSystemLogs(lgData.logs || []);
          setSystemLogStats(lgData.stats || {});
        }
      } else if (activeTab === 'ai_playbooks') {
        const [pbRes, incRes] = await Promise.all([
          fetch(`${API_BASE}/playbooks?limit=40`),
          fetch(`${API_BASE}/incidents?limit=20`)
        ]);
        if (pbRes.ok) {
          const pbData = await pbRes.json();
          setPlaybooks(pbData.playbooks || []);
          setPlaybookStats(pbData.stats || {});
        }
        if (incRes.ok) setIncidents(await incRes.json());
      } else if (activeTab === 'intel_analytics') {
        const [cacheRes, anRes] = await Promise.all([
          fetch(`${API_BASE}/intel/cache?limit=50`),
          fetch(`${API_BASE}/analytics`)
        ]);
        if (cacheRes.ok) setIntelData(await cacheRes.json());
        if (anRes.ok) setAnalytics(await anRes.json());
      }
      setLastRefreshed(new Date());
    } catch (err) {
      console.warn('Workspace feed fetch error:', err);
    }
  }, [activeTab, filterSeverity, filterCategory, filterPrediction, searchTerm]);

  // Telemetry Source Mode Switch Handler
  const handleModeChange = async (newMode) => {
    setIsUpdatingMode(true);
    try {
      const res = await fetch(`${API_BASE}/sensor/mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: newMode })
      });
      if (res.ok) {
        await fetchOverviewData();
        if (activeTab === 'telemetry') {
          await fetchWorkspaceFeed();
        }
      }
    } catch (err) {
      console.error('Failed to update telemetry mode:', err);
    } finally {
      setIsUpdatingMode(false);
    }
  };

  // Playbook Approval Handler
  const handleApprovePlaybook = async (playbookId, approved, targetName = '') => {
    if (approvingId) return;
    if (approved) {
      const confirmed = window.confirm(
        `CONFIRM RESPONSE APPROVAL (DRY-RUN MODE):\n\nApprove recommended SOC containment action for target: ${targetName || 'target host'}?\n\nThis will record analyst approval in the audit trail without executing destructive commands.`
      );
      if (!confirmed) return;
    }
    setApprovingId(playbookId);
    setActionError(null);
    setApprovalSuccessMsg(null);
    try {
      const res = await fetch(`${API_BASE}/playbooks/${playbookId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          approved: approved,
          notes: approved ? 'Approved by SOC Analyst via Dashboard' : 'Rejected by SOC Analyst',
          analyst_id: 'soc_analyst',
        }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Approval request failed.');
      }
      const updated = await res.json();
      setPlaybooks((prev) => prev.map((pb) => (pb.playbook_id === playbookId ? updated : pb)));
      setApprovalSuccessMsg(`Playbook ${playbookId.slice(0, 8)}... successfully ${approved ? 'APPROVED (DRY-RUN)' : 'REJECTED'}.`);
      setTimeout(() => setApprovalSuccessMsg(null), 4000);
    } catch (err) {
      setActionError(`Failed to update playbook: ${err.message}`);
    } finally {
      setApprovingId(null);
    }
  };

  // Master Refresh
  const handleRefresh = useCallback(() => {
    fetchOverviewData();
    fetchWorkspaceFeed();
  }, [fetchOverviewData, fetchWorkspaceFeed]);

  // Polling loop
  useEffect(() => {
    handleRefresh();
    if (!isLive) return;

    const timer = setInterval(() => {
      fetchOverviewData();
      fetchWorkspaceFeed();
    }, pollIntervalMs);

    return () => clearInterval(timer);
  }, [isLive, pollIntervalMs, handleRefresh, fetchOverviewData, fetchWorkspaceFeed]);

  // Fetch Event Detail on Selection
  useEffect(() => {
    if (!selectedEventId) {
      setEventDetail(null);
      return;
    }
    let cancelled = false;
    setDetailLoading(true);

    fetch(`${API_BASE}/events/${selectedEventId}`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
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

  // Format Helpers
  const getSeverityBadgeClass = (sev) => {
    switch ((sev || '').toUpperCase()) {
      case 'CRITICAL':
      case 'HIGH':
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
        return <span className="badge badge-info">{cat || 'Normal Baseline'}</span>;
    }
  };

  // Inspect Event Helper (Switches to Stream tab & opens drawer)
  const handleInspectEvent = (eventId) => {
    setSelectedEventId(eventId);
    setActiveTab('stream');
  };

  // Derive Overall Security Posture
  const posture = useMemo(() => {
    const critAlerts = overview?.critical_alerts || 0;
    const openIncs = overview?.open_incidents || 0;
    const threatsCount = overview?.threat_events || 0;

    if (critAlerts > 0 || openIncs > 0 || threatsCount > 0) {
      return {
        level: 'critical',
        title: 'CRITICAL SECURITY ALERT: Active Multi-Stage Threats Under Correlation',
        description: `${threatsCount} threat detections and ${openIncs} correlated multi-agent incidents detected. Immediate SOC triage advised.`,
        icon: <AlertOctagon size={24} color="#ef4444" />,
      };
    }
    if ((overview?.anomalous_events || 0) > 0) {
      return {
        level: 'warning',
        title: 'ELEVATED SURVEILLANCE: Network Baseline Outliers Active',
        description: `${overview.anomalous_events} statistical anomaly events detected. Supervised inspection active.`,
        icon: <AlertTriangle size={24} color="#f59e0b" />,
      };
    }
    return {
      level: 'safe',
      title: 'SYSTEM SECURE: Baseline Traffic Operational & Monitored',
      description: 'Continuous real-time multi-agent defense active. False positives suppressed; no active breaches.',
      icon: <ShieldCheck size={24} color="#10b981" />,
    };
  }, [overview]);

  return (
    <div className="dashboard-container">
      {/* 1. Header Bar */}
      <header className="dashboard-header glass-panel">
        <div className="brand-section">
          <div className="brand-icon">
            <ShieldAlert size={28} color="#38bdf8" />
          </div>
          <div>
            <h1 className="brand-title">
              MULTI-AGENT AI SOC PLATFORM
              <span className="badge badge-cyan font-mono" style={{ fontSize: '0.75rem', fontWeight: 600 }}>
                v2.5 ENHANCED
              </span>
            </h1>
            <p className="brand-subtitle">
              <span className={`pulsing-dot ${apiConnected ? 'pulsing-dot-green' : 'pulsing-dot-red'}`} />
              {apiConnected ? 'TELEMETRY STREAM: CONNECTED (PORT 8000)' : 'API DISCONNECTED'} | REAL-TIME SOC CORRELATION PIPELINE
            </p>
          </div>
        </div>

        <div className="header-controls">
          <button
            className={`btn-cyber ${isLive ? 'active' : ''}`}
            onClick={() => setIsLive(!isLive)}
            title={isLive ? 'Pause auto-updates' : 'Resume auto-updates'}
          >
            {isLive ? <Pause size={16} /> : <Play size={16} />}
            {isLive ? 'STREAMING ACTIVE' : 'STREAM PAUSED'}
          </button>

          <button className="btn-cyber" onClick={handleRefresh} title="Manual Refresh">
            <RefreshCw size={16} />
            REFRESH
          </button>

          <span className="badge badge-cyan font-mono" style={{ padding: '8px 12px' }}>
            LAST SYNC: {lastRefreshed.toLocaleTimeString()}
          </span>
        </div>
      </header>

      {/* 2. Security Posture Hero Banner */}
      <section className={`posture-banner ${posture.level}`}>
        <div className="posture-content">
          <div className="posture-icon" style={{ background: posture.level === 'critical' ? 'rgba(239, 68, 68, 0.2)' : posture.level === 'warning' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.2)' }}>
            {posture.icon}
          </div>
          <div>
            <div className="posture-headline">{posture.title}</div>
            <div className="posture-subtext">{posture.description}</div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
          <span className="badge badge-emerald font-mono">
            CONTENT INSPECTOR: ACTIVE
          </span>
          <span className="badge badge-purple font-mono">
            MITRE CORRELATION: READY
          </span>
          <button
            className="btn-cyber"
            onClick={() => setActiveTab(posture.level === 'critical' ? 'overview' : 'stream')}
            style={{ fontSize: '0.82rem', padding: '6px 14px' }}
          >
            {posture.level === 'critical' ? 'Review Attack Sequence' : 'Inspect Live Traffic'}
            <ArrowRight size={14} />
          </button>
        </div>
      </section>

      {/* 3. High-Readability KPI Metrics Grid */}
      <section className="metrics-grid">
        <div className="metric-card glass-panel" style={{ '--accent-color': 'var(--cyber-cyan)' }}>
          <div className="metric-header">
            <span className="metric-label">Total Ingested Events</span>
            <Activity size={20} color="var(--cyber-cyan)" />
          </div>
          <div className="metric-value">{overview ? overview.total_events.toLocaleString() : '—'}</div>
          <div className="metric-sub">Packets & telemetry logs processed</div>
        </div>

        <div className="metric-card glass-panel" style={{ '--accent-color': 'var(--cyber-green)' }}>
          <div className="metric-header">
            <span className="metric-label">Benign Baseline</span>
            <ShieldCheck size={20} color="var(--cyber-green)" />
          </div>
          <div className="metric-value">{overview ? overview.benign_events.toLocaleString() : '—'}</div>
          <div className="metric-sub">Verified benign traffic cleared</div>
        </div>

        <div className="metric-card glass-panel" style={{ '--accent-color': 'var(--cyber-red)' }}>
          <div className="metric-header">
            <span className="metric-label">Detected Threat Signatures</span>
            <ShieldAlert size={20} color="var(--cyber-red)" />
          </div>
          <div className="metric-value" style={{ color: (overview?.threat_events || 0) > 0 ? '#f87171' : '#ffffff' }}>
            {overview ? overview.threat_events.toLocaleString() : '—'}
          </div>
          <div className="metric-sub">Supervised network attack matches</div>
        </div>

        <div className="metric-card glass-panel" style={{ '--accent-color': 'var(--cyber-yellow)' }}>
          <div className="metric-header">
            <span className="metric-label">Statistical Anomalies</span>
            <Radio size={20} color="var(--cyber-yellow)" />
          </div>
          <div className="metric-value">{overview ? overview.anomalous_events.toLocaleString() : '—'}</div>
          <div className="metric-sub">Isolation Forest baseline deviations</div>
        </div>

        <div className="metric-card glass-panel" style={{ '--accent-color': '#f43f5e' }}>
          <div className="metric-header">
            <span className="metric-label">Critical Alerts</span>
            <AlertTriangle size={20} color="#f43f5e" />
          </div>
          <div className="metric-value" style={{ color: (overview?.critical_alerts || 0) > 0 ? '#fb7185' : '#ffffff' }}>
            {overview ? overview.critical_alerts.toLocaleString() : '—'}
          </div>
          <div className="metric-sub">High severity alerts recorded</div>
        </div>

        <div className="metric-card glass-panel" style={{ '--accent-color': '#a855f7' }}>
          <div className="metric-header">
            <span className="metric-label">Correlated Incidents</span>
            <Layers size={20} color="#a855f7" />
          </div>
          <div className="metric-value" style={{ color: (overview?.open_incidents || 0) > 0 ? '#c084fc' : '#ffffff' }}>
            {overview ? overview.open_incidents.toLocaleString() : '—'}
          </div>
          <div className="metric-sub">Multi-stage ATT&CK syntheses</div>
        </div>
      </section>

      {/* 4. Streamlined 5-Tab Operational Navigation */}
      <nav className="tabs-bar">
        <button
          className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          <Shield size={18} />
          Overview & Triage
          {(overview?.open_incidents || 0) > 0 && (
            <span className="tab-count" style={{ background: 'rgba(239, 68, 68, 0.3)', color: '#fca5a5' }}>
              {overview.open_incidents}
            </span>
          )}
        </button>

        <button
          className={`tab-btn ${activeTab === 'stream' ? 'active' : ''}`}
          onClick={() => setActiveTab('stream')}
        >
          <Activity size={18} />
          Live Flow Stream
          {events.length > 0 && <span className="tab-count">{events.length}</span>}
        </button>

        <button
          className={`tab-btn ${activeTab === 'telemetry' ? 'active' : ''}`}
          onClick={() => setActiveTab('telemetry')}
        >
          <Server size={18} />
          Host Telemetry & Logs
          <span className="tab-count" style={{ color: '#34d399' }}>
            {sensorStatus?.telemetry_mode ? sensorStatus.telemetry_mode.toUpperCase() : 'VM'}
          </span>
        </button>

        <button
          className={`tab-btn ${activeTab === 'ai_playbooks' ? 'active' : ''}`}
          onClick={() => setActiveTab('ai_playbooks')}
        >
          <Terminal size={18} />
          AI Reasoning & Playbooks
          {playbooks.filter((p) => p.status === 'PENDING_APPROVAL').length > 0 && (
            <span className="tab-count" style={{ background: 'rgba(234, 179, 8, 0.3)', color: '#fde047' }}>
              {playbooks.filter((p) => p.status === 'PENDING_APPROVAL').length}
            </span>
          )}
        </button>

        <button
          className={`tab-btn ${activeTab === 'intel_analytics' ? 'active' : ''}`}
          onClick={() => setActiveTab('intel_analytics')}
        >
          <Globe size={18} />
          Intelligence & Analytics
        </button>
      </nav>

      {/* =========================================================================
          TAB 1: OVERVIEW & TRIAGE COMMAND CENTER
          ========================================================================= */}
      {activeTab === 'overview' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
          {/* Active Multi-Stage ATT&CK Sequences Card */}
          <section className="table-panel">
            <div className="table-header-bar">
              <div className="table-title">
                <Layers size={20} color="var(--cyber-cyan)" />
                ACTIVE MITRE ATT&CK MULTI-STAGE PROGRESSIONS ({incidents.length})
              </div>
              <span className="badge badge-cyan font-mono">
                SLIDING-WINDOW TEMPORAL CORRELATION
              </span>
            </div>

            <div style={{ padding: '20px' }}>
              {incidents.length === 0 ? (
                <div style={{ padding: '36px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <ShieldCheck size={40} style={{ margin: '0 auto 12px auto', opacity: 0.5, color: '#10b981' }} />
                  <p style={{ fontSize: '0.95rem', fontWeight: 600, color: '#e2e8f0' }}>No Active Multi-Stage Attack Progressions</p>
                  <p style={{ fontSize: '0.85rem', marginTop: '4px' }}>
                    Temporal correlation engine is scanning live flows and host logs. Isolated events that do not form a multi-stage attack remain in baseline.
                  </p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  {incidents.map((inc) => {
                    const stages = [
                      { name: 'Reconnaissance', tech: 'T1046', label: 'Port Scan' },
                      { name: 'Initial Access', tech: 'T1110', label: 'SSH Brute Force' },
                      { name: 'Privilege Escalation', tech: 'T1068', label: 'Sudo Exploit' },
                      { name: 'Collection / Staging', tech: 'T1074', label: 'Sensitive Staging' },
                      { name: 'Exfiltration', tech: 'T1041', label: 'C2 Data Transfer' }
                    ];

                    const incidentReason = inc.correlation_reason || '';
                    const stageCount = inc.stages_count || 1;

                    return (
                      <div
                        key={inc.incident_id}
                        className="glass-panel"
                        style={{
                          padding: '18px 20px',
                          border: '1px solid rgba(239, 68, 68, 0.4)',
                          background: 'rgba(15, 23, 42, 0.75)',
                          borderRadius: '12px'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '14px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                            <span className="badge badge-high font-mono" style={{ fontSize: '0.85rem' }}>
                              INCIDENT: {inc.incident_id.slice(0, 12)}...
                            </span>
                            <span className={getSeverityBadgeClass(inc.severity)}>{inc.severity}</span>
                            <span className="badge badge-info font-mono">{inc.status}</span>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span className="font-mono text-muted" style={{ fontSize: '0.82rem' }}>
                              {inc.timestamp ? inc.timestamp.replace('T', ' ').slice(0, 19) : 'Active'}
                            </span>
                            {inc.event_id && (
                              <button
                                className="btn-cyber"
                                style={{ padding: '4px 12px', fontSize: '0.8rem' }}
                                onClick={() => handleInspectEvent(inc.event_id)}
                              >
                                <Eye size={14} /> Inspect Telemetry
                              </button>
                            )}
                          </div>
                        </div>

                        {/* MITRE 5-Stage Progression Bar */}
                        <div style={{ marginBottom: '16px' }}>
                          <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                            ATT&CK SEQUENCE PROGRESSION:
                          </div>
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px' }}>
                            {stages.map((st, sIdx) => {
                              const isActive = incidentReason.toLowerCase().includes(st.name.toLowerCase()) ||
                                               incidentReason.includes(st.tech) ||
                                               sIdx < stageCount;

                              return (
                                <div
                                  key={sIdx}
                                  style={{
                                    background: isActive ? 'rgba(239, 68, 68, 0.15)' : 'rgba(255, 255, 255, 0.03)',
                                    border: isActive ? '1px solid #ef4444' : '1px solid var(--border-subtle)',
                                    borderRadius: '8px',
                                    padding: '10px 12px'
                                  }}
                                >
                                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <span style={{ fontSize: '0.75rem', fontWeight: 700, color: isActive ? '#f87171' : 'var(--text-muted)' }}>
                                      STAGE {sIdx + 1}
                                    </span>
                                    <span className="badge font-mono" style={{ fontSize: '0.7rem', padding: '1px 6px', background: isActive ? 'rgba(239, 68, 68, 0.3)' : 'rgba(255, 255, 255, 0.05)', color: isActive ? '#fecaca' : 'var(--text-muted)' }}>
                                      {st.tech}
                                    </span>
                                  </div>
                                  <div style={{ fontSize: '0.85rem', fontWeight: 600, color: isActive ? '#ffffff' : 'var(--text-secondary)', marginTop: '4px' }}>
                                    {st.name}
                                  </div>
                                  <div style={{ fontSize: '0.78rem', color: isActive ? '#cbd5e1' : 'var(--text-muted)' }}>
                                    {st.label}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>

                        <div className="explanation-card" style={{ fontSize: '0.86rem' }}>
                          <strong>Correlation Narrative:</strong> {inc.correlation_reason}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </section>

          {/* High Priority Triage Feed & False Positive Clearance */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '20px' }}>
            {/* Priority Triage Queue */}
            <section className="table-panel">
              <div className="table-header-bar">
                <div className="table-title">
                  <AlertTriangle size={18} color="#f59e0b" />
                  HIGH-PRIORITY TRIAGE QUEUE ({threats.length})
                </div>
                <button
                  className="btn-cyber"
                  style={{ padding: '4px 10px', fontSize: '0.78rem' }}
                  onClick={() => setActiveTab('stream')}
                >
                  View All Flows <ChevronRight size={14} />
                </button>
              </div>

              <div className="table-container" style={{ maxHeight: '380px' }}>
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Posture Category</th>
                      <th>Severity</th>
                      <th>Explanation</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {threats.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                          No active threat alerts in triage queue.
                        </td>
                      </tr>
                    ) : (
                      threats.slice(0, 8).map((t) => (
                        <tr key={t.assessment_id}>
                          <td className="font-mono text-muted" style={{ whiteSpace: 'nowrap' }}>
                            {t.timestamp ? t.timestamp.replace('T', ' ').slice(11, 19) : '—'}
                          </td>
                          <td>{getCategoryBadge(t.category)}</td>
                          <td>
                            <span className={getSeverityBadgeClass(t.severity)}>{t.severity}</span>
                          </td>
                          <td style={{ maxWidth: '320px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={t.explanation}>
                            {t.explanation}
                          </td>
                          <td>
                            <button
                              className="btn-cyber"
                              style={{ padding: '3px 8px', fontSize: '0.75rem' }}
                              onClick={() => handleInspectEvent(t.event_id)}
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            {/* Content & Context False-Positive Suppression Banner */}
            <section className="table-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <ShieldCheck size={24} color="#10b981" />
                <div>
                  <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff', margin: 0 }}>
                    CONTENT & CONTEXT INSPECTION
                  </h3>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: 0 }}>
                    False-Positive Suppression & Data Loss Prevention Engine
                  </p>
                </div>
              </div>

              <div style={{ background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '10px', padding: '14px' }}>
                <div style={{ fontWeight: 600, color: '#34d399', fontSize: '0.9rem', marginBottom: '4px' }}>
                  GENUINE VOLUME AUTO-CLEARANCE
                </div>
                <p style={{ fontSize: '0.84rem', color: '#e2e8f0', margin: 0, lineHeight: 1.5 }}>
                  High-volume transfers matching routine file patterns, authorized backup destinations, or verified user activity are classified as <strong style={{ color: '#10b981' }}>GENUINE_USER_HIGH_VOLUME</strong>, preventing SOC alert fatigue.
                </p>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div className="detail-row">
                  <span className="detail-key">Sensitive Extension Filter:</span>
                  <span className="badge badge-emerald font-mono">.pem, .key, .sql, .kdbx</span>
                </div>
                <div className="detail-row">
                  <span className="detail-key">Process Lineage Validation:</span>
                  <span className="badge badge-cyan font-mono">SSH / RSYNC / SCP</span>
                </div>
                <div className="detail-row">
                  <span className="detail-key">Destination IP Profiling:</span>
                  <span className="badge badge-info font-mono">Internal & Cloud Backups</span>
                </div>
              </div>

              <button
                className="btn-cyber"
                style={{ width: '100%', justifyContent: 'center', marginTop: '6px' }}
                onClick={() => setActiveTab('stream')}
              >
                Inspect Flow Stream with Content Verdicts <ArrowRight size={14} />
              </button>
            </section>
          </div>

          {/* Agent Pipeline Operational Health Grid */}
          <section className="table-panel">
            <div className="table-header-bar">
              <div className="table-title">
                <Cpu size={18} color="var(--cyber-cyan)" />
                PIPELINE AGENT TOPOLOGY & OPERATIONAL STATUS ({agents.length} AGENTS)
              </div>
              <span className="badge badge-emerald font-mono">ALL AGENTS HEALTHY</span>
            </div>

            <div style={{ padding: '20px' }}>
              <div className="agents-grid">
                {agents.map((ag) => (
                  <div key={ag.id} className="agent-status-card">
                    <div className="agent-status-header">
                      <div>
                        <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#ffffff', margin: 0 }}>{ag.name}</h4>
                        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{ag.type}</span>
                      </div>
                      <span className={`badge ${ag.status === 'ACTIVE' || ag.status === 'ONLINE' ? 'badge-emerald' : 'badge-high'} font-mono`}>
                        {ag.status}
                      </span>
                    </div>

                    <div className="detail-row" style={{ fontSize: '0.82rem' }}>
                      <span className="detail-key">Engine Architecture:</span>
                      <span className="detail-val font-mono" style={{ color: 'var(--cyber-cyan)' }}>{ag.model}</span>
                    </div>

                    <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', background: 'rgba(255,255,255,0.02)', padding: '6px 10px', borderRadius: '6px' }}>
                      {ag.details}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </section>
        </div>
      )}

      {/* =========================================================================
          TAB 2: LIVE FLOW STREAM WORKSPACE
          ========================================================================= */}
      {activeTab === 'stream' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Search and Filters Bar */}
          <section className="filter-bar">
            <div className="search-input-group">
              <Search size={18} color="var(--text-muted)" />
              <input
                type="text"
                placeholder="Search flows by Event UUID, source host, or keyword..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>

            <div className="filter-selects">
              <select
                className="select-filter"
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">CRITICAL</option>
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
                <option value="Benign">Benign Baseline</option>
              </select>

              <select
                className="select-filter"
                value={filterPrediction}
                onChange={(e) => setFilterPrediction(e.target.value)}
              >
                <option value="ALL">All ML Predictions</option>
                <option value="Infilteration">Infiltration Attack</option>
                <option value="Benign">Benign Traffic</option>
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

          {/* Main 2-Column: Table on Left, Detail Drawer on Right */}
          <main className="main-two-col">
            {/* Table Panel */}
            <div className="table-panel">
              <div className="table-header-bar">
                <span className="table-title">
                  <Activity size={18} color="var(--cyber-cyan)" />
                  INGESTED NETWORK FLOWS ({events.length})
                </span>
                <span className="font-mono text-muted" style={{ fontSize: '0.8rem' }}>
                  Click row to inspect agent features & AI reasoning
                </span>
              </div>

              <div className="table-container">
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th style={{ width: '130px' }}>Timestamp</th>
                      <th style={{ width: '110px' }}>Event ID</th>
                      <th>Source Host</th>
                      <th>Network ML</th>
                      <th>Anomaly ML</th>
                      <th>Threat Posture</th>
                      <th>Severity</th>
                      <th style={{ textAlign: 'center' }}>Inspect</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.length === 0 ? (
                      <tr>
                        <td colSpan={8} style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
                          No flow records found matching criteria. Start replay producer or reset search filter.
                        </td>
                      </tr>
                    ) : (
                      events.map((ev) => {
                        const isSelected = selectedEventId === ev.event_id;
                        return (
                          <tr
                            key={ev.event_id}
                            className={isSelected ? 'selected' : ''}
                            onClick={() => setSelectedEventId(ev.event_id)}
                          >
                            <td className="font-mono" style={{ fontSize: '0.82rem', whiteSpace: 'nowrap' }}>
                              {ev.timestamp ? ev.timestamp.replace('T', ' ').slice(11, 19) : '—'}
                            </td>
                            <td className="font-mono" style={{ color: 'var(--cyber-cyan)', fontWeight: 600 }}>
                              {ev.event_id.slice(0, 8)}...
                            </td>
                            <td>
                              <span className="badge badge-info font-mono" style={{ fontSize: '0.75rem' }}>
                                {ev.source || 'simulated_tap'}
                              </span>
                            </td>
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
                            <td style={{ textAlign: 'center' }}>
                              <button
                                className={`btn-cyber ${isSelected ? 'active' : ''}`}
                                style={{ padding: '3px 8px', fontSize: '0.75rem' }}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedEventId(ev.event_id);
                                }}
                              >
                                <Eye size={13} />
                              </button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Event Detail Inspector Drawer */}
            <aside className="detail-panel">
              <div className="detail-header">
                <div>
                  <div className="detail-title">FLOW TELEMETRY INSPECTOR</div>
                  <div className="detail-subtitle">
                    {selectedEventId ? `EVENT: ${selectedEventId}` : 'Select a record from table'}
                  </div>
                </div>
                {selectedEventId && (
                  <button
                    className="btn-cyber"
                    style={{ padding: '4px 10px', fontSize: '0.78rem' }}
                    onClick={() => setSelectedEventId(null)}
                  >
                    Close
                  </button>
                )}
              </div>

              {!selectedEventId ? (
                <div style={{ padding: '48px 16px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <Eye size={42} style={{ margin: '0 auto 14px auto', opacity: 0.35, color: 'var(--cyber-cyan)' }} />
                  <p style={{ fontWeight: 600, color: '#cbd5e1' }}>No Flow Record Selected</p>
                  <p style={{ fontSize: '0.85rem', marginTop: '6px' }}>
                    Click on any row in the network flow stream to inspect multi-agent predictions, Google Gemini reasoning, and raw 78-feature vector.
                  </p>
                </div>
              ) : detailLoading ? (
                <div style={{ padding: '48px 16px', textAlign: 'center' }}>
                  <span className="pulsing-dot" /> Loading flow telemetry...
                </div>
              ) : eventDetail ? (
                <>
                  {/* Inspector Internal Navigation */}
                  <div style={{ display: 'flex', gap: '6px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
                    <button
                      className={`btn-cyber ${inspectorSubTab === 'posture' ? 'active' : ''}`}
                      style={{ fontSize: '0.8rem', padding: '5px 10px' }}
                      onClick={() => setInspectorSubTab('posture')}
                    >
                      Unified Posture
                    </button>
                    <button
                      className={`btn-cyber ${inspectorSubTab === 'ai' ? 'active' : ''}`}
                      style={{ fontSize: '0.8rem', padding: '5px 10px' }}
                      onClick={() => setInspectorSubTab('ai')}
                    >
                      Gemini AI
                    </button>
                    <button
                      className={`btn-cyber ${inspectorSubTab === 'playbook' ? 'active' : ''}`}
                      style={{ fontSize: '0.8rem', padding: '5px 10px' }}
                      onClick={() => setInspectorSubTab('playbook')}
                    >
                      Response Plan
                    </button>
                    <button
                      className={`btn-cyber ${inspectorSubTab === 'features' ? 'active' : ''}`}
                      style={{ fontSize: '0.8rem', padding: '5px 10px' }}
                      onClick={() => setInspectorSubTab('features')}
                    >
                      Raw Features
                    </button>
                  </div>

                  {/* Sub-tab 1: Posture & Investigation */}
                  {inspectorSubTab === 'posture' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                      <div>
                        <div className="detail-section-title">STAGE 9A UNIFIED POSTURE</div>
                        {eventDetail.threat_assessment ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <div className="detail-row">
                              <span className="detail-key">Assigned Category:</span>
                              <span>{getCategoryBadge(eventDetail.threat_assessment.category)}</span>
                            </div>
                            <div className="detail-row">
                              <span className="detail-key">Severity Level:</span>
                              <span className={getSeverityBadgeClass(eventDetail.threat_assessment.severity)}>
                                {eventDetail.threat_assessment.severity}
                              </span>
                            </div>
                            <div className="detail-row">
                              <span className="detail-key">Decision Method:</span>
                              <span className="detail-val font-mono">Stage 9A Policy Matrix</span>
                            </div>
                            <div className="explanation-card">
                              <strong>Decision Rationale:</strong> {eventDetail.threat_assessment.explanation}
                            </div>
                          </div>
                        ) : (
                          <div className="explanation-card text-muted">
                            No unified assessment recorded for this flow yet.
                          </div>
                        )}
                      </div>

                      {/* Agent Prediction Breakdown */}
                      <div>
                        <div className="detail-section-title">AGENT PREDICTION BREAKDOWN</div>
                        {eventDetail.alerts && eventDetail.alerts.length > 0 ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            {eventDetail.alerts.map((al, idx) => (
                              <div
                                key={idx}
                                style={{
                                  background: 'rgba(11, 15, 25, 0.6)',
                                  borderRadius: '8px',
                                  padding: '10px 12px',
                                  border: '1px solid var(--border-subtle)'
                                }}
                              >
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                                  <strong style={{ fontSize: '0.86rem', color: '#ffffff' }}>{al.agent}</strong>
                                  <span className={getSeverityBadgeClass(al.severity)}>{al.severity}</span>
                                </div>
                                <div className="detail-row" style={{ fontSize: '0.82rem' }}>
                                  <span className="detail-key">Classification:</span>
                                  <span className="detail-val">{al.prediction}</span>
                                </div>
                                <div className="detail-row" style={{ fontSize: '0.82rem' }}>
                                  <span className="detail-key">Score / Confidence:</span>
                                  <span className="detail-val font-mono">
                                    {al.confidence !== null && al.confidence !== undefined
                                      ? al.agent.includes('Anomaly')
                                        ? Number(al.confidence).toFixed(6)
                                        : `${(Number(al.confidence) * 100).toFixed(2)}%`
                                      : 'N/A'}
                                  </span>
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="explanation-card text-muted">No individual alerts recorded.</div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Sub-tab 2: Google Gemini AI Reasoning */}
                  {inspectorSubTab === 'ai' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                      <div className="detail-section-title">GOOGLE GEMINI FLASH REASONING</div>
                      {eventDetail.llm_reasoning ? (
                        <div style={{ background: 'rgba(56, 189, 248, 0.08)', border: '1px solid rgba(56, 189, 248, 0.3)', borderRadius: '10px', padding: '14px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: '0.86rem', fontWeight: 700, color: '#38bdf8' }}>
                              {eventDetail.llm_reasoning.model_name || 'gemini-2.5-flash'}
                            </span>
                            <span className="badge badge-emerald font-mono">
                              {eventDetail.llm_reasoning.status}
                            </span>
                          </div>

                          <div className="explanation-card" style={{ background: 'rgba(11, 15, 25, 0.8)' }}>
                            <strong>Incident Narrative:</strong> {eventDetail.llm_reasoning.summary}
                          </div>

                          <div className="detail-row">
                            <span className="detail-key">Likely Attack:</span>
                            <span className="detail-val" style={{ color: '#f87171' }}>
                              {eventDetail.llm_reasoning.likely_attack}
                            </span>
                          </div>

                          <div className="detail-row">
                            <span className="detail-key">Calibrated Confidence:</span>
                            <span className="detail-val font-mono">
                              {(eventDetail.llm_reasoning.confidence * 100).toFixed(1)}%
                            </span>
                          </div>

                          {eventDetail.llm_reasoning.mitre_techniques?.length > 0 && (
                            <div>
                              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>MITRE ATT&CK Techniques:</span>
                              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '6px' }}>
                                {eventDetail.llm_reasoning.mitre_techniques.map((tech, tIdx) => (
                                  <span key={tIdx} className="badge badge-info font-mono">{tech}</span>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="explanation-card text-muted">
                          No Gemini AI narrative generated for this event. AI reasoning triggers on suspected or confirmed threat events.
                        </div>
                      )}
                    </div>
                  )}

                  {/* Sub-tab 3: Response Playbook */}
                  {inspectorSubTab === 'playbook' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                      <div className="detail-section-title">RECOMMENDED RESPONSE PLAYBOOK</div>
                      {eventDetail.playbook ? (
                        <div style={{ background: 'rgba(234, 179, 8, 0.08)', border: '1px solid rgba(234, 179, 8, 0.3)', borderRadius: '10px', padding: '14px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span className="badge badge-amber font-mono">
                              RULE: {eventDetail.playbook.rule_id}
                            </span>
                            <span className={`badge ${eventDetail.playbook.status === 'APPROVED' ? 'badge-emerald' : 'badge-high'} font-mono`}>
                              {eventDetail.playbook.status}
                            </span>
                          </div>

                          <div className="detail-row">
                            <span className="detail-key">Execution Mode:</span>
                            <span className="badge badge-info font-mono">DRY-RUN ENFORCED</span>
                          </div>

                          <div>
                            <strong style={{ fontSize: '0.84rem', color: '#fde047' }}>Recommended Response Actions:</strong>
                            <ul style={{ paddingLeft: '18px', marginTop: '6px', fontSize: '0.84rem', color: '#e2e8f0' }}>
                              {eventDetail.playbook.recommended_actions?.map((act, idx) => (
                                <li key={idx} style={{ marginBottom: '6px' }}>
                                  <strong>{act.action}</strong> ({act.target}): {act.rationale}
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      ) : (
                        <div className="explanation-card text-muted">
                          No autonomous response playbook generated for this event. Playbooks trigger on corroborated alerts and incidents.
                        </div>
                      )}
                    </div>
                  )}

                  {/* Sub-tab 4: Raw 78-Feature Vector */}
                  {inspectorSubTab === 'features' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                      <div className="detail-section-title">CANONICAL 78-FEATURE VECTOR (SAMPLE)</div>
                      <div
                        style={{
                          maxHeight: '340px',
                          overflowY: 'auto',
                          background: '#070a0f',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: '8px',
                          padding: '12px',
                          fontSize: '0.8rem',
                          fontFamily: 'var(--font-mono)'
                        }}
                      >
                        {eventDetail.event && eventDetail.event.features ? (
                          Object.entries(eventDetail.event.features).map(([k, v]) => (
                            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0', borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                              <span style={{ color: 'var(--text-secondary)' }}>{k}:</span>
                              <span style={{ color: '#38bdf8', fontWeight: 600 }}>{String(v)}</span>
                            </div>
                          ))
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>No features available</span>
                        )}
                      </div>
                    </div>
                  )}
                </>
              ) : null}
            </aside>
          </main>
        </div>
      )}

      {/* =========================================================================
          TAB 3: HOST TELEMETRY & VICTIM VM LOGS
          ========================================================================= */}
      {activeTab === 'telemetry' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
          {/* Telemetry Source Selector */}
          <section className="table-panel" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
              <div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--cyber-cyan)', margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Server size={20} /> TELEMETRY INGEST SOURCE MODE
                </h3>
                <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', marginTop: '4px', margin: 0 }}>
                  Select the active telemetry ingest pipeline. Historical dataset replay and live victim VM sensors run independently.
                </p>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="badge badge-cyan font-mono" style={{ fontSize: '0.85rem' }}>
                  ACTIVE: {(sensorStatus?.telemetry_mode || 'replay').toUpperCase()}
                </span>
                {isUpdatingMode && <span className="pulsing-dot" title="Switching mode..." />}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px' }}>
              {/* Option 1: Historical Replay */}
              <div
                className="glass-panel"
                style={{
                  padding: '16px 18px',
                  borderRadius: '10px',
                  cursor: 'pointer',
                  background: sensorStatus?.telemetry_mode === 'replay' ? 'rgba(56, 189, 248, 0.12)' : 'rgba(255, 255, 255, 0.02)',
                  borderColor: sensorStatus?.telemetry_mode === 'replay' ? 'var(--cyber-cyan)' : 'var(--border-subtle)',
                  transition: 'all var(--transition-fast)'
                }}
                onClick={() => handleModeChange('replay')}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontWeight: 700, color: '#ffffff', fontSize: '0.95rem' }}>1. Historical Replay</span>
                  <span className={`badge ${sensorStatus?.telemetry_mode === 'replay' ? 'badge-cyan' : 'badge-subtle'} font-mono`}>
                    {sensorStatus?.telemetry_mode === 'replay' ? 'CURRENT' : 'SELECT'}
                  </span>
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  Streams sanitized CICIDS2017 benchmark dataset records for reproducible offline testing and validation.
                </div>
              </div>

              {/* Option 2: Live VM Logs */}
              <div
                className="glass-panel"
                style={{
                  padding: '16px 18px',
                  borderRadius: '10px',
                  cursor: 'pointer',
                  background: sensorStatus?.telemetry_mode === 'vm_logs' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(255, 255, 255, 0.02)',
                  borderColor: sensorStatus?.telemetry_mode === 'vm_logs' ? '#10b981' : 'var(--border-subtle)',
                  transition: 'all var(--transition-fast)'
                }}
                onClick={() => handleModeChange('vm_logs')}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontWeight: 700, color: '#ffffff', fontSize: '0.95rem' }}>2. Live VM Logs</span>
                  <span className={`badge ${sensorStatus?.telemetry_mode === 'vm_logs' ? 'badge-emerald' : 'badge-subtle'} font-mono`}>
                    {sensorStatus?.telemetry_mode === 'vm_logs' ? 'CURRENT' : 'SELECT'}
                  </span>
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  Streams real-time SSH auth failures, sudo command executions, and auth.log events from victim VM.
                </div>
              </div>

              {/* Option 3: Live VM Flows */}
              <div
                className="glass-panel"
                style={{
                  padding: '16px 18px',
                  borderRadius: '10px',
                  cursor: 'pointer',
                  background: sensorStatus?.telemetry_mode === 'vm_flows' ? 'rgba(168, 85, 247, 0.12)' : 'rgba(255, 255, 255, 0.02)',
                  borderColor: sensorStatus?.telemetry_mode === 'vm_flows' ? '#a855f7' : 'var(--border-subtle)',
                  transition: 'all var(--transition-fast)'
                }}
                onClick={() => handleModeChange('vm_flows')}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontWeight: 700, color: '#ffffff', fontSize: '0.95rem' }}>3. Live VM Flows</span>
                  <span className={`badge ${sensorStatus?.telemetry_mode === 'vm_flows' ? 'badge-purple' : 'badge-subtle'} font-mono`}>
                    {sensorStatus?.telemetry_mode === 'vm_flows' ? 'CURRENT' : 'SELECT'}
                  </span>
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  Ingests live 78-feature network flows extracted from remote victim VM packet taps.
                </div>
              </div>

              {/* Option 4: Live Dual Telemetry */}
              <div
                className="glass-panel"
                style={{
                  padding: '16px 18px',
                  borderRadius: '10px',
                  cursor: 'pointer',
                  background: sensorStatus?.telemetry_mode === 'vm_all' ? 'rgba(16, 185, 129, 0.16)' : 'rgba(255, 255, 255, 0.02)',
                  borderColor: sensorStatus?.telemetry_mode === 'vm_all' ? '#10b981' : 'var(--border-subtle)',
                  transition: 'all var(--transition-fast)'
                }}
                onClick={() => handleModeChange('vm_all')}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontWeight: 700, color: '#ffffff', fontSize: '0.95rem' }}>4. Live Dual (Logs + Flows)</span>
                  <span className={`badge ${sensorStatus?.telemetry_mode === 'vm_all' ? 'badge-emerald' : 'badge-subtle'} font-mono`}>
                    {sensorStatus?.telemetry_mode === 'vm_all' ? 'CURRENT' : 'SELECT'}
                  </span>
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  Simultaneously ingests host security logs and network flow events for full kill-chain defense.
                </div>
              </div>
            </div>
          </section>

          {/* Victim Connection Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
            <div className="table-panel" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span style={{ fontWeight: 700, color: '#ffffff', fontSize: '0.95rem' }}>REMOTE VICTIM IDENTITY</span>
                <span className="badge badge-emerald font-mono">SSH READY</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '0.86rem' }}>
                <div className="detail-row">
                  <span className="detail-key">Victim Host:</span>
                  <span className="detail-val font-mono" style={{ color: 'var(--cyber-cyan)' }}>
                    {sensorStatus?.victim_host || '45.74.156.54'}
                  </span>
                </div>
                <div className="detail-row">
                  <span className="detail-key">Private Network IP:</span>
                  <span className="detail-val font-mono">10.0.0.12</span>
                </div>
                <div className="detail-row">
                  <span className="detail-key">Host-Key Security:</span>
                  <span className="detail-val font-mono" style={{ color: '#10b981' }}>Strict (known_hosts)</span>
                </div>
              </div>
            </div>

            <div className="table-panel" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span style={{ fontWeight: 700, color: '#ffffff', fontSize: '0.95rem' }}>REVERSE SSH TUNNEL</span>
                <span className="badge badge-cyan font-mono">PORT 18000</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '0.86rem' }}>
                <div className="detail-row">
                  <span className="detail-key">Remote Ingest Port:</span>
                  <span className="detail-val font-mono" style={{ color: '#7dd3fc' }}>127.0.0.1:18000</span>
                </div>
                <div className="detail-row">
                  <span className="detail-key">Local SOC API:</span>
                  <span className="detail-val font-mono">127.0.0.1:8000</span>
                </div>
                <div className="detail-row">
                  <span className="detail-key">Public Port Exposure:</span>
                  <span className="detail-val font-mono" style={{ color: '#10b981' }}>NONE (Air-Gapped)</span>
                </div>
              </div>
            </div>

            <div className="table-panel" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span style={{ fontWeight: 700, color: '#ffffff', fontSize: '0.95rem' }}>COLLECTOR LIFECYCLE</span>
                <span className={`badge ${sensorStatus?.collector_state?.is_running ? 'badge-emerald' : 'badge-subtle'} font-mono`}>
                  {sensorStatus?.collector_state?.is_running ? 'RUNNING' : 'STANDBY'}
                </span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '0.86rem' }}>
                <div className="detail-row">
                  <span className="detail-key">System Logs Ingested:</span>
                  <span className="detail-val font-mono" style={{ color: '#10b981' }}>
                    {(sensorStatus?.collector_state?.total_logs_collected || sensorStatus?.logs_summary?.total_logs || systemLogs.length).toLocaleString()}
                  </span>
                </div>
                <div className="detail-row">
                  <span className="detail-key">Flows Accepted (201):</span>
                  <span className="detail-val font-mono" style={{ color: 'var(--cyber-cyan)' }}>
                    {(sensorStatus?.collector_state?.total_flows_accepted || 0).toLocaleString()}
                  </span>
                </div>
                <div className="detail-row">
                  <span className="detail-key">Rejections / Dups:</span>
                  <span className="detail-val font-mono" style={{ color: '#f59e0b' }}>
                    {sensorStatus?.collector_state?.total_flows_duplicated || 0} / {sensorStatus?.collector_state?.total_flows_rejected || 0}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Real-time Ubuntu System Logs Feed */}
          <section className="table-panel">
            <div className="table-header-bar">
              <span className="table-title">
                <Terminal size={18} color="#10b981" />
                LIVE NORMALIZED UBUNTU SYSTEM LOGS FEED ({systemLogs.length})
              </span>
              <button
                className="btn-cyber"
                style={{ padding: '4px 12px', fontSize: '0.8rem' }}
                onClick={() => fetchWorkspaceFeed()}
              >
                <RefreshCw size={14} /> Refresh Logs
              </button>
            </div>

            <div className="table-container">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th style={{ width: '130px' }}>Timestamp</th>
                    <th>Service</th>
                    <th>Classification</th>
                    <th>Severity</th>
                    <th>Log Message</th>
                    <th>Origin Host</th>
                  </tr>
                </thead>
                <tbody>
                  {systemLogs.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
                        No system logs recorded. Start the remote collector with:
                        <div style={{ marginTop: '8px', fontFamily: 'monospace', color: 'var(--cyber-cyan)' }}>
                          python -m agents.vm_sensor --mode vm_logs
                        </div>
                      </td>
                    </tr>
                  ) : (
                    systemLogs.map((log) => {
                      const isAuthFail = log.log_type === 'AUTH_FAILURE' || log.log_type === 'INVALID_USER';
                      const isSudo = log.log_type === 'SUDO_EXEC';
                      const isSuccess = log.log_type === 'AUTH_SUCCESS';

                      let badgeClass = 'badge-info';
                      if (isAuthFail) badgeClass = 'badge-high';
                      else if (isSudo) badgeClass = 'badge-medium';
                      else if (isSuccess) badgeClass = 'badge-low';

                      return (
                        <tr key={log.log_id || log.id}>
                          <td className="font-mono text-muted" style={{ whiteSpace: 'nowrap' }}>
                            {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '—'}
                          </td>
                          <td className="font-mono" style={{ color: 'var(--cyber-cyan)', fontWeight: 600 }}>
                            {log.service}
                          </td>
                          <td>
                            <span className={`badge ${badgeClass} font-mono`}>
                              {log.log_type}
                            </span>
                          </td>
                          <td>
                            <span className={getSeverityBadgeClass(log.severity)}>
                              {log.severity}
                            </span>
                          </td>
                          <td style={{ maxWidth: '480px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: '#cbd5e1' }} title={log.message}>
                            {log.message}
                          </td>
                          <td className="font-mono text-muted" style={{ fontSize: '0.8rem' }}>
                            {log.source_host}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}

      {/* =========================================================================
          TAB 4: AI REASONING & RESPONSE PLAYBOOKS
          ========================================================================= */}
      {activeTab === 'ai_playbooks' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
          {/* Header Notice */}
          <section className="table-panel" style={{ padding: '22px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
              <div>
                <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#facc15', margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Terminal size={22} color="#facc15" />
                  RESPONSE PLAYBOOKS & GOOGLE GEMINI FLASH REASONING
                </h2>
                <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginTop: '4px', margin: 0 }}>
                  Automated policy-validated response plans generated from correlated attack sequences. Containment actions enforce human-in-the-loop analyst approval.
                </p>
              </div>

              <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                <span className="badge badge-info font-mono" style={{ padding: '6px 12px' }}>
                  SAFETY: DRY-RUN ENFORCED
                </span>
                <span className="badge badge-cyan font-mono" style={{ padding: '6px 12px' }}>
                  PLAYBOOKS: {playbooks.length}
                </span>
              </div>
            </div>

            {approvalSuccessMsg && (
              <div style={{ marginTop: '14px', padding: '12px 16px', background: 'rgba(16, 185, 129, 0.15)', border: '1px solid #10b981', borderRadius: '8px', color: '#6ee7b7', fontSize: '0.9rem' }}>
                {approvalSuccessMsg}
              </div>
            )}
            {actionError && (
              <div style={{ marginTop: '14px', padding: '12px 16px', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', borderRadius: '8px', color: '#fca5a5', fontSize: '0.9rem' }}>
                {actionError}
              </div>
            )}
          </section>

          {/* Playbooks Feed */}
          {playbooks.length === 0 ? (
            <div className="table-panel" style={{ padding: '50px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <Terminal size={40} style={{ margin: '0 auto 12px auto', opacity: 0.4, color: '#facc15' }} />
              <p style={{ fontSize: '1rem', fontWeight: 600, color: '#e2e8f0' }}>No Response Playbooks Generated Yet</p>
              <p style={{ fontSize: '0.85rem', marginTop: '4px' }}>
                Correlated multi-stage attack incidents automatically generate response playbooks with Gemini Flash reasoning.
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              {playbooks.map((pb) => {
                const isPending = pb.status === 'PENDING_APPROVAL';
                const isApproved = pb.status === 'APPROVED';
                const isRejected = pb.status === 'REJECTED';
                const llmMeta = pb.llm_metadata || {};

                return (
                  <div key={pb.playbook_id} className="playbook-card">
                    {/* Header */}
                    <div className="playbook-header">
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
                        <span className="font-mono" style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff' }}>
                          PLAYBOOK: {pb.playbook_id?.slice(0, 16)}...
                        </span>
                        <span className={getSeverityBadgeClass(pb.severity)}>{pb.severity}</span>
                        <span className="badge badge-info">{pb.threat_category}</span>
                        <span
                          className="badge font-mono"
                          style={{
                            background: isPending ? 'rgba(234, 179, 8, 0.2)' : isApproved ? 'rgba(16, 185, 129, 0.2)' : 'rgba(148, 163, 184, 0.2)',
                            color: isPending ? '#facc15' : isApproved ? '#34d399' : '#94a3b8',
                            border: isPending ? '1px solid #facc15' : isApproved ? '1px solid #34d399' : '1px solid #94a3b8'
                          }}
                        >
                          STATUS: {pb.status}
                        </span>
                      </div>

                      {/* Action buttons */}
                      {isPending && (
                        <div style={{ display: 'flex', gap: '10px' }}>
                          <button
                            className="btn btn-primary"
                            style={{ background: '#10b981', borderColor: '#059669', color: '#ffffff', padding: '8px 16px', fontSize: '0.85rem' }}
                            disabled={approvingId === pb.playbook_id}
                            onClick={() => handleApprovePlaybook(pb.playbook_id, true, pb.event_id)}
                          >
                            <CheckCircle2 size={16} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
                            {approvingId === pb.playbook_id ? 'Recording...' : 'APPROVE (DRY-RUN)'}
                          </button>
                          <button
                            className="btn btn-danger"
                            style={{ padding: '8px 16px', fontSize: '0.85rem' }}
                            disabled={approvingId === pb.playbook_id}
                            onClick={() => handleApprovePlaybook(pb.playbook_id, false, pb.event_id)}
                          >
                            <XCircle size={16} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
                            REJECT
                          </button>
                        </div>
                      )}
                      {isApproved && (
                        <span style={{ fontSize: '0.88rem', color: '#34d399', display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600 }}>
                          <CheckCircle2 size={18} /> Analyst Approved (Dry-Run Audit Trail Logged)
                        </span>
                      )}
                      {isRejected && (
                        <span style={{ fontSize: '0.88rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <XCircle size={18} /> Analyst Rejected
                        </span>
                      )}
                    </div>

                    {/* Metadata */}
                    <div style={{ fontSize: '0.84rem', color: 'var(--text-muted)' }}>
                      Triggering Event: <button className="font-mono" onClick={() => handleInspectEvent(pb.event_id)} style={{ color: 'var(--cyber-cyan)', textDecoration: 'underline', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>{pb.event_id}</button> | Rule: <span className="font-mono">{pb.rule_id}</span> | Created: {pb.created_at?.slice(0, 19).replace('T', ' ')}
                    </div>

                    {/* Google Gemini Reasoning */}
                    {llmMeta && (llmMeta.summary || llmMeta.model_name) && (
                      <div style={{ background: 'rgba(56, 189, 248, 0.08)', border: '1px solid rgba(56, 189, 248, 0.25)', borderRadius: '10px', padding: '14px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                          <span style={{ fontSize: '0.88rem', fontWeight: 700, color: '#38bdf8' }}>
                            GOOGLE GEMINI FLASH INCIDENT NARRATIVE ({llmMeta.model_name || 'gemini-2.5-flash'})
                          </span>
                          <span className="badge badge-emerald font-mono">{llmMeta.status || 'SUCCESS'}</span>
                        </div>
                        {llmMeta.summary && (
                          <p style={{ fontSize: '0.88rem', color: '#e2e8f0', margin: 0, lineHeight: 1.5 }}>
                            {llmMeta.summary}
                          </p>
                        )}
                        {llmMeta.mitre_techniques?.length > 0 && (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '10px' }}>
                            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>MITRE ATT&CK:</span>
                            {llmMeta.mitre_techniques.map((tech, tIdx) => (
                              <span key={tIdx} className="badge badge-info font-mono">{tech}</span>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Response Actions */}
                    <div>
                      <h4 style={{ fontSize: '0.92rem', fontWeight: 700, color: '#ffffff', marginBottom: '10px' }}>
                        RECOMMENDED CONTAINMENT ACTIONS ({pb.recommended_actions?.length || 0})
                      </h4>
                      <div className="table-container">
                        <table className="cyber-table" style={{ fontSize: '0.85rem' }}>
                          <thead>
                            <tr>
                              <th>Action Type</th>
                              <th>Target</th>
                              <th>Operational Rationale</th>
                              <th>Priority</th>
                              <th>Approval Needed</th>
                              <th>Execution Mode</th>
                            </tr>
                          </thead>
                          <tbody>
                            {pb.recommended_actions?.map((act, aIdx) => (
                              <tr key={aIdx}>
                                <td className="font-mono" style={{ color: '#facc15', fontWeight: 600 }}>{act.action}</td>
                                <td className="font-mono">{act.target}</td>
                                <td style={{ color: '#cbd5e1' }}>{act.rationale}</td>
                                <td>
                                  <span className={getSeverityBadgeClass(act.priority)}>{act.priority || 'MEDIUM'}</span>
                                </td>
                                <td>
                                  {act.requires_manual_approval ? (
                                    <span className="badge badge-high font-mono">REQUIRED</span>
                                  ) : (
                                    <span className="badge badge-low font-mono">AUTO</span>
                                  )}
                                </td>
                                <td>
                                  <span className="badge badge-info font-mono">DRY_RUN</span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
          TAB 5: THREAT INTELLIGENCE & ANALYTICS
          ========================================================================= */}
      {activeTab === 'intel_analytics' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
          {/* IOC Console */}
          <section className="table-panel" style={{ padding: '20px' }}>
            <h3 style={{ fontSize: '1.15rem', marginBottom: '8px', fontWeight: 700, color: 'var(--cyber-cyan)', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Search size={20} color="var(--cyber-cyan)" /> OBSERVABLE INDICATOR LOOKUP CONSOLE
            </h3>
            <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              Query IP addresses or port services against configured Threat Intelligence providers with SQLite caching and TTL enforcement.
            </p>

            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '16px' }}>
              <input
                type="text"
                placeholder="Enter indicator (e.g. 198.51.100.1, 4444)..."
                value={intelQueryInput}
                onChange={(e) => setIntelQueryInput(e.target.value)}
                style={{
                  flex: 1,
                  minWidth: '260px',
                  background: 'rgba(11, 15, 25, 0.7)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  padding: '9px 14px',
                  color: '#ffffff',
                  fontSize: '0.9rem',
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
                className="btn-cyber active"
                disabled={!intelQueryInput.trim() || intelQueryLoading}
                onClick={async () => {
                  setIntelQueryLoading(true);
                  try {
                    const res = await fetch(
                      `${API_BASE}/intel/lookup?indicator=${encodeURIComponent(intelQueryInput.trim())}&type=${intelQueryType}&provider=${intelQueryProvider}`
                    );
                    if (res.ok) {
                      setIntelQueryResult(await res.json());
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
              <div style={{ background: 'rgba(15, 23, 42, 0.85)', border: '1px solid rgba(56, 189, 248, 0.4)', borderRadius: '10px', padding: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px', flexWrap: 'wrap', gap: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span className="font-mono" style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff' }}>
                      {intelQueryResult.indicator_type?.toUpperCase()}: {intelQueryResult.indicator_value}
                    </span>
                    <span className={`badge ${intelQueryResult.verdict === 'MALICIOUS' ? 'badge-high' : intelQueryResult.verdict === 'SUSPICIOUS' ? 'badge-medium' : 'badge-low'}`}>
                      {intelQueryResult.verdict}
                    </span>
                    {intelQueryResult.cache_hit && <span className="badge badge-info">CACHE HIT</span>}
                  </div>
                  <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                    Provider: {intelQueryResult.provider}
                  </span>
                </div>

                {intelQueryResult.reputation_score !== null && (
                  <div className="detail-row">
                    <span className="detail-key">Reputation / Risk Score:</span>
                    <span className="detail-val font-mono">{intelQueryResult.reputation_score}</span>
                  </div>
                )}
              </div>
            )}
          </section>

          {/* Cached IOCs Feed */}
          <section className="table-panel">
            <div className="table-header-bar">
              <span className="table-title">
                <Database size={18} color="var(--cyber-cyan)" />
                CACHED THREAT INTELLIGENCE INDICATORS ({intelData.items?.length || 0})
              </span>
              <span className="badge badge-cyan font-mono">SQLITE IOC STORE</span>
            </div>

            <div className="table-container">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Indicator Value</th>
                    <th>Provider</th>
                    <th>Verdict</th>
                    <th>Score</th>
                    <th>Status</th>
                    <th>Last Checked</th>
                  </tr>
                </thead>
                <tbody>
                  {!intelData.items || intelData.items.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                        No cached indicators recorded yet.
                      </td>
                    </tr>
                  ) : (
                    intelData.items.map((row) => (
                      <tr key={row.id}>
                        <td className="font-mono text-muted">{row.indicator_type?.toUpperCase()}</td>
                        <td className="font-mono" style={{ color: 'var(--cyber-cyan)', fontWeight: 600 }}>{row.indicator_value}</td>
                        <td>{row.provider}</td>
                        <td>
                          <span className={`badge ${row.verdict === 'MALICIOUS' ? 'badge-high' : row.verdict === 'SUSPICIOUS' ? 'badge-medium' : 'badge-low'}`}>
                            {row.verdict}
                          </span>
                        </td>
                        <td className="font-mono">{row.reputation_score ?? 'N/A'}</td>
                        <td>
                          <span className={`badge ${row.is_expired ? 'badge-high' : 'badge-low'}`}>
                            {row.is_expired ? 'EXPIRED' : 'ACTIVE'}
                          </span>
                        </td>
                        <td className="font-mono text-muted" style={{ fontSize: '0.8rem' }}>
                          {row.last_checked ? row.last_checked.replace('T', ' ').slice(0, 19) : '—'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>

          {/* Latency & Processing Performance */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
            <div className="table-panel" style={{ padding: '20px' }}>
              <h4 style={{ fontSize: '1rem', fontWeight: 700, color: '#ffffff', marginBottom: '14px' }}>
                PIPELINE INFERENCE LATENCY
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div className="detail-row">
                  <span className="detail-key">Average Inference Time:</span>
                  <span className="detail-val font-mono" style={{ color: 'var(--cyber-cyan)', fontSize: '1.15rem' }}>
                    {analytics?.latency_stats?.avg_ms !== null ? `${analytics.latency_stats.avg_ms} ms` : 'N/A'}
                  </span>
                </div>
                <div className="detail-row">
                  <span className="detail-key">Minimum Latency:</span>
                  <span className="detail-val font-mono">{analytics?.latency_stats?.min_ms ?? 'N/A'} ms</span>
                </div>
                <div className="detail-row">
                  <span className="detail-key">Maximum Latency:</span>
                  <span className="detail-val font-mono">{analytics?.latency_stats?.max_ms ?? 'N/A'} ms</span>
                </div>
              </div>
            </div>

            <div className="table-panel" style={{ padding: '20px' }}>
              <h4 style={{ fontSize: '1rem', fontWeight: 700, color: '#ffffff', marginBottom: '14px' }}>
                SEVERITY DISTRIBUTION
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {analytics?.severities && Object.keys(analytics.severities).length > 0 ? (
                  Object.entries(analytics.severities).map(([sev, cnt]) => (
                    <div key={sev} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className={getSeverityBadgeClass(sev)}>{sev}</span>
                      <span className="font-mono" style={{ fontWeight: 600 }}>{cnt}</span>
                    </div>
                  ))
                ) : (
                  <span className="text-muted" style={{ fontSize: '0.85rem' }}>No severity metrics recorded.</span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
