import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import api, { dashboardAPI } from '../services/api';

const REFRESH_INTERVAL = 5000; // 5 seconds

function formatTime(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    return d.toLocaleString();
  } catch {
    return ts;
  }
}

function RiskBar({ score }) {
  const level = score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low';
  const color = score >= 80 ? '#ef4444' : score >= 60 ? '#f59e0b' : score >= 30 ? '#3b82f6' : '#10b981';
  return (
    <div className="risk-bar-container">
      <div className="risk-bar">
        <div className="risk-bar-fill" style={{ width: `${Math.min(score, 100)}%` }} data-level={level}>
          <style>{`.risk-bar-fill[data-level="${level}"] { background: linear-gradient(90deg, ${color}, ${color}cc); }`}</style>
        </div>
      </div>
      <span className="risk-score-value" style={{ color }}>{score.toFixed(1)}</span>
    </div>
  );
}

function SeverityBadge({ severity }) {
  const cls = `badge badge-${severity || 'low'}`;
  const icons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', none: '⚪' };
  return <span className={cls}>{icons[severity] || '⚪'} {severity?.toUpperCase()}</span>;
}

function StatusBadge({ active }) {
  return (
    <span className={`badge ${active ? 'badge-active' : 'badge-expired'}`}>
      {active ? '🔒 Active' : '✅ Expired'}
    </span>
  );
}

export default function Dashboard() {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState('overview');
  const [stats, setStats] = useState(null);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [warnedIPs, setWarnedIPs] = useState([]);
  const [failedLogins, setFailedLogins] = useState([]);
  const [threatEvents, setThreatEvents] = useState([]);
  const [riskScores, setRiskScores] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [isClearing, setIsClearing] = useState(false);
  const [toast, setToast] = useState(null);

  const showToast = useCallback((message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => {
      setToast((prev) => (prev?.message === message ? null : prev));
    }, 3500);
  }, []);

  const fetchAll = useCallback(async () => {
    try {
      const [statsRes, blockedRes, warnedRes, loginsRes, threatsRes, riskRes] =
        await Promise.all([
          dashboardAPI.getStats(),
          dashboardAPI.getBlockedIPs(),
          dashboardAPI.getWarnedIPs(),
          dashboardAPI.getFailedLogins(),
          dashboardAPI.getThreatEvents(),
          dashboardAPI.getRiskScores(),
        ]);
      setStats(statsRes.data);
      setBlockedIPs(blockedRes.data);
      setWarnedIPs(warnedRes.data);
      setFailedLogins(loginsRes.data);
      setThreatEvents(threatsRes.data);
      setRiskScores(riskRes.data);
      setLastRefresh(new Date());
    } catch (err) {
      console.error('Failed to fetch dashboard data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    if (!autoRefresh) return;
    const interval = setInterval(fetchAll, REFRESH_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchAll, autoRefresh]);

  const handleUnblock = async (ip) => {
    try {
      await dashboardAPI.unblockIP(ip);
      await fetchAll();
      showToast(`IP ${ip} unblocked successfully`);
    } catch (err) {
      console.error('Failed to unblock:', err);
      showToast(`Failed to unblock IP ${ip}`, 'error');
    }
  };

  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    try {
      await fetchAll();
      showToast('Dashboard metrics refreshed');
    } catch (err) {
      console.error('Failed to refresh:', err);
      showToast('Failed to refresh metrics', 'error');
    } finally {
      setTimeout(() => setIsRefreshing(false), 300);
    }
  };

  const handleResetAll = async () => {
    setIsResetting(true);
    try {
      await dashboardAPI.resetAll();
      await fetchAll();
      showToast('All active blocks & threat tracking reset');
    } catch (err) {
      // Fallback to /api/test/reset-all
      try {
        await api.post('/api/test/reset-all');
        await fetchAll();
        showToast('All active blocks & threat tracking reset');
      } catch (e) {
        console.error('Failed to reset:', err);
        showToast('Failed to reset system state', 'error');
      }
    } finally {
      setTimeout(() => setIsResetting(false), 300);
    }
  };

  const handleClearData = async () => {
    setIsClearing(true);
    try {
      await dashboardAPI.clearData();
      await fetchAll();
      showToast('All logs, blocks & threat events cleared to 0');
    } catch (err) {
      // Fallback to /api/test/clear-data
      try {
        await api.post('/api/test/clear-data');
        await fetchAll();
        showToast('All logs, blocks & threat events cleared to 0');
      } catch (e) {
        console.error('Failed to clear data:', err);
        showToast('Failed to clear log data', 'error');
      }
    } finally {
      setTimeout(() => setIsClearing(false), 300);
    }
  };

  if (loading) {
    return (
      <>
        <Navbar user={user} logout={logout} />
        <div className="loading-overlay">
          <div className="spinner" />
          <span>Loading dashboard...</span>
        </div>
      </>
    );
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: '📊' },
    { id: 'blocked', label: 'Blocked IPs', icon: '🚫' },
    { id: 'warnings', label: 'Warnings', icon: '⚠️' },
    { id: 'logins', label: 'Failed Logins', icon: '🔐' },
    { id: 'threats', label: 'Threat Events', icon: '🛡️' },
    { id: 'risk', label: 'Risk Scores', icon: '📈' },
  ];

  return (
    <>
      <Navbar user={user} logout={logout} />
      <div className="dashboard">
        <div className="dashboard-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <h1 className="dashboard-title">Security Dashboard</h1>
              <span className="badge badge-low" style={{ fontSize: '0.75rem', padding: '3px 8px' }}>
                💻 App Host: Localhost (127.0.0.1)
              </span>
            </div>
            <p className="dashboard-subtitle">Real-time IP monitoring, threat detection & perimeter defense</p>
          </div>

          <div className="dashboard-actions">
            <div className="refresh-info">
              <div
                className="refresh-dot"
                style={{
                  background: autoRefresh ? 'var(--accent-green)' : 'var(--text-muted)',
                  animation: autoRefresh ? 'pulse-glow 2s infinite' : 'none',
                }}
              />
              <span>
                {autoRefresh ? 'Live Polling (5s)' : 'Polling Paused'}
                {lastRefresh && ` · ${lastRefresh.toLocaleTimeString()}`}
              </span>
            </div>

            <button
              className="btn-action"
              onClick={() => setAutoRefresh(!autoRefresh)}
              title={autoRefresh ? 'Pause automatic polling' : 'Resume automatic polling'}
            >
              {autoRefresh ? '⏸ Pause' : '▶ Resume'}
            </button>

            <button
              className="btn-action"
              onClick={handleManualRefresh}
              disabled={isRefreshing}
              title="Refresh dashboard metrics now"
            >
              <span className={isRefreshing ? 'spin-icon' : ''}>🔄</span>
              {isRefreshing ? 'Refreshing...' : 'Refresh'}
            </button>

            <button
              className="btn-action btn-action-danger"
              onClick={handleResetAll}
              disabled={isResetting}
              title="Reset all active IP blocks and in-memory tracking"
            >
              <span className={isResetting ? 'spin-icon' : ''}>🛡️</span>
              {isResetting ? 'Resetting...' : 'Reset State'}
            </button>

            <button
              className="btn-action"
              style={{ color: 'var(--text-muted)' }}
              onClick={handleClearData}
              disabled={isClearing}
              title="Wipe historical request logs for a fresh presentation"
            >
              <span className={isClearing ? 'spin-icon' : ''}>🗑️</span>
              {isClearing ? 'Clearing...' : 'Clear Logs'}
            </button>
          </div>
        </div>

        {/* Stats Cards */}
        {stats && <StatsCards stats={stats} />}

        {/* Tab Navigation */}
        <div className="tab-bar">
          {tabs.map((t) => (
            <button
              key={t.id}
              className={`tab-btn ${activeTab === t.id ? 'active' : ''}`}
              onClick={() => setActiveTab(t.id)}
            >
              <span>{t.icon}</span> {t.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div className="two-col-grid">
            <BlockedIPsTable data={blockedIPs.filter(b => b.is_active)} onUnblock={handleUnblock} title="Active Blocks" />
            <ThreatEventsTable data={threatEvents.slice(0, 10)} title="Recent Threats" />
            <WarnedIPsTable data={warnedIPs.slice(0, 10)} title="Recent Warnings" />
            <FailedLoginsTable data={failedLogins.slice(0, 10)} title="Recent Failed Logins" />
          </div>
        )}

        {activeTab === 'blocked' && (
          <BlockedIPsTable data={blockedIPs} onUnblock={handleUnblock} title="All Blocked IPs" />
        )}

        {activeTab === 'warnings' && (
          <WarnedIPsTable data={warnedIPs} title="All Warnings" />
        )}

        {activeTab === 'logins' && (
          <FailedLoginsTable data={failedLogins} title="All Failed Login Attempts" />
        )}

        {activeTab === 'threats' && (
          <ThreatEventsTable data={threatEvents} title="All Threat Events" />
        )}

        {activeTab === 'risk' && (
          <RiskScoresTable data={riskScores} />
        )}
      </div>

      {toast && (
        <div className="toast-container">
          <div className={`toast toast-${toast.type}`}>
            <span>{toast.type === 'success' ? '✅' : '❌'}</span>
            <span>{toast.message}</span>
          </div>
        </div>
      )}
    </>
  );
}

/* ═══════════════════ Sub-Components ═══════════════════ */

function Navbar({ user, logout }) {
  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <div className="navbar-logo">IP</div>
        <span className="navbar-title">IP Monitor</span>
      </div>
      <div className="navbar-right">
        <div className="navbar-status">
          <span className="dot" />
          <span>Monitoring Active</span>
        </div>
        <div className="navbar-user">
          <div className="navbar-avatar">{user?.username?.[0]?.toUpperCase() || 'A'}</div>
          <span>{user?.username || 'Admin'}</span>
        </div>
        <button className="btn-logout" onClick={logout}>Logout</button>
      </div>
    </nav>
  );
}

function StatsCards({ stats }) {
  const cards = [
    { label: 'Total Requests', value: stats.total_requests, icon: '📊', color: 'blue' },
    { label: 'Active Blocks', value: stats.active_blocks, icon: '🚫', color: 'red' },
    { label: 'Warnings', value: stats.total_warnings, icon: '⚠️', color: 'yellow' },
    { label: 'Threat Events', value: stats.total_threat_events, icon: '🛡️', color: 'purple' },
    { label: 'Failed Logins', value: stats.failed_logins, icon: '🔐', color: 'red' },
    { label: 'Unique IPs', value: stats.unique_ips, icon: '🌐', color: 'cyan' },
  ];

  return (
    <div className="stats-grid">
      {cards.map((c, i) => (
        <div key={i} className={`stat-card ${c.color}`} style={{ animationDelay: `${i * 0.08}s` }}>
          <div className="stat-icon">{c.icon}</div>
          <div className="stat-value">{c.value?.toLocaleString()}</div>
          <div className="stat-label">{c.label}</div>
        </div>
      ))}
    </div>
  );
}

function BlockedIPsTable({ data, onUnblock, title }) {
  return (
    <div className="table-container">
      <div className="table-header">
        <h3>🚫 {title}</h3>
        <span className="table-count red">{data.length}</span>
      </div>
      {data.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">✅</div>
          <p>No blocked IPs</p>
          <p className="empty-sub">All clear — no IPs are currently blocked</p>
        </div>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Reason</th>
              <th>Risk Score</th>
              <th>Status</th>
              <th>Blocked At</th>
              <th>Expires At</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {data.map((row) => (
              <tr key={row.id}>
                <td className="ip-cell">{row.ip}</td>
                <td>{row.reason}</td>
                <td><RiskBar score={row.risk_score || 0} /></td>
                <td><StatusBadge active={row.is_active} /></td>
                <td className="timestamp">{formatTime(row.blocked_at)}</td>
                <td className="timestamp">{formatTime(row.expires_at)}</td>
                <td>
                  {row.is_active ? (
                    <button className="btn-sm btn-unblock" onClick={() => onUnblock(row.ip)}>
                      Unblock
                    </button>
                  ) : (
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function WarnedIPsTable({ data, title }) {
  return (
    <div className="table-container">
      <div className="table-header">
        <h3>⚠️ {title}</h3>
        <span className="table-count yellow">{data.length}</span>
      </div>
      {data.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">✅</div>
          <p>No warnings</p>
          <p className="empty-sub">No suspicious activity detected yet</p>
        </div>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Reason</th>
              <th>Risk Score</th>
              <th>Warned At</th>
            </tr>
          </thead>
          <tbody>
            {data.map((row) => (
              <tr key={row.id}>
                <td className="ip-cell">{row.ip}</td>
                <td>{row.reason}</td>
                <td><RiskBar score={row.risk_score || 0} /></td>
                <td className="timestamp">{formatTime(row.warned_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function FailedLoginsTable({ data, title }) {
  return (
    <div className="table-container">
      <div className="table-header">
        <h3>🔐 {title}</h3>
        <span className="table-count red">{data.length}</span>
      </div>
      {data.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">🔐</div>
          <p>No failed login attempts</p>
          <p className="empty-sub">No brute force activity detected</p>
        </div>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Username</th>
              <th>Attempts</th>
              <th>First Attempt</th>
              <th>Last Attempt</th>
            </tr>
          </thead>
          <tbody>
            {data.map((row, i) => (
              <tr key={i}>
                <td className="ip-cell">{row.ip}</td>
                <td>{row.username}</td>
                <td>
                  <span className={`badge ${row.attempt_count >= 5 ? 'badge-critical' : row.attempt_count >= 3 ? 'badge-high' : 'badge-medium'}`}>
                    {row.attempt_count}x
                  </span>
                </td>
                <td className="timestamp">{formatTime(row.first_attempt)}</td>
                <td className="timestamp">{formatTime(row.last_attempt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function ThreatEventsTable({ data, title }) {
  return (
    <div className="table-container">
      <div className="table-header">
        <h3>🛡️ {title}</h3>
        <span className="table-count purple">{data.length}</span>
      </div>
      {data.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">🛡️</div>
          <p>No threat events</p>
          <p className="empty-sub">System is clean — no threats detected</p>
        </div>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Event Type</th>
              <th>Severity</th>
              <th>Risk Score</th>
              <th>Details</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {data.map((row) => (
              <tr key={row.id}>
                <td className="ip-cell">{row.ip}</td>
                <td>{row.event_type?.replace(/_/g, ' ')}</td>
                <td><SeverityBadge severity={row.severity} /></td>
                <td><RiskBar score={row.risk_score || 0} /></td>
                <td className="threat-detail" title={row.details}>{row.details}</td>
                <td className="timestamp">{formatTime(row.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function RiskScoresTable({ data }) {
  return (
    <div className="table-container">
      <div className="table-header">
        <h3>📈 IP Risk Scores</h3>
        <span className="table-count blue">{data.length}</span>
      </div>
      {data.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📈</div>
          <p>No risk data</p>
          <p className="empty-sub">Run the test script to generate activity</p>
        </div>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Risk Score</th>
              <th>Requests</th>
              <th>Failed Logins</th>
              <th>Warnings</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {data.map((row, i) => (
              <tr key={i}>
                <td className="ip-cell">{row.ip}</td>
                <td><RiskBar score={row.risk_score || 0} /></td>
                <td>{row.request_count}</td>
                <td>{row.failed_logins}</td>
                <td>{row.warnings}</td>
                <td>
                  {row.is_blocked ? (
                    <span className="badge badge-critical">🚫 Blocked</span>
                  ) : row.risk_score >= 60 ? (
                    <span className="badge badge-high">⚠ High Risk</span>
                  ) : (
                    <span className="badge badge-low">✅ Normal</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
