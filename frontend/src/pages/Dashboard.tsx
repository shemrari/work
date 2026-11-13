import { useEffect, useState } from 'react';
import PageLayout from '../components/PageLayout';
import { wazuhService, WazuhAlert } from '../services/wazuhApi';
import './Dashboard.css';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unrated';

type DashboardAlert = {
  id: string;
  source: string;
  description: string;
  ruleId: string;
  ruleLevel: number | null;
  severity: Severity;
  timestamp: string;
};

type Incident = {
  id: number;
  title: string;
  severity: string | null;
  status: string;
  source: string | null;
  detected_at: string | null;
  created_at: string;
};

type WazuhHealth = {
  wazuh_manager_api?: string;
  wazuh_indexer?: string;
  status?: string;
};

type AnomalyStatus = {
  model?: string;
  analysis_status?: string;
  summary?: { alerts_analyzed?: number; anomalies_detected?: number };
  message?: string;
};

type LabStatus = {
  status?: string;
  scope?: string;
};

type ReadResult<T> = {
  value: T | null;
  error: string | null;
};

const apiBase = '';

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${apiBase}${path}`);
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json() as Promise<T>;
}

async function readSafely<T>(source: string, request: () => Promise<T>): Promise<ReadResult<T>> {
  try {
    return { value: await request(), error: null };
  } catch {
    return { value: null, error: source };
  }
}

function severityFromRuleLevel(level?: number): Severity {
  if (typeof level !== 'number') return 'unrated';
  if (level >= 15) return 'critical';
  if (level >= 12) return 'high';
  if (level >= 7) return 'medium';
  return 'low';
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`soc-dashboard__severity-badge soc-dashboard__severity-badge--${severity}`}>
      {severity === 'unrated' ? 'Unrated' : severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const normalized = status.toLowerCase();
  const modifier = ['healthy', 'active', 'trained'].includes(normalized)
    ? 'soc-dashboard__status-badge--healthy'
    : ['insufficient_data', 'checking', 'lab'].includes(normalized)
      ? 'soc-dashboard__status-badge--checking'
      : '';

  return (
    <span className={`soc-dashboard__status-badge ${modifier}`}>
      {status.replace(/_/g, ' ')}
    </span>
  );
}

function SectionHeading({ eyebrow, title, detail }: { eyebrow: string; title: string; detail?: string }) {
  return (
    <div className="soc-dashboard__panel-heading">
      <div>
        <p className="soc-dashboard__section-label">{eyebrow}</p>
        <h2 className="soc-dashboard__panel-title">{title}</h2>
      </div>
      {detail && <p className="soc-dashboard__panel-detail">{detail}</p>}
    </div>
  );
}

function formatTime(value: string | null | undefined) {
  if (!value) return 'N/A';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'N/A' : date.toLocaleString();
}

const Dashboard = () => {
  const [alerts, setAlerts] = useState<DashboardAlert[] | null>(null);
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [agentCount, setAgentCount] = useState<number | null>(null);
  const [wazuhHealth, setWazuhHealth] = useState<WazuhHealth | null>(null);
  const [anomalyStatus, setAnomalyStatus] = useState<AnomalyStatus | null>(null);
  const [labStatus, setLabStatus] = useState<LabStatus | null>(null);
  const [failedSources, setFailedSources] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let mounted = true;
    const refresh = async () => {
      setLoading(true);
      const results = await Promise.all([
        readSafely('Wazuh alerts', () => wazuhService.getAlerts(50)),
        readSafely('Wazuh agents', () => wazuhService.getAgents(50)),
        readSafely('PostgreSQL incidents', () => getJson<Incident[]>('/api/incidents?skip=0&limit=500')),
        readSafely('Wazuh service status', () => getJson<WazuhHealth>('/wazuh/status')),
        readSafely('AI analysis', () => getJson<AnomalyStatus>('/ai/anomalies?limit=50')),
        readSafely('Attack Lab health', () => getJson<LabStatus>('/api/simulations/lab-status')),
      ]);
      if (!mounted) return;

      const [alertResult, agentResult, incidentResult, healthResult, anomalyResult, labResult] = results;
      const transformedAlerts = alertResult.value
        ? alertResult.value.data.affected_items.map((alert: WazuhAlert): DashboardAlert => ({
          id: String(alert._id || alert.id || 'N/A'),
          source: alert.agent?.name || 'N/A',
          description: alert.rule?.description || alert.full_log || 'N/A',
          ruleId: String(alert.rule?.id || 'N/A'),
          ruleLevel: typeof alert.rule?.level === 'number' ? alert.rule.level : null,
          severity: severityFromRuleLevel(alert.rule?.level),
          timestamp: alert['@timestamp'] || alert.timestamp || '',
        }))
        : null;

      setAlerts(transformedAlerts);
      setIncidents(incidentResult.value);
      setAgentCount(agentResult.value
        ? agentResult.value.data.total_affected_items ?? agentResult.value.data.affected_items.length
        : null);
      setWazuhHealth(healthResult.value);
      setAnomalyStatus(anomalyResult.value);
      setLabStatus(labResult.value);
      setFailedSources(results.map((result) => result.error).filter((source): source is string => source !== null));
      setLastChecked(new Date());
      setLoading(false);
    };

    void refresh();
    return () => {
      mounted = false;
    };
  }, [refreshKey]);

  const severityCount = (severity: Severity) =>
    alerts === null ? 'N/A' : alerts.filter((alert) => alert.severity === severity).length;
  const activeIncidents = incidents === null
    ? 'N/A'
    : incidents.filter((incident) => ['open', 'investigating'].includes(incident.status.toLowerCase())).length;
  const alertBuckets = Array.from({ length: 6 }, (_, index) => ({
    label: `${20 - index * 4}-${24 - index * 4}h`,
    value: 0,
  }));
  alerts?.forEach((alert) => {
    const ageInHours = Math.floor((Date.now() - Date.parse(alert.timestamp)) / 3_600_000);
    if (Number.isFinite(ageInHours) && ageInHours >= 0 && ageInHours < 24) {
      alertBuckets[5 - Math.floor(ageInHours / 4)].value += 1;
    }
  });
  const maxBucket = Math.max(1, ...alertBuckets.map((bucket) => bucket.value));
  const analyzedAlertCount = alerts?.length ?? 0;
  const aiState = anomalyStatus?.analysis_status || (loading ? 'checking' : 'unavailable');
  const attackLabState = labStatus?.status || (loading ? 'checking' : 'unavailable');
  const systemOperational = !loading
    && failedSources.length === 0
    && wazuhHealth?.status === 'healthy'
    && labStatus?.status === 'healthy';
  const systemStateLabel = loading
    ? 'Checking systems'
    : systemOperational ? 'System Operational' : 'Status unavailable';

  return (
    <PageLayout>
      <div className="soc-dashboard">
        <div className="soc-dashboard__inner">
          <header className="soc-dashboard__header">
            <div>
              <p className="soc-dashboard__eyebrow">SOC / Overview</p>
              <h1 className="soc-dashboard__title">Industrial Cybersecurity SOC</h1>
              <p className="soc-dashboard__subtitle">Security monitoring and incident response</p>
            </div>
            <div className="soc-dashboard__header-actions">
              <span className={`soc-dashboard__system-state ${systemOperational ? '' : 'soc-dashboard__system-state--partial'}`}>
                <span className="soc-dashboard__system-dot" />
                {systemStateLabel}
              </span>
              <button aria-label="Refresh dashboard data" type="button" onClick={() => setRefreshKey((key) => key + 1)} disabled={loading} className="soc-dashboard__refresh">
                {loading ? 'Refreshing...' : 'Refresh data'}
              </button>
            </div>
          </header>

          {failedSources.length > 0 && (
            <div role="status" className="soc-dashboard__notice">
              Unavailable sources: {failedSources.join(', ')}. Affected metrics are shown as N/A.
            </div>
          )}

          <section aria-label="Security key performance indicators" className="soc-dashboard__kpis">
            {[
              { label: 'Critical alerts', value: severityCount('critical'), note: 'Latest 50 Wazuh alerts', glyph: '!', iconClass: 'soc-dashboard__kpi-icon--critical' },
              { label: 'High alerts', value: severityCount('high'), note: 'Latest 50 Wazuh alerts', glyph: 'H', iconClass: 'soc-dashboard__kpi-icon--high' },
              { label: 'Active incidents', value: activeIncidents, note: 'Open or investigating · PostgreSQL', glyph: 'IR', iconClass: 'soc-dashboard__kpi-icon--incidents' },
              { label: 'Monitored assets', value: agentCount ?? 'N/A', note: 'Wazuh Manager agent count', glyph: 'AG', iconClass: 'soc-dashboard__kpi-icon--assets' },
            ].map((metric) => (
              <article aria-label={metric.label} key={metric.label} className="soc-dashboard__kpi">
                <div className="soc-dashboard__kpi-top">
                  <div>
                    <p className="soc-dashboard__kpi-label">{metric.label}</p>
                    <p className="soc-dashboard__kpi-value">{metric.value}</p>
                  </div>
                  <span className={`soc-dashboard__kpi-icon ${metric.iconClass}`}>{metric.glyph}</span>
                </div>
                <p className="soc-dashboard__kpi-note">{metric.note}</p>
              </article>
            ))}
          </section>

          <section className="soc-dashboard__main-grid">
            <article className="soc-dashboard__panel">
              <SectionHeading eyebrow="Threat telemetry" title="Security Activity" detail="Observed alerts · rolling 24-hour window" />
              {alerts === null ? (
                <div className="soc-dashboard__empty">{loading ? 'Loading Wazuh activity...' : 'N/A · Wazuh alert source unavailable'}</div>
              ) : alertBuckets.every((bucket) => bucket.value === 0) ? (
                <div className="soc-dashboard__empty">No returned Wazuh alerts fall within the last 24 hours.</div>
              ) : (
                <>
                  <div className="soc-dashboard__chart-meta"><span>Alerts per 4-hour interval</span><span>{analyzedAlertCount} latest events</span></div>
                  <div className="soc-dashboard__chart">
                    <span className="soc-dashboard__chart-grid soc-dashboard__chart-grid--one" />
                    <span className="soc-dashboard__chart-grid soc-dashboard__chart-grid--two" />
                    <span className="soc-dashboard__chart-grid soc-dashboard__chart-grid--three" />
                    {alertBuckets.map((bucket) => (
                      <div key={bucket.label} className="soc-dashboard__chart-bar-group">
                        <span className="soc-dashboard__chart-value">{bucket.value}</span>
                        <div className="soc-dashboard__chart-bar-track">
                          <div className="soc-dashboard__chart-bar" style={{ height: `${Math.max(4, (bucket.value / maxBucket) * 84)}%` }} title={`${bucket.label}: ${bucket.value} Wazuh alerts`} />
                        </div>
                        <span className="soc-dashboard__chart-label">{bucket.label}</span>
                      </div>
                    ))}
                  </div>
                  <p className="soc-dashboard__chart-note">Aggregated from timestamps in the latest {analyzedAlertCount} Wazuh alerts.</p>
                </>
              )}
            </article>

            <article className="soc-dashboard__panel">
              <SectionHeading eyebrow="Platform health" title="System Status" detail={lastChecked ? `Last checked ${lastChecked.toLocaleTimeString()}` : 'Awaiting live checks'} />
              <div className="soc-dashboard__services">
                {[
                  { label: 'Wazuh Manager', code: 'WM', status: wazuhHealth?.wazuh_manager_api || (loading ? 'checking' : 'unavailable'), detail: 'Manager API health' },
                  { label: 'Wazuh Indexer', code: 'WI', status: wazuhHealth?.wazuh_indexer || (loading ? 'checking' : 'unavailable'), detail: 'Alert indexing service' },
                  { label: 'AI Detection', code: 'AI', status: aiState, detail: anomalyStatus ? `${anomalyStatus.model || 'Anomaly model'} · ${anomalyStatus.summary?.alerts_analyzed ?? 'N/A'} alerts analyzed` : 'Analysis status unavailable' },
                  { label: 'Attack Lab', code: 'LAB', status: attackLabState, detail: labStatus ? `Local simulator · ${labStatus.scope || 'LAB'}` : 'Lab health unavailable' },
                ].map((service) => (
                  <div key={service.label} className="soc-dashboard__service">
                    <span className="soc-dashboard__service-icon">{service.code}</span>
                    <div className="soc-dashboard__service-body">
                      <div className="soc-dashboard__service-line"><h3 className="soc-dashboard__service-name">{service.label}</h3><StatusBadge status={service.status} /></div>
                      <p className="soc-dashboard__service-detail">{service.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </article>
          </section>

          <section aria-label="Recent Security Events" className="soc-dashboard__panel soc-dashboard__events-panel">
            <SectionHeading eyebrow="Wazuh Indexer / newest first" title="Recent Security Events" detail={alerts === null ? 'N/A' : `${alerts.length} latest alerts loaded`} />
            {alerts === null ? (
              <div className="soc-dashboard__empty">{loading ? 'Loading Wazuh security events...' : 'N/A · Wazuh event source unavailable.'}</div>
            ) : alerts.length === 0 ? (
              <div className="soc-dashboard__empty">No Wazuh security events returned.</div>
            ) : (
              <div className="soc-dashboard__table-wrap">
                <table className="soc-dashboard__table">
                  <thead><tr><th>Severity</th><th>Security event</th><th>Agent</th><th>Wazuh rule</th><th>Detected</th></tr></thead>
                  <tbody>
                    {alerts.slice(0, 10).map((alert, index) => (
                      <tr key={`${alert.id}-${index}`}>
                        <td><SeverityBadge severity={alert.severity} /></td>
                        <td><span className="soc-dashboard__event-description" title={alert.description}>{alert.description}</span></td>
                        <td>{alert.source}</td>
                        <td>{alert.ruleId} <span className="soc-dashboard__event-id">Level {alert.ruleLevel ?? 'N/A'}</span></td>
                        <td>{formatTime(alert.timestamp)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <footer className="soc-dashboard__source-note">
            <span>Source: Wazuh Indexer · Wazuh Manager · PostgreSQL · AI analysis API</span>
            <span>{loading ? 'Updating live sources' : failedSources.length ? 'Partial source availability' : 'Live telemetry'}</span>
          </footer>
        </div>
      </div>
    </PageLayout>
  );
};

export default Dashboard;