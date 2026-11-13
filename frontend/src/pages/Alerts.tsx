import { useEffect, useState } from 'react';
import PageLayout from '../components/PageLayout';
import SeverityBadge from '../components/SeverityBadge';
import { wazuhService, WazuhAlert } from '../services/wazuhApi';

type Alert = {
  id: string;
  ruleId: string;
  ruleLevel: number | null;
  description: string;
  agent: string;
  severity: 'low' | 'medium' | 'high' | 'critical' | 'unrated';
  timestamp: string;
};

const severityFromRuleLevel = (level?: number): Alert['severity'] => {
  if (typeof level !== 'number') return 'unrated';
  if (level >= 15) return 'critical';
  if (level >= 12) return 'high';
  if (level >= 7) return 'medium';
  return 'low';
};

const AlertsPage = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low' | 'unrated'>(
    'all'
  );
  const [query, setQuery] = useState('');

  const fetchData = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await wazuhService.getAlerts(100);
      const transformedAlerts: Alert[] = response.data.affected_items.map((alert: WazuhAlert) => ({
        id: String(alert._id || alert.id || 'N/A'),
        ruleId: String(alert.rule?.id || 'N/A'),
        ruleLevel: typeof alert.rule?.level === 'number' ? alert.rule.level : null,
        description: alert.rule?.description || alert.full_log || 'N/A',
        agent: alert.agent?.name || alert.agent?.id || 'N/A',
        severity: severityFromRuleLevel(alert.rule?.level),
        timestamp: alert.timestamp || alert['@timestamp'] || '',
      }));

      setAlerts(transformedAlerts);
    } catch (err) {
      console.error('Failed to fetch Wazuh alerts:', err);
      setError('Failed to load Wazuh alerts.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const normalizedQuery = query.trim().toLowerCase();
  const filteredAlerts = alerts.filter((alert) => {
    const matchesSeverity = filter === 'all' || alert.severity === filter;
    const matchesQuery = !normalizedQuery || [alert.id, alert.ruleId, alert.description, alert.agent]
      .some((value) => value.toLowerCase().includes(normalizedQuery));
    return matchesSeverity && matchesQuery;
  });

  return (
    <PageLayout>
      <div className="soc-page-stack">
        <header className="soc-page-heading">
          <div>
            <h1 className="soc-page-title">Alerts</h1>
            <p className="soc-page-description">Wazuh Indexer events, ordered by the Manager API response.</p>
          </div>
          <button type="button" onClick={() => void fetchData()} disabled={loading} className="soc-button soc-button--secondary">
            {loading ? 'Refreshing...' : 'Refresh alerts'}
          </button>
        </header>

        {error && <div role="alert" className="soc-state soc-state--error">{error}</div>}

        <section className="soc-panel">
          <div className="soc-toolbar">
            <label className="soc-search">
              <span className="soc-search__label">Search alerts</span>
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Rule, agent, description or ID" />
            </label>
            <label className="soc-select-label">
              <span>Severity</span>
              <select value={filter} onChange={(event) => setFilter(event.target.value as typeof filter)}>
                {(['all', 'critical', 'high', 'medium', 'low', 'unrated'] as const).map((level) => (
                  <option key={level} value={level}>{level === 'all' ? 'All levels' : level[0].toUpperCase() + level.slice(1)}</option>
                ))}
              </select>
            </label>
            <span className="soc-result-count">{loading ? 'Loading Wazuh alerts...' : `${filteredAlerts.length} of ${alerts.length} alerts`}</span>
          </div>

          <div className="soc-table-wrap">
            <table className="soc-table">
              <thead><tr><th>Rule ID</th><th>Level</th><th>Description</th><th>Agent</th><th>Timestamp</th><th>Severity</th></tr></thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={6} className="soc-table__message">Loading Wazuh alerts...</td></tr>
                ) : filteredAlerts.length === 0 ? (
                  <tr><td colSpan={6} className="soc-table__message">{error ? 'Wazuh alert data is unavailable.' : 'No alerts match these filters.'}</td></tr>
                ) : filteredAlerts.map((alert, index) => (
                  <tr key={`${alert.id}-${index}`}>
                    <td className="soc-table__mono">{alert.ruleId}</td>
                    <td>{alert.ruleLevel ?? 'N/A'}</td>
                    <td className="soc-table__description">{alert.description}</td>
                    <td>{alert.agent}</td>
                    <td>{alert.timestamp ? new Date(alert.timestamp).toLocaleString() : 'N/A'}</td>
                    <td><SeverityBadge severity={alert.severity} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </PageLayout>
  );
};

export default AlertsPage;