import { useEffect, useState } from 'react';
import PageLayout from '../components/PageLayout';
import { wazuhService, WazuhAlert } from '../services/wazuhApi';

type LogEntry = {
  id: string;
  timestamp: string;
  level: 'low' | 'medium' | 'high' | 'critical' | 'unrated';
  ruleId: string;
  ruleLevel: number | null;
  message: string;
  source: string;
};

const severityFromRuleLevel = (level?: number): LogEntry['level'] => {
  if (typeof level !== 'number') return 'unrated';
  if (level >= 15) return 'critical';
  if (level >= 12) return 'high';
  if (level >= 7) return 'medium';
  return 'low';
};

const LogsPage = () => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterLevel, setFilterLevel] = useState<'all' | 'low' | 'medium' | 'high' | 'critical' | 'unrated'>('all');
  const [query, setQuery] = useState('');

  const fetchData = async () => {
    try {
      const response = await wazuhService.getAlerts(100);
      setLogs(response.data.affected_items.map((alert: WazuhAlert) => ({
        id: String(alert._id || alert.id || 'N/A'),
        timestamp: alert['@timestamp'] || alert.timestamp || '',
        level: severityFromRuleLevel(alert.rule?.level),
        ruleId: String(alert.rule?.id || 'N/A'),
        ruleLevel: typeof alert.rule?.level === 'number' ? alert.rule.level : null,
        message: alert.rule?.description || alert.full_log || 'N/A',
        source: alert.agent?.name || alert.agent?.id || 'N/A',
      })));
      setError(null);
    } catch (requestError) {
      console.error('Failed to fetch Wazuh events:', requestError);
      setError('Unable to load Wazuh events from the backend.');
      setLogs([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const normalizedQuery = query.trim().toLowerCase();
  const filteredLogs = logs.filter((log) => {
    const matchesLevel = filterLevel === 'all' || log.level === filterLevel;
    const matchesQuery = !normalizedQuery || [log.ruleId, log.message, log.source]
      .some((value) => value.toLowerCase().includes(normalizedQuery));
    return matchesLevel && matchesQuery;
  });

  return (
    <PageLayout>
      <div className="soc-page-stack">
        <header className="soc-page-heading">
          <div>
            <h1 className="soc-page-title">Logs</h1>
            <p className="soc-page-description">Recent alert documents returned by the Wazuh Indexer API.</p>
          </div>
          <button type="button" onClick={() => void fetchData()} disabled={loading} className="soc-button soc-button--secondary">
            {loading ? 'Refreshing...' : 'Refresh logs'}
          </button>
        </header>

        {error && <div role="alert" className="soc-state soc-state--error">{error}</div>}

        <section className="soc-panel">
          <div className="soc-toolbar">
            <label className="soc-search">
              <span className="soc-search__label">Search logs</span>
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Rule, agent or message" />
            </label>
            <label className="soc-select-label">
              <span>Severity</span>
              <select value={filterLevel} onChange={(event) => setFilterLevel(event.target.value as typeof filterLevel)}>
                {(['all', 'critical', 'high', 'medium', 'low', 'unrated'] as const).map((level) => (
                  <option key={level} value={level}>{level === 'all' ? 'All levels' : level[0].toUpperCase() + level.slice(1)}</option>
                ))}
              </select>
            </label>
            <span className="soc-result-count">{loading ? 'Loading Indexer events...' : `${filteredLogs.length} of ${logs.length} events`}</span>
          </div>
          <div className="soc-table-wrap">
            <table className="soc-table">
              <thead><tr><th>Timestamp</th><th>Rule / level</th><th>Severity</th><th>Agent</th><th>Event details</th></tr></thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={5} className="soc-table__message">Loading Wazuh Indexer events...</td></tr>
                ) : filteredLogs.length === 0 ? (
                  <tr><td colSpan={5} className="soc-table__message">{error ? 'Indexer data is unavailable.' : 'No events match these filters.'}</td></tr>
                ) : filteredLogs.map((log, index) => (
                  <tr key={`${log.id}-${index}`}>
                    <td>{log.timestamp ? new Date(log.timestamp).toLocaleString() : 'N/A'}</td>
                    <td className="soc-table__mono">{log.ruleId} / {log.ruleLevel ?? 'N/A'}</td>
                    <td><span className={`soc-severity soc-severity--${log.level}`}>{log.level}</span></td>
                    <td>{log.source}</td>
                    <td className="soc-table__description">{log.message}</td>
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

export default LogsPage;
