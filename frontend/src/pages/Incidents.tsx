import { useEffect, useState } from 'react';
import PageLayout from '../components/PageLayout';
import StatCard from '../components/StatCard';

type Incident = {
  id: number;
  title: string;
  description: string;
  severity: string | null;
  status: string;
  source: string | null;
  detected_at: string | null;
  anomaly_score: number | null;
  wazuh_alert_id: string | null;
  wazuh_alert: Record<string, unknown> | null;
  assigned_to: string | null;
  created_at: string;
};

type SyncResult = {
  analysis_status: string;
  alerts_analyzed: number;
  anomalies_detected: number;
  incidents_created: number;
  already_synced: number;
  skipped_missing_wazuh_reference: number;
  message: string;
};

type ResponseAction = {
  id: number;
  incident_id: number;
  action_type: string;
  target: string;
  status: string;
  description: string;
  executed_at: string;
  result: string;
};

type ResponseActionSummary = {
  total_actions: number;
  simulated_blocks: number;
  notifications: number;
  successful_actions: number;
};

type IncidentTimeline = {
  incident: Incident;
  response_actions: ResponseAction[];
};

const apiBase = '/api/incidents';
const severities = ['critical', 'high', 'medium', 'low'] as const;

const severityStyles: Record<string, string> = {
  critical: 'bg-red-950 text-red-300',
  high: 'bg-orange-950 text-orange-300',
  medium: 'bg-yellow-950 text-yellow-200',
  low: 'bg-green-950 text-green-300',
};

const statusStyles: Record<string, string> = {
  open: 'bg-red-950 text-red-300',
  investigating: 'bg-orange-950 text-orange-300',
  resolved: 'bg-green-950 text-green-300',
};

const IncidentsPage = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [syncResult, setSyncResult] = useState<SyncResult | null>(null);
  const [actionSummary, setActionSummary] = useState<ResponseActionSummary | null>(null);
  const [incidentDataLoaded, setIncidentDataLoaded] = useState(false);
  const [selectedIncidentId, setSelectedIncidentId] = useState<number | null>(null);
  const [timeline, setTimeline] = useState<ResponseAction[]>([]);
  const [timelineLoading, setTimelineLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadIncidents = async (syncAi: boolean) => {
    setLoading(true);
    setError(null);

    if (syncAi) {
      try {
        const syncResponse = await fetch(`${apiBase}/sync-ai`, { method: 'POST' });
        if (!syncResponse.ok) {
          throw new Error(`AI synchronization failed (${syncResponse.status})`);
        }
        setSyncResult(await syncResponse.json() as SyncResult);
      } catch (requestError) {
        console.error('Failed to synchronize AI anomalies:', requestError);
        setError('AI synchronization failed. Existing persisted incidents are still loaded.');
      }
    }

    try {
      const [response, summaryResponse] = await Promise.all([
        fetch(`${apiBase}?skip=0&limit=500`),
        fetch(`${apiBase}/response-actions/summary`),
      ]);
      if (!response.ok || !summaryResponse.ok) {
        throw new Error(`Incident data request failed (${response.status}/${summaryResponse.status})`);
      }
      setIncidents(await response.json() as Incident[]);
      setActionSummary(await summaryResponse.json() as ResponseActionSummary);
      setIncidentDataLoaded(true);
    } catch (requestError) {
      console.error('Failed to fetch incidents:', requestError);
      setError('Unable to load persisted incidents from the backend.');
      setIncidents([]);
      setActionSummary(null);
      setIncidentDataLoaded(false);
    } finally {
      setLoading(false);
    }
  };

  const loadTimeline = async (incidentId: number) => {
    setSelectedIncidentId(incidentId);
    setTimelineLoading(true);
    setActionMessage(null);
    try {
      const response = await fetch(`${apiBase}/${incidentId}/timeline`);
      if (!response.ok) {
        throw new Error(`Timeline request failed (${response.status})`);
      }
      const data = await response.json() as IncidentTimeline;
      setTimeline(data.response_actions);
    } catch (requestError) {
      console.error('Failed to load response timeline:', requestError);
      setActionMessage('Unable to load this incident timeline.');
      setTimeline([]);
    } finally {
      setTimelineLoading(false);
    }
  };

  const runSimulatedAction = async (actionType: string) => {
    if (selectedIncidentId === null) return;
    setActionLoading(actionType);
    setActionMessage(null);
    try {
      const response = await fetch(`${apiBase}/${selectedIncidentId}/respond`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action_type: actionType }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || `Response simulation failed (${response.status})`);
      }
      setActionMessage(data.message);
      const [timelineResponse, summaryResponse] = await Promise.all([
        fetch(`${apiBase}/${selectedIncidentId}/timeline`),
        fetch(`${apiBase}/response-actions/summary`),
      ]);
      if (timelineResponse.ok) {
        const timelineData = await timelineResponse.json() as IncidentTimeline;
        setTimeline(timelineData.response_actions);
      }
      if (summaryResponse.ok) {
        setActionSummary(await summaryResponse.json() as ResponseActionSummary);
      }
    } catch (requestError) {
      setActionMessage(requestError instanceof Error ? requestError.message : 'Response simulation failed.');
    } finally {
      setActionLoading(null);
    }
  };

  useEffect(() => {
    void loadIncidents(false);
  }, []);

  const severityCounts = incidents.reduce<Record<string, number>>((counts, incident) => {
    const severity = (incident.severity || 'unrated').toLowerCase();
    counts[severity] = (counts[severity] || 0) + 1;
    return counts;
  }, {});

  const selectedIncident = incidents.find((incident) => incident.id === selectedIncidentId) || null;
  const originalAlert = selectedIncident?.wazuh_alert || {};
  const alertData = originalAlert.data && typeof originalAlert.data === 'object'
    ? originalAlert.data as Record<string, unknown>
    : {};
  const sourceData = originalAlert.source && typeof originalAlert.source === 'object'
    ? originalAlert.source as Record<string, unknown>
    : {};
  const alertAgent = originalAlert.agent && typeof originalAlert.agent === 'object'
    ? originalAlert.agent as Record<string, unknown>
    : {};
  const hasSourceIp = [originalAlert.srcip, alertData.srcip, sourceData.ip]
    .some((value) => typeof value === 'string' && value.length > 0);
  const hasAgent = Boolean(alertAgent.name || alertAgent.id);

  return (
    <PageLayout>
      <div className="space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="soc-page-title">Incidents</h1>
            <p className="soc-page-description">Persisted PostgreSQL incidents linked to their original Wazuh alerts.</p>
          </div>
          <button
            type="button"
            onClick={() => void loadIncidents(true)}
            disabled={loading}
            className="soc-button bg-blue-700 text-white hover:bg-blue-600 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? 'Synchronizing...' : 'Synchronize AI anomalies'}
          </button>
        </div>

        {error && (
          <div role="alert" className="rounded border border-red-800 bg-red-950 p-3 text-sm text-red-200">
            {error}
          </div>
        )}

        {syncResult && (
          <p role="status" className="text-sm text-gray-400">
            {syncResult.message} Created {syncResult.incidents_created}; already present {syncResult.already_synced};
            {' '}without Wazuh reference {syncResult.skipped_missing_wazuh_reference}.
          </p>
        )}

        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
          <StatCard title="Total incidents" value={incidentDataLoaded ? incidents.length : 'N/A'} />
          {severities.map((severity) => (
            <StatCard
              key={severity}
              title={severity[0].toUpperCase() + severity.slice(1)}
              value={incidentDataLoaded ? severityCounts[severity] || 0 : 'N/A'}
            />
          ))}
        </div>

        <section className="space-y-3 border-y border-gray-200 py-5">
          <div>
            <h2 className="text-lg font-semibold">Response actions</h2>
            <p className="mt-1 text-sm text-gray-500">Persisted action records; no response command is run from this summary.</p>
          </div>
          <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
            <StatCard title="Total actions" value={actionSummary?.total_actions ?? 'N/A'} />
            <StatCard title="Simulated blocks" value={actionSummary?.simulated_blocks ?? 'N/A'} />
            <StatCard title="Notifications" value={actionSummary?.notifications ?? 'N/A'} />
            <StatCard title="Successful simulations" value={actionSummary?.successful_actions ?? 'N/A'} />
          </div>
        </section>

        {selectedIncident && (
          <section className="soc-panel space-y-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="text-lg font-semibold">Incident #{selectedIncident.id}: {selectedIncident.title}</h2>
                <p className="mt-1 text-sm text-gray-400">{selectedIncident.description}</p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedIncidentId(null)}
                className="soc-button soc-button--secondary"
              >
                Close
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 text-sm lg:grid-cols-4">
              <p>Severity: <span className="font-medium uppercase">{selectedIncident.severity || 'unrated'}</span></p>
              <p>Source: <span className="font-medium">{selectedIncident.source || 'N/A'}</span></p>
              <p>AI score: <span className="font-medium">{selectedIncident.anomaly_score === null ? 'N/A' : `${selectedIncident.anomaly_score.toFixed(1)} / 100`}</span></p>
              <p>Wazuh alert ID: <span className="break-all font-mono text-xs">{selectedIncident.wazuh_alert_id || 'N/A'}</span></p>
            </div>

            <details className="text-sm text-gray-300">
              <summary className="cursor-pointer">Original Wazuh alert details</summary>
              <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap rounded bg-gray-900 p-3 text-xs">
                {JSON.stringify(selectedIncident.wazuh_alert, null, 2)}
              </pre>
            </details>

            <div className="space-y-3 border-t border-gray-700 pt-4">
              <div>
                <h3 className="font-semibold">Simulate a response</h3>
                <p className="mt-1 text-xs text-yellow-200">
                  These controls record simulated response actions only; they do not execute commands on a host or network.
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                {[
                  { type: 'block_ip', label: 'Block IP (simulated)', enabled: hasSourceIp },
                  { type: 'isolate_asset', label: 'Isolate asset (simulated)', enabled: hasAgent },
                  { type: 'notify_admin', label: 'Notify admin (simulated)', enabled: true },
                  { type: 'create_report', label: 'Create report (simulated)', enabled: true },
                ].map((action) => {
                  const alreadyRecorded = timeline.some((item) => item.action_type === action.type);
                  return (
                    <button
                      key={action.type}
                      type="button"
                      title={!action.enabled ? 'Required target is absent from the stored Wazuh alert.' : undefined}
                      disabled={!action.enabled || alreadyRecorded || actionLoading !== null}
                      onClick={() => void runSimulatedAction(action.type)}
                      className="soc-button bg-blue-700 text-white hover:bg-blue-600 disabled:cursor-not-allowed disabled:opacity-45"
                    >
                      {actionLoading === action.type ? 'Recording...' : alreadyRecorded ? `${action.label} · recorded` : action.label}
                    </button>
                  );
                })}
              </div>
              {actionMessage && <p role="status" className="text-sm text-gray-300">{actionMessage}</p>}
            </div>

            <div className="space-y-3 border-t border-gray-700 pt-4">
              <h3 className="font-semibold">Timeline / audit</h3>
              {timelineLoading ? (
                <p className="text-sm text-gray-400">Loading response timeline...</p>
              ) : timeline.length === 0 ? (
                <p className="text-sm text-gray-400">No response actions recorded for this incident.</p>
              ) : (
                <ol className="space-y-3">
                  {timeline.map((action) => (
                    <li key={action.id} className="border-l-2 border-blue-600 pl-3">
                      <div className="flex flex-wrap justify-between gap-2 text-sm">
                        <span className="font-medium">{action.action_type.replace('_', ' ')} · {action.status}</span>
                        <time className="text-gray-400">{new Date(action.executed_at).toLocaleString()}</time>
                      </div>
                      <p className="mt-1 text-sm text-gray-300">Target: {action.target}</p>
                      <p className="text-xs text-gray-400">{action.description} Result: {action.result}</p>
                    </li>
                  ))}
                </ol>
              )}
            </div>
          </section>
        )}

        <div className="soc-panel overflow-x-auto p-0">
          <table className="soc-table min-w-[1050px]">
            <thead>
              <tr>
                <th className="p-3">ID</th>
                <th className="p-3">Incident</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Status</th>
                <th className="p-3">Source</th>
                <th className="p-3">AI score</th>
                <th className="p-3">Detected at</th>
                <th className="p-3">Wazuh reference</th>
                <th className="p-3">Response</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={9} className="soc-table__message">Loading persisted incidents...</td></tr>
              ) : incidents.length === 0 ? (
                <tr>
                  <td colSpan={9} className="soc-table__message">
                    {incidentDataLoaded
                      ? 'No persisted incidents. An incident is created only when the AI model flags a real Wazuh alert.'
                      : 'Incident data is unavailable; persisted counts are not shown.'}
                  </td>
                </tr>
              ) : incidents.map((incident) => {
                const severity = (incident.severity || 'unrated').toLowerCase();
                const detectedAt = incident.detected_at || incident.created_at;
                return (
                  <tr key={incident.id}>
                    <td className="p-3">{incident.id}</td>
                    <td className="max-w-md p-3">
                      <p className="font-medium">{incident.title}</p>
                      <p className="mt-1 whitespace-normal text-sm text-gray-400">{incident.description}</p>
                      {incident.wazuh_alert && (
                        <details className="mt-2 text-xs text-gray-400">
                          <summary className="cursor-pointer">Original Wazuh alert</summary>
                          <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap rounded bg-gray-900 p-3">
                            {JSON.stringify(incident.wazuh_alert, null, 2)}
                          </pre>
                        </details>
                      )}
                    </td>
                    <td className="p-3">
                      <span className={`rounded px-2 py-1 text-xs uppercase ${severityStyles[severity] || 'bg-gray-700 text-gray-300'}`}>
                        {severity}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className={`rounded px-2 py-1 text-xs ${statusStyles[incident.status] || 'bg-gray-700 text-gray-300'}`}>
                        {incident.status}
                      </span>
                    </td>
                    <td className="p-3">{incident.source || 'Unknown'}</td>
                    <td className="p-3">{incident.anomaly_score === null ? 'N/A' : `${incident.anomaly_score.toFixed(1)} / 100`}</td>
                    <td className="whitespace-nowrap p-3">{new Date(detectedAt).toLocaleString()}</td>
                    <td className="max-w-xs break-all p-3 font-mono text-xs">{incident.wazuh_alert_id || 'N/A'}</td>
                    <td className="p-3">
                      <button
                        type="button"
                        onClick={() => void loadTimeline(incident.id)}
                        className="rounded border border-blue-700 px-3 py-1.5 text-sm text-blue-200 hover:bg-blue-950"
                      >
                        Open details
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </PageLayout>
  );
};

export default IncidentsPage;
