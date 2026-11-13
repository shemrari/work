import { useEffect, useState } from 'react';
import PageLayout from '../components/PageLayout';

type IncidentSummary = {
  id: number;
  title: string;
  severity: string | null;
  status: string;
  source: string | null;
  detected_at: string | null;
  anomaly_score: number | null;
  wazuh_alert_id: string | null;
};

type ReportResponseAction = {
  action_type: string;
  target: string;
  status: string;
  description: string;
  executed_at: string;
  result: string;
};

type ReportTimelineEvent = {
  event: string;
  timestamp: string;
  description: string;
  reference: string | null;
};

type ReportSimulation = {
  id: number;
  scenario: string;
  target: string;
  status: string;
  attempt_count: number;
  started_at: string;
  completed_at: string | null;
  result: string;
  wazuh_status: string;
  wazuh_alert_id: string | null;
};

type IncidentReport = {
  incident: IncidentSummary & {
    description: string;
    wazuh_alert: Record<string, unknown> | null;
  };
  wazuh_rule_id: string | null;
  wazuh_rule_level: number | null;
  wazuh_description: string | null;
  agent_target: string | null;
  ai_anomaly_score: number | null;
  ai_anomaly_status: string;
  response_actions: ReportResponseAction[];
  timeline: ReportTimelineEvent[];
  simulations: ReportSimulation[];
};

const apiBase = '/api';
const unavailable = 'Not available in persisted data';

const valueOrUnavailable = (value: string | number | null | undefined) =>
  value === null || value === undefined || value === '' ? unavailable : String(value);

const ReportsPage = () => {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [report, setReport] = useState<IncidentReport | null>(null);
  const [loadingIncidents, setLoadingIncidents] = useState(true);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [downloaded, setDownloaded] = useState(false);

  useEffect(() => {
    const loadIncidents = async () => {
      try {
        const response = await fetch(`${apiBase}/incidents?skip=0&limit=500`);
        if (!response.ok) throw new Error(`Incident list request failed (${response.status})`);
        const data = await response.json() as IncidentSummary[];
        setIncidents(data);
        if (data.length > 0) setSelectedId(String(data[0].id));
      } catch (requestError) {
        setError(requestError instanceof Error ? requestError.message : 'Unable to load persisted incidents.');
      } finally {
        setLoadingIncidents(false);
      }
    };
    void loadIncidents();
  }, []);

  useEffect(() => {
    if (!selectedId) {
      setReport(null);
      return;
    }
    const loadReportPreview = async () => {
      setLoadingPreview(true);
      setError(null);
      setDownloaded(false);
      try {
        const response = await fetch(`${apiBase}/reports/incidents/${selectedId}`);
        if (!response.ok) throw new Error(`Report preview request failed (${response.status})`);
        setReport(await response.json() as IncidentReport);
      } catch (requestError) {
        setReport(null);
        setError(requestError instanceof Error ? requestError.message : 'Unable to load incident report data.');
      } finally {
        setLoadingPreview(false);
      }
    };
    void loadReportPreview();
  }, [selectedId]);

  const generatePdf = async () => {
    if (!selectedId) return;
    setGenerating(true);
    setError(null);
    setDownloaded(false);
    try {
      const response = await fetch(`${apiBase}/reports/incidents/${selectedId}/pdf`);
      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(body?.detail || `PDF generation failed (${response.status})`);
      }
      const pdfBlob = await response.blob();
      if (pdfBlob.type !== 'application/pdf' || pdfBlob.size === 0) {
        throw new Error('The report endpoint did not return a valid PDF.');
      }
      const objectUrl = URL.createObjectURL(pdfBlob);
      const anchor = document.createElement('a');
      anchor.href = objectUrl;
      anchor.download = `cybersoc-incident-${report?.incident.id || selectedId}-report.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(objectUrl);
      setDownloaded(true);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'PDF generation failed.');
    } finally {
      setGenerating(false);
    }
  };

  const incident = report?.incident;

  return (
    <PageLayout>
      <div className="soc-page-stack">
        <header className="soc-page-heading">
          <div>
            <h1 className="soc-page-title">Incident reports</h1>
            <p className="soc-page-description">
              Report data comes from persisted incidents, their Wazuh alerts, simulation runs, and response-action records.
            </p>
          </div>
        </header>

        <section className="soc-panel flex flex-wrap items-end gap-4">
          <label className="flex min-w-64 flex-1 flex-col gap-2 text-sm font-medium">
            Select incident
            <select
              value={selectedId}
              onChange={(event) => setSelectedId(event.target.value)}
              disabled={loadingIncidents || incidents.length === 0}
              className="min-h-10 rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-800 disabled:opacity-50"
            >
              {incidents.length === 0 && <option value="">No persisted incidents</option>}
              {incidents.map((item) => (
                <option key={item.id} value={item.id}>
                  #{item.id} · {item.severity || 'Unrated'} · {item.title}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            onClick={() => void generatePdf()}
            disabled={!report || generating || loadingPreview}
            className="soc-button bg-blue-700 text-white hover:bg-blue-600 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {generating ? 'Generating PDF...' : 'Generate PDF Report'}
          </button>
        </section>

        {error && <div role="alert" className="rounded border border-red-800 bg-red-950 p-3 text-sm text-red-200">{error}</div>}
        {downloaded && <p role="status" className="text-sm text-green-300">PDF generated from persisted incident data and downloaded.</p>}
        {loadingIncidents && <p className="text-sm text-gray-400">Loading persisted incidents...</p>}
        {loadingPreview && <p className="text-sm text-gray-400">Loading report preview...</p>}
        {!loadingIncidents && incidents.length === 0 && !error && (
          <p className="soc-state">
            No persisted incidents are available to include in a report.
          </p>
        )}

        {report && incident && (
          <section className="soc-panel space-y-5">
            <div className="flex flex-wrap items-start justify-between gap-3 border-b border-gray-700 pb-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-blue-700">Report preview · Incident #{incident.id}</p>
                <h2 className="mt-1 text-xl font-semibold">{incident.title}</h2>
                <p className="mt-2 text-sm text-gray-400">{incident.description}</p>
              </div>
            </div>

            <dl className="grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2 xl:grid-cols-4">
              {[
                ['Severity', incident.severity],
                ['Status', incident.status],
                ['Source', incident.source],
                ['Detected at', incident.detected_at],
                ['Wazuh alert ID', incident.wazuh_alert_id],
                ['Wazuh rule ID', report.wazuh_rule_id],
                ['Wazuh rule level', report.wazuh_rule_level],
                ['Wazuh description', report.wazuh_description],
                ['Agent / target', report.agent_target],
                ['AI anomaly score', report.ai_anomaly_score],
                ['AI anomaly status', report.ai_anomaly_status],
              ].map(([label, value]) => (
                <div key={String(label)} className="min-w-0">
                  <dt className="text-xs uppercase tracking-wider text-gray-400">{label}</dt>
                  <dd className="mt-1 break-words text-sm">{valueOrUnavailable(value as string | number | null)}</dd>
                </div>
              ))}
            </dl>

            <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
              <section>
                <h3 className="mb-2 font-semibold">Response actions ({report.response_actions.length})</h3>
                {report.response_actions.length ? (
                  <ul className="space-y-2 text-sm">
                    {report.response_actions.map((action, index) => (
                      <li key={`${action.action_type}-${index}`} className="border-b border-gray-200 py-3 last:border-0">
                        <p className="font-medium">{action.action_type} · {action.status}</p>
                        <p className="mt-1 text-gray-400">{action.description}</p>
                        <p className="text-xs text-gray-500">Target: {action.target} · {action.result}</p>
                      </li>
                    ))}
                  </ul>
                ) : <p className="text-sm text-gray-400">No persisted response actions.</p>}
              </section>

              <section>
                <h3 className="mb-2 font-semibold">Timeline ({report.timeline.length})</h3>
                {report.timeline.length ? (
                  <ol className="space-y-2 text-sm">
                    {report.timeline.map((event, index) => (
                      <li key={`${event.event}-${event.reference || index}`} className="border-l-2 border-blue-600 pl-3">
                        <p className="font-medium">{event.event.replace(/_/g, ' ')}</p>
                        <p className="text-xs text-gray-500">{event.timestamp}</p>
                        <p className="text-gray-400">{event.description}</p>
                      </li>
                    ))}
                  </ol>
                ) : <p className="text-sm text-gray-400">No persisted timeline events.</p>}
              </section>

              <section>
                <h3 className="mb-2 font-semibold">Related simulations ({report.simulations.length})</h3>
                {report.simulations.length ? (
                  <ul className="space-y-2 text-sm">
                    {report.simulations.map((simulation) => (
                      <li key={simulation.id} className="border-b border-gray-200 py-3 last:border-0">
                        <p className="font-medium">Run #{simulation.id} · {simulation.scenario}</p>
                        <p className="text-gray-400">{simulation.target} · {simulation.status}</p>
                        <p>Attempts: {simulation.attempt_count}</p>
                        <p className="text-gray-400">Wazuh: {simulation.wazuh_status} · {valueOrUnavailable(simulation.wazuh_alert_id)}</p>
                        <p className="mt-1 text-xs text-gray-500">{simulation.result}</p>
                      </li>
                    ))}
                  </ul>
                ) : <p className="text-sm text-gray-400">No simulation with this incident's persisted Wazuh alert ID.</p>}
              </section>
            </div>

            <p className="border-t border-gray-200 pt-4 text-sm text-gray-500">
              Response actions in this report are persisted simulation audit records; this report does not execute response commands.
            </p>
          </section>
        )}
      </div>
    </PageLayout>
  );
};

export default ReportsPage;
