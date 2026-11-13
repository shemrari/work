import { useEffect, useState } from 'react';
import PageLayout from '../components/PageLayout';
import StatCard from '../components/StatCard';
import './Simulations.css';

type WazuhAlert = {
  _id?: string;
  id?: string;
  '@timestamp'?: string;
  agent?: { id?: string; name?: string };
  rule?: { id?: string; level?: number; description?: string; groups?: string[] };
  location?: string;
};

type SimulationRun = {
  id: number;
  scenario: string;
  target: string;
  status: string;
  attempt_count: number;
  started_at: string;
  completed_at: string | null;
  result: string;
  ports_tested: number[] | null;
  wazuh_status: string;
  wazuh_alert_id: string | null;
  wazuh_alert: WazuhAlert | null;
  wazuh_rule_id: string | null;
  wazuh_rule_level: number | null;
  ai_status: string | null;
  ai_score: number | null;
  incident_id: number | null;
  error: string | null;
};

type WazuhAgent = {
  id: string;
  name: string;
  status: string;
};

type WazuhAgentsResponse = {
  data?: { affected_items?: WazuhAgent[] };
};

type WazuhStatus = {
  wazuh_manager_api?: string;
  wazuh_indexer?: string;
};

type LabHealth = {
  status?: string;
  scope?: string;
};

const apiBase = '/api/simulations';

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  return response.json() as Promise<T>;
}

function statusTone(status: string) {
  const normalized = status.toLowerCase();
  if (['healthy', 'active', 'connected', 'completed', 'detected', 'trained'].includes(normalized)) return 'healthy';
  if (['running', 'pending', 'checking', 'starting'].includes(normalized)) return 'pending';
  if (['failed', 'unavailable', 'not_detected'].includes(normalized)) return 'unavailable';
  return 'neutral';
}

function StatusPill({ status }: { status: string }) {
  return <span className={`simulation-pill simulation-pill--${statusTone(status)}`}>{status.replace(/_/g, ' ')}</span>;
}

function HistoryRunCard({ run }: { run: SimulationRun }) {
  const isSsh = run.scenario === 'ssh_brute_force';
  const scenario = isSsh ? 'SSH Brute Force' : 'Port Scan';
  const wazuhLabel = run.wazuh_status === 'detected'
    ? 'Detected'
    : run.wazuh_status === 'not_detected'
      ? 'Not detected'
      : run.wazuh_status === 'pending'
        ? 'Pending'
        : run.wazuh_status.replace(/_/g, ' ');
  const aiLabel = run.ai_status === 'pending'
    ? 'Pending'
    : run.ai_status && run.ai_status !== 'not_analyzed'
      ? `${run.ai_status.replace(/_/g, ' ')}${run.ai_score == null ? '' : ` · ${run.ai_score}`}`
      : 'N/A';
  const ruleLabel = run.wazuh_rule_id
    ? `${run.wazuh_rule_id} · Level ${run.wazuh_rule_level ?? 'N/A'}`
    : 'N/A';
  const executionTime = run.completed_at || run.started_at;
  const flow = isSsh
    ? ['ATTACKER', 'SSH :22', run.target || 'Target', 'WAZUH', 'AI', run.incident_id == null ? 'INCIDENT · N/A' : `INCIDENT · #${run.incident_id}`]
    : ['ATTACKER', 'TCP Scan', run.target || 'Target', `WAZUH · ${wazuhLabel}`];

  return (
    <article className={`simulation-run-card${isSsh ? ' simulation-run-card--ssh' : ' simulation-run-card--scan'}`}>
      <header className="simulation-run-card__header">
        <div className="simulation-run-card__scenario">
          <span className="simulation-run-card__icon" aria-hidden="true">{isSsh ? 'SSH' : 'TCP'}</span>
          <div><p>Scenario</p><h3>{scenario}</h3></div>
        </div>
        <StatusPill status={run.status} />
      </header>

      <div className="simulation-run-flow" aria-label={`${scenario} event path`}>
        {flow.map((step, index) => (
          <span className="simulation-run-flow__item" key={`${run.id}-${step}`}>
            <span className={`simulation-run-flow__step${index === 0 ? ' simulation-run-flow__step--attacker' : ''}${index === 2 ? ' simulation-run-flow__step--target' : ''}`}>{step}</span>
            {index < flow.length - 1 && <span className="simulation-run-flow__arrow" aria-hidden="true">→</span>}
          </span>
        ))}
      </div>

      <dl className="simulation-run-card__details">
        <div><dt>Target</dt><dd>{run.target || 'N/A'}</dd></div>
        <div><dt>Status</dt><dd><StatusPill status={run.status} /></dd></div>
        <div><dt>Wazuh</dt><dd><StatusPill status={wazuhLabel} /></dd></div>
        <div><dt>Attempts</dt><dd>{run.attempt_count}</dd></div>
        <div><dt>Ports</dt><dd>{run.ports_tested?.length ? run.ports_tested.join(', ') : 'N/A'}</dd></div>
        <div><dt>Rule</dt><dd>{ruleLabel}</dd></div>
        <div><dt>AI</dt><dd>{aiLabel}</dd></div>
        <div><dt>Incident</dt><dd>{run.incident_id == null ? 'N/A' : `#${run.incident_id}`}</dd></div>
        <div><dt>Execution</dt><dd><time dateTime={executionTime}>{new Date(executionTime).toLocaleString()}</time></dd></div>
      </dl>

      {run.wazuh_alert_id && <p className="simulation-run-card__alert-id">Wazuh alert ID · <span>{run.wazuh_alert_id}</span></p>}
      <p className="simulation-run-card__result" title={run.result || 'N/A'}>{run.result || 'N/A'}</p>
      {run.error && <p className="simulation-run-card__error">{run.error}</p>}
    </article>
  );
}

const SimulationsPage = () => {
  const [runs, setRuns] = useState<SimulationRun[]>([]);
  const [activeSshRun, setActiveSshRun] = useState<SimulationRun | null>(null);
  const [sshStartedAt, setSshStartedAt] = useState<number | null>(null);
  const [labHealth, setLabHealth] = useState<LabHealth | null>(null);
  const [wazuhAgent, setWazuhAgent] = useState<WazuhAgent | null>(null);
  const [wazuhStatus, setWazuhStatus] = useState<WazuhStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [runningScenario, setRunningScenario] = useState<'ssh_brute_force' | 'port_scan' | null>(null);
  const [refreshingDetection, setRefreshingDetection] = useState(false);
  const [historyAvailable, setHistoryAvailable] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const loadRuns = async () => {
    try {
      const data = await fetchJson<SimulationRun[]>(`${apiBase}/?limit=50`);
      setRuns(data);
      setHistoryAvailable(true);
      setError(null);
    } catch (requestError) {
      console.error('Failed to load simulation history:', requestError);
      setHistoryAvailable(false);
      setError(requestError instanceof Error ? requestError.message : 'Unable to load simulation history.');
    } finally {
      setLoading(false);
    }
  };

  const loadLabComponents = async () => {
    const results = await Promise.allSettled([
      fetchJson<LabHealth>(`${apiBase}/lab-status`),
      fetchJson<WazuhAgentsResponse>('/wazuh/agents?limit=500&sort=name'),
      fetchJson<WazuhStatus>('/wazuh/status'),
    ]);
    setLabHealth(results[0].status === 'fulfilled' ? results[0].value : null);
    setWazuhAgent(results[1].status === 'fulfilled'
      ? results[1].value.data?.affected_items?.find((agent) => agent.name === 'ssh-lab-target') || null
      : null);
    setWazuhStatus(results[2].status === 'fulfilled' ? results[2].value : null);
  };

  useEffect(() => {
    void loadRuns();
    void loadLabComponents();
  }, []);

  useEffect(() => {
    if (!running) return undefined;
    const pollId = window.setInterval(() => void loadRuns(), 1000);
    return () => window.clearInterval(pollId);
  }, [running]);

  const runSshSimulation = async () => {
    setActiveSshRun(null);
    setSshStartedAt(Date.now());
    setRunning(true);
    setRunningScenario('ssh_brute_force');
    setError(null);
    setNotice('Starting the existing SSH simulation in the isolated Docker lab.');
    try {
      const response = await fetch(`${apiBase}/ssh-brute-force`, { method: 'POST' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Simulation request failed (${response.status})`);
      const run = data as SimulationRun;
      setActiveSshRun(run);
      setNotice(run.wazuh_status === 'detected' && run.wazuh_alert_id
        ? 'Attack completed. Wazuh returned a matching alert.'
        : run.wazuh_status === 'unavailable'
          ? 'Attack completed. Wazuh detection status is unavailable.'
          : 'Attack completed. Wazuh detection: Not detected / Pending.');
      await loadRuns();
    } catch (requestError) {
      console.error('SSH lab simulation failed:', requestError);
      setError(requestError instanceof Error ? requestError.message : 'SSH lab simulation failed.');
      await loadRuns();
    } finally {
      setRunning(false);
      setRunningScenario(null);
    }
  };

  const runPortScanSimulation = async () => {
    setRunning(true);
    setRunningScenario('port_scan');
    setError(null);
    setNotice('Testing ports on the isolated lab target.');
    try {
      const response = await fetch(`${apiBase}/port-scan`, { method: 'POST' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Port scan request failed (${response.status})`);
      setNotice(data.wazuh_status === 'detected'
        ? 'The local port scan completed and a corresponding Wazuh alert was indexed.'
        : 'The local port scan completed. No matching Wazuh alert is confirmed yet.');
      await loadRuns();
    } catch (requestError) {
      console.error('Local port scan simulation failed:', requestError);
      setError(requestError instanceof Error ? requestError.message : 'Local port scan simulation failed.');
      await loadRuns();
    } finally {
      setRunning(false);
      setRunningScenario(null);
    }
  };

  const refreshPendingDetection = async () => {
    setRefreshingDetection(true);
    setError(null);
    try {
      const response = await fetch(`${apiBase}/refresh-pending`, { method: 'POST' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Wazuh refresh failed (${response.status})`);
      await loadRuns();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to refresh pending Wazuh detection.');
    } finally {
      setRefreshingDetection(false);
    }
  };

  const latestSshRun = activeSshRun
    ? runs.find((run) => run.id === activeSshRun.id) || activeSshRun
    : runs.find((run) => run.scenario === 'ssh_brute_force') || null;
  const sshExecutionActive = running && runningScenario === 'ssh_brute_force';
  const liveSshRun = sshExecutionActive && sshStartedAt !== null
    ? runs.find((run) => run.scenario === 'ssh_brute_force' && new Date(run.started_at).getTime() >= sshStartedAt) || null
    : null;
  const runningSshRun = liveSshRun?.status === 'running' ? liveSshRun : null;
  const displayedSshRun = sshExecutionActive ? liveSshRun : latestSshRun;
  const resultRun = sshExecutionActive ? liveSshRun : latestSshRun;
  const labServiceStatus = labHealth?.status === 'healthy' && labHealth.scope === 'LAB'
    ? 'healthy'
    : loading ? 'checking' : 'unavailable';
  const agentStatus = wazuhAgent?.status || (loading ? 'checking' : 'unavailable');
  const sshRunStatus = sshExecutionActive
    ? runningSshRun ? 'Running' : 'Starting'
    : latestSshRun?.status === 'completed' ? 'Completed'
      : latestSshRun?.status === 'failed' ? 'Failed'
        : labServiceStatus === 'healthy' ? 'Ready' : 'Unavailable';
  const detectionStatus = !displayedSshRun
    ? 'Waiting for simulation'
    : displayedSshRun.status === 'running'
      ? 'Waiting for simulator result'
      : displayedSshRun.wazuh_status === 'detected' && displayedSshRun.wazuh_alert_id
        ? 'Detected'
        : displayedSshRun.wazuh_status === 'unavailable'
          ? 'Unavailable'
          : displayedSshRun.wazuh_status === 'pending'
            ? 'Detection pending'
            : displayedSshRun.wazuh_status === 'not_detected'
              ? 'Not detected'
              : displayedSshRun.wazuh_status.replace(/_/g, ' ');

  const completedRuns = runs.filter((run) => run.status === 'completed').length;
  const detectedRuns = runs.filter((run) => run.wazuh_status === 'detected').length;
  const attemptsSent = runs.reduce((sum, run) => sum + run.attempt_count, 0);
  return (
    <PageLayout>
      <div className="simulation-page">
        <header className="simulation-header">
          <div>
            <p className="simulation-eyebrow">Security operations / lab</p>
            <h1>Attack Simulator</h1>
            <p>Real SSH attempts inside the isolated Docker lab. Wazuh remains responsible for detection.</p>
          </div>
          <div className="simulation-header__actions">
            <button type="button" onClick={() => { void loadRuns(); void loadLabComponents(); }} disabled={loading || running || refreshingDetection} className="simulation-button simulation-button--secondary">
              {loading ? 'Loading history...' : 'Refresh status'}
            </button>
            {runs.some((run) => ['pending', 'unavailable', 'not_detected'].includes(run.wazuh_status)) && (
              <button type="button" onClick={() => void refreshPendingDetection()} disabled={running || loading || refreshingDetection} className="simulation-button simulation-button--secondary">
                {refreshingDetection ? 'Checking Wazuh...' : 'Check pending detection'}
              </button>
            )}
            <button type="button" onClick={() => void runPortScanSimulation()} disabled={running || loading} className="simulation-button simulation-button--secondary">
              {running ? 'Lab busy...' : 'Run Port Scan'}
            </button>
          </div>
        </header>

        {error && <div role="alert" className="simulation-state simulation-state--error">{error}</div>}
        {notice && <p role="status" className="simulation-state">{notice}</p>}

        <section className="simulation-architecture" aria-labelledby="attack-execution-flow-title">
          <header className="simulation-architecture__header">
            <div>
              <p className="simulation-eyebrow">Isolated lab / real security chain</p>
              <h2 id="attack-execution-flow-title">Attack Execution Flow</h2>
              <p>Simulated attacker traffic reaches the lab target; Wazuh detects it, AI analyzes the alert, and the backend links an incident.</p>
            </div>
            <span className="simulation-isolation-label">Isolated Docker lab — simulation only</span>
          </header>

          <div className="simulation-architecture__nodes">
            <article className="simulation-architecture-node simulation-architecture-node--attacker">
              <div className="simulation-architecture-node__top"><span className="simulation-architecture-node__mark">!</span><StatusPill status={sshRunStatus} /></div>
              <p className="simulation-architecture-node__eyebrow">Attacker</p>
              <h3>Attack Simulator</h3>
              <p className="simulation-architecture-node__detail">Simulated attacker · real lab traffic</p>
            </article>
            <div className="simulation-architecture-link"><span>SSH :22</span><b aria-hidden="true">→</b></div>
            <article className="simulation-architecture-node simulation-architecture-node--target">
              <div className="simulation-architecture-node__top"><span className="simulation-architecture-node__mark">02</span><span className="simulation-architecture-node__tag">Isolated</span></div>
              <p className="simulation-architecture-node__eyebrow">Target</p>
              <h3>{resultRun?.target || 'ssh-lab-target'}</h3>
              <p className="simulation-architecture-node__detail">Docker Lab Target</p>
            </article>
            <div className="simulation-architecture-link"><span>Agent → Manager → Indexer</span><b aria-hidden="true">→</b></div>
            <article className="simulation-architecture-node simulation-architecture-node--wazuh">
              <div className="simulation-architecture-node__top"><span className="simulation-architecture-node__mark">W</span><StatusPill status={detectionStatus} /></div>
              <p className="simulation-architecture-node__eyebrow">Wazuh · real lab detection</p>
              <div className="simulation-wazuh-stack">
                <div><span>Agent</span><strong>{agentStatus}</strong></div>
                <div><span>Manager</span><strong>{wazuhStatus?.wazuh_manager_api || 'unavailable'}</strong></div>
                <div><span>Indexer</span><strong>{wazuhStatus?.wazuh_indexer || 'unavailable'}</strong></div>
              </div>
            </article>
            <div className="simulation-architecture-link"><span>Real alert</span><b aria-hidden="true">→</b></div>
            <article className="simulation-architecture-node simulation-architecture-node--alert">
              <div className="simulation-architecture-node__top"><span className="simulation-architecture-node__mark">!</span><StatusPill status={resultRun?.wazuh_alert_id ? 'detected' : detectionStatus} /></div>
              <p className="simulation-architecture-node__eyebrow">Wazuh alert</p>
              <h3>{resultRun?.wazuh_alert_id ? `Rule ${resultRun.wazuh_rule_id || resultRun.wazuh_alert?.rule?.id || 'N/A'}` : 'No alert yet'}</h3>
              <p className="simulation-architecture-node__detail">{resultRun?.wazuh_alert_id ? `Level ${resultRun.wazuh_rule_level ?? resultRun.wazuh_alert?.rule?.level ?? 'N/A'}` : 'Waiting for Wazuh detection'}</p>
              {resultRun?.wazuh_alert?.rule?.description && <p className="simulation-architecture-node__subdetail">{resultRun.wazuh_alert.rule.description}</p>}
            </article>
            <div className="simulation-architecture-link"><span>AI analysis</span><b aria-hidden="true">→</b></div>
            <article className="simulation-architecture-node simulation-architecture-node--ai">
              <div className="simulation-architecture-node__top"><span className="simulation-architecture-node__mark">AI</span><StatusPill status={resultRun?.ai_status || 'N/A'} /></div>
              <p className="simulation-architecture-node__eyebrow">AI detection</p>
              <h3>{resultRun?.ai_status || 'Awaiting alert'}</h3>
              <p className="simulation-architecture-node__detail">Score: {resultRun?.ai_score == null ? 'N/A' : resultRun.ai_score}</p>
              <p className="simulation-architecture-node__subdetail">Real returned AI analysis</p>
            </article>
            <div className="simulation-architecture-link"><span>Correlated incident</span><b aria-hidden="true">→</b></div>
            <article className="simulation-architecture-node simulation-architecture-node--incident">
              <div className="simulation-architecture-node__top"><span className="simulation-architecture-node__mark">IR</span><StatusPill status={resultRun?.incident_id == null ? 'N/A' : 'created'} /></div>
              <p className="simulation-architecture-node__eyebrow">Incident</p>
              <h3>{resultRun?.incident_id == null ? 'N/A' : `Incident #${resultRun.incident_id}`}</h3>
              <p className="simulation-architecture-node__detail">{resultRun?.incident_id == null ? 'No linked incident returned' : 'Created from correlated backend data'}</p>
            </article>
          </div>

          <div className="simulation-response-note">
            <div><strong>Response actions remain simulated</strong><span>Notify Admin · Isolate Asset · Block IP · Generate Report</span></div>
            <span>Audit records only · no host or network commands</span>
          </div>
        </section>

        <section className="simulation-attacker" aria-labelledby="simulation-attacker-title">
          <header className="simulation-attacker__header">
            <div className="simulation-attacker__identity">
              <span className="simulation-attacker__icon" aria-hidden="true">!</span>
              <div>
                <p className="simulation-eyebrow simulation-eyebrow--red">Attacker machine</p>
                <h2 id="simulation-attacker-title">ATTACKER</h2>
                <p>Attack Simulator · isolated lab service</p>
              </div>
            </div>
            <StatusPill status={sshRunStatus} />
          </header>

          <div className="simulation-attacker__body">
            <dl className="simulation-config">
              <div><dt>Target</dt><dd>{resultRun?.target || 'ssh-lab-target:22'}</dd></div>
              <div><dt>Protocol</dt><dd>SSH</dd></div>
              <div><dt>Attack type</dt><dd>SSH Brute Force</dd></div>
              <div><dt>Launch state</dt><dd>{sshRunStatus}</dd></div>
            </dl>
            <button type="button" onClick={() => void runSshSimulation()} disabled={running || loading || refreshingDetection} className="simulation-launch">
              <span aria-hidden="true">▶</span>
              {running ? 'SSH simulation running...' : 'Launch SSH Brute Force'}
            </button>
          </div>

          <section className="simulation-execution" aria-labelledby="simulation-execution-title" aria-live="polite">
            <div className="simulation-execution__heading">
              <div><p className="simulation-eyebrow">Real backend response</p><h3 id="simulation-execution-title">SSH Brute Force execution</h3></div>
              <span className="simulation-execution__target">Target: {resultRun?.target || 'ssh-lab-target:22'}</span>
            </div>
            {sshExecutionActive ? (
              <div className="simulation-execution__live">
                <span className="simulation-live-indicator" />
                <div>
                  <strong>{resultRun?.status === 'completed' ? 'Attack completed · waiting for Wazuh response' : runningSshRun ? 'Attack started' : 'Starting attack'}</strong>
                  <p>{resultRun
                    ? `${resultRun.attempt_count} attempt${resultRun.attempt_count === 1 ? '' : 's'} reported by the backend.`
                    : 'Waiting for the existing simulation endpoint to register the run.'}</p>
                  <p className="simulation-execution__note">The existing API returns its actual attempt count after the simulator finishes; per-attempt progress is not streamed.</p>
                </div>
              </div>
            ) : resultRun ? (
              <dl className="simulation-result-grid">
                <div><dt>Target</dt><dd>{resultRun.target || 'N/A'}</dd></div>
                <div><dt>Protocol</dt><dd>SSH · 22</dd></div>
                <div><dt>Attack type</dt><dd>SSH Brute Force</dd></div>
                <div><dt>Attempts</dt><dd>{resultRun.attempt_count}</dd></div>
                <div><dt>Run status</dt><dd><StatusPill status={resultRun.status} /></dd></div>
                <div><dt>Wazuh status</dt><dd><StatusPill status={detectionStatus} /></dd></div>
                <div><dt>Wazuh alert ID</dt><dd>{resultRun.wazuh_alert_id || 'N/A'}</dd></div>
                <div><dt>Rule ID</dt><dd>{resultRun.wazuh_rule_id || resultRun.wazuh_alert?.rule?.id || 'N/A'}</dd></div>
                <div><dt>Rule level</dt><dd>{resultRun.wazuh_rule_level ?? resultRun.wazuh_alert?.rule?.level ?? 'N/A'}</dd></div>
                <div><dt>AI anomaly status</dt><dd>{resultRun.ai_status || 'N/A'}</dd></div>
                <div><dt>AI score</dt><dd>{resultRun.ai_score == null ? 'N/A' : resultRun.ai_score}</dd></div>
                <div><dt>Incident ID</dt><dd>{resultRun.incident_id == null ? 'N/A' : `#${resultRun.incident_id}`}</dd></div>
              </dl>
            ) : (
              <p className="simulation-execution__empty">No SSH run is selected. Launch a lab simulation to display its real backend result.</p>
            )}
          </section>
        </section>

        <section className="simulation-totals" aria-label="Persisted simulation totals">
          <StatCard title="Recorded runs" value={historyAvailable ? runs.length : loading ? '...' : 'N/A'} />
          <StatCard title="Completed runs" value={historyAvailable ? completedRuns : loading ? '...' : 'N/A'} />
          <StatCard title="Attempts sent" value={historyAvailable ? attemptsSent : loading ? '...' : 'N/A'} />
          <StatCard title="Runs with Wazuh alert" value={historyAvailable ? detectedRuns : loading ? '...' : 'N/A'} />
        </section>

        <section className="simulation-history" aria-labelledby="recorded-runs-title">
          <header className="simulation-history__header">
            <div><p className="simulation-eyebrow">Persisted lab activity</p><h2 id="recorded-runs-title">Recorded Runs</h2></div>
            <span>{historyAvailable ? `${runs.length} runs` : loading ? 'Loading history...' : 'History unavailable'}</span>
          </header>
          {loading ? (
            <p className="simulation-history__message">Loading persisted lab runs...</p>
          ) : !historyAvailable ? (
            <p className="simulation-history__message">Simulation history is unavailable.</p>
          ) : runs.length === 0 ? (
            <p className="simulation-history__message">No persisted simulations have been recorded.</p>
          ) : (
            <div className="simulation-run-list">
              {runs.map((run) => <HistoryRunCard key={run.id} run={run} />)}
            </div>
          )}
        </section>
      </div>
    </PageLayout>
  );
};

export default SimulationsPage;