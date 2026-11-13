import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import PageLayout from '../components/PageLayout';
import './Network.css';

type ApiHealth = {
  status?: string;
  database?: string;
};

type WazuhStatus = {
  status?: string;
  wazuh_manager_api?: string;
  wazuh_indexer?: string;
};

type WazuhAgent = {
  id: string;
  name: string;
  ip?: string;
  status: string;
};

type AgentResponse = {
  data?: { affected_items?: WazuhAgent[] };
};

type AnomalyStatus = {
  model?: string;
  analysis_status?: string;
  summary?: { alerts_analyzed?: number };
};

type LabStatus = {
  status?: string;
  scope?: string;
};

const apiBase = '';

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${apiBase}${path}`);
  if (!response.ok) {
    throw new Error(`${path} returned ${response.status}`);
  }
  return response.json() as Promise<T>;
}

function settledValue<T>(result: PromiseSettledResult<T>): T | null {
  return result.status === 'fulfilled' ? result.value : null;
}

function StatusBadge({ status }: { status: string }) {
  const normalized = status.toLowerCase();
  const tone = ['healthy', 'active', 'connected', 'reachable'].includes(normalized)
    ? 'healthy'
    : normalized === 'available' || normalized === 'trained'
      ? 'available'
      : 'neutral';
  const label = normalized === 'not_enrolled' ? 'not available' : status.replace(/_/g, ' ');

  return (
    <span className={`network-status network-status--${tone}`}>
      <span className="network-status__dot" aria-hidden="true" />
      {label}
    </span>
  );
}

function ServiceNode({
  code,
  title,
  status,
  detail,
}: {
  code: string;
  title: string;
  status: string;
  detail: string;
}) {
  return (
    <article className="network-service-node">
      <span className="network-service-node__code" aria-hidden="true">{code}</span>
      <div className="network-service-node__content">
        <div className="network-service-node__heading">
          <h3>{title}</h3>
          <StatusBadge status={status} />
        </div>
        <p>{detail}</p>
      </div>
    </article>
  );
}

function SimulatedAsset({ title, label }: { title: string; label: string }) {
  return (
    <div className="network-asset">
      <span className="network-asset__glyph" aria-hidden="true" />
      <span className="network-asset__title">{title}</span>
      <span className="network-asset__label">{label}</span>
    </div>
  );
}

const NetworkPage = () => {
  const [refreshKey, setRefreshKey] = useState(0);
  const [loading, setLoading] = useState(true);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);
  const [health, setHealth] = useState<ApiHealth | null>(null);
  const [wazuh, setWazuh] = useState<WazuhStatus | null>(null);
  const [agents, setAgents] = useState<WazuhAgent[] | null>(null);
  const [anomaly, setAnomaly] = useState<AnomalyStatus | null>(null);
  const [lab, setLab] = useState<LabStatus | null>(null);
  const [failedSources, setFailedSources] = useState<string[]>([]);

  useEffect(() => {
    let current = true;
    const loadStatus = async () => {
      setLoading(true);
      const results = await Promise.allSettled([
        getJson<ApiHealth>('/health'),
        getJson<WazuhStatus>('/wazuh/status'),
        getJson<AgentResponse>('/wazuh/agents?limit=500&sort=name'),
        getJson<AnomalyStatus>('/ai/anomalies?limit=50'),
        getJson<LabStatus>('/api/simulations/lab-status'),
      ]);

      if (!current) return;

      const [healthResult, wazuhResult, agentsResult, anomalyResult, labResult] = results;
      const healthValue = settledValue(healthResult as PromiseSettledResult<ApiHealth>);
      const wazuhValue = settledValue(wazuhResult as PromiseSettledResult<WazuhStatus>);
      const agentsValue = settledValue(agentsResult as PromiseSettledResult<AgentResponse>);
      const anomalyValue = settledValue(anomalyResult as PromiseSettledResult<AnomalyStatus>);
      const labValue = settledValue(labResult as PromiseSettledResult<LabStatus>);

      setHealth(healthValue);
      setWazuh(wazuhValue);
      setAgents(agentsValue?.data?.affected_items || null);
      setAnomaly(anomalyValue);
      setLab(labValue);
      setFailedSources(results.flatMap((result, index) => result.status === 'rejected'
        ? [['Backend API', 'Wazuh status', 'Wazuh agents', 'AI analysis', 'Attack Lab'][index]]
        : []));
      setLastChecked(new Date());
      setLoading(false);
    };

    void loadStatus();
    return () => {
      current = false;
    };
  }, [refreshKey]);

  const labAgent = agents?.find((agent) => agent.name === 'ssh-lab-target');
  const apiStatus = health?.status === 'ok' ? 'reachable' : health ? 'unavailable' : 'unavailable';
  const databaseStatus = health?.database === 'connected'
    ? 'connected'
    : health?.database?.startsWith('error') ? 'error' : 'unavailable';
  const labStatus = lab?.status === 'healthy' && lab.scope === 'LAB' ? 'healthy' : 'unavailable';
  const agentStatus = agents === null
    ? loading ? 'checking' : 'unavailable'
    : labAgent?.status === 'active' ? 'active' : labAgent ? 'unavailable' : 'not_enrolled';
  const aiAnalysisStatus = anomaly?.analysis_status || (loading ? 'checking' : 'unavailable');
  const aiDetail = anomaly
    ? `${anomaly.model || 'AI analysis'} · ${anomaly.summary?.alerts_analyzed ?? 'N/A'} real alerts analyzed`
    : 'Analysis endpoint unavailable';

  return (
    <PageLayout>
      <main className="network-page">
        <div className="network-page__inner">
          <header className="network-header">
            <div>
              <p className="network-eyebrow">Industrial cybersecurity / architecture</p>
              <h1>Network Architecture</h1>
              <p className="network-header__summary">A visual map of the industrial environment and the connected SOC services.</p>
            </div>
            <div className="network-header__actions">
              <span className="network-maquette-tag">Architecture maquette</span>
              <button
                type="button"
                onClick={() => setRefreshKey((value) => value + 1)}
                disabled={loading}
                className="network-refresh"
              >
                {loading ? 'Checking status...' : 'Refresh status'}
              </button>
            </div>
          </header>

          {failedSources.length > 0 && (
            <div role="status" className="network-source-warning">
              Live checks unavailable: {failedSources.join(', ')}. Those statuses are not inferred.
            </div>
          )}

          <section className="network-board" aria-labelledby="architecture-title">
            <div className="network-board__heading">
              <div>
                <p className="network-eyebrow">Live services + illustrative assets</p>
                <h2 id="architecture-title">Industrial / SOC architecture</h2>
              </div>
              <div className="network-legend" aria-label="Architecture legend">
                <span><i className="network-legend__swatch network-legend__swatch--blue" />Security infrastructure</span>
                <span><i className="network-legend__swatch network-legend__swatch--green" />Healthy / active</span>
                <span><i className="network-legend__swatch network-legend__swatch--red" />Attack / security event</span>
                <span><i className="network-legend__swatch network-legend__swatch--gray" />Simulated asset</span>
              </div>
            </div>

            <section className="network-attack-lane" aria-labelledby="attacker-title">
              <div className="network-attacker-node">
                <div className="network-attacker-node__topline">
                  <span className="network-attacker-mark" aria-hidden="true">!</span>
                  <span className="network-lab-tag">LAB SIMULATION</span>
                </div>
                <p className="network-node-kicker">Attack origin · illustrative</p>
                <h3 id="attacker-title">Attacker</h3>
                <p className="network-attacker-node__name">Attack Simulator</p>
                <div className="network-attacker-node__status">
                  <span>Lab service</span>
                  <StatusBadge status={labStatus} />
                </div>
              </div>
              <div className="network-attack-route" aria-label="Illustrative lab paths toward the virtual industrial site">
                <div className="network-attack-route__label">Illustrative paths · no external attacks</div>
                <div className="network-attack-route__line"><span>→</span></div>
                <div className="network-attack-route__scenarios">
                  <span>SSH Brute Force · LAB</span>
                  <span>Port Scan · LAB</span>
                </div>
              </div>
              <Link to="/simulations" className="network-text-link">Open simulation history <span aria-hidden="true">→</span></Link>
            </section>

            <div className="network-sites" aria-label="Industrial site connected to the SOC security zone">
              <section className="network-zone-card network-industrial-site" aria-labelledby="industrial-title">
                <header className="network-zone-card__header">
                  <div>
                    <p className="network-node-kicker">Virtual site · illustrative only</p>
                    <h3 id="industrial-title">Industrial Site — Virtual IT/OT Environment</h3>
                  </div>
                  <span className="network-illustrative-label">Simulated environment</span>
                </header>
                <div className="network-zones">
                  <section className="network-asset-zone network-asset-zone--it" aria-labelledby="it-zone-title">
                    <div className="network-asset-zone__heading">
                      <span className="network-zone-index">01</span>
                      <div><h4 id="it-zone-title">IT Zone</h4><p>Virtual enterprise systems</p></div>
                    </div>
                    <div className="network-asset-list">
                      <SimulatedAsset title="Application / Server" label="Virtual Industrial Asset" />
                      <SimulatedAsset title="Engineering Workstation" label="Virtual Industrial Asset" />
                      <SimulatedAsset title="File / Authentication Server" label="Virtual Industrial Asset" />
                    </div>
                  </section>
                  <section className="network-asset-zone network-asset-zone--ot" aria-labelledby="ot-zone-title">
                    <div className="network-asset-zone__heading">
                      <span className="network-zone-index">02</span>
                      <div><h4 id="ot-zone-title">OT Zone</h4><p>Industrial control systems</p></div>
                    </div>
                    <div className="network-asset-list">
                      <SimulatedAsset title="HMI" label="Simulated OT Asset" />
                      <SimulatedAsset title="PLC" label="Simulated OT Asset" />
                      <SimulatedAsset title="Industrial Server" label="Simulated OT Asset" />
                    </div>
                  </section>
                </div>
                <p className="network-zone-card__note">No industrial asset inventory is connected. These nodes have no claimed IP, health, or monitoring state.</p>
              </section>

              <div className="network-ipsec" role="note" aria-label="IPsec VPN simulated, no real tunnel configured">
                <div className="network-ipsec__line"><span>↔</span></div>
                <span className="network-ipsec__icon" aria-hidden="true">VPN</span>
                <p className="network-ipsec__title">IPsec VPN</p>
                <StatusBadge status="SIMULATED" />
                <p className="network-ipsec__note">Architecture simulation — no real IPsec tunnel configured</p>
              </div>

              <section className="network-zone-card network-soc-zone" aria-labelledby="soc-zone-title">
                <header className="network-zone-card__header">
                  <div>
                    <p className="network-node-kicker">Security destination</p>
                    <h3 id="soc-zone-title">SOC / Security Zone</h3>
                  </div>
                  <span className="network-infra-label">Application layer</span>
                </header>
                <div className="network-app-stack">
                  <div className="network-app-node network-app-node--ui">
                    <span className="network-app-node__code">UI</span>
                    <div><h4>React SOC Dashboard</h4><p>Current interface</p></div>
                  </div>
                  <span className="network-stack-arrow" aria-hidden="true">↓</span>
                  <div className="network-app-node">
                    <span className="network-app-node__code">API</span>
                    <div className="network-app-node__body"><h4>FastAPI Backend</h4><p>Health endpoint</p></div>
                    <StatusBadge status={apiStatus} />
                  </div>
                  <span className="network-stack-arrow" aria-hidden="true">↓</span>
                  <div className="network-app-node">
                    <span className="network-app-node__code">DB</span>
                    <div className="network-app-node__body"><h4>PostgreSQL</h4><p>{health?.database || 'Database health unavailable'}</p></div>
                    <StatusBadge status={databaseStatus} />
                  </div>
                </div>
                <p className="network-zone-card__note">Backend and database badges reflect the existing <code>/health</code> response.</p>
              </section>
            </div>

            <section className="network-layer" aria-labelledby="wazuh-layer-title">
              <div className="network-layer__heading">
                <div><p className="network-node-kicker">Live service health</p><h3 id="wazuh-layer-title">Wazuh Monitoring Layer</h3></div>
                <p>Agent shown here is the isolated SSH lab agent, not an industrial-site asset.</p>
              </div>
              <div className="network-service-chain">
                <ServiceNode
                  code="AG"
                  title="Wazuh Agent · LAB"
                  status={agentStatus}
                  detail={labAgent ? `${labAgent.name} · agent ${labAgent.id}${labAgent.ip ? ` · ${labAgent.ip}` : ''}` : agents === null ? 'Agent API not available' : 'No ssh-lab-target agent returned'}
                />
                <span className="network-chain-arrow" aria-hidden="true">→</span>
                <ServiceNode code="WM" title="Wazuh Manager" status={wazuh?.wazuh_manager_api || (loading ? 'checking' : 'unavailable')} detail="Manager API health" />
                <span className="network-chain-arrow" aria-hidden="true">→</span>
                <ServiceNode code="IX" title="Wazuh Indexer" status={wazuh?.wazuh_indexer || (loading ? 'checking' : 'unavailable')} detail="Indexer health" />
              </div>
              <p className="network-layer__footnote">Wazuh Dashboard status: <StatusBadge status="unavailable" /> No dashboard health endpoint is exposed.</p>
            </section>

            <section className="network-layer network-detection-layer" aria-labelledby="detection-title">
              <div className="network-layer__heading">
                <div><p className="network-node-kicker">Alert-to-response path</p><h3 id="detection-title">AI Detection &amp; Incident Response</h3></div>
                <span className="network-logic-note">Logical flow · no incident count inferred on this page</span>
              </div>
              <div className="network-response-chain">
                <article className="network-process-node">
                  <span className="network-process-node__step">01 / INPUT</span>
                  <h4>Wazuh Alerts</h4>
                  <p>Event stream from the Indexer. This page does not query or claim a live alert count.</p>
                </article>
                <span className="network-chain-arrow" aria-hidden="true">→</span>
                <article className="network-process-node network-process-node--ai">
                  <span className="network-process-node__step">02 / ANALYSIS</span>
                  <div className="network-process-node__title"><h4>AI Anomaly Detection</h4><StatusBadge status={aiAnalysisStatus} /></div>
                  <p className="network-model">{anomaly?.model || 'N/A'}</p>
                  <p>{anomaly ? `${anomaly.summary?.alerts_analyzed ?? 'N/A'} real alerts analyzed` : aiDetail}</p>
                </article>
                <span className="network-chain-arrow" aria-hidden="true">→</span>
                <article className="network-process-node">
                  <span className="network-process-node__step">03 / CASE</span>
                  <h4>Incident</h4>
                  <p>Persisted incident records are available in the incident queue.</p>
                  <Link to="/incidents" className="network-text-link">Open incidents <span aria-hidden="true">→</span></Link>
                </article>
                <span className="network-chain-arrow" aria-hidden="true">→</span>
                <article className="network-process-node network-process-node--response">
                  <span className="network-process-node__step">04 / RESPONSE</span>
                  <h4>Simulated Response</h4>
                  <div className="network-action-list"><span>Notify Admin</span><span>Isolate Asset</span><span>Block IP</span><span>Generate Report</span></div>
                  <p>Audit-only actions; no host or network commands are executed.</p>
                </article>
                <span className="network-chain-arrow" aria-hidden="true">→</span>
                <article className="network-process-node network-process-node--report">
                  <span className="network-process-node__step">05 / OUTPUT</span>
                  <h4>Report</h4>
                  <p>Incident report and PDF endpoint.</p>
                  <Link to="/reports" className="network-text-link">Open reports <span aria-hidden="true">→</span></Link>
                </article>
              </div>
            </section>

            <section className="network-workflow" aria-labelledby="workflow-title">
              <div className="network-workflow__heading">
                <p className="network-node-kicker">Investigation workflow</p>
                <h3 id="workflow-title">Network Event → Wazuh Agent → Wazuh Manager → Wazuh Alert → AI Detection → Incident → Simulated Response → Report</h3>
              </div>
              <div className="network-workflow__steps" aria-label="Network event to report workflow">
                {['Network Event', 'Wazuh Agent', 'Wazuh Manager', 'Wazuh Alert', 'AI Detection', 'Incident', 'Simulated Response', 'Report'].map((step, index) => (
                  <span className="network-workflow__item" key={step}>
                    <span className={`network-workflow__step${index === 0 || index === 3 ? ' network-workflow__step--event' : ''}`}>{step}</span>
                    {index < 7 && <span className="network-workflow__arrow" aria-hidden="true">→</span>}
                  </span>
                ))}
              </div>
            </section>

            <footer className="network-footer">
              <span>{lastChecked ? `Live checks updated ${lastChecked.toLocaleTimeString()}` : 'Waiting for live status checks'}</span>
              <span>{failedSources.length > 0 ? `Partial availability · ${failedSources.join(', ')}` : loading ? 'Checking existing API sources...' : 'Statuses sourced from existing APIs'}</span>
            </footer>
          </section>
        </div>
      </main>
    </PageLayout>
  );
};

export default NetworkPage;