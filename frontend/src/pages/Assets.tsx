import { useEffect, useState } from 'react';
import PageLayout from '../components/PageLayout';
import { wazuhService, WazuhAgent } from '../services/wazuhApi';

// Define types for UI components that match the existing UI expectations
type Asset = {
  id: string;
  hostname: string;
  ip_address: string;
  os: string;
  groups: string;
  status: string;
  risk_level: string;
};

const AssetsPage = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);

    try {
      // Fetch agents from Wazuh Manager API
      const response = await wazuhService.getAgents(100); // Get 100 agents for the assets page

      // Transform Wazuh agents to match the existing Asset type used by UI components
      const transformedAssets: Asset[] = response.data.affected_items.map((agent: WazuhAgent) => ({
        id: agent.id || 'N/A',
        hostname: agent.name || 'N/A',
        ip_address: agent.ip && agent.ip !== 'any' ? agent.ip : 'N/A',
        os: [agent.os?.name, agent.os?.version].filter(Boolean).join(' ') || 'N/A',
        groups: agent.group?.join(', ') || 'N/A',
        status: agent.status || 'N/A',
        risk_level: 'N/A',
      }));

      setAssets(transformedAssets);
    } catch (err) {
      console.error('Failed to fetch Wazuh agents:', err);
      setError('Failed to load Wazuh agents.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <PageLayout>
      <div className="soc-page-stack">
        <header className="soc-page-heading">
          <div>
            <h1 className="soc-page-title">Assets</h1>
            <p className="soc-page-description">Registered Wazuh agents only. Risk is not provided by the connected inventory.</p>
          </div>
          <button type="button" onClick={() => void fetchData()} disabled={loading} className="soc-button soc-button--secondary">
            {loading ? 'Refreshing...' : 'Refresh assets'}
          </button>
        </header>
        {error && <div role="alert" className="soc-state soc-state--error">{error}</div>}
        <section className="soc-panel">
          <div className="soc-table-wrap">
          <table className="soc-table">
            <thead>
              <tr><th>Wazuh ID</th><th>Hostname</th><th>IP address</th><th>Operating system</th><th>Wazuh groups</th><th>Status</th><th>Risk</th></tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7} className="soc-table__message">Loading registered agents...</td></tr>
              ) : assets.length === 0 ? (
                <tr><td colSpan={7} className="soc-table__message">{error ? 'Agent inventory is unavailable.' : 'No Wazuh agents are currently returned.'}</td></tr>
              ) : (
                assets.map((asset) => (
                  <tr key={asset.id}>
                    <td className="soc-table__mono">{asset.id}</td>
                    <td>{asset.hostname}</td>
                    <td>{asset.ip_address}</td>
                    <td>{asset.os}</td>
                    <td>{asset.groups}</td>
                    <td>
                      <span className={`soc-status-pill ${asset.status === 'active' ? 'soc-status-pill--healthy' : ''}`}>
                        {asset.status}
                      </span>
                    </td>
                    <td>{asset.risk_level}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          </div>
        </section>
      </div>
    </PageLayout>
  );
};

export default AssetsPage;