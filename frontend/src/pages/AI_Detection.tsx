import { useEffect, useState } from 'react';
import PageLayout from '../components/PageLayout';
import StatCard from '../components/StatCard';

type WazuhAlert = {
  '@timestamp'?: string;
  timestamp?: string;
  location?: string;
  _id?: string;
  id?: string;
  agent?: { id?: string; name?: string };
  decoder?: { name?: string };
  rule?: { id?: string; level?: number; description?: string; groups?: string[] };
};

type AnalyzedAlert = {
  alert: WazuhAlert;
  anomaly_score: number | null;
  is_anomaly: boolean;
  risk_level: string;
};

type AnomalyAnalysis = {
  model: string;
  analysis_status: 'trained' | 'insufficient_data';
  message: string;
  minimum_training_alerts: number;
  summary: {
    alerts_analyzed: number;
    anomalies_detected: number;
    average_score: number | null;
    risk_level: string;
  };
  results: AnalyzedAlert[];
  anomalies: AnalyzedAlert[];
};

const riskColor: Record<string, string> = {
  low: 'text-green-400',
  elevated: 'text-yellow-300',
  medium: 'text-yellow-300',
  high: 'text-orange-400',
  critical: 'text-red-400',
  unrated: 'text-gray-400',
};

const AIDetectionPage = () => {
  const [analysis, setAnalysis] = useState<AnomalyAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchAnalysis = async () => {
      try {
        const response = await fetch('/ai/anomalies?limit=500');
        if (!response.ok) {
          throw new Error(`AI analysis request failed (${response.status})`);
        }
        setAnalysis(await response.json() as AnomalyAnalysis);
      } catch (requestError) {
        console.error('Failed to load Wazuh anomaly analysis:', requestError);
        setError('Unable to load anomaly analysis from the backend.');
      } finally {
        setLoading(false);
      }
    };

    void fetchAnalysis();
  }, []);

  if (loading) {
    return (
      <PageLayout>
        <div className="text-center py-12">Loading anomaly analysis...</div>
      </PageLayout>
    );
  }

  if (error || !analysis) {
    return (
      <PageLayout>
        <div role="alert" className="rounded-lg border border-red-700 bg-red-950 p-4 text-red-200">
          {error || 'No analysis response was received.'}
        </div>
      </PageLayout>
    );
  }

  const scoreRanges = [
    { name: '0-20', value: 0 },
    { name: '21-40', value: 0 },
    { name: '41-60', value: 0 },
    { name: '61-80', value: 0 },
    { name: '81-100', value: 0 },
  ];

  analysis.results.forEach(({ anomaly_score: score }) => {
    if (score === null) return;
    const bucket = Math.min(Math.floor(score / 20), 4);
    scoreRanges[bucket].value += 1;
  });

  const averageScore = analysis.summary.average_score === null
    ? 'N/A'
    : `${analysis.summary.average_score.toFixed(1)} / 100`;

  return (
    <PageLayout>
      <div className="space-y-6">
        <div>
          <h1 className="soc-page-title">AI Detection</h1>
          <p className="soc-page-description">
            {analysis.model} analysis of recent Wazuh Indexer alerts. Scores are relative to this batch, not probabilities.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard title="AI status" value={analysis.analysis_status === 'trained' ? 'Trained' : 'Insufficient data'} />
          <StatCard title="Anomalies detected" value={analysis.summary.anomalies_detected} />
          <StatCard title="Average anomaly score" value={averageScore} />
          <StatCard
            title="Overall risk"
            value={analysis.summary.risk_level.toUpperCase()}
          />
        </div>

        {analysis.analysis_status === 'insufficient_data' && (
          <div role="status" className="rounded-lg border border-yellow-700 bg-yellow-950 p-4 text-yellow-200">
            {analysis.message} At least {analysis.minimum_training_alerts} alerts are needed for training.
          </div>
        )}

        {analysis.analysis_status === 'trained' && (
          <p className="text-sm text-gray-400">{analysis.message}</p>
        )}

        <section className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div className="soc-panel">
            <h2 className="mb-4 text-lg font-semibold">Score distribution</h2>
            <div className="space-y-3" aria-label="Anomaly score distribution">
              {scoreRanges.map((range) => {
                const width = analysis.results.length ? (range.value / analysis.results.length) * 100 : 0;
                return (
                  <div key={range.name} className="grid grid-cols-[52px_minmax(0,1fr)_32px] items-center gap-3 text-xs">
                    <span className="text-gray-500">{range.name}</span>
                    <div className="h-2 overflow-hidden rounded-full bg-gray-100">
                      <div className="h-full rounded-full bg-cyan-600" style={{ width: `${width}%` }} />
                    </div>
                    <span className="text-right tabular-nums text-gray-500">{range.value}</span>
                  </div>
                );
              })}
            </div>
            <p className="mt-4 text-xs text-gray-500">{analysis.summary.alerts_analyzed} real alerts analyzed</p>
          </div>

          <div className="soc-panel">
            <div className="mb-4 flex items-center justify-between gap-3">
              <h2 className="text-lg font-semibold">Detected anomalies</h2>
              <span className="text-sm text-gray-400">{analysis.anomalies.length} alerts</span>
            </div>
            {analysis.anomalies.length === 0 ? (
              <p className="text-sm text-gray-400">
                {analysis.analysis_status === 'trained'
                  ? 'No anomalies were flagged in this alert batch.'
                  : 'Anomaly results are unavailable until enough real alerts are available.'}
              </p>
            ) : (
              <div className="space-y-3">
                {analysis.anomalies.map((item, index) => {
                  const alert = item.alert;
                  const alertId = String(alert._id || alert.id || index);
                  const timestamp = alert['@timestamp'] || alert.timestamp;
                  const source = alert.agent?.name || alert.agent?.id || 'Unknown agent';
                  const category = alert.rule?.description || alert.decoder?.name || 'Wazuh alert';

                  return (
                    <article key={alertId} className="border-b border-gray-200 py-4 last:border-0">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div className="min-w-0">
                          <h3 className="font-medium text-white">{category}</h3>
                          <p className="mt-1 break-all text-sm text-gray-400">
                            {source} · {alert.location || 'Unknown location'}
                          </p>
                        </div>
                        <div className="shrink-0 text-right">
                          <p className="font-semibold text-orange-300">
                            {item.anomaly_score === null ? 'N/A' : `${item.anomaly_score.toFixed(1)} / 100`}
                          </p>
                          <p className={`text-xs uppercase ${riskColor[item.risk_level] || 'text-gray-400'}`}>
                            {item.risk_level}
                          </p>
                        </div>
                      </div>
                      <p className="mt-3 text-xs text-gray-500">
                        Rule {alert.rule?.id || 'N/A'} · Level {alert.rule?.level ?? 'N/A'}
                        {timestamp ? ` · ${new Date(timestamp).toLocaleString()}` : ''}
                      </p>
                    </article>
                  );
                })}
              </div>
            )}
          </div>
        </section>
      </div>
    </PageLayout>
  );
};

export default AIDetectionPage;
