type Alert = {
  id: string;
  source: string;
  destination: string;
  alert_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical' | 'unrated';
  status: string;
  ia_score: number | null;
  timestamp: string;
};

type RecentEventsProps = {
  alerts: Alert[];
};

const RecentEvents = ({ alerts }: RecentEventsProps) => {
  if (alerts.length === 0) {
    return <p className="text-gray-500">No recent events.</p>;
  }

  // Sort by timestamp descending
  const sortedAlerts = [...alerts].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  return (
    <div className="bg-gray-800 text-white p-4 rounded-lg">
      <h3 className="text-sm font-bold mb-3">Recent Events</h3>
      <div className="space-y-2">
        {sortedAlerts.slice(0, 5).map((alert, index) => (
          <div key={`${alert.id}-${index}`} className="p-3 border-b border-gray-700">
            <div className="flex justify-between text-sm">
              <span>
                {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : 'N/A'}
              </span>
              <span className={`text-xs px-1.5 py-0.5 rounded ${
                alert.severity === 'low'
                  ? 'bg-green-100 text-green-800'
                  : alert.severity === 'medium'
                  ? 'bg-yellow-100 text-yellow-800'
                  : alert.severity === 'high'
                  ? 'bg-orange-100 text-orange-800'
                  : alert.severity === 'critical'
                  ? 'bg-red-100 text-red-800'
                  : 'bg-gray-100 text-gray-800'
              }`}>
                {alert.alert_type}
              </span>
            </div>
            <div className="mt-1 text-xs text-gray-400">
              {alert.source} → {alert.destination}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default RecentEvents;
