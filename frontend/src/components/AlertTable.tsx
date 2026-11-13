import React from 'react';
import SeverityBadge from './SeverityBadge';

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

type AlertTableProps = {
  alerts: Alert[];
};

const AlertTable = ({ alerts }: AlertTableProps) => {
  if (alerts.length === 0) {
    return <p className="text-gray-500">No alerts to display.</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full bg-gray-800 text-white">
        <thead>
          <tr className="bg-gray-700">
            <th className="p-3 text-left">Wazuh Alert ID</th>
            <th className="p-3 text-left">Time</th>
            <th className="p-3 text-left">Source</th>
            <th className="p-3 text-left">Destination</th>
            <th className="p-3 text-left">Type</th>
            <th className="p-3 text-left">Severity</th>
            <th className="p-3 text-left">Status</th>
            <th className="p-3 text-left">AI Score</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert, index) => (
            <tr key={`${alert.id}-${index}`} className="border-t border-gray-700 hover:bg-gray-700">
              <td className="p-3">{alert.id}</td>
              <td className="p-3">
                {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : 'N/A'}
              </td>
              <td className="p-3">{alert.source}</td>
              <td className="p-3">{alert.destination}</td>
              <td className="p-3">{alert.alert_type}</td>
              <td className="p-3">
                <SeverityBadge severity={alert.severity} />
              </td>
              <td className="p-3">{alert.status}</td>
              <td className="p-3">{alert.ia_score ?? 'N/A'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default AlertTable;
