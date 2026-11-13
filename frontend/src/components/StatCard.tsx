import React from 'react';

type StatCardProps = {
  title: string;
  value: string | number;
  icon?: React.ReactNode;
  trend?: {
    label: string;
    value: number; // positive for increase, negative for decrease
  };
};

const StatCard = ({ title, value, icon, trend }: StatCardProps) => {
  return (
    <div className="soc-stat-card">
      {icon && <div className="mb-3">{icon}</div>}
      <h3 className="soc-stat-card__label">{title}</h3>
      <p className="soc-stat-card__value">{value}</p>
      {trend && (
        <p className={`mt-1 text-sm ${trend.value >= 0 ? 'text-green-400' : 'text-red-400'}`}>
          {trend.value >= 0 ? '+' : ''}{trend.value}% {trend.label}
        </p>
      )}
    </div>
  );
};

export default StatCard;
