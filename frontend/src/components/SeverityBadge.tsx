type SeverityBadgeProps = {
  severity: 'low' | 'medium' | 'high' | 'critical' | 'unrated';
};

const SeverityBadge = ({ severity }: SeverityBadgeProps) => {
  const getColor = () => {
    switch (severity) {
      case 'low':
        return 'bg-green-100 text-green-800';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800';
      case 'high':
        return 'bg-orange-100 text-orange-800';
      case 'critical':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <span className={`px-2 py-1 text-xs rounded-full font-medium ${getColor()}`}>
      {severity.toUpperCase()}
    </span>
  );
};

export default SeverityBadge;
