type SecurityChartProps = {
  data: { name: string; value: number }[];
  title?: string;
};

const SecurityChart = ({ data, title }: SecurityChartProps) => {
  if (data.length === 0) {
    return <p className="text-gray-500">No data to display.</p>;
  }

  const maxValue = Math.max(1, ...data.map((d) => d.value));

  return (
    <div>
      {title && <h3 className="text-sm font-bold mb-3">{title}</h3>}
      <div className="space-y-2">
        {data.map((item, index) => (
          <div key={index} className="flex items-center">
            <div className="w-20 text-right">{item.name}</div>
            <div className="flex-1 bg-gray-700 rounded-full h-2.5">
              <div
                className="bg-blue-500 h-full rounded-full"
                style={{ width: `${(item.value / maxValue) * 100}%` }}
              ></div>
            </div>
            <div className="w-20 text-left">{item.value}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SecurityChart;
