import type { LucideIcon } from 'lucide-react';

interface Props {
  label: string;
  value: string | number;
  icon?: LucideIcon;
}

export default function MetricCard({ label, value, icon: Icon }: Props) {
  return (
    <div className="bg-cardalt rounded-lg p-3 flex items-center gap-3">
      {Icon && <Icon className="w-5 h-5 text-muted shrink-0" />}
      <div>
        <div className="text-primary font-bold text-sm">{value}</div>
        <div className="text-muted text-xs">{label}</div>
      </div>
    </div>
  );
}
