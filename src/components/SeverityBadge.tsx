interface Props {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  large?: boolean;
}

export default function SeverityBadge({ severity, large }: Props) {
  const config = {
    CRITICAL: { bg: 'bg-red/20', border: 'border-red', text: 'text-red' },
    HIGH: { bg: 'bg-orange/20', border: 'border-orange', text: 'text-orange' },
    MEDIUM: { bg: 'bg-yellow-500/20', border: 'border-yellow-500', text: 'text-yellow-400' },
    LOW: { bg: 'bg-muted/20', border: 'border-border', text: 'text-muted' },
    NONE: { bg: 'bg-muted/20', border: 'border-border', text: 'text-muted' },
  };

  const c = config[severity];

  return (
    <span
      className={`inline-flex items-center rounded-full border font-semibold ${c.bg} ${c.border} ${c.text} ${
        large ? 'text-2xl px-6 py-3' : 'text-xs px-2.5 py-0.5'
      }`}
    >
      {severity}
    </span>
  );
}
