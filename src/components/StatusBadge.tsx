import { Circle } from 'lucide-react';

interface Props {
  status: 'queued' | 'running' | 'done' | 'failed' | 'idle' | string;
}

export default function StatusBadge({ status }: Props) {
  const config: Record<string, { bg: string; border: string; text: string; label: string }> = {
    queued: { bg: 'bg-muted/20', border: 'border-muted', text: 'text-muted', label: 'Queued' },
    running: { bg: 'bg-orange/20', border: 'border-orange', text: 'text-orange', label: 'Running' },
    done: { bg: 'bg-green/20', border: 'border-green', text: 'text-green', label: 'Done' },
    failed: { bg: 'bg-red/20', border: 'border-red', text: 'text-red', label: 'Failed' },
    idle: { bg: 'bg-muted/20', border: 'border-muted', text: 'text-muted', label: 'Idle' },
  };

  const c = config[status] ?? config['idle'];

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${c.bg} ${c.border} ${c.text}`}>
      {status === 'running' && <Circle className="w-2 h-2 fill-current animate-pulse" />}
      {c.label}
    </span>
  );
}
