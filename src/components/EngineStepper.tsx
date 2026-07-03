import { Check, X, Loader2 } from 'lucide-react';
import type { EngineProgress } from '../types';

interface Props {
  engines: EngineProgress[];
}

function StatusIcon({ status }: { status: EngineProgress['status'] }) {
  if (status === 'done')
    return (
      <div className="w-10 h-10 rounded-full bg-green flex items-center justify-center shrink-0">
        <Check className="w-5 h-5 text-dfir" />
      </div>
    );
  if (status === 'failed')
    return (
      <div className="w-10 h-10 rounded-full bg-red flex items-center justify-center shrink-0">
        <X className="w-5 h-5 text-dfir" />
      </div>
    );
  if (status === 'running')
    return (
      <div className="w-10 h-10 rounded-full border-2 border-blue flex items-center justify-center shrink-0">
        <Loader2 className="w-5 h-5 text-blue animate-spin-slow" />
      </div>
    );
  return (
    <div className="w-10 h-10 rounded-full border-2 border-border flex items-center justify-center shrink-0" />
  );
}

export default function EngineStepper({ engines }: Props) {
  const sorted = [...engines].sort((a, b) => a.engineNum - b.engineNum);

  return (
    <div className="space-y-0">
      {sorted.map((eng, idx) => (
        <div key={eng.engineNum} className="relative">
          {idx < sorted.length - 1 && (
            <div className="absolute left-5 top-10 bottom-0 w-px bg-border" />
          )}
          <div className="flex gap-4 pb-6">
            <div className="pt-1">
              <StatusIcon status={eng.status} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-primary font-semibold text-sm">
                  {String(eng.engineNum).padStart(2, '0')} &middot; {eng.name}
                </span>
              </div>
              <p className="text-muted text-xs mt-0.5">{eng.message}</p>
              {eng.status === 'running' && (
                <div className="mt-2 h-1.5 w-full rounded-full overflow-hidden bg-cardalt">
                  <div
                    className="h-full shimmer-bar rounded-full"
                    style={{ width: `${eng.percent}%` }}
                  />
                </div>
              )}
              {eng.status === 'done' && eng.metrics && (
                <p className="text-muted text-xs font-mono mt-1.5">{eng.metrics}</p>
              )}
              {eng.status === 'failed' && eng.error && (
                <p className="text-red text-xs mt-1.5">{eng.error}</p>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
