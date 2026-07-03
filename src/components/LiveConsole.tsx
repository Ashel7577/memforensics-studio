import { useRef, useEffect, useState } from 'react';
import { Copy, Trash2 } from 'lucide-react';
import type { LogLine } from '../types';
import { toast } from 'sonner';

interface Props {
  logs: LogLine[];
}

function getLineColor(text: string, level: LogLine['level']) {
  if (level === 'error') return 'text-red';
  if (level === 'warning') return 'text-orange';
  if (level === 'success') return 'text-green';
  if (/^\[ENGINE\s*\d+\]/i.test(text)) return 'text-blue';
  if (text.includes('✓') || text.toLowerCase().includes('complete')) return 'text-green';
  if (text.includes('ERROR') || text.toLowerCase().includes('failed')) return 'text-red';
  if (text.includes('WARNING')) return 'text-orange';
  return 'text-primary';
}

export default function LiveConsole({ logs }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTo({ top: containerRef.current.scrollHeight, behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  const handleCopy = () => {
    const text = logs.map((l) => `[${l.timestamp}] ${l.text}`).join('\n');
    navigator.clipboard.writeText(text).then(() => toast.success('Log copied'));
  };

  return (
    <div className="flex flex-col h-full min-h-[500px]">
      <div className="flex items-center justify-between mb-2">
        <span className="text-primary font-semibold text-sm">Live Output</span>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-muted text-xs cursor-pointer">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="accent-blue"
            />
            Auto-scroll
          </label>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 text-muted text-xs hover:text-primary transition-colors"
          >
            <Copy className="w-3.5 h-3.5" />
            Copy Log
          </button>
        </div>
      </div>
      <div
        ref={containerRef}
        className="flex-1 bg-dfir border border-border rounded-xl p-3 overflow-y-auto font-mono text-xs space-y-0.5"
      >
        {logs.length === 0 && (
          <span className="text-muted italic">Waiting for pipeline output...</span>
        )}
        {logs.map((log) => (
          <div key={log.id} className={`${getLineColor(log.text, log.level)}`}>
            <span className="text-muted opacity-50 mr-1.5">[{log.timestamp}]</span>
            {log.text}
          </div>
        ))}
      </div>
    </div>
  );
}
