import { useMemo } from 'react';
import { Crosshair, Globe, Fingerprint, Target, FileWarning, Hash } from 'lucide-react';
import type { LogLine } from '../types';

interface Props {
  logs: LogLine[];
  /** Max indicators to render (newest first). */
  limit?: number;
}

export type IocKind = 'ip' | 'hash' | 'mitre' | 'process' | 'path';

export interface Ioc {
  key: string;
  kind: IocKind;
  value: string;
  hits: number;
  firstSeen: string;
  severity: 'critical' | 'high' | 'medium';
}

const KIND_META: Record<IocKind, { label: string; icon: typeof Globe; color: string; ring: string }> = {
  ip: { label: 'NETWORK', icon: Globe, color: 'text-orange', ring: 'border-orange/30 bg-orange/5' },
  hash: { label: 'HASH', icon: Fingerprint, color: 'text-blue', ring: 'border-blue/30 bg-blue/5' },
  mitre: { label: 'ATT&CK', icon: Target, color: 'text-red', ring: 'border-red/30 bg-red/5' },
  process: { label: 'PROCESS', icon: FileWarning, color: 'text-purple', ring: 'border-purple/30 bg-purple/5' },
  path: { label: 'ARTIFACT', icon: Hash, color: 'text-green', ring: 'border-green/30 bg-green/5' },
};

/* Private/loopback ranges are noise, not indicators. */
function isRoutableIp(ip: string): boolean {
  const host = ip.split(':')[0];
  const o = host.split('.').map(Number);
  if (o.length !== 4 || o.some((n) => Number.isNaN(n) || n > 255)) return false;
  if (o[0] === 0 || o[0] === 127 || o[0] === 255) return false;
  if (o[0] === 10) return false;
  if (o[0] === 192 && o[1] === 168) return false;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false;
  if (o[0] === 169 && o[1] === 254) return false;
  // version strings like 3.11.2.0 slip through as ints — require a real first octet
  if (o[0] < 1) return false;
  return true;
}

const PATTERNS: { kind: IocKind; re: RegExp; severity: Ioc['severity'] }[] = [
  { kind: 'mitre', re: /\bT1\d{3}(?:\.\d{3})?\b/g, severity: 'critical' },
  { kind: 'ip', re: /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b/g, severity: 'critical' },
  { kind: 'hash', re: /\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{32}\b/g, severity: 'medium' },
  { kind: 'process', re: /\b[\w.-]+\.(?:exe|dll|sys)\b/g, severity: 'high' },
];

const BENIGN_PROCESSES = new Set([
  'system.exe',
  'ntdll.dll',
  'kernel32.dll',
  'kernelbase.dll',
  'user32.dll',
  'advapi32.dll',
  'ntoskrnl.exe',
  'msvcrt.dll',
]);

export function extractIocs(logs: LogLine[]): Ioc[] {
  const map = new Map<string, Ioc>();

  for (const log of logs) {
    for (const { kind, re, severity } of PATTERNS) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(log.text)) !== null) {
        const raw = m[0];
        if (kind === 'ip' && !isRoutableIp(raw)) continue;
        if (kind === 'process' && BENIGN_PROCESSES.has(raw.toLowerCase())) continue;

        const key = `${kind}:${raw.toLowerCase()}`;
        const existing = map.get(key);
        if (existing) {
          existing.hits++;
        } else {
          map.set(key, { key, kind, value: raw, hits: 1, firstSeen: log.timestamp, severity });
        }
      }
    }
  }

  const order: Record<Ioc['severity'], number> = { critical: 0, high: 1, medium: 2 };
  return [...map.values()].sort((a, b) => order[a.severity] - order[b.severity] || b.hits - a.hits);
}

export default function ThreatFeed({ logs, limit = 14 }: Props) {
  const iocs = useMemo(() => extractIocs(logs), [logs]);
  const shown = iocs.slice(0, limit);

  const byKind = useMemo(() => {
    const c: Record<IocKind, number> = { ip: 0, hash: 0, mitre: 0, process: 0, path: 0 };
    for (const i of iocs) c[i.kind]++;
    return c;
  }, [iocs]);

  return (
    <div className="rounded-xl border border-[#1c2333] bg-[#0a0e14] overflow-hidden flex flex-col">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-[#1c2333]">
        <Crosshair className={`w-3.5 h-3.5 ${iocs.length ? 'text-red' : 'text-muted'}`} />
        <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-muted">Indicator Feed</span>
        <span className="ml-auto flex items-center gap-2 text-[9px] font-mono">
          {(Object.keys(KIND_META) as IocKind[])
            .filter((k) => byKind[k] > 0)
            .map((k) => (
              <span key={k} className={KIND_META[k].color}>
                {KIND_META[k].label} {byKind[k]}
              </span>
            ))}
          {iocs.length === 0 && <span className="text-muted">SCANNING…</span>}
        </span>
      </div>

      <div className="max-h-[220px] overflow-y-auto divide-y divide-[#141a26]">
        {shown.length === 0 && (
          <div className="px-3 py-4 text-[11px] font-mono text-muted italic">
            No indicators extracted yet — the feed populates as the engines surface artifacts.
          </div>
        )}
        {shown.map((ioc, i) => {
          const meta = KIND_META[ioc.kind];
          const Icon = meta.icon;
          return (
            <div
              key={ioc.key}
              className="flex items-center gap-2 px-3 py-1.5 hover:bg-white/[0.03] animate-fade-in-up"
              style={{ animationDelay: `${Math.min(i, 8) * 40}ms`, opacity: 0 }}
            >
              <span className={`flex items-center justify-center w-5 h-5 rounded border shrink-0 ${meta.ring}`}>
                <Icon className={`w-3 h-3 ${meta.color}`} />
              </span>
              <span className={`text-[9px] font-mono w-14 shrink-0 ${meta.color}`}>{meta.label}</span>
              <span className="text-[11px] font-mono text-primary truncate flex-1" title={ioc.value}>
                {ioc.value}
              </span>
              {ioc.hits > 1 && (
                <span className="text-[9px] font-mono text-muted shrink-0">×{ioc.hits}</span>
              )}
              <span
                className={`text-[8px] font-mono uppercase tracking-wider shrink-0 px-1 py-px rounded border ${
                  ioc.severity === 'critical'
                    ? 'text-red border-red/40 bg-red/10'
                    : ioc.severity === 'high'
                    ? 'text-orange border-orange/40 bg-orange/10'
                    : 'text-muted border-border'
                }`}
              >
                {ioc.severity}
              </span>
            </div>
          );
        })}
      </div>

      {iocs.length > limit && (
        <div className="px-3 py-1.5 border-t border-[#1c2333] text-[9px] font-mono text-muted">
          +{iocs.length - limit} more indicators — full set in the forensic report
        </div>
      )}
    </div>
  );
}
