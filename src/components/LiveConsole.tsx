import { useRef, useEffect, useState, useMemo, Fragment } from 'react';
import { Copy, Search, Activity, Cpu, ShieldAlert, Radio, ArrowDownCircle } from 'lucide-react';
import type { LogLine, EngineProgress } from '../types';
import { extractFindings, findingsSummary } from '../lib/findings';
import { toast } from 'sonner';

interface Props {
  logs: LogLine[];
  /** Optional — the engine currently executing, used for the telemetry deck. */
  activeEngine?: EngineProgress | null;
  /** Optional — overall pipeline status ('queued' | 'running' | 'done' | 'failed'). */
  status?: string;
}

type Filter = 'all' | 'info' | 'success' | 'warning' | 'error';

/* ------------------------------------------------------------------ *
 * Severity classification (unchanged semantics from the original)
 * ------------------------------------------------------------------ */

function classify(text: string, level: LogLine['level']): Exclude<Filter, 'all'> {
  if (level === 'error' || text.includes('ERROR') || text.toLowerCase().includes('failed')) return 'error';
  if (level === 'warning' || text.includes('WARNING')) return 'warning';
  if (level === 'success' || text.includes('✓') || text.includes('✅') || text.toLowerCase().includes('complete'))
    return 'success';
  return 'info';
}

const SEVERITY = {
  info: { color: 'text-[#3fb950]', accent: '#3fb950', glyph: '$', tag: 'INF' },
  success: { color: 'text-green', accent: '#3fb950', glyph: '✓', tag: 'OK ' },
  warning: { color: 'text-orange', accent: '#d29922', glyph: '⚠', tag: 'WRN' },
  error: { color: 'text-red', accent: '#f85149', glyph: '✗', tag: 'ERR' },
} as const;

/* ------------------------------------------------------------------ *
 * Token highlighting — makes raw engine stdout read like real tooling
 * ------------------------------------------------------------------ */

const TOKEN_RE = new RegExp(
  [
    '\\b[a-fA-F0-9]{64}\\b', // sha256
    '\\b[a-fA-F0-9]{40}\\b', // sha1
    '\\b[a-fA-F0-9]{32}\\b', // md5
    '0x[a-fA-F0-9]+', // hex address
    '\\b(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d+)?\\b', // ipv4[:port]
    '\\b[A-Za-z]:\\\\[^\\s"\']+', // windows path
    '\\b[\\w.-]+\\.(?:exe|dll|sys|json|pdf|dmp|py|bin)\\b', // file names
    '\\bT1\\d{3}(?:\\.\\d{3})?\\b', // MITRE technique
    '\\bPID\\s+\\d+\\b', // pid references
    '\\b\\d+(?:\\.\\d+)?%?\\b', // numbers
  ].join('|'),
  'g'
);

function tokenClass(t: string): string {
  if (/^0x/i.test(t)) return 'text-purple';
  if (/^T1\d{3}/.test(t)) return 'text-red font-semibold';
  if (/^(?:\d{1,3}\.){3}\d{1,3}/.test(t)) return 'text-orange font-semibold';
  if (/^[a-fA-F0-9]{32,64}$/.test(t)) return 'text-blue/80';
  if (/^PID/i.test(t)) return 'text-blue font-semibold';
  if (/^[A-Za-z]:\\/.test(t)) return 'text-blue/90';
  if (/\.(exe|dll|sys|json|pdf|dmp|py|bin)$/i.test(t)) return 'text-blue';
  return 'text-primary';
}

function Highlighted({ text, query }: { text: string; query: string }) {
  const parts = useMemo(() => {
    const out: { s: string; cls: string | null }[] = [];
    let last = 0;
    TOKEN_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = TOKEN_RE.exec(text)) !== null) {
      if (m.index > last) out.push({ s: text.slice(last, m.index), cls: null });
      out.push({ s: m[0], cls: tokenClass(m[0]) });
      last = m.index + m[0].length;
    }
    if (last < text.length) out.push({ s: text.slice(last), cls: null });
    return out;
  }, [text]);

  const q = query.trim().toLowerCase();

  return (
    <>
      {parts.map((p, i) => {
        if (!q || !p.s.toLowerCase().includes(q)) {
          return p.cls ? (
            <span key={i} className={p.cls}>
              {p.s}
            </span>
          ) : (
            <Fragment key={i}>{p.s}</Fragment>
          );
        }
        // highlight the search term inside this chunk
        const idx = p.s.toLowerCase().indexOf(q);
        return (
          <span key={i} className={p.cls ?? undefined}>
            {p.s.slice(0, idx)}
            <mark className="bg-orange/30 text-orange rounded-sm px-0.5">{p.s.slice(idx, idx + q.length)}</mark>
            {p.s.slice(idx + q.length)}
          </span>
        );
      })}
    </>
  );
}

/* ------------------------------------------------------------------ *
 * Throughput sparkline — proves the stream is alive at a glance
 * ------------------------------------------------------------------ */

const BUCKETS = 48;

function Sparkline({ data }: { data: number[] }) {
  const peak = Math.max(1, ...data);
  return (
    <div className="flex items-end gap-[2px] h-6" title="Events per second (last 48s)">
      {data.map((v, i) => {
        const h = Math.max(2, Math.round((v / peak) * 24));
        const hot = v > 0;
        return (
          <div
            key={i}
            className="w-[3px] rounded-sm transition-all duration-200"
            style={{
              height: `${h}px`,
              background: hot ? '#3fb950' : '#1c2333',
              boxShadow: hot ? '0 0 6px rgba(63,185,80,0.6)' : 'none',
              opacity: 0.35 + (i / BUCKETS) * 0.65,
            }}
          />
        );
      })}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Long-run messaging
 *
 * Some stages (notably the Volatility kernel walks in Engine 2) legitimately
 * run for minutes between stdout writes. Reporting that as "no output" reads
 * like a hang, so describe the work instead and keep a live clock on it.
 * ------------------------------------------------------------------ */

function longRunPhase(idle: number): string {
  if (idle < 15) return 'processing';
  if (idle < 45) return 'walking kernel structures';
  if (idle < 120) return 'deep scan in progress — this stage is expected to take minutes';
  return 'long-running Volatility scan — still executing';
}

function formatIdle(sec: number): string {
  if (sec < 60) return `${sec.toFixed(0)}s`;
  const m = Math.floor(sec / 60);
  return `${m}m ${String(Math.floor(sec % 60)).padStart(2, '0')}s`;
}

/* ------------------------------------------------------------------ *
 * Console
 * ------------------------------------------------------------------ */

export default function LiveConsole({ logs, activeEngine, status }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [filter, setFilter] = useState<Filter>('all');
  const [query, setQuery] = useState('');
  const [now, setNow] = useState(Date.now());

  const mountRef = useRef<number>(Date.now());
  const lastEventRef = useRef<number>(Date.now());
  const bucketsRef = useRef<number[]>(new Array(BUCKETS).fill(0));
  const [buckets, setBuckets] = useState<number[]>(bucketsRef.current);
  const prevCountRef = useRef(0);

  const isLive = status !== 'done' && status !== 'failed';

  /* heartbeat clock — drives the "still working" telemetry */
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(t);
  }, []);

  /* 1-second throughput bucketing */
  useEffect(() => {
    const t = setInterval(() => {
      const delta = logs.length - prevCountRef.current;
      prevCountRef.current = logs.length;
      bucketsRef.current = [...bucketsRef.current.slice(1), delta];
      setBuckets(bucketsRef.current);
    }, 1000);
    return () => clearInterval(t);
  }, [logs.length]);

  /* track last inbound event for the idle detector */
  useEffect(() => {
    if (logs.length > 0) lastEventRef.current = Date.now();
  }, [logs.length]);

  const findings = useMemo(() => extractFindings(logs), [logs]);

  const counts = useMemo(() => {
    const c = { info: 0, success: 0, warning: 0, error: 0 };
    for (const l of logs) c[classify(l.text, l.level)]++;
    return c;
  }, [logs]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return logs.filter((l) => {
      if (filter !== 'all' && classify(l.text, l.level) !== filter) return false;
      if (q && !l.text.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [logs, filter, query]);

  /* ---- smart auto-scroll -------------------------------------------
   * Sticks to the newest line without any user input. If the operator
   * scrolls up to inspect something we pause and surface a "jump to live"
   * pill; scrolling back to the bottom silently re-arms the follow. */
  const pinnedRef = useRef(true);
  const [showJump, setShowJump] = useState(false);

  const scrollToBottom = (smooth: boolean) => {
    const el = containerRef.current;
    if (!el) return;
    el.scrollTo({ top: el.scrollHeight, behavior: smooth ? 'smooth' : 'auto' });
  };

  const handleScroll = () => {
    const el = containerRef.current;
    if (!el) return;
    const distance = el.scrollHeight - el.scrollTop - el.clientHeight;
    const atBottom = distance < 40;
    pinnedRef.current = atBottom;
    setShowJump(!atBottom && autoScroll);
  };

  useEffect(() => {
    if (!autoScroll || !pinnedRef.current) return;
    const el = containerRef.current;
    if (!el) return;
    // Long bursts jump instantly so the view never lags behind the stream;
    // single new lines glide so the output reads smoothly during the demo.
    const distance = el.scrollHeight - el.scrollTop - el.clientHeight;
    scrollToBottom(distance < 600);
    setShowJump(false);
  }, [visible.length, autoScroll]);

  /* Re-arm following whenever the operator turns auto-scroll back on. */
  useEffect(() => {
    if (autoScroll) {
      pinnedRef.current = true;
      scrollToBottom(true);
    } else {
      setShowJump(false);
    }
  }, [autoScroll]);

  const handleCopy = () => {
    const text = logs.map((l) => `[${l.timestamp}] ${l.text}`).join('\n');
    navigator.clipboard.writeText(text).then(() => toast.success('Log copied'));
  };

  const idleSeconds = (now - lastEventRef.current) / 1000;
  const uptime = Math.floor((now - mountRef.current) / 1000);
  const rate = buckets[buckets.length - 1] ?? 0;
  const totalWindow = buckets.reduce((a, b) => a + b, 0);
  const avgRate = (totalWindow / BUCKETS).toFixed(1);

  const stageElapsed = activeEngine?.startTime ? Math.floor((now - activeEngine.startTime * 1000) / 1000) : null;

  const filters: { key: Filter; label: string; n: number; color: string }[] = [
    { key: 'all', label: 'ALL', n: logs.length, color: 'text-primary' },
    { key: 'info', label: 'INFO', n: counts.info, color: 'text-[#3fb950]' },
    { key: 'success', label: 'OK', n: counts.success, color: 'text-green' },
    { key: 'warning', label: 'WARN', n: counts.warning, color: 'text-orange' },
    { key: 'error', label: 'ERR', n: counts.error, color: 'text-red' },
  ];

  return (
    /* Bounded to the viewport: without a height cap the log list grows without
       limit, pushing the page down so the operator has to chase it with the
       scrollbar. Capping it here keeps the terminal's own auto-scroll in charge. */
    <div className="flex flex-col h-[calc(100vh-15rem)] min-h-[440px] max-h-[860px] lg:sticky lg:top-4">
      {/* ── header ───────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
        <span className="flex items-center gap-2 text-primary font-semibold text-sm">
          <Radio className="w-4 h-4 text-green" />
          Forensic Operations Console
          <span
            className={`flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider rounded-full px-2 py-0.5 border ${
              isLive ? 'text-green bg-green/10 border-green/30' : 'text-muted bg-cardalt border-border'
            }`}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${isLive ? 'bg-green animate-pulse' : 'bg-muted'}`} />
            {isLive ? 'Live' : 'Sealed'}
          </span>
        </span>
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

      {/* ── telemetry deck ───────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-2">
        <Stat icon={<Activity className="w-3 h-3" />} label="Events" value={String(logs.length)} tone="text-blue" />
        <Stat icon={<Cpu className="w-3 h-3" />} label="Rate" value={`${rate} ev/s`} sub={`avg ${avgRate}`} tone="text-green" />
        <Stat
          icon={<ShieldAlert className="w-3 h-3" />}
          label="Findings"
          value={`${findings.total}`}
          sub={findingsSummary(findings)}
          tone={
            findings.total > 0
              ? 'text-red'
              : findings.errors > 0
              ? 'text-orange'
              : 'text-muted'
          }
        />
        <div className="rounded-lg border border-[#1c2333] bg-[#0a0e14] px-3 py-2">
          <div className="flex items-center justify-between">
            <span className="text-[9px] font-mono uppercase tracking-[0.18em] text-muted">Throughput</span>
            <span className="text-[9px] font-mono text-muted">{uptime}s</span>
          </div>
          <Sparkline data={buckets} />
        </div>
      </div>

      {/* ── toolbar ──────────────────────────────────────────── */}
      <div className="flex items-center gap-2 mb-2 flex-wrap">
        <div className="flex items-center gap-1">
          {filters.map((f) => (
            <button
              key={f.key}
              onClick={() => setFilter(f.key)}
              className={`text-[10px] font-mono uppercase tracking-wider px-2 py-1 rounded-md border transition-colors ${
                filter === f.key
                  ? 'border-blue/50 bg-blue/10 text-blue'
                  : `border-[#1c2333] bg-[#0a0e14] ${f.color} opacity-70 hover:opacity-100`
              }`}
            >
              {f.label} <span className="opacity-60">{f.n}</span>
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1.5 flex-1 min-w-[140px] rounded-md border border-[#1c2333] bg-[#0a0e14] px-2 py-1">
          <Search className="w-3 h-3 text-muted shrink-0" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="grep stream — pid, hash, ip, technique…"
            className="w-full bg-transparent outline-none text-[11px] font-mono text-primary placeholder:text-muted/60"
          />
        </div>
      </div>

      {/* ── terminal ─────────────────────────────────────────── */}
      <div className="flex-1 rounded-xl border border-[#1c2333] overflow-hidden shadow-[0_0_40px_rgba(88,166,255,0.08)] flex flex-col">
        <div className="flex items-center gap-2 px-3 py-2 bg-[#0a0e14] border-b border-[#1c2333] shrink-0">
          <span className="terminal-dot bg-[#ff5f57]" />
          <span className="terminal-dot bg-[#febc2e]" />
          <span className="terminal-dot bg-[#28c840]" />
          <span className="ml-2 text-[10px] font-mono text-muted tracking-wide truncate">
            root@memforensics-engine — vol3 · python3 · zsh
            {activeEngine ? ` — stage ${String(activeEngine.engineNum).padStart(2, '0')}` : ''}
          </span>
        </div>

        <div
          ref={containerRef}
          onScroll={handleScroll}
          className="terminal-crt relative flex-1 p-3 overflow-y-auto font-mono text-xs"
        >
          {showJump && (
            <button
              onClick={() => {
                pinnedRef.current = true;
                scrollToBottom(true);
                setShowJump(false);
              }}
              className="sticky top-0 z-[3] float-right flex items-center gap-1 rounded-full border border-blue/40 bg-blue/15 px-2.5 py-1 text-[10px] font-mono text-blue backdrop-blur hover:bg-blue/25 transition-colors"
            >
              <ArrowDownCircle className="w-3 h-3" />
              JUMP TO LIVE
            </button>
          )}
          <div className="relative z-[2] space-y-[3px]">
            {logs.length === 0 && (
              <div className="text-muted italic">
                Waiting for pipeline output<span className="console-ellipsis" />
              </div>
            )}
            {logs.length > 0 && visible.length === 0 && (
              <div className="text-muted italic">No events match the current filter.</div>
            )}
            {visible.map((log, i) => {
              const sev = classify(log.text, log.level);
              const s = SEVERITY[sev];
              return (
                <div
                  key={log.id}
                  className={`group flex gap-2 items-start rounded-sm px-1 -mx-1 hover:bg-white/[0.03] ${
                    i === visible.length - 1 ? 'animate-fade-in-up' : ''
                  }`}
                >
                  <span
                    className="w-[2px] self-stretch rounded-full shrink-0"
                    style={{ background: s.accent, opacity: sev === 'info' ? 0.25 : 0.9 }}
                  />
                  <span className="text-muted/30 select-none shrink-0 tabular-nums w-8 text-right">
                    {String(i + 1).padStart(4, '0')}
                  </span>
                  <span className={`${s.color} terminal-text-glow select-none shrink-0 opacity-70`}>{s.glyph}</span>
                  <span className="text-muted/50 shrink-0 select-none">[{log.timestamp}]</span>
                  {log.engineNum !== undefined && log.engineNum !== null && (
                    <span className="shrink-0 text-[9px] font-bold text-blue/70 border border-blue/25 rounded px-1 py-px leading-4 select-none">
                      E{String(log.engineNum).padStart(2, '0')}
                    </span>
                  )}
                  <span className={`break-all ${s.color} terminal-text-glow`}>
                    <Highlighted text={log.text} query={query} />
                  </span>
                </div>
              );
            })}

            {/* heartbeat: the stream is quiet but the engine is grinding */}
            {isLive && logs.length > 0 && idleSeconds > 2.5 && (
              <div className="mt-2 rounded-md border border-blue/20 bg-blue/[0.04] px-2 py-2 space-y-1">
                <div className="flex items-center gap-2">
                  <span className="relative flex h-2 w-2 shrink-0">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue opacity-75" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-blue" />
                  </span>
                  <span className="text-blue/90 text-[11px]">
                    {activeEngine
                      ? `stage ${String(activeEngine.engineNum).padStart(2, '0')} · ${activeEngine.name}`
                      : 'engine'}{' '}
                    — {longRunPhase(idleSeconds)}
                    <span className="console-ellipsis" />
                  </span>
                  <span className="ml-auto text-muted text-[10px] tabular-nums shrink-0">
                    {formatIdle(idleSeconds)} in this step
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-1 rounded-full bg-cardalt overflow-hidden">
                    <div className="h-full w-1/3 shimmer-bar console-indeterminate" />
                  </div>
                  <span className="text-muted/70 text-[9px] shrink-0">
                    process alive · deep scans run without interim output
                  </span>
                </div>
              </div>
            )}

            {logs.length > 0 && isLive && (
              <div className="flex items-center gap-1.5 pt-1 text-[#3fb950] terminal-text-glow">
                <span>&gt;</span>
                <span className="inline-block w-1.5 h-3.5 bg-[#3fb950] animate-pulse" />
              </div>
            )}
          </div>
        </div>

        {/* ── status bar ─────────────────────────────────────── */}
        <div className="shrink-0 flex items-center gap-3 px-3 py-1.5 bg-[#0a0e14] border-t border-[#1c2333] text-[10px] font-mono text-muted flex-wrap">
          <span className={`flex items-center gap-1 ${isLive ? 'text-green' : 'text-muted'}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${isLive ? 'bg-green animate-pulse' : 'bg-muted'}`} />
            {isLive ? 'STREAM ACTIVE' : 'STREAM CLOSED'}
          </span>
          <span className="opacity-40">│</span>
          <span>
            showing <span className="text-primary">{visible.length}</span>/{logs.length}
          </span>
          <span className="opacity-40">│</span>
          <span className={counts.error > 0 ? 'text-red' : counts.warning > 0 ? 'text-orange' : ''}>
            {counts.error} err · {counts.warning} warn
          </span>
          {activeEngine && (
            <>
              <span className="opacity-40">│</span>
              <span className="text-blue truncate max-w-[240px]">
                E{String(activeEngine.engineNum).padStart(2, '0')} {activeEngine.name} · {activeEngine.percent}%
                {stageElapsed !== null && stageElapsed >= 0 ? ` · ${stageElapsed}s` : ''}
              </span>
            </>
          )}
          <span className="ml-auto tabular-nums">
            last event {logs.length ? `${formatIdle(idleSeconds)} ago` : '—'}
          </span>
        </div>
      </div>
    </div>
  );
}

function Stat({
  icon,
  label,
  value,
  sub,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub?: string;
  tone: string;
}) {
  return (
    <div className="rounded-lg border border-[#1c2333] bg-[#0a0e14] px-3 py-2">
      <div className="flex items-center gap-1 text-[9px] font-mono uppercase tracking-[0.18em] text-muted">
        {icon}
        {label}
      </div>
      <div className={`text-sm font-mono font-semibold tabular-nums ${tone}`}>{value}</div>
      {sub && <div className="text-[9px] font-mono text-muted/70 truncate">{sub}</div>}
    </div>
  );
}
