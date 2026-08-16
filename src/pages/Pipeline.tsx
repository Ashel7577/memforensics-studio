import { useEffect, useRef, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { Copy, ArrowLeft, FileJson, FileText, Download, FileCheck } from 'lucide-react';
import { toast } from 'sonner';
import StatusBadge from '../components/StatusBadge';
import EngineStepper from '../components/EngineStepper';
import LiveConsole from '../components/LiveConsole';
import PipelineGraph from '../components/PipelineGraph';
import ThreatFeed from '../components/ThreatFeed';
import type { LogLine, EngineProgress, Artifact } from '../types';

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}m ${s}s`;
}

export default function Pipeline() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [elapsed, setElapsed] = useState(0);
  const [status, setStatus] = useState('queued');
  const [engines, setEngines] = useState<EngineProgress[]>([]);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const logIndexRef = useRef<number>(0);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const startTimeRef = useRef<number>(Date.now());
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const jobId = id ?? '';

  useEffect(() => {
    if (!jobId) return;
    startTimeRef.current = Date.now();

    const timer = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTimeRef.current) / 1000));
    }, 1000);

    pollRef.current = setInterval(async () => {
      try {
        const s = await invoke<string>('get_pipeline_status', { jobId });
        setStatus(s);
        const e = await invoke<EngineProgress[]>('get_engine_progress', { jobId });
        setEngines(e);
        const a = await invoke<Artifact[]>('get_artifacts', { jobId });
        setArtifacts(a);
        const newLogs = await invoke<any[]>('get_logs', { jobId, since: logIndexRef.current });
        if (newLogs.length > 0) {
          logIndexRef.current += newLogs.length;
          setLogs(prev => [...prev, ...newLogs]);
        }
        if (s === 'done') {
          toast.success('Report ready');
          clearInterval(pollRef.current!);
        }
        if (s === 'failed') {
          toast.error('Pipeline failed');
          clearInterval(pollRef.current!);
        }
      } catch {}
    }, 2000);

    const setupListener = async () => {
      try {
        const unlisten = await listen('pipeline_log', (event: any) => {
          const payload = event.payload as LogLine;
          setLogs(prev => [...prev, payload]);
        });
        return unlisten;
      } catch {
        return () => {};
      }
    };

    let unlisten: () => void = () => {};
    setupListener().then(fn => { unlisten = fn; });

    return () => {
      clearInterval(timer);
      if (pollRef.current) clearInterval(pollRef.current);
      unlisten();
    };
  }, [jobId]);

  const handleDownload = async (filename: string) => {
    try {
      await invoke('download_artifact', { jobId, filename });
      toast.success(`Opening ${filename}`);
    } catch (err: any) {
      toast.error(err?.message || 'Download failed');
    }
  };

  const failedEngines = engines.filter(e => e.status === 'failed');

  const runningEngine = engines.find(e => e.status === 'running');

  /* The moment the first engine output arrives, bring the live console into
   * view so attention lands where the action is. This fires once per run —
   * after that the operator is free to scroll wherever they like without the
   * page pulling itself back. */
  const consoleRef = useRef<HTMLDivElement>(null);
  const focusedConsoleRef = useRef(false);
  const [consoleFlash, setConsoleFlash] = useState(false);
  useEffect(() => {
    if (focusedConsoleRef.current || logs.length === 0) return;
    if (!consoleRef.current) return;
    focusedConsoleRef.current = true;
    const t = setTimeout(() => {
      consoleRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      setConsoleFlash(true);
    }, 300);
    const clear = setTimeout(() => setConsoleFlash(false), 2400);
    return () => {
      clearTimeout(t);
      clearTimeout(clear);
    };
  }, [logs.length]);

  /* When the run finishes, walk the viewport down to the artifacts on its own
   * so the operator never has to reach for the scrollbar mid-demonstration. */
  const artifactsRef = useRef<HTMLDivElement>(null);
  const scrolledToArtifactsRef = useRef(false);
  useEffect(() => {
    if (status !== 'done' || scrolledToArtifactsRef.current) return;
    if (!artifactsRef.current) return;
    scrolledToArtifactsRef.current = true;
    const t = setTimeout(() => {
      artifactsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 900);
    return () => clearTimeout(t);
  }, [status, artifacts.length]);

  return (
    <div className="relative max-w-6xl mx-auto px-4 py-6 space-y-6">
      {status === 'running' && (
        <div className="pointer-events-none fixed inset-0 -z-10 bg-hex-pattern opacity-30" />
      )}
      <div className="flex items-center justify-between animate-fade-in-up" style={{ opacity: 0 }}>
        <Link to="/" className="flex items-center gap-1.5 text-muted text-sm hover:text-primary transition-colors">
          <ArrowLeft className="w-4 h-4" />
          Back to Dashboard
        </Link>
        <div className="flex items-center gap-3">
          <span className="text-muted text-xs font-mono">{jobId}</span>
          <button
            onClick={() => navigator.clipboard.writeText(jobId).then(() => toast.success('Copied'))}
            className="text-muted hover:text-primary transition-colors"
          >
            <Copy className="w-3.5 h-3.5" />
          </button>
          <StatusBadge status={status} />
          <span className="text-muted text-xs font-mono">{formatDuration(elapsed)}</span>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-card/60 overflow-hidden animate-fade-in-up" style={{ opacity: 0, animationDelay: '80ms' }}>
        <div className="flex items-center justify-between px-4 pt-3">
          <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-muted">Evidence Processing Graph</span>
          {runningEngine && (
            <span className="text-[10px] font-mono text-blue">
              STAGE {String(runningEngine.engineNum).padStart(2, '0')}/07 &middot; {runningEngine.percent}%
            </span>
          )}
        </div>
        <PipelineGraph engines={engines} activity={logs.length} />
      </div>

      {status === 'running' && runningEngine && (
        <div className="rounded-xl border border-blue/25 bg-blue/5 px-4 py-3 flex items-center gap-3 animate-fade-in-up" style={{ opacity: 0 }}>
          <span className="relative flex h-2.5 w-2.5 shrink-0">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue opacity-75" />
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-blue" />
          </span>
          <span className="text-sm text-primary">
            <span className="text-blue font-semibold">{runningEngine.name}</span> is running
            {runningEngine.message ? <> &mdash; <span className="font-mono text-xs text-muted">{runningEngine.message}</span></> : '.'}
          </span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 items-start">
        <div className="lg:col-span-2 space-y-4 lg:sticky lg:top-4">
          <h2 className="text-sm font-semibold text-primary uppercase tracking-wide mb-3">Stage Detail</h2>
          <EngineStepper engines={engines} />
          <ThreatFeed logs={logs} />
        </div>
        <div
          ref={consoleRef}
          className={`lg:col-span-3 scroll-mt-4 ${consoleFlash ? 'console-focus-flash' : ''}`}
        >
          <LiveConsole logs={logs} activeEngine={runningEngine} status={status} />
        </div>
      </div>

      {failedEngines.length > 0 && (
        <div className="bg-red/10 border border-red rounded-xl p-4">
          <h3 className="text-red font-semibold text-sm mb-2">Pipeline Errors</h3>
          {failedEngines.map(e => (
            <div key={e.engineNum} className="text-red text-xs mb-1">{e.name}: {e.error}</div>
          ))}
        </div>
      )}

      {artifacts.length > 0 && (
        <div ref={artifactsRef} className="scroll-mt-6">
          <h2 className="text-sm font-semibold text-primary uppercase tracking-wide mb-3">Output Artifacts</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {artifacts.map(artifact => (
              <div key={artifact.filename} className="bg-card border border-border rounded-xl p-3 flex items-center gap-3">
                {artifact.filename.endsWith('.pdf') ? (
                  <FileCheck className="w-8 h-8 text-blue shrink-0" />
                ) : artifact.filename.endsWith('.json') ? (
                  <FileJson className="w-8 h-8 text-blue shrink-0" />
                ) : (
                  <FileText className="w-8 h-8 text-blue shrink-0" />
                )}
                <div className="flex-1 min-w-0">
                  <div className="text-primary text-sm font-mono truncate">{artifact.filename}</div>
                  <div className="text-muted text-xs">{(artifact.sizeBytes / 1024).toFixed(1)} KB</div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-green text-xs font-medium">Ready</span>
                  <button onClick={() => handleDownload(artifact.filename)} className="text-muted hover:text-primary transition-colors">
                    <Download className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
          {artifacts.some(a => a.filename.endsWith('.pdf')) && (
            <div className="mt-4">
              <button
                onClick={() => navigate('/report/' + jobId)}
                className="flex items-center gap-2 bg-blue text-white rounded-xl px-6 py-3 font-semibold hover:bg-blue/90 transition-colors"
              >
                <FileCheck className="w-5 h-5" />
                View Report
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
