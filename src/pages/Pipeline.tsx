import { useEffect, useRef, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { Copy, ArrowLeft, FileJson, FileText, Download, FileCheck } from 'lucide-react';
import { toast } from 'sonner';
import { useStore } from '../store';
import StatusBadge from '../components/StatusBadge';
import EngineStepper from '../components/EngineStepper';
import LiveConsole from '../components/LiveConsole';
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

  return (
    <div className="max-w-6xl mx-auto px-4 py-6 space-y-6">
      <div className="flex items-center justify-between">
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

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <div className="lg:col-span-2">
          <h2 className="text-sm font-semibold text-primary uppercase tracking-wide mb-3">Pipeline Progress</h2>
          <EngineStepper engines={engines} />
        </div>
        <div className="lg:col-span-3">
          <LiveConsole logs={logs} />
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
        <div>
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
