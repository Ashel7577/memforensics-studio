import { useEffect, useState, useRef, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { invoke } from '@tauri-apps/api/core';
import { Download, ArrowLeft, FileText, FileJson, Globe, X } from 'lucide-react';
import { toast } from 'sonner';
import { JSON_ANALYZER_LOCAL_URL } from '../lib/constants';

export default function Report() {
  const { id } = useParams<{ id: string }>();
  const jobId = id ?? '';
  const [artifacts, setArtifacts] = useState<any[]>([]);
  const [pdfPath, setPdfPath] = useState<string | null>(null);
  const [showAnalyzer, setShowAnalyzer] = useState(false);
   const iframeRef = useRef<HTMLIFrameElement>(null);
  const dataSentRef = useRef(false);
  const filesRef = useRef<{ files: Record<string, any>; issues: { name: string; reason: string }[] } | null>(null);
  const ackedRef = useRef(false);
  const retryRef = useRef<number | null>(null);

  const [runStatus, setRunStatus] = useState<string>('');
  const [runError, setRunError] = useState<string>('');

  useEffect(() => {
    if (!jobId) return;
    invoke<any[]>('get_artifacts', { jobId }).then(a => {
      setArtifacts(a);
      const pdf = a.find(x => x.filename.endsWith('.pdf'));
      if (pdf) setPdfPath(pdf.path);
    });
    // A run that produced nothing must say why rather than render an empty
    // card: read its status and the error the failing stage recorded.
    invoke<string>('get_pipeline_status', { jobId }).then(setRunStatus).catch(() => {});
    invoke<any[]>('get_engine_progress', { jobId })
      .then(engines => {
        const failed = engines.find(e => e.status === 'failed' && e.error);
        if (failed) setRunError(String(failed.error));
      })
      .catch(() => {});
  }, [jobId]);

  const loadAnalyzerData = async (artifacts: any[]) => {
    const jsonFiles = [
      '01_memory_evidence', '02_os_structures',
      '03_private_exec_regions', '04_execution_evidence',
      '05_execution_timeline', '06_classification',
    ];
    const files: Record<string, any> = {};
    const issues: { name: string; reason: string }[] = [];
    for (const name of jsonFiles) {
      const artifact = artifacts.find(a => a.filename.startsWith(name));
      if (!artifact) { issues.push({ name, reason: 'missing' }); continue; }
      try {
        const c = await invoke<string>('read_file', { path: artifact.path });
        files[name] = JSON.parse(c);
      } catch { issues.push({ name, reason: 'parse error' }); }
    }
    return { files, issues };
  };

  const openPDF = async () => {
    if (!pdfPath) return toast.error('PDF not found');
    try {
      await invoke('open_file', { path: pdfPath });
      toast.success('Opening PDF in Preview');
    } catch { toast.error('Failed to open PDF'); }
  };

  // Post the parsed engine outputs into the analyzer iframe. Safe to call
  // repeatedly: the analyzer applies the payload exactly once and acks back,
  // and we stop as soon as that ack arrives.
  const postToAnalyzer = useCallback(() => {
    if (ackedRef.current) return;
    const data = filesRef.current;
    if (!data) return;
    iframeRef.current?.contentWindow?.postMessage(
      { type: 'MEMFORENSICS_AUTO_LOAD', files: data.files, issues: data.issues }, '*'
    );
  }, []);

  const openAnalyzer = () => {
    ackedRef.current = false;
    dataSentRef.current = false;
    filesRef.current = null;
    setShowAnalyzer(true);
    toast.success('Loading JSON Analyzer — auto-loading pipeline outputs...');
  };

  // Read + parse the six engine JSON files once the iframe has loaded, then
  // hand them to the delivery loop below.
  const handleIframeLoad = async () => {
    try {
      if (dataSentRef.current) return;
      dataSentRef.current = true;
      filesRef.current = await loadAnalyzerData(artifacts);
      postToAnalyzer(); // in case the iframe's READY ping fired before we listened
    } catch {}
  };

  // Guaranteed delivery: send when the analyzer says it is READY, keep retrying
  // on a short interval, and stop the moment it acks with LOADED. This removes
  // the old reliance on a single fixed-delay message that could be missed.
  useEffect(() => {
    if (!showAnalyzer) return;

    const onMessage = (event: MessageEvent) => {
      const t = event.data?.type;
      if (t === 'MEMFORENSICS_READY') {
        postToAnalyzer();
      } else if (t === 'MEMFORENSICS_LOADED') {
        ackedRef.current = true;
        if (retryRef.current) { clearInterval(retryRef.current); retryRef.current = null; }
        toast.success(`Analyzer loaded ${event.data?.count ?? ''} engine outputs`.trim());
      }
    };
    window.addEventListener('message', onMessage);

    let attempts = 0;
    retryRef.current = window.setInterval(() => {
      attempts += 1;
      if (ackedRef.current || attempts > 40) { // ~20s ceiling
        if (retryRef.current) { clearInterval(retryRef.current); retryRef.current = null; }
        return;
      }
      postToAnalyzer();
    }, 500);

    return () => {
      window.removeEventListener('message', onMessage);
      if (retryRef.current) { clearInterval(retryRef.current); retryRef.current = null; }
    };
  }, [showAnalyzer, postToAnalyzer]);

  const downloadArtifact = async (path: string) => {
    try {
      await invoke('open_file', { path });
    } catch { toast.error('Failed to open file'); }
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-6">
      <div className="flex items-center gap-4 mb-6">
        <Link to="/" className="flex items-center gap-1.5 text-muted text-sm hover:text-primary transition-colors">
          <ArrowLeft className="w-4 h-4" /> Dashboard
        </Link>
        <Link to={`/pipeline/${jobId}`} className="flex items-center gap-1.5 text-muted text-sm hover:text-primary transition-colors">
          <ArrowLeft className="w-4 h-4" /> Pipeline
        </Link>
      </div>

      {/* Actions */}
      <div className="bg-card border border-border rounded-xl p-6 mb-6">
        <h2 className="text-primary font-semibold text-lg mb-1">Forensic Report</h2>
        <p className="text-muted text-xs font-mono mb-5">{jobId}</p>
        <div className="flex flex-wrap gap-3">
          <button onClick={openPDF} disabled={!pdfPath}
            className="flex items-center gap-2 bg-blue text-white rounded-lg px-6 py-3 font-semibold hover:bg-blue/90 transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
            <FileText className="w-5 h-5" /> Open PDF Report
          </button>
          <button onClick={openAnalyzer} disabled={artifacts.length === 0}
            className="flex items-center gap-2 border border-blue/30 text-blue rounded-lg px-6 py-3 font-medium hover:bg-blue/10 transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
            <Globe className="w-5 h-5" /> {showAnalyzer ? 'Reload Analyzer' : 'Open JSON Analyzer'}
          </button>
        </div>
      </div>

      {/* Embedded Analyzer */}
      {showAnalyzer && (
        <div className="bg-card border border-border rounded-xl overflow-hidden mb-6">
          <div className="flex items-center justify-between px-4 py-2 border-b border-border">
            <span className="text-primary text-sm font-semibold">JSON Analyzer</span>
            <div className="flex items-center gap-3">
              <span className="text-muted text-xs">Auto-loading all 6 engine outputs...</span>
<button onClick={() => { setShowAnalyzer(false); dataSentRef.current = false; ackedRef.current = false; }} className="text-muted hover:text-primary">                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
          <iframe
            ref={iframeRef}
            src={JSON_ANALYZER_LOCAL_URL}
            className="w-full"
            style={{ height: '85vh', border: 'none' }}
            title="JSON Analyzer"
            onLoad={handleIframeLoad}
          />
        </div>
      )}

      {/* Output Files */}
      <div className="bg-card border border-border rounded-xl p-6">
        <h3 className="text-primary font-semibold text-sm uppercase tracking-wide mb-4">Output Files</h3>
        {artifacts.length === 0 && (
          <div className="border border-red/30 bg-red/5 rounded-lg p-4">
            <p className="text-primary text-sm mb-2">
              {runStatus === 'failed'
                ? 'This run stopped before it produced any output files.'
                : 'No output files were written for this run yet.'}
            </p>
            {runError && (
              <pre className="text-red text-xs font-mono whitespace-pre-wrap max-h-48 overflow-auto mb-2">
                {runError}
              </pre>
            )}
            <Link to={`/pipeline/${jobId}`} className="text-blue text-sm hover:underline">
              Open the pipeline console for this run →
            </Link>
          </div>
        )}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {artifacts.map(a => (
            <div key={a.filename}
              onClick={() => downloadArtifact(a.path)}
              className="flex items-center gap-3 bg-cardalt border border-border rounded-lg p-3 cursor-pointer hover:border-blue/50 transition-colors">
              {a.filename.endsWith('.pdf')
                ? <FileText className="w-8 h-8 text-blue shrink-0" />
                : <FileJson className="w-8 h-8 text-blue shrink-0" />}
              <div className="flex-1 min-w-0">
                <p className="text-primary text-sm font-mono truncate">{a.filename}</p>
                <p className="text-muted text-xs">{(a.sizeBytes / 1024).toFixed(1)} KB</p>
              </div>
              <Download className="w-4 h-4 text-muted shrink-0" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
