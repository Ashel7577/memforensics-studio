import { useEffect, useState, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { invoke } from '@tauri-apps/api/core';
import { Download, ExternalLink, ArrowLeft, FileText, FileJson, Globe, X } from 'lucide-react';
import { toast } from 'sonner';
import { JSON_ANALYZER_URL } from '../lib/constants';

export default function Report() {
  const { id } = useParams<{ id: string }>();
  const jobId = id ?? '';
  const [artifacts, setArtifacts] = useState<any[]>([]);
  const [pdfPath, setPdfPath] = useState<string | null>(null);
  const [showAnalyzer, setShowAnalyzer] = useState(false);
   const iframeRef = useRef<HTMLIFrameElement>(null);
  const dataSentRef = useRef(false);

  useEffect(() => {
    if (!jobId) return;
    invoke<any[]>('get_artifacts', { jobId }).then(a => {
      setArtifacts(a);
      const pdf = a.find(x => x.filename.endsWith('.pdf'));
      if (pdf) setPdfPath(pdf.path);
    });
  }, [jobId]);

  const loadAnalyzerData = async (artifacts: any[]) => {
    const jsonFiles = [
      '01_memory_evidence', '02_os_structures',
      '03_private_exec_regions', '04_execution_evidence',
      '05_execution_timeline', '06_classification',
    ];
    const files: Record<string, any> = {};
    for (const name of jsonFiles) {
      try {
        const artifact = artifacts.find(a => a.filename.startsWith(name));
        if (artifact) {
          const c = await invoke<string>('read_file', { path: artifact.path });
          files[name] = JSON.parse(c);
        }
      } catch {}
    }
    return files;
  };

  const openPDF = async () => {
    if (!pdfPath) return toast.error('PDF not found');
    try {
      await invoke('open_file', { path: pdfPath });
      toast.success('Opening PDF in Preview');
    } catch { toast.error('Failed to open PDF'); }
  };

    const openAnalyzer = async () => {
    dataSentRef.current = false;
    setShowAnalyzer(true);
    toast.success('Loading JSON Analyzer — auto-loading pipeline outputs...');
  };
    const handleIframeLoad = async () => {
    try {
      if (dataSentRef.current) return;
      const files = await loadAnalyzerData(artifacts);
      dataSentRef.current = true;
      setTimeout(() => {
        iframeRef.current?.contentWindow?.postMessage(
          { type: 'MEMFORENSICS_AUTO_LOAD', files }, '*'
        );
      }, 1500);
    } catch {}
  };

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
          <button onClick={openPDF}
            className="flex items-center gap-2 bg-blue text-white rounded-lg px-6 py-3 font-semibold hover:bg-blue/90 transition-colors">
            <FileText className="w-5 h-5" /> Open PDF Report
          </button>
          <button onClick={openAnalyzer}
            className="flex items-center gap-2 border border-blue/30 text-blue rounded-lg px-6 py-3 font-medium hover:bg-blue/10 transition-colors">
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
<button onClick={() => { setShowAnalyzer(false); dataSentRef.current = false; }} className="text-muted hover:text-primary">                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
          <iframe
            ref={iframeRef}
            src={JSON_ANALYZER_URL}
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
