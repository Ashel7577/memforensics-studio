import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { invoke } from '@tauri-apps/api/core';
import { ShieldAlert, Trash2, Eye, FileText } from 'lucide-react';
import { toast } from 'sonner';
import { useStore } from '../store';
import StatusBadge from '../components/StatusBadge';
import type { PipelineRun } from '../types';

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}m ${s}s`;
}

export default function History() {
  const store = useStore();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    document.title = 'History · MemForensics Studio';
  }, []);

  useEffect(() => {
    const load = async () => {
      try {
        const data = await invoke<PipelineRun[]>('get_history');
        store.loadHistory(data);
      } catch (err: any) {
        toast.error(err?.message || 'Failed to load history');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [store]);

  const handleDelete = async (jobId: string) => {
    try {
      await invoke('delete_job', { jobId });
      store.loadHistory(store.history.filter((h) => h.id !== jobId));
      toast.success('Job deleted');
    } catch (err: any) {
      toast.error(err?.message || 'Delete failed');
    }
  };

  const history = store.history;

  return (
    <div className="max-w-5xl mx-auto px-4 py-8">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-primary mb-1">History</h1>
        <p className="text-muted text-sm">Past forensic analyses</p>
      </div>

      {loading && (
        <div className="space-y-3">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="bg-cardalt animate-pulse h-14 rounded-xl" />
          ))}
        </div>
      )}

      {!loading && history.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 gap-4">
          <ShieldAlert className="w-16 h-16 text-muted" />
          <h2 className="text-primary text-xl font-semibold">No analyses yet</h2>
          <p className="text-muted text-sm">Upload a memory dump on the dashboard to begin</p>
          <Link
            to="/"
            className="mt-2 bg-blue text-white rounded-xl px-5 py-2.5 font-medium hover:bg-blue/90 transition-colors"
          >
            Go to Dashboard
          </Link>
        </div>
      )}

      {!loading && history.length > 0 && (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left text-muted text-xs uppercase tracking-wide font-medium px-4 py-3">
                    Job ID
                  </th>
                  <th className="text-left text-muted text-xs uppercase tracking-wide font-medium px-4 py-3">
                    Filename
                  </th>
                  <th className="text-left text-muted text-xs uppercase tracking-wide font-medium px-4 py-3">
                    Engines
                  </th>
                  <th className="text-left text-muted text-xs uppercase tracking-wide font-medium px-4 py-3">
                    Status
                  </th>
                  <th className="text-left text-muted text-xs uppercase tracking-wide font-medium px-4 py-3">
                    Started
                  </th>
                  <th className="text-left text-muted text-xs uppercase tracking-wide font-medium px-4 py-3">
                    Duration
                  </th>
                  <th className="text-right text-muted text-xs uppercase tracking-wide font-medium px-4 py-3">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {history.map((run) => (
                  <tr key={run.id} className="border-b border-border last:border-0 hover:bg-cardalt/50 transition-colors">
                    <td className="px-4 py-3 font-mono text-muted text-xs">{run.id}</td>
                    <td className="px-4 py-3 text-primary">{run.filename}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {run.engines.map((n) => (
                          <span key={n} className="bg-cardalt text-muted text-xs font-mono px-1.5 py-0.5 rounded">
                            {String(n).padStart(2, '0')}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={run.status} />
                    </td>
                    <td className="px-4 py-3 text-muted text-xs">{run.startedAt}</td>
                    <td className="px-4 py-3 text-muted text-xs font-mono">{formatDuration(run.duration)}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => navigate('/pipeline/' + run.id)}
                          className="text-muted hover:text-primary p-1.5 rounded hover:bg-cardalt transition-colors"
                          title="View Pipeline"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => navigate('/report/' + run.id)}
                          className="text-muted hover:text-primary p-1.5 rounded hover:bg-cardalt transition-colors"
                          title="View Report"
                        >
                          <FileText className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(run.id)}
                          className="text-muted hover:text-red p-1.5 rounded hover:bg-cardalt transition-colors"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
