import { useEffect, useCallback, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { invoke } from '@tauri-apps/api/core';
import { Play, ExternalLink, Rocket, Shield, Cpu, Search, Clock } from 'lucide-react';
import { motion } from 'framer-motion';
import { toast } from 'sonner';
import { useStore } from '../store';
import { ENGINES, JSON_ANALYZER_URL } from '../lib/constants';
import FileUpload from '../components/FileUpload';
import EngineCard from '../components/EngineCard';

const STATS = [
  { label: '7 Engines', icon: Cpu },
  { label: 'MITRE ATT&CK', icon: Shield },
  { label: 'Memory Forensics', icon: Search },
  { label: 'Real-time Analysis', icon: Clock },
];

export default function Dashboard() {
  const navigate = useNavigate();
  const store = useStore();
  const [running, setRunning] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 'Enter') {
        e.preventDefault();
        handleRun();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [store.filePath, store.selectedEngines, store.limit, store.verbose]);

  useEffect(() => {
    document.title = 'MemForensics Studio';
  }, []);

  const handleRun = useCallback(async () => {
    if (!store.filePath) {
      toast.error('Please select a memory dump first');
      return;
    }
    if (store.selectedEngines.length === 0) {
      toast.error('Select at least one engine');
      return;
    }

    setRunning(true);
    try {
      const jobId = await invoke<string>('start_pipeline', {
        filePath: store.filePath,
        engines: store.selectedEngines,
        options: { limit: store.limit, verbose: store.verbose },
      });
      store.setActivePipelineId(jobId);
      store.setPipelineStatus('queued');
      toast.success('Pipeline started');
      navigate('/pipeline/' + jobId);
    } catch (err: any) {
      toast.error(err?.message || 'Failed to start pipeline');
    } finally {
      setRunning(false);
    }
  }, [store, navigate]);

  const openAnalyzer = () => {
    invoke('open_url', { url: JSON_ANALYZER_URL });
  };

  const isReady = !!store.filePath && store.selectedEngines.length > 0;

  return (
    <div className="min-h-screen bg-dfir bg-grid-pattern">
      {/* Hero Section */}
      <div className="relative overflow-hidden border-b border-border">
        <div className="absolute inset-0 bg-hex-pattern opacity-50" />
        <div className="absolute inset-0 bg-gradient-to-b from-purple/5 via-transparent to-transparent" />

        <div className="relative max-w-5xl mx-auto px-4 py-16 text-center">
          <motion.h1 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-5xl md:text-6xl font-bold bg-gradient-to-r from-purple via-blue to-purple bg-clip-text text-transparent mb-3"
          >
            MemForensics Studio
          </motion.h1>
          <p className="text-muted text-lg md:text-xl font-light">
            Memory-Only Malware Detection Pipeline
          </p>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="border-b border-border bg-card/50 backdrop-blur">
        <div className="max-w-5xl mx-auto px-4">
          <div className="flex items-center justify-center gap-6 md:gap-10 py-3">
            {STATS.map((stat) => (
              <motion.div key={stat.label} whileHover={{ scale: 1.1 }} className="flex items-center gap-2 text-muted">
                <stat.icon className="w-4 h-4 text-blue" />
                <span className="text-xs font-medium uppercase tracking-wider">{stat.label}</span>
              </motion.div>
            ))}
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-5xl mx-auto px-4 py-8 space-y-10">
        <section>
          <div className="section-header-accent mb-4">
            <h2 className="text-sm font-semibold text-primary uppercase tracking-wide">Memory Dump</h2>
            <p className="text-muted text-xs mt-0.5">Select a Windows memory dump file to analyze</p>
          </div>
          <FileUpload />
        </section>

        <section>
          <div className="section-header-accent mb-4">
            <h2 className="text-sm font-semibold text-primary uppercase tracking-wide">Select Engines</h2>
            <p className="text-muted text-xs mt-0.5">Engines run sequentially — each feeds into the next</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 auto-rows-fr">
            {ENGINES.map((engine, i) => (
              <motion.div
                key={engine.num}
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <EngineCard
                  engine={engine}
                  selected={store.selectedEngines.includes(engine.num)}
                  onToggle={() => store.toggleEngine(engine.num)}
                />
              </motion.div>
            ))}
          </div>
        </section>

        <section className="space-y-3">
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={handleRun}
            disabled={!isReady || running}
            className={`w-full flex items-center justify-center gap-3 rounded-xl py-5 text-lg font-bold transition-all duration-300 ${
              !isReady || running
                ? 'bg-cardalt text-muted cursor-not-allowed border border-border'
                : 'bg-gradient-to-r from-[#6366f1] to-[#a78bfa] text-white hover:shadow-xl hover:shadow-purple-500/25'
            }`}
          >
            {running ? 'Starting...' : 'Run Pipeline'}
            <Rocket className="w-5 h-5" />
          </motion.button>

          <button onClick={openAnalyzer} className="w-full flex items-center justify-center gap-2 rounded-xl py-3 text-sm font-medium border border-blue/30 text-blue hover:bg-blue/10">
            Open JSON Analyzer <ExternalLink className="w-4 h-4" />
          </button>
        </section>
      </div>
    </div>
  );
}
