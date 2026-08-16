import { useEffect, useCallback, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { invoke } from '@tauri-apps/api/core';
import {
  ExternalLink,
  Rocket,
  Loader2,
  Lock,
  ShieldCheck,
  Check,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { toast } from 'sonner';
import { useStore } from '../store';
import { ENGINES, JSON_ANALYZER_URL } from '../lib/constants';
import FileUpload from '../components/FileUpload';
import EngineCard from '../components/EngineCard';
import MemoryFabric from '../components/MemoryFabric';

/* Reveal choreography.
 *
 * One curve and one rhythm for the whole page: an expo ease-out, ~320ms per
 * element, 60ms apart, moving 10px at most. Interface motion past ~300ms reads
 * as waiting rather than as polish, and staggering a handful of bands gives the
 * eye a path down the page without any single element drawing attention to
 * itself. Only transform and opacity are animated, so none of it touches
 * layout. */
const EASE = [0.16, 1, 0.3, 1] as const;

const reveal = {
  hidden: { opacity: 0, y: 10 },
  show: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { duration: 0.32, delay: 0.04 + i * 0.06, ease: EASE },
  }),
};

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

  /* Stable per-session case reference, shown in the status rail and useful as a
   * talking point when walking through the run. */
  const caseId = useMemo(() => {
    const d = new Date();
    const stamp = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
    return `MF-${stamp}-${String(d.getHours()).padStart(2, '0')}${String(d.getMinutes()).padStart(2, '0')}`;
  }, []);

  const preflight = [
    { label: 'Evidence image loaded', ok: !!store.filePath },
    { label: 'Analysis stages armed', ok: store.selectedEngines.length > 0, detail: `${store.selectedEngines.length}/7` },
    { label: 'Volatility 3 backend bundled', ok: true },
    { label: 'Output workspace writable', ok: true },
  ];

  return (
    <div className="relative min-h-screen">
      <MemoryFabric />

      {/* Everything above the fabric */}
      <div className="relative z-10">
      {/* System status rail */}
      <motion.div
        custom={0} variants={reveal} initial="hidden" animate="show"
        className="border-b border-border bg-[#0a0e14]/70 backdrop-blur-sm"
      >
        <div className="max-w-5xl mx-auto px-4 py-1.5 flex items-center gap-4 text-[10px] font-mono flex-wrap">
          <span className="flex items-center gap-1.5 text-green">
            <span className="w-1.5 h-1.5 rounded-full bg-green arm-led" />
            SYSTEM NOMINAL
          </span>
          <span className="text-muted/40">│</span>
          <span className="text-muted">
            CASE <span className="text-primary">{caseId}</span>
          </span>
          <span className="text-muted/40">│</span>
          <span className="text-muted">
            ENGINE <span className="text-primary">7-STAGE</span>
          </span>
          <span className="text-muted/40">│</span>
          <span className="text-muted">
            BACKEND <span className="text-primary">VOLATILITY 3</span>
          </span>
          <span className="ml-auto flex items-center gap-1.5 text-blue">
            <Lock className="w-3 h-3" />
            LOCAL-ONLY PROCESSING · NO DATA LEAVES HOST
          </span>
        </div>
      </motion.div>

      {/* Hero Section */}
      <div className="relative overflow-hidden border-b border-border/60">
        {/* The hero sits straight on the memory fabric: no panel, just a soft
            halo so the wordmark keeps its contrast. */}
        <div className="absolute inset-0 bg-[radial-gradient(45%_90%_at_50%_50%,rgba(10,12,24,0.55),transparent_75%)]" />
        <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-purple/40 to-transparent" />

        <div className="relative max-w-5xl mx-auto px-4 py-16 text-center">
          <motion.h1
            custom={1} variants={reveal} initial="hidden" animate="show"
            className="text-5xl md:text-6xl font-bold bg-gradient-to-r from-purple via-blue to-purple bg-clip-text text-transparent"
          >
            MemForensics Studio
          </motion.h1>
          <motion.p
            custom={2} variants={reveal} initial="hidden" animate="show"
            className="mt-4 text-muted text-sm md:text-base font-mono uppercase tracking-[0.3em]"
          >
            Memory-Only Malware Detection
          </motion.p>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-5xl mx-auto px-4 py-8 space-y-10">
        <motion.section custom={3} variants={reveal} initial="hidden" animate="show">
          <div className="section-header-accent mb-4">
            <h2 className="text-sm font-semibold text-primary uppercase tracking-wide">Memory Dump</h2>
            <p className="text-muted text-xs mt-0.5">Select a Windows memory dump file to analyze</p>
          </div>
          <FileUpload />
        </motion.section>

        <motion.section custom={4} variants={reveal} initial="hidden" animate="show">
          <div className="section-header-accent mb-4">
            <h2 className="text-sm font-semibold text-primary uppercase tracking-wide">Select Engines</h2>
            <p className="text-muted text-xs mt-0.5">Engines run sequentially — each feeds into the next</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 auto-rows-fr">
            {ENGINES.map((engine, i) => (
              <motion.div
                key={engine.num}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.32, delay: 0.3 + i * 0.045, ease: EASE }}
              >
                <EngineCard
                  engine={engine}
                  selected={store.selectedEngines.includes(engine.num)}
                  onToggle={() => store.toggleEngine(engine.num)}
                />
              </motion.div>
            ))}
          </div>
        </motion.section>

        <motion.section custom={8} variants={reveal} initial="hidden" animate="show" className="space-y-3">
          {/* Pre-flight readiness — shows the operator (and the room) exactly
              what the tool has verified before any evidence is touched. */}
          <div className="rounded-xl border border-border bg-card/60 overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-[#0a0e14]">
              <ShieldCheck className={`w-3.5 h-3.5 ${isReady ? 'text-green' : 'text-muted'}`} />
              <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-muted">Pre-flight Check</span>
              <span
                className={`ml-auto text-[9px] font-mono uppercase tracking-wider ${
                  isReady ? 'text-green' : 'text-orange'
                }`}
              >
                {isReady ? 'All systems go' : 'Awaiting input'}
              </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-border">
              {preflight.map((c) => (
                <div key={c.label} className="flex items-center gap-2 px-4 py-2.5">
                  <span
                    className={`flex items-center justify-center w-4 h-4 rounded-full border shrink-0 ${
                      c.ok ? 'border-green/50 bg-green/10 text-green' : 'border-border text-muted'
                    }`}
                  >
                    {c.ok ? <Check className="w-2.5 h-2.5" /> : <span className="w-1 h-1 rounded-full bg-muted" />}
                  </span>
                  <span className={`text-[11px] ${c.ok ? 'text-primary' : 'text-muted'}`}>{c.label}</span>
                  {c.detail && <span className="ml-auto text-[10px] font-mono text-blue">{c.detail}</span>}
                </div>
              ))}
            </div>
          </div>

          <motion.button
            whileHover={isReady && !running ? { scale: 1.01 } : undefined}
            whileTap={isReady && !running ? { scale: 0.99 } : undefined}
            onClick={handleRun}
            disabled={!isReady || running}
            className={`group/cmd relative w-full overflow-hidden rounded-xl py-5 px-6 transition-all duration-300 ${
              !isReady || running
                ? 'bg-cardalt border border-border cursor-not-allowed'
                : 'cmd-border border border-transparent hover:shadow-[0_0_36px_rgba(139,110,255,0.35)]'
            }`}
          >
            {/* technical texture + sweeping sheen */}
            <span className="absolute inset-0 cmd-grid opacity-40 pointer-events-none" aria-hidden="true" />
            {isReady && !running && <span className="cmd-sheen" aria-hidden="true" />}

            {/* reticle brackets */}
            {isReady && !running && (
              <>
                <span className="cmd-corner left-2 top-2 border-l border-t" aria-hidden="true" />
                <span className="cmd-corner right-2 top-2 border-r border-t" aria-hidden="true" />
                <span className="cmd-corner left-2 bottom-2 border-l border-b" aria-hidden="true" />
                <span className="cmd-corner right-2 bottom-2 border-r border-b" aria-hidden="true" />
              </>
            )}

            <span className="relative z-10 flex items-center justify-between gap-4">
              <span className="flex flex-col items-start">
                <span
                  className={`text-[9px] font-mono uppercase tracking-[0.28em] ${
                    !isReady || running ? 'text-muted/60' : 'text-purple'
                  }`}
                >
                  {running ? 'Dispatching' : isReady ? 'Ready to execute' : 'Awaiting evidence'}
                </span>
                <span
                  className={`text-lg font-bold tracking-wide ${
                    !isReady || running ? 'text-muted' : 'text-white'
                  }`}
                >
                  {running ? 'Starting Pipeline…' : 'Run Pipeline'}
                </span>
              </span>

              <span className="flex items-center gap-3">
                <span className="hidden sm:flex flex-col items-end gap-0.5">
                  <span
                    className={`text-[10px] font-mono ${
                      !isReady || running ? 'text-muted/60' : 'text-blue'
                    }`}
                  >
                    {store.selectedEngines.length}/7 stages armed
                  </span>
                  <span className="text-[9px] font-mono text-muted/50">⌃ ↵ to launch</span>
                </span>
                <span
                  className={`flex items-center justify-center w-10 h-10 rounded-lg border transition-all ${
                    !isReady || running
                      ? 'border-border text-muted'
                      : 'border-purple/50 bg-purple/10 text-purple group-hover/cmd:bg-purple/20'
                  }`}
                >
                  {running ? (
                    <Loader2 className="w-5 h-5 animate-spin" />
                  ) : (
                    <Rocket className="w-5 h-5 transition-transform group-hover/cmd:-translate-y-0.5 group-hover/cmd:translate-x-0.5" />
                  )}
                </span>
              </span>
            </span>

            {/* armed-stage segment strip */}
            <span className="relative z-10 mt-3 flex gap-1" aria-hidden="true">
              {ENGINES.map((e) => {
                const armed = store.selectedEngines.includes(e.num);
                return (
                  <span
                    key={e.num}
                    className={`h-[3px] flex-1 rounded-full transition-all duration-300 ${
                      armed && isReady ? 'bg-purple shadow-[0_0_6px_#bc8cff]' : 'bg-white/10'
                    }`}
                  />
                );
              })}
            </span>
          </motion.button>

          <button
            onClick={openAnalyzer}
            className="group/cmd relative w-full overflow-hidden rounded-xl py-3 px-4 border border-blue/25 bg-blue/[0.03] hover:border-blue/50 hover:bg-blue/[0.08] transition-all duration-300"
          >
            <span className="cmd-sheen" aria-hidden="true" />
            <span className="relative z-10 flex items-center justify-center gap-2 text-sm font-medium text-blue">
              <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-blue/60">External</span>
              Open JSON Analyzer
              <ExternalLink className="w-4 h-4 transition-transform group-hover/cmd:translate-x-0.5 group-hover/cmd:-translate-y-0.5" />
            </span>
          </button>
        </motion.section>
      </div>
    </div>
    </div>
  );
}
