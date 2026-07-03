import { Shield, Cpu, Search, Clock, GitBranch, Zap, FileText } from 'lucide-react';
import type { EngineConfig } from '../types';

interface Props {
  engine: EngineConfig;
  selected: boolean;
  onToggle: () => void;
}

const ENGINE_ICONS = [Shield, Cpu, Search, Clock, GitBranch, Zap, FileText];
const ENGINE_COLORS = [
  'text-blue',
  'text-green',
  'text-orange',
  'text-purple',
  'text-red',
  'text-blue',
  'text-green',
];

const ENGINE_BORDER_COLORS = [
  '#58a6ff',
  '#3fb950',
  '#d29922',
  '#bc8cff',
  '#f85149',
  '#58a6ff',
  '#3fb950',
];

const ENGINE_GLOW_CLASSES = [
  'engine-glow-1',
  'engine-glow-2',
  'engine-glow-3',
  'engine-glow-4',
  'engine-glow-5',
  'engine-glow-6',
  'engine-glow-7',
];

const ENGINE_BG_COLORS = [
  'bg-blue/5',
  'bg-green/5',
  'bg-orange/5',
  'bg-purple/5',
  'bg-red/5',
  'bg-blue/5',
  'bg-green/5',
];

export default function EngineCard({ engine, selected, onToggle }: Props) {
  const idx = engine.num - 1;
  const Icon = ENGINE_ICONS[idx];
  const colorClass = ENGINE_COLORS[idx];
  const borderColor = ENGINE_BORDER_COLORS[idx];
  const glowClass = ENGINE_GLOW_CLASSES[idx];
  const bgClass = ENGINE_BG_COLORS[idx];

  return (
    <div
      onClick={onToggle}
      className={`cursor-pointer rounded-xl border border-border p-5 relative overflow-hidden transition-all duration-300 ${
        selected
          ? `${bgClass} ${glowClass}`
          : 'bg-card hover:border-[#484f58]'
      }`}
      style={{
        borderLeftWidth: '3px',
        borderLeftColor: selected ? borderColor : 'transparent',
      }}
    >
      {/* Large background number */}
      <span
        className="absolute top-1 right-3 text-6xl font-bold text-[#30363d]/30 select-none pointer-events-none leading-none"
        aria-hidden="true"
      >
        {String(engine.num).padStart(2, '0')}
      </span>

      <div className="relative z-10 flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2.5 mb-2">
            <div className={`w-8 h-8 rounded-lg ${bgClass} flex items-center justify-center shrink-0`}>
              <Icon className={`w-4 h-4 ${colorClass}`} />
            </div>
            <span className="text-primary font-semibold text-sm truncate">
              {engine.name}
            </span>
          </div>
          <p className="text-muted text-xs mb-3 leading-relaxed">{engine.description}</p>
          <div className="text-[11px] font-mono">
            <span className="text-muted bg-cardalt px-1.5 py-0.5 rounded break-all">{engine.input}</span>
            <span className="text-muted mx-1">→</span>
            <span className="text-blue bg-blue/5 px-1.5 py-0.5 rounded break-all">{engine.output}</span>
          </div>
        </div>
        <div className="shrink-0 mt-1 relative z-10">
          <div
            className={`w-11 h-6 rounded-full border transition-all duration-300 flex items-center px-0.5 ${
              selected
                ? 'bg-blue border-blue toggle-glow'
                : 'bg-cardalt border-border'
            }`}
          >
            <div
              className={`w-5 h-5 rounded-full bg-primary transition-all duration-300 shadow-sm ${
                selected ? 'translate-x-5' : 'translate-x-0'
              }`}
            />
          </div>
        </div>
      </div>

    </div>
  );
}
