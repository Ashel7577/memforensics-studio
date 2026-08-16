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
        {/* Arm switch — reads as instrument hardware rather than an OS toggle */}
        <div className="shrink-0 mt-0.5 relative z-10 flex flex-col items-end gap-1">
          <div
            role="switch"
            aria-checked={selected}
            aria-label={`${engine.name} — ${selected ? 'armed' : 'offline'}`}
            className={`arm-track relative w-[52px] h-[22px] rounded-[5px] border transition-all duration-300 flex items-center px-[3px] ${
              selected ? 'bg-black/40' : 'bg-black/30 border-border'
            }`}
            style={{
              borderColor: selected ? borderColor : undefined,
              boxShadow: selected ? `0 0 12px ${borderColor}55, inset 0 0 8px ${borderColor}22` : undefined,
            }}
          >
            {/* notch marks on the track */}
            <span className="absolute inset-y-[5px] left-1/2 w-px bg-white/10" aria-hidden="true" />
            <div
              className={`relative w-[22px] h-[15px] rounded-[3px] transition-transform duration-300 ease-out flex items-center justify-center gap-[2px] ${
                selected ? 'translate-x-[25px]' : 'translate-x-0'
              }`}
              style={{
                background: selected ? borderColor : '#30363d',
                boxShadow: selected ? `0 0 10px ${borderColor}` : 'none',
              }}
            >
              {/* grip lines on the thumb */}
              <span className="w-px h-[7px] bg-black/40" />
              <span className="w-px h-[7px] bg-black/40" />
              <span className="w-px h-[7px] bg-black/40" />
            </div>
          </div>
          <span
            className={`flex items-center gap-1 text-[8px] font-mono uppercase tracking-[0.16em] transition-colors ${
              selected ? '' : 'text-muted/60'
            }`}
            style={{ color: selected ? borderColor : undefined }}
          >
            <span
              className={`w-1 h-1 rounded-full ${selected ? 'arm-led' : ''}`}
              style={{ background: selected ? borderColor : '#484f58' }}
            />
            {selected ? 'Armed' : 'Offline'}
          </span>
        </div>
      </div>

    </div>
  );
}
