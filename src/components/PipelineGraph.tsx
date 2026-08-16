import { useEffect, useRef } from 'react';
import type { EngineProgress } from '../types';

interface Props {
  engines: EngineProgress[];
  /** Optional — total log lines seen so far. Rising values emit data packets. */
  activity?: number;
}

type Node = { x: number; y: number; num: number; name: string };
type Particle = { edge: number; t: number; speed: number; size: number; hot: boolean };
type Star = { x: number; y: number; r: number; tw: number; phase: number };
type Ripple = { x: number; y: number; t: number; color: [number, number, number] };

const PURPLE: [number, number, number] = [167, 139, 250];
const BLUE: [number, number, number] = [96, 165, 250];
const GREEN: [number, number, number] = [63, 185, 80];
const RED: [number, number, number] = [248, 81, 73];
const SLATE: [number, number, number] = [110, 122, 145];

function rgba(c: number[], a: number) {
  return `rgba(${c[0]},${c[1]},${c[2]},${a})`;
}

export default function PipelineGraph({ engines, activity = 0 }: Props) {
  const cvRef = useRef<HTMLCanvasElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const enginesRef = useRef(engines);
  enginesRef.current = engines;

  // Burst counter: incremented by the render pass whenever new log lines land,
  // consumed by the animation loop to emit packets tied to real engine output.
  const burstRef = useRef(0);
  const lastActivityRef = useRef(activity);
  if (activity > lastActivityRef.current) {
    burstRef.current += Math.min(6, activity - lastActivityRef.current);
    lastActivityRef.current = activity;
  }

  // Remember each stage's last status so completions can fire a ripple.
  const prevStatusRef = useRef<Record<number, string>>({});

  useEffect(() => {
    const cv = cvRef.current!;
    const wrap = wrapRef.current!;
    const ctx = cv.getContext('2d')!;
    let dpr = Math.min(2, window.devicePixelRatio || 1);
    let W = 0, H = 0;
    let nodes: Node[] = [];
    const stars: Star[] = [];
    for (let i = 0; i < 90; i++) {
      stars.push({
        x: Math.random(), y: Math.random(),
        r: Math.random() * 1.1 + 0.2,
        tw: 0.5 + Math.random() * 2.5,
        phase: Math.random() * Math.PI * 2,
      });
    }
    const particles: Particle[] = [];
    const ripples: Ripple[] = [];

    function layout() {
      dpr = Math.min(2, window.devicePixelRatio || 1);
      W = wrap.clientWidth; H = wrap.clientHeight;
      cv.width = W * dpr; cv.height = H * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      const names = ['Acquisition', 'OS Structures', 'Private Regions', 'Execution Evidence', 'Timeline', 'Classifier', 'Report'];
      const n: number = 7;
      const padX = Math.min(70, W * 0.09);
      const usableW = W - padX * 2;
      nodes = Array.from({ length: n }, (_, i) => {
        const t = n === 1 ? 0 : i / (n - 1);
        const arc = Math.sin(t * Math.PI) * (H * 0.16);
        return { x: padX + usableW * t, y: H * 0.5 - arc + H * 0.06, num: i + 1, name: names[i] };
      });
    }
    layout();
    window.addEventListener('resize', layout);

    let raf = 0;
    let last = performance.now();

    function statusColor(status: string): [number, number, number] {
      if (status === 'done') return GREEN;
      if (status === 'failed') return RED;
      if (status === 'running') return BLUE;
      return SLATE;
    }

    function frame(ts: number) {
      const dt = Math.min(48, ts - last); last = ts;
      const eng = enginesRef.current;
      ctx.clearRect(0, 0, W, H);

      // ambient starfield
      stars.forEach(s => {
        const a = 0.15 + 0.5 * (0.5 + 0.5 * Math.sin(ts * 0.001 * s.tw + s.phase));
        ctx.beginPath();
        ctx.arc(s.x * W, s.y * H, s.r, 0, Math.PI * 2);
        ctx.fillStyle = rgba(PURPLE, a * 0.35);
        ctx.fill();
      });

      // Fire completion ripples when a stage flips to done/failed.
      eng.forEach(e => {
        const prev = prevStatusRef.current[e.engineNum];
        if (prev && prev !== e.status && (e.status === 'done' || e.status === 'failed')) {
          const n = nodes.find(nd => nd.num === e.engineNum);
          if (n) ripples.push({ x: n.x, y: n.y, t: 0, color: e.status === 'done' ? GREEN : RED });
        }
        prevStatusRef.current[e.engineNum] = e.status;
      });

      // Drain the activity burst into packets on the running edge.
      const runningIdx = nodes.findIndex(n => eng.find(e => e.engineNum === n.num)?.status === 'running');
      if (burstRef.current > 0 && runningIdx > 0) {
        particles.push({
          edge: runningIdx - 1,
          t: 0,
          speed: 0.0011 + Math.random() * 0.0006,
          size: 2.6 + Math.random() * 1.4,
          hot: true,
        });
        burstRef.current--;
      } else if (burstRef.current > 0) {
        burstRef.current--;
      }

      const edgePoint = (i: number, t: number) => {
        const a = nodes[i], b = nodes[i + 1];
        const midX = (a.x + b.x) / 2, midY = Math.min(a.y, b.y) - 18;
        const it = 1 - t;
        return {
          x: it * it * a.x + 2 * it * t * midX + t * t * b.x,
          y: it * it * a.y + 2 * it * t * midY + t * t * b.y,
        };
      };

      // edges
      for (let i = 0; i < nodes.length - 1; i++) {
        const a = nodes[i], b = nodes[i + 1];
        const engA = eng.find(e => e.engineNum === a.num);
        const engB = eng.find(e => e.engineNum === b.num);
        const done = engA?.status === 'done';
        const active = done && (engB?.status === 'running' || engB?.status === 'done');
        const midX = (a.x + b.x) / 2, midY = Math.min(a.y, b.y) - 18;

        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.quadraticCurveTo(midX, midY, b.x, b.y);
        ctx.strokeStyle = active ? rgba(BLUE, 0.35) : rgba(SLATE, 0.18);
        ctx.lineWidth = active ? 1.6 : 1;
        ctx.stroke();

        // Marching-ants overlay on the edge feeding the running stage —
        // reads as data physically moving between stages.
        if (active && engB?.status === 'running') {
          ctx.save();
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.quadraticCurveTo(midX, midY, b.x, b.y);
          ctx.setLineDash([5, 9]);
          ctx.lineDashOffset = -(ts * 0.045) % 14;
          ctx.strokeStyle = rgba(BLUE, 0.75);
          ctx.lineWidth = 1.8;
          ctx.shadowColor = rgba(BLUE, 0.7);
          ctx.shadowBlur = 6;
          ctx.stroke();
          ctx.restore();
        }

        // ambient trickle so completed edges still feel alive
        if (active && engB?.status === 'running' && Math.random() < dt * 0.0035) {
          particles.push({ edge: i, t: 0, speed: 0.00045 + Math.random() * 0.0002, size: 2.2, hot: false });
        }
      }

      // particles flowing along edges
      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];
        p.t += p.speed * dt;
        if (p.t >= 1) { particles.splice(i, 1); continue; }
        const { x, y } = edgePoint(p.edge, p.t);

        // comet tail behind hot (log-driven) packets
        if (p.hot) {
          const tail = edgePoint(p.edge, Math.max(0, p.t - 0.06));
          const grad = ctx.createLinearGradient(tail.x, tail.y, x, y);
          grad.addColorStop(0, rgba(BLUE, 0));
          grad.addColorStop(1, rgba(BLUE, 0.55));
          ctx.beginPath();
          ctx.moveTo(tail.x, tail.y);
          ctx.lineTo(x, y);
          ctx.strokeStyle = grad;
          ctx.lineWidth = p.size * 0.8;
          ctx.lineCap = 'round';
          ctx.stroke();
        }

        ctx.beginPath();
        ctx.arc(x, y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = rgba(p.hot ? [190, 220, 255] : BLUE, 0.95);
        ctx.shadowColor = rgba(BLUE, 0.9);
        ctx.shadowBlur = p.hot ? 14 : 8;
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      // completion shockwaves
      for (let i = ripples.length - 1; i >= 0; i--) {
        const r = ripples[i];
        r.t += dt * 0.0011;
        if (r.t >= 1) { ripples.splice(i, 1); continue; }
        const ease = 1 - Math.pow(1 - r.t, 3);
        ctx.beginPath();
        ctx.arc(r.x, r.y, 20 + ease * 46, 0, Math.PI * 2);
        ctx.strokeStyle = rgba(r.color, 0.55 * (1 - r.t));
        ctx.lineWidth = 2 * (1 - r.t) + 0.4;
        ctx.stroke();
      }

      // nodes
      nodes.forEach(node => {
        const e = eng.find(x => x.engineNum === node.num);
        const status = e?.status ?? 'idle';
        const col = statusColor(status);
        const r = 20;

        if (status === 'running') {
          const p = 0.5 + 0.5 * Math.sin(ts * 0.0035);
          ctx.beginPath();
          ctx.arc(node.x, node.y, r + 6 + p * 5, 0, Math.PI * 2);
          ctx.strokeStyle = rgba(col, 0.35 * (1 - p * 0.5));
          ctx.lineWidth = 1.4;
          ctx.stroke();

          // Real percent as an arc gauge around the node — the demo-facing
          // proof that a long stage (e.g. 02) is genuinely advancing.
          const pct = Math.max(2, Math.min(100, e?.percent ?? 0)) / 100;
          const start = -Math.PI / 2;
          ctx.beginPath();
          ctx.arc(node.x, node.y, r + 5, 0, Math.PI * 2);
          ctx.strokeStyle = rgba(SLATE, 0.25);
          ctx.lineWidth = 2.5;
          ctx.stroke();
          ctx.beginPath();
          ctx.arc(node.x, node.y, r + 5, start, start + pct * Math.PI * 2);
          ctx.strokeStyle = rgba(col, 0.95);
          ctx.lineWidth = 2.5;
          ctx.lineCap = 'round';
          ctx.shadowColor = rgba(col, 0.8);
          ctx.shadowBlur = 10;
          ctx.stroke();
          ctx.shadowBlur = 0;

          // orbiting scanner tick
          const orbit = ts * 0.0016;
          ctx.beginPath();
          ctx.arc(node.x + Math.cos(orbit) * (r + 12), node.y + Math.sin(orbit) * (r + 12), 1.8, 0, Math.PI * 2);
          ctx.fillStyle = rgba(col, 0.8);
          ctx.fill();
        }
        if (status === 'done') {
          ctx.beginPath();
          ctx.arc(node.x, node.y, r + 4, 0, Math.PI * 2);
          ctx.strokeStyle = rgba(col, 0.18);
          ctx.lineWidth = 1;
          ctx.stroke();
        }

        ctx.beginPath();
        ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
        ctx.fillStyle = '#0b0e17';
        ctx.fill();
        ctx.strokeStyle = rgba(col, status === 'idle' ? 0.4 : 0.95);
        ctx.lineWidth = 1.8;
        ctx.stroke();

        ctx.font = '600 11px ui-monospace, monospace';
        ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
        ctx.fillStyle = rgba(col, status === 'idle' ? 0.5 : 1);
        if (status === 'done') {
          ctx.font = '700 13px ui-monospace, monospace';
          ctx.fillText('✓', node.x, node.y);
        } else if (status === 'failed') {
          ctx.font = '700 13px ui-monospace, monospace';
          ctx.fillText('✗', node.x, node.y);
        } else {
          ctx.fillText(String(node.num).padStart(2, '0'), node.x, node.y);
        }

        ctx.font = '500 10.5px -apple-system, sans-serif';
        ctx.fillStyle = rgba(status === 'idle' ? SLATE : col, status === 'idle' ? 0.55 : 0.9);
        ctx.fillText(node.name, node.x, node.y + r + 16);

        if (status === 'running') {
          ctx.font = '600 9.5px ui-monospace, monospace';
          ctx.fillStyle = rgba(col, 0.85);
          ctx.fillText(`${e?.percent ?? 0}%`, node.x, node.y + r + 28);
        }
      });

      raf = requestAnimationFrame(frame);
    }
    raf = requestAnimationFrame(frame);
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', layout); };
  }, []);

  return (
    <div ref={wrapRef} className="relative w-full h-[190px]">
      <canvas ref={cvRef} className="absolute inset-0 w-full h-full" />
    </div>
  );
}
