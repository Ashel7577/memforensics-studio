import { useEffect, useRef } from 'react';

/**
 * Dashboard backdrop — an optic hunting a memory-resident implant.
 *
 * Two stacked layers:
 *
 *   1. A WebGL plasma field. Domain-warped fBm noise, pulled into horizontal
 *      strata so it reads as an address space seen edge-on rather than as
 *      clouds: deep, slow, mostly void, with thin filaments of light where
 *      regions are dense.
 *   2. A 2D scene over it: byte dust drifting through the field, the implant
 *      itself, and the optic that hunts it.
 *
 * The quarry is fileless malware — a cluster of opcodes squatting in private
 * RWX memory with no backing file. Unmagnified it is a smudge; the optic
 * resolves it into readable bytes, brackets it, lifts the pixels as evidence,
 * fires, and quarantine takes what is left.
 */

/* ============================ layer 2: the hunt ============================ */

type Phase = 'scan' | 'acquire' | 'focus' | 'capture' | 'evidence' | 'fire' | 'purge' | 'settle';

interface Implant {
  x: number;
  y: number;
  a: number;
  speed: number;
  alpha: number;
  eaten: number;
  addr: string;
  pid: number;
}

interface Flake { x: number; y: number; vx: number; vy: number; life: number }
interface Dust  { x: number; y: number; v: number; g: string; a: number }

const SCOPE_R = 46;
const GLYPH = 3.2;
const OPCODES = ['4d', '5a', '90', 'e8', 'ff', 'd0', '31', 'c0', '6a', '00', '68', 'cc', '8b', '45', 'fc', 'eb'];

export default function MemoryFabric() {
  const sceneRef = useRef<HTMLCanvasElement>(null);

  /* ---- hunt layer ---- */
  useEffect(() => {
    const canvas = sceneRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);

    let w = 0, h = 0, raf = 0, time = 0;
    let last = performance.now();

    let phase: Phase = 'scan';
    let phaseT = 0;
    const scope = { x: 0, y: 0, vx: 0, vy: 0, tx: 0, ty: 0, zoom: 1.6, zoomV: 0, breathe: 0, drift: Math.random() * 100 };
    let implant: Implant | null = null;
    let flakes: Flake[] = [];
    let dust: Dust[] = [];
    let evidence: { img: HTMLCanvasElement; x: number; y: number; t: number } | null = null;
    let purge = 0;
    let flash = 0;
    /** expanding ring from the shot */
    let shock = 0;

    const rnd = (a: number, b: number) => a + Math.random() * (b - a);

    const newScanTarget = () => {
      scope.tx = rnd(SCOPE_R, w - SCOPE_R);
      scope.ty = rnd(SCOPE_R, h * 0.8);
    };


    const spawnImplant = () => {
      implant = {
        x: rnd(w * 0.15, w * 0.85),
        y: rnd(h * 0.15, h * 0.75),
        a: rnd(0, Math.PI * 2),
        speed: 9,
        alpha: 0,
        eaten: 0,
        addr: '0x' + Math.floor(rnd(0x10, 0xff)).toString(16) + Math.floor(rnd(0x100000, 0xffffff)).toString(16),
        pid: Math.floor(rnd(600, 9000)),
      };
    };

    const setPhase = (p: Phase) => { phase = p; phaseT = 0; };

    const seedDust = () => {
      dust = Array.from({ length: Math.round((w * h) / 34000) }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        v: rnd(3, 11),
        g: OPCODES[Math.floor(Math.random() * OPCODES.length)],
        a: rnd(0.05, 0.18),
      }));
    };

    /* ---------- the implant ---------- */

    const drawImplant = (c: CanvasRenderingContext2D, m: Implant) => {
      const s = 1 - m.eaten;
      if (s <= 0.02) return;
      const flicker = 0.72 + 0.28 * Math.sin(time * 13 + m.x * 0.05);

      c.save();
      c.translate(m.x, m.y);
      c.scale(s, s);
      c.globalAlpha = m.alpha * flicker;

      // injection tendrils reaching into neighbouring memory
      c.lineCap = 'round';
      for (let i = 0; i < 5; i++) {
        const ang = (i / 5) * Math.PI * 2 + time * 0.45 + Math.sin(time + i) * 0.4;
        const len = 15 + Math.sin(time * 2.4 + i * 2) * 7;
        const gx = Math.cos(ang) * len;
        const gy = Math.sin(ang) * len;
        c.strokeStyle = `rgba(226, 72, 120, ${0.13 + 0.11 * Math.sin(time * 4 + i)})`;
        c.lineWidth = 1;
        c.beginPath();
        c.moveTo(0, 0);
        c.quadraticCurveTo(gx * 0.5 + Math.sin(time * 3 + i) * 5, gy * 0.5, gx, gy);
        c.stroke();
        c.fillStyle = `rgba(255, 120, 150, ${0.28 * flicker})`;
        c.fillRect(gx - 0.7, gy - 0.7, 1.4, 1.4);
      }

      // body: opcodes, unreadable until the optic resolves them
      c.font = `${GLYPH}px ui-monospace, SFMono-Regular, Menlo, monospace`;
      c.textAlign = 'center';
      c.textBaseline = 'middle';
      const rows = 7, cols = 6;
      for (let r = 0; r < rows; r++) {
        for (let col = 0; col < cols; col++) {
          const nx = (col - (cols - 1) / 2) / (cols / 2);
          const ny = (r - (rows - 1) / 2) / (rows / 2);
          const d = nx * nx + ny * ny;
          if (d > 1) continue;
          const idx = Math.floor(Math.abs(Math.sin(r * 12.9 + col * 7.7 + Math.floor(time * 3))) * OPCODES.length);
          const hot = 1 - d;
          c.fillStyle = `rgba(${230 + hot * 25}, ${92 - hot * 42}, ${122 - hot * 22}, ${0.34 + hot * 0.54})`;
          c.fillText(
            OPCODES[idx % OPCODES.length],
            (col - (cols - 1) / 2) * GLYPH * 2.1 + Math.sin(time * 6 + r * 2.1 + col) * 0.4,
            (r - (rows - 1) / 2) * GLYPH * 1.5,
          );
        }
      }

      if (Math.sin(time * 2.7) > 0.86) {
        c.fillStyle = 'rgba(255, 90, 130, 0.2)';
        c.fillRect(-11, Math.sin(time * 9) * 6, 22, 1.5);
      }

      const pulse = 0.55 + 0.45 * Math.sin(time * 6);
      const core = c.createRadialGradient(0, 0, 0, 0, 0, 16);
      core.addColorStop(0, `rgba(255, 70, 110, ${0.38 * pulse})`);
      core.addColorStop(0.4, `rgba(220, 50, 130, ${0.13 * pulse})`);
      core.addColorStop(1, 'rgba(220, 50, 130, 0)');
      c.fillStyle = core;
      c.fillRect(-16, -16, 32, 32);
      c.restore();
    };

    /* ---------- the optic ---------- */

    /**
     * A sniper's scope rather than a magnifier: mil-dot reticle, elevation and
     * windage ladders, a ranging arc, and a first-focal-plane feel where the
     * reticle sits over magnified ground. The glass still magnifies for real,
     * eased off toward the rim so it curves.
     */
    const drawScope = (c: CanvasRenderingContext2D) => {
      const { x, y, zoom } = scope;
      const R = SCOPE_R;

      // Everything outside the tube falls away — you are looking through it.
      c.save();
      const outside = c.createRadialGradient(x, y, R * 0.9, x, y, R * 3.4);
      outside.addColorStop(0, 'rgba(2, 4, 9, 0)');
      outside.addColorStop(1, 'rgba(2, 4, 9, 0.58)');
      c.fillStyle = outside;
      c.fillRect(0, 0, w, h);
      c.restore();

      c.save();
      c.beginPath();
      c.arc(x, y, R - 2, 0, Math.PI * 2);
      c.clip();

      c.fillStyle = 'rgba(4, 8, 14, 0.55)';
      c.fillRect(x - R, y - R, R * 2, R * 2);

      // magnified ground, eased toward the rim
      const RINGS = 4;
      for (let i = RINGS; i >= 1; i--) {
        const k = i / RINGS;
        const m = 1 + (zoom - 1) * (1 - 0.4 * k * k);
        c.save();
        c.beginPath();
        c.arc(x, y, (R - 2) * k, 0, Math.PI * 2);
        c.clip();
        c.translate(x, y);
        c.scale(m, m);
        c.translate(-x, -y);
        for (const d of dust) {
          c.fillStyle = `rgba(150, 200, 255, ${d.a})`;
          c.fillText(d.g, d.x, d.y);
        }
        if (implant) drawImplant(c, implant);
        c.restore();
      }

      // optical tint + edge falloff
      const tint = c.createRadialGradient(x, y, 0, x, y, R);
      tint.addColorStop(0, 'rgba(90, 160, 210, 0.04)');
      tint.addColorStop(0.75, 'rgba(40, 90, 150, 0.10)');
      tint.addColorStop(1, 'rgba(0, 0, 0, 0.65)');
      c.fillStyle = tint;
      c.fillRect(x - R, y - R, R * 2, R * 2);

      /* --- reticle --- */
      const armed = phase === 'focus' || phase === 'capture' || phase === 'fire';
      const rc = armed ? 'rgba(255, 105, 130, ' : 'rgba(140, 210, 240, ';

      c.lineWidth = 0.9;
      c.strokeStyle = rc + '0.55)';
      // main posts, stopping short of centre
      c.beginPath();
      c.moveTo(x - R, y); c.lineTo(x - 10, y);
      c.moveTo(x + 10, y); c.lineTo(x + R, y);
      c.moveTo(x, y - R); c.lineTo(x, y - 10);
      c.moveTo(x, y + 10); c.lineTo(x, y + R);
      c.stroke();

      // mil-dots along both axes
      c.fillStyle = rc + '0.45)';
      for (let i = 1; i <= 4; i++) {
        const d = 10 + i * 8;
        for (const s of [-1, 1]) {
          c.beginPath(); c.arc(x + s * d, y, 1.1, 0, Math.PI * 2); c.fill();
          c.beginPath(); c.arc(x, y + s * d, 1.1, 0, Math.PI * 2); c.fill();
        }
      }

      // elevation ladder on the left, windage on the bottom
      c.strokeStyle = rc + '0.28)';
      for (let i = 1; i <= 5; i++) {
        const len = i % 3 === 0 ? 6 : 3.5;
        c.beginPath();
        c.moveTo(x - R + 5, y - 22 + i * 8);
        c.lineTo(x - R + 5 + len, y - 22 + i * 8);
        c.stroke();
      }

      // centre aiming dot with a fine ring
      c.fillStyle = rc + '0.95)';
      c.beginPath(); c.arc(x, y, 1.5, 0, Math.PI * 2); c.fill();
      c.strokeStyle = rc + '0.32)';
      c.beginPath(); c.arc(x, y, 7, 0, Math.PI * 2); c.stroke();

      // lock arc sweeps closed while focusing
      if (armed) {
        const k = Math.min(1, phaseT / 1.6);
        c.strokeStyle = 'rgba(255, 105, 130, 0.55)';
        c.lineWidth = 1.4;
        c.beginPath();
        c.arc(x, y, R - 9, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * k);
        c.stroke();
      }

      c.restore();

      /* --- tube: near-black, lit only by a thin edge. The frame should read
             as an instrument housing, not as jewellery. --- */
      const rim = c.createLinearGradient(x - R, y - R, x + R, y + R);
      rim.addColorStop(0, '#1b232c');
      rim.addColorStop(0.4, '#0c1116');
      rim.addColorStop(0.75, '#070a0e');
      rim.addColorStop(1, '#141c24');
      c.strokeStyle = rim;
      c.lineWidth = 2.6;
      c.beginPath();
      c.arc(x, y, R, 0, Math.PI * 2);
      c.stroke();

      // A single cold hairline inside the housing — the only bright edge.
      c.strokeStyle = 'rgba(120, 200, 235, 0.16)';
      c.lineWidth = 1;
      c.beginPath();
      c.arc(x, y, R - 1.8, 0, Math.PI * 2);
      c.stroke();

      // Housing seats into the dark rather than outlining against it.
      c.strokeStyle = 'rgba(0, 0, 0, 0.5)';
      c.beginPath();
      c.arc(x, y, R + 1.6, 0, Math.PI * 2);
      c.stroke();

      /* --- segmented outer ring: four arcs with gaps, slowly counter-rotating.
             Reads as an optic's tracking collar. --- */
      c.strokeStyle = armed ? 'rgba(255, 105, 130, 0.30)' : 'rgba(120, 200, 235, 0.22)';
      c.lineWidth = 1;
      for (let i = 0; i < 4; i++) {
        const a0 = (i / 4) * Math.PI * 2 - time * 0.25;
        c.beginPath();
        c.arc(x, y, R + 6, a0, a0 + Math.PI * 0.34);
        c.stroke();
      }
      // corner index marks on the collar
      c.strokeStyle = armed ? 'rgba(255, 105, 130, 0.45)' : 'rgba(140, 215, 245, 0.3)';
      for (let i = 0; i < 4; i++) {
        const ang = (i / 4) * Math.PI * 2 + Math.PI / 4;
        c.beginPath();
        c.moveTo(x + Math.cos(ang) * (R + 3), y + Math.sin(ang) * (R + 3));
        c.lineTo(x + Math.cos(ang) * (R + 10), y + Math.sin(ang) * (R + 10));
        c.stroke();
      }

      /* --- status strip under the tube --- */
      c.font = '7px ui-monospace, SFMono-Regular, Menlo, monospace';
      c.textAlign = 'center';
      c.fillStyle = armed ? 'rgba(255, 120, 145, 0.6)' : 'rgba(140, 195, 230, 0.4)';
      const label =
        phase === 'scan' ? 'SCANNING' :
        phase === 'acquire' ? 'ACQUIRING' :
        phase === 'focus' ? 'LOCKED' :
        phase === 'capture' ? 'CAPTURE' :
        phase === 'fire' ? 'NEUTRALISE' :
        phase === 'purge' ? 'QUARANTINE' : 'CLEAR';
      // letter-spaced by hand; canvas has no tracking control
      c.fillText(label.split('').join(' '), x, y + R + 18);
      c.fillStyle = 'rgba(130, 175, 210, 0.28)';
      c.fillText(`${zoom.toFixed(1)}X`, x, y + R + 28);
    };

    const drawReadout = (c: CanvasRenderingContext2D, m: Implant, k: number) => {
      const x = m.x + 62;
      const y = m.y - 40;
      c.save();
      c.globalAlpha = Math.min(1, k * 1.6);
      c.strokeStyle = 'rgba(255, 110, 145, 0.45)';
      c.lineWidth = 1;
      c.beginPath();
      c.moveTo(m.x + 16, m.y - 14);
      c.lineTo(x - 6, y + 6);
      c.lineTo(x + 108, y + 6);
      c.stroke();
      c.font = '9px ui-monospace, SFMono-Regular, Menlo, monospace';
      c.textAlign = 'left';
      c.fillStyle = 'rgba(255, 140, 165, 0.9)';
      c.fillText('PRIVATE · RWX · NO BACKING FILE', x, y);
      c.fillStyle = 'rgba(170, 200, 235, 0.6)';
      c.fillText(`${m.addr}  ·  PID ${m.pid}  ·  T1055`, x, y - 12);
      c.restore();
    };

    /* ---------- loop ---------- */

    const resize = () => {
      const nw = canvas.clientWidth;
      const nh = canvas.clientHeight;
      if (nw < 2 || nh < 2) return;
      if (nw === w && nh === h) return;
      w = nw;
      h = nh;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      scope.x = w * 0.5;
      scope.y = h * 0.4;
      seedDust();
      newScanTarget();
    };

    const step = (dt: number) => {
      phaseT += dt;
      scope.breathe += dt;

      /** Magnification rides its own spring so it glides instead of snapping. */
      const zoomTo = (target: number) => {
        scope.zoomV += ((target - scope.zoom) * 34 - scope.zoomV * 11) * dt;
        scope.zoom += scope.zoomV * dt;
      };

      const hunting = phase !== 'scan' && phase !== 'settle' && implant;

      /* While searching, the optic wanders a slow Lissajous path rather than
       * jumping between random points — the two frequencies never line up, so
       * it never repeats, and every leg of it is a curve. */
      scope.drift += dt * 0.13;
      if (!hunting) {
        const m = SCOPE_R * 1.4;
        scope.tx = m + (Math.sin(scope.drift * 1.0) * 0.5 + 0.5) * (w - m * 2);
        scope.ty = m + (Math.sin(scope.drift * 1.37 + 1.2) * 0.5 + 0.5) * (h * 0.82 - m * 2);
      } else if (implant) {
        scope.tx = implant.x;
        scope.ty = implant.y;
      }

      /* Critically-damped spring: the optic accelerates toward the mark and
       * settles without snapping, which is what makes the motion read as a
       * held instrument rather than a tween. */
      const stiff = phase === 'acquire' ? 26 : phase === 'focus' ? 40 : 9;
      const damp = 2 * Math.sqrt(stiff) * (phase === 'focus' ? 1.05 : 0.92);
      const sway = Math.sin(scope.breathe * 1.15) * (phase === 'focus' ? 0.5 : 3.2);
      const swayY = Math.cos(scope.breathe * 0.93) * (phase === 'focus' ? 0.4 : 2.4);

      scope.vx += ((scope.tx + sway - scope.x) * stiff - scope.vx * damp) * dt;
      scope.vy += ((scope.ty + swayY - scope.y) * stiff - scope.vy * damp) * dt;
      scope.x += scope.vx * dt;
      scope.y += scope.vy * dt;

      for (const d of dust) {
        d.y -= d.v * dt;
        if (d.y < -6) { d.y = h + 6; d.x = Math.random() * w; }
      }

      if (implant && (phase === 'scan' || phase === 'acquire')) {
        implant.a += Math.sin(time * 1.5 + implant.x * 0.01) * dt * 1.2;
        implant.x += Math.cos(implant.a) * implant.speed * dt;
        implant.y += Math.sin(implant.a) * implant.speed * dt;
        if (implant.x < 60 || implant.x > w - 60) implant.a = Math.PI - implant.a;
        if (implant.y < 60 || implant.y > h * 0.85) implant.a = -implant.a;
        implant.alpha = Math.min(1, implant.alpha + dt * 1.1);
      }

      switch (phase) {
        case 'scan':
          zoomTo(1.6);
          if (!implant && phaseT > 1.3) spawnImplant();
          if (phaseT > 3.2 && implant) setPhase('acquire');
          break;
        case 'acquire': {
          zoomTo(2.3);
          const d = implant ? Math.hypot(implant.x - scope.x, implant.y - scope.y) : 999;
          if (d < 12 || phaseT > 5) setPhase('focus');
          break;
        }
        case 'focus':
          zoomTo(4.2);
          if (implant) {
            implant.x += Math.sin(time * 18) * 7 * dt;
            implant.y += Math.cos(time * 15) * 7 * dt;
          }
          if (phaseT > 1.9) setPhase('capture');
          break;
        case 'capture':
          if (phaseT < 0.02) flash = 1;
          if (phaseT > 0.35) setPhase('evidence');
          break;
        case 'evidence':
          if (phaseT > 1.4) { evidence = null; setPhase('fire'); }
          break;
        case 'fire':
          if (phaseT < 0.02) { shock = 0.001; flash = 0.7; }
          if (shock > 0) shock += dt * 2.2;
          if (implant) implant.eaten = Math.min(1, implant.eaten + dt * 2.2);
          if (phaseT > 0.7) {
            if (implant && flakes.length < 24) {
              for (let i = 0; i < 16; i++) {
                flakes.push({ x: implant.x, y: implant.y, vx: rnd(-70, 70), vy: rnd(-80, 20), life: 1 });
              }
            }
            setPhase('purge');
          }
          break;
        case 'purge':
          purge = Math.min(1, purge + dt * 1.4);
          if (phaseT > 1.2) { implant = null; setPhase('settle'); }
          break;
        case 'settle':
          purge = Math.max(0, purge - dt * 1.4);
          shock = 0;
          zoomTo(1.6);
          if (phaseT > 1.8) setPhase('scan');
          break;
      }

      flakes = flakes.filter((f) => {
        f.x += f.vx * dt;
        f.y += f.vy * dt;
        f.vy += 55 * dt;
        f.life -= dt * 1.1;
        return f.life > 0;
      });

      flash = Math.max(0, flash - dt * 3.2);
    };

    const render = () => {
      ctx.clearRect(0, 0, w, h);

      // byte dust drifting up through the field
      ctx.font = `${GLYPH * 1.6}px ui-monospace, SFMono-Regular, Menlo, monospace`;
      ctx.textAlign = 'left';
      ctx.textBaseline = 'alphabetic';
      for (const d of dust) {
        ctx.fillStyle = `rgba(150, 200, 255, ${d.a})`;
        ctx.fillText(d.g, d.x, d.y);
      }

      if (implant) drawImplant(ctx, implant);

      // quarantine closing over the remains
      if (implant && purge > 0) {
        const R = 46 * purge;
        const g = ctx.createRadialGradient(implant.x, implant.y, 0, implant.x, implant.y, R);
        g.addColorStop(0, 'rgba(2, 2, 6, 0.95)');
        g.addColorStop(0.6, 'rgba(8, 5, 18, 0.6)');
        g.addColorStop(1, 'rgba(8, 5, 18, 0)');
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(implant.x, implant.y, R, 0, Math.PI * 2);
        ctx.fill();
        ctx.strokeStyle = `rgba(150, 90, 230, ${0.4 * (1 - purge)})`;
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        ctx.arc(implant.x, implant.y, R * 0.85, 0, Math.PI * 2);
        ctx.stroke();
      }

      for (const f of flakes) {
        ctx.fillStyle = `rgba(236, 96, 130, ${f.life * 0.6})`;
        ctx.fillRect(f.x, f.y, 1.6, 1.6);
      }

      // shot shockwave
      if (shock > 0 && implant) {
        const r = shock * 90;
        ctx.strokeStyle = `rgba(255, 190, 200, ${Math.max(0, 0.6 - shock * 0.5)})`;
        ctx.lineWidth = 2.5 * Math.max(0.2, 1 - shock * 0.6);
        ctx.beginPath();
        ctx.arc(implant.x, implant.y, r, 0, Math.PI * 2);
        ctx.stroke();
      }

      drawScope(ctx);

      if (implant && (phase === 'focus' || phase === 'capture')) {
        drawReadout(ctx, implant, Math.min(1, phaseT / 1.2));
      }

      if (phase === 'capture' && !evidence && implant) {
        const size = 76;
        const thumb = document.createElement('canvas');
        thumb.width = size;
        thumb.height = size;
        const tc = thumb.getContext('2d');
        if (tc) {
          tc.fillStyle = '#060a12';
          tc.fillRect(0, 0, size, size);
          tc.drawImage(
            canvas,
            Math.max(0, (implant.x - size / 2) * dpr),
            Math.max(0, (implant.y - size / 2) * dpr),
            size * dpr, size * dpr, 0, 0, size, size,
          );
          evidence = { img: thumb, x: implant.x, y: implant.y, t: 0 };
        }
      }

      if (evidence) {
        evidence.t = Math.min(1, evidence.t + 0.022);
        const k = evidence.t;
        const sc = 1 - 0.5 * k;
        const ex = evidence.x + 110 * k;
        const ey = evidence.y - 80 * k;
        const size = 76 * sc;
        ctx.save();
        ctx.globalAlpha = 1 - k * 0.85;
        ctx.drawImage(evidence.img, ex - size / 2, ey - size / 2, size, size);
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.65)';
        ctx.lineWidth = 1.2;
        ctx.strokeRect(ex - size / 2, ey - size / 2, size, size);
        ctx.strokeStyle = 'rgba(255, 110, 145, 0.85)';
        const q = size * 0.2;
        const l = ex - size / 2, tp = ey - size / 2;
        ctx.beginPath();
        ctx.moveTo(l, tp + q); ctx.lineTo(l, tp); ctx.lineTo(l + q, tp);
        ctx.moveTo(l + size - q, tp + size); ctx.lineTo(l + size, tp + size); ctx.lineTo(l + size, tp + size - q);
        ctx.stroke();
        ctx.restore();
      }

      if (flash > 0) {
        ctx.fillStyle = `rgba(215, 235, 255, ${flash * 0.16})`;
        ctx.fillRect(0, 0, w, h);
      }
    };

    const loop = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      time += dt;
      step(dt);
      render();
      raf = requestAnimationFrame(loop);
    };

    resize();
    /* ResizeObserver rather than a window listener: the canvas box can change
     * shape without the window doing so (a transform settling on an ancestor,
     * content reflow), and measuring the buffer against a stale box is what
     * stretches circles into ellipses. */
    const ro = new ResizeObserver(() => resize());
    ro.observe(canvas);
    if (reduced) render();
    else raf = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, []);

  return (
    <div className="fixed inset-0 z-0 pointer-events-none" aria-hidden="true">
      <canvas ref={sceneRef} className="absolute inset-0 w-full h-full" />
    </div>
  );
}
