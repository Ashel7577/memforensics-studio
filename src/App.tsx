import { useState, useEffect, useRef } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Pipeline from "./pages/Pipeline";
import History from "./pages/History";
import Report from "./pages/Report";

function injectFont() {
  if (document.getElementById("mf-font")) return;
  const l = document.createElement("link");
  l.id = "mf-font"; l.rel = "stylesheet";
  l.href = "https://fonts.googleapis.com/css2?family=Rajdhani:wght@300;500;700&family=Share+Tech+Mono&display=swap";
  document.head.appendChild(l);
}

const eOut = (t: number) => 1 - Math.pow(1 - t, 3);
const eIn  = (t: number) => t * t * t;
const eOutBack = (t: number) => { const c = 1.6; return 1 + c * Math.pow(t - 1, 3) + c * Math.pow(t - 1, 2); };

const PURPLE: [number, number, number] = [167, 139, 250];
const BLUE: [number, number, number] = [96, 165, 250];
const RED: [number, number, number] = [248, 113, 113];
const RED_LIGHT: [number, number, number] = [252, 165, 165];

function rgba(c: number[], a: number) { return `rgba(${c[0]},${c[1]},${c[2]},${a})`; }

type Ring = { x: number; y: number; r: number; born: number; maxR: number; spd: number };
type Spark = { x: number; y: number; vx: number; vy: number; life: number; r: number };
type Hex = { x: number; y: number; lit: number; baseAlpha: number; malware?: boolean };
type Particle = { sx: number; sy: number; tx: number; ty: number; delay: number; size: number; isBlue: boolean };

function LoadingScreen({ onComplete }: { onComplete: () => void }) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const [bugOverlay, setBugOverlay] = useState<{x:number;y:number;r:number;alpha:number}|null>(null);
  const cvRef   = useRef<HTMLCanvasElement>(null);
  const nmRef   = useRef<HTMLDivElement>(null);
  const h1Ref   = useRef<HTMLHeadingElement>(null);
  const sbRef   = useRef<HTMLParagraphElement>(null);
  const stRef   = useRef<HTMLDivElement>(null);
  const progRef = useRef<HTMLDivElement>(null);
  const progBarRef = useRef<HTMLDivElement>(null);

  const onCompleteRef = useRef(onComplete);
  useEffect(() => { onCompleteRef.current = onComplete; }, [onComplete]);

  useEffect(() => {
    injectFont();
    const wrap = wrapRef.current!;
    const cv = cvRef.current!;
    const nm = nmRef.current!;
    const h1 = h1Ref.current!;
    const sb = sbRef.current!;
    const st = stRef.current!;
    const prog = progRef.current!;
    const progBar = progBarRef.current!;
    const ctx = cv.getContext("2d")!;
    let W = cv.width = wrap.clientWidth;
    let H = cv.height = wrap.clientHeight;
    let cx = W / 2, cy = H / 2;

    const handleResize = () => {
      W = cv.width = wrap.clientWidth;
      H = cv.height = wrap.clientHeight;
      cx = W / 2; cy = H / 2;
    };
    window.addEventListener('resize', handleResize);

    const T_FORM = 1900, T_SCAN = 4000, T_LOCK = 4900, T_FADE = 5700, T_NAME = 7600, T_DASH = 9600;

    const COLS = 18, ROWS = 11, HW = 34, HH = 29;
    const hexes: Hex[] = [];
    for (let r = 0; r < ROWS; r++)
      for (let c = 0; c < COLS; c++)
        hexes.push({
          x: (c - COLS / 2 + .5) * HW + cx,
          y: (r - ROWS / 2 + .5) * HH + (c % 2 ? .5 : 0) * HH + cy,
          lit: 0, baseAlpha: 0.025 + Math.random() * 0.02
        });
    const TARGET = hexes[Math.floor(ROWS / 2) * COLS + Math.floor(COLS / 2) + 4];
    TARGET.malware = true;

    const LENS_R = 50;
    const PARTICLES: Particle[] = [];
    for (let i = 0; i < 140; i++) {
      const a = Math.random() * Math.PI * 2;
      const targetR = LENS_R * (0.85 + Math.random() * 0.3);
      PARTICLES.push({
        sx: cx + (Math.random() - .5) * W * 1.1,
        sy: cy + (Math.random() - .5) * H * 1.1,
        tx: cx + Math.cos(a) * targetR,
        ty: cy + Math.sin(a) * targetR,
        delay: Math.random() * 600,
        size: Math.random() * 1.8 + .6,
        isBlue: Math.random() < .5
      });
    }

    const rings: Ring[] = [];
    const sparks: Spark[] = [];
    function fireRings(x: number, y: number) {
      for (let i = 0; i < 6; i++)
        setTimeout(() => rings.push({ x, y, r: 0, born: elapsed, maxR: 70 + i * 48, spd: .85 + i * .1 }), i * 140);
    }
    function fireSparks(x: number, y: number) {
      for (let i = 0; i < 24; i++) {
        const a = Math.random() * Math.PI * 2, spd = 1.2 + Math.random() * 2.6;
        sparks.push({ x, y, vx: Math.cos(a) * spd, vy: Math.sin(a) * spd, life: 1, r: Math.random() * 2 + .5 });
      }
    }
    function setStatus(txt: string, color = "rgba(167,139,250,.4)") {
      st.textContent = txt; st.style.opacity = "1"; st.style.color = color;
    }
    function hexPath(x: number, y: number, r: number) {
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const a = Math.PI / 180 * (60 * i - 30);
        i === 0 ? ctx.moveTo(x + r * Math.cos(a), y + r * Math.sin(a)) : ctx.lineTo(x + r * Math.cos(a), y + r * Math.sin(a));
      }
      ctx.closePath();
    }

    function drawMagnifier(x: number, y: number, r: number, alpha: number, red: boolean) {
      if (alpha <= 0) return;
      ctx.save(); ctx.globalAlpha = alpha;
      const ac = red ? RED : PURPLE;
      const ac2 = red ? RED_LIGHT : BLUE;
      const halo = ctx.createRadialGradient(x, y, r * .9, x, y, r * 1.7);
      halo.addColorStop(0, rgba(ac, .08)); halo.addColorStop(1, rgba(ac, 0));
      ctx.beginPath(); ctx.arc(x, y, r * 1.7, 0, Math.PI * 2); ctx.fillStyle = halo; ctx.fill();

      const lg = ctx.createRadialGradient(x - r * .25, y - r * .25, r * .04, x, y, r);
      lg.addColorStop(0, red ? "#1f0d0d" : "#13152a");
      lg.addColorStop(.6, red ? "#150707" : "#0c0e1e");
      lg.addColorStop(1, red ? "#0a0303" : "#070815");
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fillStyle = lg; ctx.fill();

      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.strokeStyle = rgba(ac, .88); ctx.lineWidth = 1.8; ctx.stroke();
      ctx.beginPath(); ctx.arc(x, y, r - 1.4, 0, Math.PI * 2);
      ctx.strokeStyle = rgba(ac2, .25); ctx.lineWidth = .6; ctx.stroke();

      for (let i = 0; i < 48; i++) {
        const a = (i / 48) * Math.PI * 2;
        const major = i % 6 === 0, mid = i % 3 === 0;
        const len = major ? r * .17 : mid ? r * .095 : r * .05;
        const useC = i % 2 === 0 ? ac : ac2;
        ctx.beginPath();
        ctx.moveTo(x + Math.cos(a) * (r - len), y + Math.sin(a) * (r - len));
        ctx.lineTo(x + Math.cos(a) * r, y + Math.sin(a) * r);
        ctx.strokeStyle = rgba(useC, major ? .7 : mid ? .32 : .15);
        ctx.lineWidth = major ? 1.2 : mid ? .6 : .35; ctx.stroke();
      }

      ctx.setLineDash([2.5, 3.5]);
      ctx.beginPath(); ctx.arc(x, y, r * .6, 0, Math.PI * 2);
      ctx.strokeStyle = rgba(ac2, .18); ctx.lineWidth = .6; ctx.stroke();
      ctx.beginPath(); ctx.arc(x, y, r * .32, 0, Math.PI * 2);
      ctx.strokeStyle = rgba(ac, .1); ctx.lineWidth = .5; ctx.stroke();
      ctx.setLineDash([]);

      const gap = r * .16;
      [[1, 0], [-1, 0], [0, 1], [0, -1]].forEach(([dx, dy], i) => {
        ctx.beginPath();
        ctx.moveTo(x + dx * gap, y + dy * gap);
        ctx.lineTo(x + dx * r * .88, y + dy * r * .88);
        ctx.strokeStyle = rgba(i % 2 === 0 ? ac : ac2, .38); ctx.lineWidth = .7; ctx.stroke();
      });

      ctx.lineCap = "round";
      const h1x = x + r * .7, h1y = y + r * .7, h2x = x + r * 1.7, h2y = y + r * 1.7;
      ctx.beginPath(); ctx.moveTo(h1x, h1y); ctx.lineTo(h2x, h2y);
      ctx.strokeStyle = rgba(ac, .85); ctx.lineWidth = r * .26; ctx.stroke();
      ctx.beginPath(); ctx.moveTo(h1x, h1y); ctx.lineTo(h2x, h2y);
      ctx.strokeStyle = "#05060d"; ctx.lineWidth = r * .12; ctx.stroke();
      ctx.lineCap = "butt";

      const sh = ctx.createRadialGradient(x - r * .28, y - r * .3, 0, x - r * .06, y - r * .08, r * .55);
      sh.addColorStop(0, "rgba(255,255,255,.08)"); sh.addColorStop(1, "rgba(255,255,255,0)");
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fillStyle = sh; ctx.fill();
      ctx.restore();
    }

    function drawScanBeam(x: number, y: number, angle: number, alpha: number) {
      if (alpha <= 0) return;
      const nb = ((angle % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2);
      ctx.save(); ctx.globalCompositeOperation = "screen"; ctx.globalAlpha = alpha * .11;
      ctx.beginPath(); ctx.moveTo(x, y); ctx.arc(x, y, 280, nb - .13, nb + .13); ctx.closePath();
      const bg = ctx.createRadialGradient(x, y, 0, x, y, 280);
      bg.addColorStop(0, rgba(PURPLE, .8)); bg.addColorStop(.5, rgba(BLUE, .12)); bg.addColorStop(1, rgba(BLUE, 0));
      ctx.fillStyle = bg; ctx.fill(); ctx.restore();
      ctx.save(); ctx.globalAlpha = alpha * .36;
      ctx.beginPath(); ctx.moveTo(x, y); ctx.lineTo(x + Math.cos(nb) * 280, y + Math.sin(nb) * 280);
      ctx.strokeStyle = rgba(BLUE, .45); ctx.lineWidth = .7; ctx.stroke(); ctx.restore();
    }

    // no image preload needed — icon drawn directly

    function drawBugGlyph(x: number, y: number, r: number, alpha: number, pulse: number) {
      if (alpha <= 0) { setBugOverlay(null); return; }
      const p = .5 + .5 * Math.sin(pulse * 4);
      ctx.save(); ctx.globalAlpha = alpha;
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = "#0d1020"; ctx.fill();
      ctx.strokeStyle = rgba(RED, .7); ctx.lineWidth = 1.5; ctx.stroke();
      ctx.beginPath(); ctx.arc(x, y, r*(1.08+p*.06), 0, Math.PI*2);
      ctx.strokeStyle = rgba(RED, p*.3); ctx.lineWidth=1; ctx.stroke();
      ctx.beginPath(); ctx.arc(x+r*.65,y-r*.6,r*.09,0,Math.PI*2);
      ctx.fillStyle=rgba(RED,p); ctx.fill();
      ctx.restore();
      setBugOverlay({x, y, r, alpha});
    }

    let mAlpha = 0, mRed = false, mr = LENS_R, mx = cx, my = cy;
    let beamAngle = 0, found = false, foundT = 0;
    let flashAlpha = 0, flashR = 0;
    let elapsed = 0, startT = 0;
    let raf: number;

    function frame(ts: number) {
      if (!startT) startT = ts;
      elapsed = ts - startT;
      const t = elapsed * .001;
      ctx.clearRect(0, 0, W, H);

      hexes.forEach(h => {
        hexPath(h.x, h.y, 15);
        ctx.strokeStyle = rgba(PURPLE, h.baseAlpha);
        ctx.lineWidth = .5; ctx.stroke();
      });

      if (elapsed < T_FORM) {
        mAlpha = 0;
        PARTICLES.forEach(pt => {
          const localT = Math.max(0, Math.min(1, (elapsed - pt.delay) / (T_FORM - pt.delay)));
          const pe = eOut(localT);
          const px = pt.sx + (pt.tx - pt.sx) * pe;
          const py = pt.sy + (pt.ty - pt.sy) * pe;
          const al = localT;
          const c = pt.isBlue ? BLUE : PURPLE;
          ctx.beginPath(); ctx.arc(px, py, pt.size, 0, Math.PI * 2);
          ctx.fillStyle = rgba(c, .5 * al); ctx.fill();
          if (localT < 1 && localT > .05) {
            ctx.beginPath(); ctx.moveTo(px, py);
            ctx.lineTo(pt.sx + (pt.tx - pt.sx) * Math.max(0, pe - .08), pt.sy + (pt.ty - pt.sy) * Math.max(0, pe - .08));
            ctx.strokeStyle = rgba(c, .15 * al); ctx.lineWidth = .5; ctx.stroke();
          }
        });
        if (elapsed > T_FORM * .7) {
          const fp = (elapsed - T_FORM * .7) / (T_FORM * .3);
          mAlpha = fp; mr = LENS_R * (.7 + .3 * fp); mx = cx; my = cy; mRed = false;
          drawMagnifier(mx, my, mr, mAlpha, false);
        }
        if (elapsed < 80) setStatus("CALIBRATING SENSOR ARRAY...");
      }

      if (elapsed >= T_FORM && elapsed < T_SCAN) {
        mx = cx; my = cy; mr = LENS_R; mAlpha = 1; mRed = found;
        const sp = (elapsed - T_FORM) / (T_SCAN - T_FORM);
        beamAngle = sp * Math.PI * 7;
        const nb = ((beamAngle % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2);
        if (!found && elapsed > T_FORM + 100) setStatus("SCANNING MEMORY SECTORS...");
        hexes.forEach(h => {
          const dx = h.x - mx, dy = h.y - my, dist = Math.sqrt(dx * dx + dy * dy);
          const ang = (Math.atan2(dy, dx) + Math.PI * 2) % (Math.PI * 2);
          const diff = Math.min(Math.abs(ang - nb), Math.PI * 2 - Math.abs(ang - nb));
          if (dist < mr * 3 && diff < .27) h.lit = Math.min(1, h.lit + .1);
          else h.lit = Math.max(0, h.lit - .012);
        });
        drawScanBeam(mx, my, beamAngle, 1);
        if (!found && sp > .3) {
          const tdx = TARGET.x - mx, tdy = TARGET.y - my;
          const tang = (Math.atan2(tdy, tdx) + Math.PI * 2) % (Math.PI * 2);
          const tdiff = Math.min(Math.abs(tang - nb), Math.PI * 2 - Math.abs(tang - nb));
          if (tdiff < .2) {
            found = true; foundT = elapsed; mRed = true; flashAlpha = 1; flashR = 0;
            fireRings(TARGET.x, TARGET.y); fireSparks(TARGET.x, TARGET.y);
            setStatus("MALWARE SIGNATURE CONFIRMED", "rgba(248,113,113,.75)");
          }
        }
      }

      if (elapsed >= T_SCAN && elapsed < T_LOCK) {
        const p = eOut((elapsed - T_SCAN) / (T_LOCK - T_SCAN));
        mx = cx + (TARGET.x - cx) * p; my = cy + (TARGET.y - cy) * p;
        mr = LENS_R + (20 - LENS_R) * p; mAlpha = 1; mRed = true;
        if (elapsed < T_SCAN + 60) setStatus("ISOLATING THREAT VECTOR...", "rgba(248,113,113,.65)");
      }

      if (elapsed >= T_LOCK && elapsed < T_FADE) {
        const p = eIn((elapsed - T_LOCK) / (T_FADE - T_LOCK));
        mAlpha = 1 - p; mx = TARGET.x; my = TARGET.y; mr = 20; mRed = true;
      }
      if (elapsed >= T_FADE) { mAlpha = 0; const el=document.getElementById('mf-bug-overlay'); if(el)(el as HTMLElement).style.display='none'; }

      hexes.forEach(h => {
        if (h.lit < .01 && !h.malware) return;
        if (!h.malware) {
          hexPath(h.x, h.y, 14);
          ctx.fillStyle = rgba(BLUE, .12 * h.lit); ctx.fill();
          ctx.strokeStyle = rgba(BLUE, .22 * h.lit); ctx.lineWidth = .6; ctx.stroke();
        }
      });

      if (found) {
        const fa = Math.min(1, (elapsed - foundT) / 350);
        drawBugGlyph(TARGET.x, TARGET.y, 30, fa, t);
      }

      if (flashAlpha > 0) {
        ctx.beginPath(); ctx.arc(TARGET.x, TARGET.y, flashR, 0, Math.PI * 2);
        ctx.strokeStyle = rgba(RED_LIGHT, flashAlpha); ctx.lineWidth = 2; ctx.stroke();
        flashR += 6; flashAlpha = Math.max(0, flashAlpha - .04);
      }

      for (let i = rings.length - 1; i >= 0; i--) {
        const rng = rings[i], age = (elapsed - rng.born) / (1050 / rng.spd);
        if (age >= 1) { rings.splice(i, 1); continue; }
        const pr = rng.maxR * eOut(age), pa = (1 - age) * .85;
        ctx.beginPath(); ctx.arc(rng.x, rng.y, pr, 0, Math.PI * 2);
        ctx.strokeStyle = rgba(RED, pa); ctx.lineWidth = 1.3; ctx.stroke();
        if (pr > 20) {
          ctx.beginPath(); ctx.arc(rng.x, rng.y, pr * .5, 0, Math.PI * 2);
          ctx.strokeStyle = rgba(RED_LIGHT, pa * .3); ctx.lineWidth = .5; ctx.stroke();
        }
      }

      for (let i = sparks.length - 1; i >= 0; i--) {
        const sk = sparks[i];
        sk.x += sk.vx; sk.y += sk.vy; sk.vx *= .93; sk.vy *= .93; sk.life -= .027;
        if (sk.life <= 0) { sparks.splice(i, 1); continue; }
        ctx.beginPath(); ctx.arc(sk.x, sk.y, sk.r * sk.life, 0, Math.PI * 2);
        ctx.fillStyle = rgba(sk.life > .5 ? RED : RED_LIGHT, sk.life * .85); ctx.fill();
      }

      if (elapsed < T_FORM * .7 || elapsed >= T_FORM) drawMagnifier(mx, my, mr, mAlpha, mRed);

      if (elapsed >= T_LOCK) { setBugOverlay(null); }

      if (elapsed >= T_FADE && elapsed < T_NAME) {
        const p = eOut(Math.min(1, (elapsed - T_FADE) / (T_NAME - T_FADE)));
        nm.style.opacity = "1";
        nm.style.transform = `translate(-50%,-50%) scale(${.9 + .1 * p})`;
        h1.style.filter = `blur(${(1 - p) * 6}px)`;
        h1.style.opacity = String(p);
        sb.style.opacity = p > .55 ? String((p - .55) / .45) : "0";
        if (elapsed < T_FADE + 60) setStatus("SYNCHRONIZING INTERFACE...");
        prog.style.opacity = String(p);
        progBar.style.width = `${p * 100}%`;
      }
      if (elapsed >= T_NAME) {
        nm.style.opacity = "1"; nm.style.transform = "translate(-50%,-50%) scale(1)";
        h1.style.filter = "blur(0)"; h1.style.opacity = "1"; sb.style.opacity = "1";
        progBar.style.width = "100%"; st.style.opacity = "0";
      }
      if (elapsed >= T_NAME + 800) {
        prog.style.opacity = String(Math.max(0, 1 - (elapsed - T_NAME - 800) / 400));
      }

      if (elapsed < T_DASH) { raf = requestAnimationFrame(frame); }
      else { onCompleteRef.current(); }
    }

    raf = requestAnimationFrame(frame);
    const safety = setTimeout(() => onCompleteRef.current(), T_DASH + 1500);
    return () => { cancelAnimationFrame(raf); clearTimeout(safety); window.removeEventListener('resize', handleResize); };
  }, []);

  return (
    <div ref={wrapRef} style={{ minHeight: "100vh", background: "#0a0e1a", position: "relative", overflow: "hidden" }}>
      <canvas ref={cvRef} style={{ position: "absolute", inset: 0, width: "100%", height: "100%" }} />
      {([
        { top: 13, left: 13, borderWidth: "1px 0 0 1px" },
        { top: 13, right: 13, borderWidth: "1px 1px 0 0" },
        { bottom: 13, left: 13, borderWidth: "0 0 1px 1px" },
        { bottom: 13, right: 13, borderWidth: "0 1px 1px 0" },
      ] as React.CSSProperties[]).map((s, i) => (
        <div key={i} style={{ position: "absolute", width: 16, height: 16, borderStyle: "solid", borderColor: "rgba(167,139,250,0.12)", ...s }} />
      ))}
      <div ref={nmRef} style={{ position: "absolute", left: "50%", top: "50%", transform: "translate(-50%,-50%)", textAlign: "center", opacity: 0, pointerEvents: "none", whiteSpace: "nowrap" }}>
        <h1 ref={h1Ref} style={{
          fontFamily: "'Rajdhani','Share Tech Mono',sans-serif", fontWeight: 700, fontSize: "3.1rem",
          letterSpacing: ".02em", lineHeight: 1, margin: 0, opacity: 0,
          backgroundImage: "linear-gradient(90deg,#a78bfa,#7aa8fb,#60a5fa)",
          WebkitBackgroundClip: "text", backgroundClip: "text", color: "transparent",
        }}>
          MemForensics
        </h1>
        <p ref={sbRef} style={{
          fontFamily: "'Share Tech Mono',monospace", fontSize: ".6rem", letterSpacing: ".32em",
          color: "rgba(148,163,184,.7)", margin: "11px 0 0", textTransform: "uppercase", opacity: 0,
        }}>
          Memory-Only Malware Detection
        </p>
      </div>
      <div ref={progRef} style={{ position: "absolute", bottom: 48, left: "50%", transform: "translateX(-50%)", width: 180, height: 1, background: "rgba(167,139,250,0.12)", opacity: 0 }}>
        <div ref={progBarRef} style={{ height: "100%", width: "0%", background: "linear-gradient(90deg,#a78bfa,#60a5fa)" }} />
      </div>

      {bugOverlay && (
        <img
          src="/ashel.png"
          style={{
            position: "absolute",
            left: bugOverlay.x - bugOverlay.r * 0.9,
            top: bugOverlay.y - bugOverlay.r * 0.9,
            width: bugOverlay.r * 1.8,
            height: bugOverlay.r * 1.8,
            opacity: bugOverlay.alpha,
            borderRadius: "50%",
            pointerEvents: "none",
            zIndex: 10,
            filter: "invert(1) sepia(1) saturate(2) hue-rotate(320deg) brightness(0.55) contrast(1.2)",
          }}
        />
      )}
      <div ref={stRef} style={{ position: "absolute", bottom: 22, left: "50%", transform: "translateX(-50%)", fontFamily: "'Share Tech Mono',monospace", fontSize: ".52rem", letterSpacing: ".2em", color: "rgba(167,139,250,.4)", whiteSpace: "nowrap", opacity: 0 }} />
    </div>
  );
}

import AuthScreen from "./components/AuthScreen";

type Stage = "splash" | "auth" | "app";

export default function App() {
  const [stage, setStage] = useState<Stage>("splash");
  if (stage === "splash") return <LoadingScreen onComplete={() => setStage("auth")} />;
  if (stage === "auth")   return <AuthScreen onContinue={() => setStage("app")} />;
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="pipeline/:id" element={<Pipeline />} />
          <Route path="history" element={<History />} />
          <Route path="report/:id" element={<Report />} />
        </Route>
      </Routes>
    </Router>
  );
}
