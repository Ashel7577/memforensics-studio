import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { signInWithGoogle } from "../lib/supabase";

const SITE_KEY = import.meta.env.VITE_TURNSTILE_SITE_KEY as string;

declare global {
  interface Window {
    turnstile?: {
      render: (el: HTMLElement, opts: object) => string;
      reset: (id: string) => void;
    };
  }
}

function GlitchTransition({ onDone }: { onDone: () => void }) {
  const cvRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const cv = cvRef.current!;
    const ctx = cv.getContext("2d")!;
    cv.width = window.innerWidth;
    cv.height = window.innerHeight;
    const W = cv.width, H = cv.height;
    const cx = W / 2, cy = H / 2;

    const RED: [number,number,number] = [248,113,113];
    const rgba = (c: number[], a: number) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;

    let start = 0, raf = 0;
    // phases: 0-800 bug slams in, 800-2200 bug pulses, 2200-3200 glitch dissolve
    const T_SLAM = 800, T_PULSE = 2200, T_DONE = 3200;

    const eOut = (t: number) => 1 - Math.pow(1 - t, 3);
    const eOutBack = (t: number) => { const c = 1.8; return 1 + c * Math.pow(t-1,3) + c * Math.pow(t-1,2); };

    // icon drawn directly as paths

    function drawBug(x: number, y: number, r: number, alpha: number, glow: number) {
      ctx.save(); ctx.globalAlpha = alpha;
      for (let i = 3; i >= 1; i--) {
        ctx.beginPath(); ctx.arc(x, y, r*(1+i*.18), 0, Math.PI*2);
        ctx.strokeStyle=`rgba(180,40,40,${0.06*glow/i})`; ctx.lineWidth=1.5; ctx.stroke();
      }
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI*2);
      ctx.fillStyle="#0d1020"; ctx.fill();
      ctx.strokeStyle="rgba(180,40,40,0.7)"; ctx.lineWidth=2; ctx.stroke();
      ctx.restore();
      // use HTML img overlay
      let el = document.getElementById("mf-glitch-bug") as HTMLElement;
      if (!el) {
        el = document.createElement("img");
        el.id = "mf-glitch-bug";
        (el as HTMLImageElement).src = "/ashel.png";
        el.style.cssText = "position:fixed;pointer-events:none;z-index:10001;border-radius:50%;filter:invert(1) sepia(1) saturate(2) hue-rotate(320deg) brightness(0.55) contrast(1.2);";
        document.body.appendChild(el);
      }
      el.style.display = "block";
      el.style.opacity = String(alpha);
      const sz = r * 1.8;
      el.style.left = `${x - sz/2}px`;
      el.style.top = `${y - sz/2}px`;
      el.style.width = `${sz}px`;
      el.style.height = `${sz}px`;
    }

    function frame(ts: number) {
      if (!start) start = ts;
      const el = ts - start;
      ctx.clearRect(0, 0, W, H);

      // dark bg
      ctx.fillStyle = "#0a0e1a";
      ctx.fillRect(0, 0, W, H);

      // hex grid
      ctx.save(); ctx.strokeStyle = "rgba(167,139,250,0.04)"; ctx.lineWidth = 0.5;
      for (let gx = 0; gx < W; gx += 34) { ctx.beginPath(); ctx.moveTo(gx,0); ctx.lineTo(gx,H); ctx.stroke(); }
      for (let gy = 0; gy < H; gy += 29) { ctx.beginPath(); ctx.moveTo(0,gy); ctx.lineTo(W,gy); ctx.stroke(); }
      ctx.restore();

      if (el < T_SLAM) {
        // slam in with overshoot
        const p = eOutBack(Math.min(1, el / T_SLAM));
        const r = 120 * p;
        const alpha = eOut(Math.min(1, el / 400));
        drawBug(cx, cy, r, alpha, 1);
        // impact rings on slam
        if (el > 600) {
          const rp = (el - 600) / 200;
          ctx.beginPath(); ctx.arc(cx, cy, 120 + rp * 80, 0, Math.PI*2);
          ctx.strokeStyle = `rgba(248,113,113,${(1-rp)*0.5})`; ctx.lineWidth = 2; ctx.stroke();
        }
      } else if (el < T_PULSE) {
        // steady pulse
        const pulse = Math.sin((el - T_SLAM) * 0.004) * 0.5 + 0.5;
        drawBug(cx, cy, 120, 1, pulse);
        // warning text
        ctx.save();
        ctx.font = "700 11px 'Share Tech Mono',monospace";
        ctx.textAlign = "center"; ctx.fillStyle = `rgba(248,113,113,${0.4 + pulse * 0.4})`;
        ctx.letterSpacing = "0.2em";
        ctx.fillText("MALWARE DETECTED", cx, cy + 155);
        ctx.fillStyle = `rgba(148,163,184,${0.3 + pulse * 0.2})`;
        ctx.font = "9px 'Share Tech Mono',monospace";
        ctx.fillText("ISOLATING THREAT VECTOR...", cx, cy + 172);
        ctx.restore();
      } else {
        // glitch dissolve — dashboard bleeds through
        const gp = (el - T_PULSE) / (T_DONE - T_PULSE);
        drawBug(cx, cy, 120, 1 - gp, 1);
        // glitch slices — soft, not sharp
        const slices = Math.floor(4 + gp * 12);
        for (let i = 0; i < slices; i++) {
          const gy2 = Math.random() * H;
          const gh = Math.random() * (2 + gp * 6);
          const shift = (Math.random() - 0.5) * gp * 40;
          ctx.save();
          ctx.globalAlpha = Math.random() * gp * 0.35;
          ctx.fillStyle = Math.random() < 0.5 ? "rgba(167,139,250,0.8)" : "rgba(96,165,250,0.8)";
          ctx.fillRect(shift, gy2, W, gh);
          ctx.restore();
        }
        // white flash at end
        if (gp > 0.85) {
          ctx.save();
          ctx.globalAlpha = (gp - 0.85) / 0.15;
          ctx.fillStyle = "#0a0e1a";
          ctx.fillRect(0, 0, W, H);
          ctx.restore();
        }
        if (gp >= 1) { cancelAnimationFrame(raf); onDone(); return; }
      }

      raf = requestAnimationFrame(frame);
    }

    raf = requestAnimationFrame(frame);
    return () => {
      cancelAnimationFrame(raf);
      const el = document.getElementById("mf-glitch-bug");
      if (el) el.remove();
    };
  }, [onDone]);

  return (
    <canvas ref={cvRef} style={{ position: "fixed", inset: 0, zIndex: 10000, width: "100%", height: "100%" }} />
  );
}

export default function AuthScreen({ onContinue }: { onContinue: () => void }) {
  const widgetRef  = useRef<HTMLDivElement>(null);
  const widgetId   = useRef<string>("");
  const isTauri = !!(window as any).__TAURI_INTERNALS__ || !!(window as any).__TAURI__;
  const [verified,  setVerified]  = useState(false);
  const [signingIn, setSigningIn] = useState(false);
  const [error,     setError]     = useState("");
  const [showGlitch, setShowGlitch] = useState(false);

  useEffect(() => {
    // In Tauri desktop app, skip Turnstile (unsupported origin) — auto-verify
    const isTauri = !!(window as any).__TAURI_INTERNALS__ || !!(window as any).__TAURI__;
    if (isTauri) { setVerified(true); return; }
    const load = () => {
      if (!window.turnstile || !widgetRef.current) return;
      widgetId.current = window.turnstile.render(widgetRef.current, {
        sitekey: SITE_KEY,
        theme: "dark",
        callback:           () => setVerified(true),
        "error-callback":   () => setVerified(false),
        "expired-callback": () => setVerified(false),
      });
    };
    if (window.turnstile) { load(); return; }
    const sc = document.createElement("script");
    sc.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
    sc.async = true; sc.onload = load;
    document.head.appendChild(sc);
  }, []);

  async function handleGoogle() {
    setError(""); setSigningIn(true);
    try { await signInWithGoogle(); }
    catch (e: any) { setError(e?.message ?? "Sign-in failed. Check Google is enabled in Supabase."); setSigningIn(false); }
  }

  return (
    <>
      {showGlitch && <GlitchTransition onDone={onContinue} />}

      <AnimatePresence>
        {!showGlitch && (
          <motion.div
            key="auth"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0, scale: 0.95, filter: "blur(10px)" }}
            transition={{ duration: 0.5 }}
            style={{
              position: "fixed", inset: 0, zIndex: 9999,
              background: "#0a0e1a",
              display: "flex", alignItems: "center", justifyContent: "center",
            }}
          >
            {/* hex grid */}
            <div style={{
              position: "absolute", inset: 0, pointerEvents: "none",
              backgroundImage: "linear-gradient(rgba(167,139,250,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(167,139,250,0.04) 1px,transparent 1px)",
              backgroundSize: "34px 29px",
            }} />

            {/* corner brackets */}
            {([
              {top:16,left:16,borderWidth:"1px 0 0 1px"},
              {top:16,right:16,borderWidth:"1px 1px 0 0"},
              {bottom:16,left:16,borderWidth:"0 0 1px 1px"},
              {bottom:16,right:16,borderWidth:"0 1px 1px 0"},
            ] as React.CSSProperties[]).map((s,i)=>(
              <div key={i} style={{position:"absolute",width:18,height:18,borderStyle:"solid",borderColor:"rgba(167,139,250,0.15)",...s}}/>
            ))}

            {/* card */}
            <motion.div
              initial={{ opacity:0, y:28, scale:0.94 }}
              animate={{ opacity:1, y:0,  scale:1    }}
              transition={{ delay:0.1, duration:0.55, ease:[0.22,1,0.36,1] }}
              style={{
                position:"relative", width:390, maxWidth:"90vw",
                background:"rgba(11,14,26,0.97)",
                border:"0.5px solid rgba(167,139,250,0.2)",
                borderRadius:18, padding:"2.4rem 2rem",
                textAlign:"center",
                boxShadow:"0 0 80px rgba(167,139,250,0.07),0 30px 60px rgba(0,0,0,0.6)",
              }}
            >
              {/* top glow */}
              <div style={{position:"absolute",top:0,left:"20%",right:"20%",height:1,background:"linear-gradient(90deg,transparent,rgba(167,139,250,0.55),transparent)",borderRadius:1}}/>

              {/* logo */}
              <motion.div initial={{opacity:0,y:-8}} animate={{opacity:1,y:0}} transition={{delay:0.25,duration:0.5}}>
                <h1 style={{
                  fontFamily:"'Rajdhani',sans-serif",fontWeight:700,fontSize:"1.9rem",margin:"0 0 5px",
                  backgroundImage:"linear-gradient(90deg,#a78bfa,#7aa8fb,#60a5fa)",
                  WebkitBackgroundClip:"text",backgroundClip:"text",color:"transparent",
                }}>MemForensics</h1>
                <p style={{fontSize:12.5,color:"rgba(148,163,184,0.6)",margin:"0 0 28px",letterSpacing:".05em"}}>
                  Sign in to access your workspace
                </p>
              </motion.div>

              {/* cloudflare section */}
              <motion.div initial={{opacity:0}} animate={{opacity:1}} transition={{delay:0.4}}>
                <div style={{
                  border:"0.5px solid rgba(167,139,250,0.12)",
                  borderRadius:12, padding:"16px 16px 12px",
                  background:"rgba(167,139,250,0.03)",
                  marginBottom:20,
                }}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:12}}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="rgba(167,139,250,0.6)" strokeWidth="2" strokeLinecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    <span style={{fontSize:10.5,color:"rgba(148,163,184,0.5)",letterSpacing:".12em",textTransform:"uppercase"}}>Security Verification</span>
                  </div>
                  <div style={{display:"flex",justifyContent:"center",minHeight:68}}>
                     {!!(window as any).__TAURI_INTERNALS__ || !!(window as any).__TAURI__
                       ? <div style={{display:"flex",alignItems:"center",gap:8,color:"rgba(100,220,120,0.85)",fontSize:12,marginTop:22}}>
                           <span>✓</span><span style={{letterSpacing:'.1em',fontFamily:"'Share Tech Mono',monospace"}}>DEVICE VERIFIED</span>
                         </div>
                       : !SITE_KEY
                         ? <p style={{fontSize:11,color:"rgba(248,113,113,0.8)",marginTop:22}}>VITE_TURNSTILE_SITE_KEY missing</p>
                         : <>
                             <style>{`
                               .cf-turnstile iframe { border-radius: 8px !important; }
                               .cf-turnstile { background: transparent !important; }
                             `}</style>
                             <div ref={widgetRef} className="cf-turnstile" style={{
                               background:"transparent",
                               borderRadius:8,
                               overflow:"hidden",
                               filter:"hue-rotate(230deg) saturate(0.6) brightness(0.85)",
                             }}/>
                           </>
                     }
                  </div>
                </div>
              </motion.div>

              {/* divider */}
              <div style={{display:"flex",alignItems:"center",gap:10,margin:"0 0 18px"}}>
                <div style={{flex:1,height:"0.5px",background:"rgba(167,139,250,0.1)"}}/>
                <span style={{fontSize:10,color:"rgba(148,163,184,0.3)",letterSpacing:".12em"}}>THEN SIGN IN</span>
                <div style={{flex:1,height:"0.5px",background:"rgba(167,139,250,0.1)"}}/>
              </div>

              {/* google button */}
              <motion.button
                onClick={handleGoogle}
                disabled={!verified||signingIn}
                whileHover={verified&&!signingIn?{scale:1.02,boxShadow:"0 0 28px rgba(167,139,250,0.18)"}:{}}
                whileTap={verified&&!signingIn?{scale:0.97}:{}}
                style={{
                  width:"100%",height:48,
                  display:"flex",alignItems:"center",justifyContent:"center",gap:10,
                  borderRadius:11,
                  border:`0.5px solid ${verified?"rgba(167,139,250,0.4)":"rgba(148,163,184,0.1)"}`,
                  background:verified?"rgba(255,255,255,0.05)":"rgba(255,255,255,0.02)",
                  color:verified?"#e6e9f5":"rgba(148,163,184,0.28)",
                  fontSize:14,fontWeight:500,
                  cursor:verified&&!signingIn?"pointer":"not-allowed",
                  transition:"all 0.3s",
                }}
              >
                {signingIn
                  ? <motion.div animate={{rotate:360}} transition={{duration:1,repeat:Infinity,ease:"linear"}}
                      style={{width:18,height:18,border:"2px solid rgba(167,139,250,0.25)",borderTopColor:"#a78bfa",borderRadius:"50%"}}/>
                  : <svg width="18" height="18" viewBox="0 0 18 18">
                      <path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.92c1.7-1.57 2.68-3.88 2.68-6.62z"/>
                      <path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.81.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.7H.96v2.33A9 9 0 0 0 9 18z"/>
                      <path fill="#FBBC05" d="M3.97 10.72A5.4 5.4 0 0 1 3.69 9c0-.6.1-1.18.28-1.72V4.95H.96A9 9 0 0 0 0 9c0 1.45.35 2.83.96 4.05l3.01-2.33z"/>
                      <path fill="#EA4335" d="M9 3.58c1.32 0 2.51.45 3.44 1.35l2.59-2.59C13.46.89 11.43 0 9 0A9 9 0 0 0 .96 4.95l3.01 2.33C4.68 5.16 6.66 3.58 9 3.58z"/>
                    </svg>
                }
                {signingIn?"Connecting to Google...":"Continue with Google"}
              </motion.button>

              {error&&(
                <motion.p initial={{opacity:0,y:4}} animate={{opacity:1,y:0}}
                  style={{fontSize:11.5,color:"rgba(248,113,113,0.85)",marginTop:10,lineHeight:1.5}}>
                  {error}
                </motion.p>
              )}

              {/* skip */}
              <motion.button
                onClick={()=>setShowGlitch(true)}
                whileHover={{color:"rgba(167,139,250,0.75)"}}
                whileTap={{scale:0.95}}
                initial={{opacity:0}} animate={{opacity:1}} transition={{delay:0.8}}
                style={{
                  width:"100%",marginTop:18,
                  background:"transparent",border:"none",
                  color:"rgba(148,163,184,0.35)",
                  fontSize:12.5,cursor:"pointer",padding:"8px 0",
                  transition:"color 0.25s",
                }}
              >
                Sign in later →
              </motion.button>

              {/* bottom glow */}
              <div style={{position:"absolute",bottom:0,left:"25%",right:"25%",height:"0.5px",background:"linear-gradient(90deg,transparent,rgba(96,165,250,0.35),transparent)"}}/>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
