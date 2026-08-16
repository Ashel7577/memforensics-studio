import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { signInWithGoogle, completeSignIn } from "../lib/supabase";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const SITE_KEY = import.meta.env.VITE_TURNSTILE_SITE_KEY as string;

export default function AuthScreen({ onContinue }: { onContinue: () => void }) {
  const widgetRef  = useRef<HTMLDivElement>(null);
  const widgetId   = useRef<string>("");
  const [verified,  setVerified]  = useState(false);
  const [signingIn, setSigningIn] = useState(false);
  const [error,     setError]     = useState("");

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
    setError("");
    setSigningIn(true);
    const isTauri = !!(window as any).__TAURI_INTERNALS__ || !!(window as any).__TAURI__;

    try {
      if (!isTauri) {
        // In a browser the normal redirect flow is fine.
        const url = await signInWithGoogle(window.location.origin);
        window.location.href = url;
        return;
      }

      /* Desktop: sign in through the real browser and catch the callback on a
       * loopback listener, because Google blocks OAuth in embedded webviews. */
      const port = await invoke<number>("start_oauth_listener");
      const unlisten = await listen<{ code?: string; error?: string }>("oauth-callback", async (evt) => {
        unlisten();
        if (evt.payload?.error || !evt.payload?.code) {
          setError(evt.payload?.error ?? "Sign-in was cancelled.");
          setSigningIn(false);
          return;
        }
        try {
          await completeSignIn(evt.payload.code);
          onContinue();
        } catch (e: any) {
          setError(e?.message ?? "Could not complete sign-in.");
          setSigningIn(false);
        }
      });

      const url = await signInWithGoogle(`http://127.0.0.1:${port}`);
      await invoke("open_url", { url });
    } catch (e: any) {
      setError(e?.message ?? "Sign-in failed. Check Google is enabled in Supabase.");
      setSigningIn(false);
    }
  }

  return (
    <>
      <AnimatePresence>
        {true && (
          <motion.div
            key="auth"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5 }}
            style={{
              position: "fixed", inset: 0, zIndex: 9999,
              background: "transparent",
              display: "flex", alignItems: "center", justifyContent: "center",
              overflow: "hidden",
            }}
          >
            {/* Darkening is pushed to the edges of the frame, never behind the
                card — clear glass needs something lit underneath it. */}
            <div style={{
              position: "absolute", inset: 0, pointerEvents: "none",
              background: "radial-gradient(58% 62% at 50% 50%, transparent 42%, rgba(2,4,10,0.55) 100%)",
            }} />

            {/* corner brackets */}
            {([
              {top:16,left:16,borderWidth:"1px 0 0 1px"},
              {top:16,right:16,borderWidth:"1px 1px 0 0"},
              {bottom:16,left:16,borderWidth:"0 0 1px 1px"},
              {bottom:16,right:16,borderWidth:"0 1px 1px 0"},
            ] as React.CSSProperties[]).map((s,i)=>(
              <div key={i} style={{position:"absolute",width:18,height:18,borderStyle:"solid",borderColor:"rgba(120,180,220,0.16)",...s}}/>
            ))}

            {/* card */}
            <motion.div
              initial={{ opacity:0, y:22, scale:0.96, filter:"blur(6px)" }}
              animate={{ opacity:1, y:0,  scale:1, filter:"blur(0px)" }}
              transition={{ delay:0.12, duration:0.75, ease:[0.16,1,0.3,1] }}
              style={{
                position:"relative", width:390, maxWidth:"90vw",
                background:"linear-gradient(160deg,rgba(170,215,255,0.045) 0%,rgba(90,140,190,0.02) 50%,rgba(10,20,34,0.06) 100%)",
                border:"0.5px solid rgba(200,232,255,0.26)",
                borderRadius:18, padding:"2.4rem 2rem",
                textAlign:"center",
                overflow:"hidden",
                boxShadow:"0 30px 80px rgba(0,0,0,0.42),inset 0 1px 0 rgba(226,245,255,0.26),inset 1px 0 0 rgba(190,225,255,0.10),inset -1px 0 0 rgba(120,180,230,0.06),inset 0 -1px 0 rgba(0,0,0,0.28)",
              }}
            >
              {/* top glow */}
              <motion.div
                animate={{backgroundPosition:["0% 0","200% 0"]}}
                transition={{duration:7,repeat:Infinity,ease:"linear"}}
                style={{
                  position:"absolute",top:0,left:"14%",right:"14%",height:1,borderRadius:1,
                  backgroundImage:"linear-gradient(90deg,transparent,rgba(124,196,232,0.7),rgba(150,140,220,0.45),transparent)",
                  backgroundSize:"200% 100%",
                }}/>

              <div style={{position:"relative", zIndex:1}}>
              <motion.div initial={{opacity:0,y:-8}} animate={{opacity:1,y:0}} transition={{delay:0.25,duration:0.5}}>
                <h1 style={{
                  fontFamily:"'Rajdhani',sans-serif",fontWeight:700,fontSize:"1.9rem",margin:"0 0 5px",
                  backgroundImage:"linear-gradient(96deg,#8ea9f0,#7cc0e8,#63d0d8)",
                  WebkitBackgroundClip:"text",backgroundClip:"text",color:"transparent",
                }}>MemForensics</h1>
                <p style={{fontSize:12.5,color:"rgba(148,163,184,0.6)",margin:"0 0 28px",letterSpacing:".05em"}}>
                  Sign in to access your workspace
                </p>
              </motion.div>

              {/* cloudflare section */}
              <motion.div initial={{opacity:0}} animate={{opacity:1}} transition={{delay:0.4}}>
                <div style={{
                  border:"0.5px solid rgba(150,200,235,0.12)",
                  borderRadius:12, padding:"16px 16px 12px",
                  background:"rgba(150,205,240,0.02)",
                  marginBottom:20,
                }}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:12}}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="rgba(130,195,230,0.6)" strokeWidth="2" strokeLinecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    <span style={{fontSize:10.5,color:"rgba(148,163,184,0.5)",letterSpacing:".12em",textTransform:"uppercase"}}>Security Verification</span>
                  </div>
                  <div style={{display:"flex",justifyContent:"center",minHeight:68}}>
                     {!!(window as any).__TAURI_INTERNALS__ || !!(window as any).__TAURI__
                       ? <motion.div
                           initial={{opacity:0,scale:0.9}} animate={{opacity:1,scale:1}}
                           transition={{delay:0.55,duration:0.5,ease:[0.16,1,0.3,1]}}
                           style={{display:"flex",alignItems:"center",gap:9,color:"rgba(110,225,140,0.9)",fontSize:12,marginTop:22}}>
                           <motion.span
                             animate={{boxShadow:["0 0 0 0 rgba(110,225,140,0.35)","0 0 0 7px rgba(110,225,140,0)"]}}
                             transition={{duration:2,repeat:Infinity,ease:"easeOut"}}
                             style={{
                               width:17,height:17,borderRadius:"50%",
                               border:"1px solid rgba(110,225,140,0.55)",
                               display:"flex",alignItems:"center",justifyContent:"center",
                               fontSize:10,lineHeight:1,
                             }}>✓</motion.span>
                           <span style={{letterSpacing:'.14em',fontFamily:"'Share Tech Mono',monospace"}}>DEVICE VERIFIED</span>
                         </motion.div>
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
                <div style={{flex:1,height:"0.5px",background:"rgba(120,175,215,0.12)"}}/>
                <span style={{fontSize:10,color:"rgba(148,163,184,0.3)",letterSpacing:".12em"}}>THEN SIGN IN</span>
                <div style={{flex:1,height:"0.5px",background:"rgba(120,175,215,0.12)"}}/>
              </div>

              {/* google button */}
              <motion.button
                onClick={handleGoogle}
                disabled={!verified||signingIn}
                whileHover={verified&&!signingIn?{scale:1.02,boxShadow:"0 0 30px rgba(110,180,225,0.20)"}:{}}
                whileTap={verified&&!signingIn?{scale:0.97}:{}}
                style={{
                  width:"100%",height:48,
                  display:"flex",alignItems:"center",justifyContent:"center",gap:10,
                  borderRadius:11,
                  border:`0.5px solid ${verified?"rgba(130,195,230,0.42)":"rgba(148,163,184,0.1)"}`,
                  background:verified?"rgba(200,232,255,0.06)":"rgba(200,232,255,0.02)",
                  color:verified?"#e6e9f5":"rgba(148,163,184,0.28)",
                  fontSize:14,fontWeight:500,
                  cursor:verified&&!signingIn?"pointer":"not-allowed",
                  transition:"all 0.3s",
                }}
              >
                {signingIn
                  ? <motion.div animate={{rotate:360}} transition={{duration:1,repeat:Infinity,ease:"linear"}}
                      style={{width:18,height:18,border:"2px solid rgba(130,195,230,0.25)",borderTopColor:"#7cc4e8",borderRadius:"50%"}}/>
                  : <svg width="18" height="18" viewBox="0 0 18 18">
                      <path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.92c1.7-1.57 2.68-3.88 2.68-6.62z"/>
                      <path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.81.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.7H.96v2.33A9 9 0 0 0 9 18z"/>
                      <path fill="#FBBC05" d="M3.97 10.72A5.4 5.4 0 0 1 3.69 9c0-.6.1-1.18.28-1.72V4.95H.96A9 9 0 0 0 0 9c0 1.45.35 2.83.96 4.05l3.01-2.33z"/>
                      <path fill="#EA4335" d="M9 3.58c1.32 0 2.51.45 3.44 1.35l2.59-2.59C13.46.89 11.43 0 9 0A9 9 0 0 0 .96 4.95l3.01 2.33C4.68 5.16 6.66 3.58 9 3.58z"/>
                    </svg>
                }
                {signingIn?"Waiting for browser sign-in...":"Continue with Google"}
              </motion.button>

              {error&&(
                <motion.p initial={{opacity:0,y:4}} animate={{opacity:1,y:0}}
                  style={{fontSize:11.5,color:"rgba(248,113,113,0.85)",marginTop:10,lineHeight:1.5}}>
                  {error}
                </motion.p>
              )}

              {/* skip */}
              <motion.button
                onClick={onContinue}
                whileHover={{color:"rgba(140,200,235,0.8)"}}
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

              </div>

              {/* bottom glow */}
              <div style={{position:"absolute",bottom:0,left:"25%",right:"25%",height:"0.5px",background:"linear-gradient(90deg,transparent,rgba(110,190,230,0.38),transparent)"}}/>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
