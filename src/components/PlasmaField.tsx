import { useEffect, useRef } from 'react';

/**
 * The shared backdrop for every full-screen surface in the app: splash, auth
 * and dashboard all sit on this, so the product reads as one piece.
 *
 * It is a single fullscreen fragment shader. Domain-warped fBm noise is pulled
 * into horizontal strata so it reads as an address space seen edge-on rather
 * than as clouds — deep, slow, mostly void, with thin filaments of light where
 * regions are dense and rare hot pockets where entropy spikes.
 *
 * One draw call per frame on a single triangle. If WebGL is unavailable it
 * renders nothing and the host keeps its flat background; under reduced-motion
 * it paints one still frame.
 */

const VERT = `
attribute vec2 aPos;
void main() { gl_Position = vec4(aPos, 0.0, 1.0); }
`;

const FRAG = `
precision highp float;
uniform vec2  uRes;
uniform float uTime;
uniform float uIntensity;

vec3 mod289(vec3 x) { return x - floor(x * (1.0 / 289.0)) * 289.0; }
vec2 mod289(vec2 x) { return x - floor(x * (1.0 / 289.0)) * 289.0; }
vec3 permute(vec3 x) { return mod289(((x * 34.0) + 1.0) * x); }

float snoise(vec2 v) {
  const vec4 C = vec4(0.211324865405187, 0.366025403784439,
                     -0.577350269189626, 0.024390243902439);
  vec2 i  = floor(v + dot(v, C.yy));
  vec2 x0 = v -   i + dot(i, C.xx);
  vec2 i1 = (x0.x > x0.y) ? vec2(1.0, 0.0) : vec2(0.0, 1.0);
  vec4 x12 = x0.xyxy + C.xxzz;
  x12.xy -= i1;
  i = mod289(i);
  vec3 p = permute(permute(i.y + vec3(0.0, i1.y, 1.0))
                        + i.x + vec3(0.0, i1.x, 1.0));
  vec3 m = max(0.5 - vec3(dot(x0, x0), dot(x12.xy, x12.xy),
                          dot(x12.zw, x12.zw)), 0.0);
  m = m * m; m = m * m;
  vec3 x = 2.0 * fract(p * C.www) - 1.0;
  vec3 hh = abs(x) - 0.5;
  vec3 ox = floor(x + 0.5);
  vec3 a0 = x - ox;
  m *= 1.79284291400159 - 0.85373472095314 * (a0 * a0 + hh * hh);
  vec3 g;
  g.x  = a0.x  * x0.x  + hh.x  * x0.y;
  g.yz = a0.yz * x12.xz + hh.yz * x12.yw;
  return 130.0 * dot(m, g);
}

float fbm(vec2 p) {
  float v = 0.0, a = 0.5;
  for (int i = 0; i < 5; i++) { v += a * snoise(p); p *= 2.03; a *= 0.5; }
  return v;
}

float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123); }

void main() {
  vec2 uv = gl_FragCoord.xy / uRes;
  vec2 p  = (gl_FragCoord.xy - 0.5 * uRes) / uRes.y;
  float t = uTime * 0.03;

  /* Squash vertically: the field stretches into strata, the way regions of an
     address space stack, instead of forming round clouds. */
  vec2 sp = vec2(p.x * 0.55, p.y * 2.6);

  vec2 q = vec2(fbm(sp + vec2(0.0, t)), fbm(sp + vec2(4.4, 1.2 - t)));
  vec2 r = vec2(fbm(sp * 1.4 + 2.6 * q + vec2(1.7, 9.2) + 0.3 * t),
                fbm(sp * 1.4 + 2.6 * q + vec2(8.3, 2.8) - 0.2 * t));
  float f = fbm(sp * 1.2 + 2.0 * r);

  float dens = smoothstep(-0.25, 0.9, f);
  dens *= dens;

  vec3 base   = vec3(0.010, 0.017, 0.033);
  vec3 deep   = vec3(0.078, 0.157, 0.353);
  vec3 teal   = vec3(0.110, 0.400, 0.545);
  vec3 violet = vec3(0.353, 0.235, 0.588);

  vec3 col = base;
  col = mix(col, deep,   dens * 0.75);
  col = mix(col, teal,   smoothstep(0.5, 1.0, dens) * 0.35);
  col = mix(col, violet, smoothstep(0.35, 1.0, length(q)) * 0.22 * dens);

  /* Filaments: the thin bright ridges where the field folds — this is the
     detail that keeps a dark background from looking flat and cheap. */
  float ridge = 1.0 - abs(f - 0.28) * 3.6;
  ridge = clamp(ridge, 0.0, 1.0);
  col += mix(teal, violet, 0.5) * pow(ridge, 7.0) * 0.30;

  // Rare hot pockets: dense, high-entropy regions.
  float hot = smoothstep(0.86, 1.0, dens);
  col += vec3(0.65, 0.25, 0.45) * hot * 0.18;

  // Vignette, heaviest low where the working UI sits.
  float vig = smoothstep(1.35, 0.30, length(vec2(p.x * 0.65, p.y + 0.22)));
  col *= mix(0.32, 1.0, vig);
  col *= mix(1.0, 0.5, smoothstep(0.2, 1.0, 1.0 - uv.y));

  col *= uIntensity;
  col += (hash(gl_FragCoord.xy + fract(uTime)) - 0.5) * 0.014;
  gl_FragColor = vec4(col, 1.0);
}
`;

function compile(gl: WebGLRenderingContext, type: number, src: string) {
  const sh = gl.createShader(type);
  if (!sh) return null;
  gl.shaderSource(sh, src);
  gl.compileShader(sh);
  if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
    console.warn('[MemoryFabric] shader:', gl.getShaderInfoLog(sh));
    return null;
  }
  return sh;
}


interface Props {
  /** overall brightness, 1 = full. Lower it behind dense UI. */
  intensity?: number;
  className?: string;
}

export default function PlasmaField({ intensity = 1, className }: Props) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const gl = canvas.getContext('webgl', { antialias: false, alpha: false, powerPreference: 'low-power' });
    if (!gl) return;
    const vs = compile(gl, gl.VERTEX_SHADER, VERT);
    const fs = compile(gl, gl.FRAGMENT_SHADER, FRAG);
    if (!vs || !fs) return;
    const prog = gl.createProgram();
    if (!prog) return;
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return;
    gl.useProgram(prog);

    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const aPos = gl.getAttribLocation(prog, 'aPos');
    gl.enableVertexAttribArray(aPos);
    gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0);

    const uRes = gl.getUniformLocation(prog, 'uRes');
    const uTime = gl.getUniformLocation(prog, 'uTime');
    const uIntensity = gl.getUniformLocation(prog, 'uIntensity');
    gl.uniform1f(uIntensity, intensity);

    const dpr = Math.min(window.devicePixelRatio || 1, 1.25);
    const resize = () => {
      const cw = Math.max(1, Math.round(canvas.clientWidth * dpr));
      const ch = Math.max(1, Math.round(canvas.clientHeight * dpr));
      if (canvas.width === cw && canvas.height === ch) return;
      canvas.width = cw;
      canvas.height = ch;
      gl.viewport(0, 0, cw, ch);
      gl.uniform2f(uRes, cw, ch);
    };
    resize();
    // See MemoryFabric: observe the element so the buffer always matches its box.
    const ro = new ResizeObserver(() => resize());
    ro.observe(canvas);

    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let raf = 0;
    const start = performance.now();
    const draw = (now: number) => {
      resize();
      gl.uniform1f(uTime, (now - start) / 1000);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      raf = requestAnimationFrame(draw);
    };
    if (reduced) {
      gl.uniform1f(uTime, 0);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    } else raf = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, [intensity]);

  return <canvas ref={ref} className={className ?? 'absolute inset-0 w-full h-full'} />;
}
