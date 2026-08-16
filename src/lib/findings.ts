import type { LogLine } from '../types';

/**
 * Forensic findings surfaced by the engines while they run.
 *
 * These are deliberately distinct from log severity: a clean run with zero
 * errors can still be full of findings, which is exactly the interesting case.
 * Every number here is parsed from a line an engine actually printed.
 */
export interface Findings {
  vadAnomalies: number;
  malfindHits: number;
  persistence: number;
  suspiciousServices: number;
  techniques: number;
  injections: number;
  errors: number;
  warnings: number;
  /** Total forensic findings (excludes errors/warnings). */
  total: number;
}

const EMPTY: Findings = {
  vadAnomalies: 0,
  malfindHits: 0,
  persistence: 0,
  suspiciousServices: 0,
  techniques: 0,
  injections: 0,
  errors: 0,
  warnings: 0,
  total: 0,
};

/** Sum every `<n> <label>` occurrence across the stream. */
function sumMatches(text: string, re: RegExp): number {
  re.lastIndex = 0;
  let total = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) total += Number(m[1]) || 0;
  return total;
}

export function extractFindings(logs: LogLine[]): Findings {
  if (logs.length === 0) return EMPTY;

  const f: Findings = { ...EMPTY };
  const techniques = new Set<string>();

  for (const log of logs) {
    const t = log.text;

    if (log.level === 'error' || /ERROR|❌/.test(t)) f.errors++;
    else if (log.level === 'warning' || /WARNING|⚠/.test(t)) f.warnings++;

    // "... 107 VADs, 3 threads, 1 VAD anomalies"
    f.vadAnomalies += sumMatches(t, /(\d+)\s+VAD anomal/gi);

    // "✓ malfind reference scan: 4 hit(s)"
    f.malfindHits += sumMatches(t, /malfind[^:]*:\s*(\d+)\s*hit/gi);

    // "✓ Found 39 registry auto-start entries"
    f.persistence += sumMatches(t, /Found\s+(\d+)\s+registry auto-start/gi);

    // "✓ Scanned 12 services, 2 flagged as suspicious"
    f.suspiciousServices += sumMatches(t, /(\d+)\s+flagged as suspicious/gi);

    // Injection / private-exec candidates surfaced by engines 3 and 6
    f.injections += sumMatches(t, /(\d+)\s+(?:inject|private-exec candidate|suspicious region)/gi);

    const mitre = t.match(/\bT1\d{3}(?:\.\d{3})?\b/g);
    if (mitre) for (const id of mitre) techniques.add(id);
  }

  f.techniques = techniques.size;
  // Registry auto-start entries are an inventory, not a verdict — a clean
  // Windows image has dozens of legitimate ones, so counting them here would
  // inflate the headline into meaninglessness. They still appear in the
  // breakdown line, just not in the total.
  f.total =
    f.vadAnomalies + f.malfindHits + f.suspiciousServices + f.techniques + f.injections;

  return f;
}

/** Compact breakdown for the telemetry tile, most significant first. */
export function findingsSummary(f: Findings): string {
  const parts: string[] = [];
  if (f.techniques) parts.push(`${f.techniques} ATT&CK`);
  if (f.injections) parts.push(`${f.injections} injection`);
  if (f.vadAnomalies) parts.push(`${f.vadAnomalies} VAD`);
  if (f.malfindHits) parts.push(`${f.malfindHits} malfind`);
  if (f.persistence) parts.push(`${f.persistence} persist`);
  if (f.suspiciousServices) parts.push(`${f.suspiciousServices} svc`);
  if (parts.length === 0) {
    return f.errors || f.warnings ? `${f.errors} err · ${f.warnings} warn` : 'none surfaced yet';
  }
  return parts.slice(0, 2).join(' · ');
}
