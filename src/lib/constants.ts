import type { EngineConfig } from '../types';

export const ENGINES: EngineConfig[] = [
  {
    num: 1,
    name: 'Memory Acquisition',
    description: 'Evidence integrity: SHA256 + Merkle block manifest, chain of custody',
    input: 'memory dump (.dmp / .raw)',
    output: '01_memory_evidence.json',
  },
  {
    num: 2,
    name: 'OS Structure Extractor',
    description: 'Volatility 3 extraction: processes, threads, VADs, modules, handles, network',
    input: '01_memory_evidence.json + memory dump',
    output: '02_os_structures.json',
  },
  {
    num: 3,
    name: 'Private Exec Regions',
    description: 'Isolates private, unbacked executable memory regions from the VAD trees',
    input: '02_os_structures.json',
    output: '03_private_exec_regions.json',
  },
  {
    num: 4,
    name: 'Execution Evidence',
    description: 'Proof of execution: ThreadStart ∈ private exec VAD, plus handle/network correlation',
    input: '02_os_structures.json + 03_private_exec_regions.json',
    output: '04_execution_evidence.json',
  },
  {
    num: 5,
    name: 'Execution Timeline',
    description: 'Chronological attack chain reconstruction, execution roles, burst analysis',
    input: '04_execution_evidence.json + 02_os_structures.json',
    output: '05_execution_timeline.json',
  },
  {
    num: 6,
    name: 'Injection Classifier',
    description: 'Weighted technique scoring, C2 intelligence, MITRE ATT&CK kill chain',
    input: '05_execution_timeline.json + 03_private_exec_regions.json',
    output: '06_classification.json',
  },
  {
    num: 7,
    name: 'Forensic Report Generator',
    description: 'Sectioned DFIR PDF, CVSS scoring, IOC / STIX / CSV exports',
    input: 'all six preceding artifacts',
    output: '07_forensic_report.pdf',
  },
];

export const JSON_ANALYZER_URL = 'https://memforensics-dashboard.pages.dev';

// Local, offline copy of the analyzer bundled into the app (public/analyzer/).
// The iframe on the Report page loads this so analysis works with no internet.
// The Navbar / Dashboard 'open in browser' buttons keep using JSON_ANALYZER_URL above.
export const JSON_ANALYZER_LOCAL_URL = 'analyzer/index.html';
