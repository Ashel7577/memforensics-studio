import type { EngineConfig } from '../types';

export const ENGINES: EngineConfig[] = [
  {
    num: 1,
    name: 'Memory Acquisition',
    description: 'Evidence integrity, SHA256/MD5 hashing, metadata extraction',
    input: '.dmp',
    output: '01_memory_evidence.json',
  },
  {
    num: 2,
    name: 'OS Structure Extractor',
    description: 'Process tree, kernel structures, loaded modules, KDBG',
    input: '01_memory_evidence.json',
    output: '02_os_structures.json',
  },
  {
    num: 3,
    name: 'Private Exec Regions',
    description: 'VAD enumeration, PE header carving, executable region analysis',
    input: '02_os_structures.json',
    output: '03_private_exec_regions.json',
  },
  {
    num: 4,
    name: 'Execution Evidence',
    description: 'Prefetch, shimcache, amcache, MRU registry artifacts',
    input: '03_private_exec_regions.json',
    output: '04_execution_evidence.json',
  },
  {
    num: 5,
    name: 'Execution Timeline',
    description: 'Chronological attack chain reconstruction from correlated artifacts',
    input: '04_execution_evidence.json',
    output: '05_execution_timeline.json',
  },
  {
    num: 6,
    name: 'Injection Classifier',
    description: 'MITRE ATT&CK T1055 fingerprinting, technique confidence scoring',
    input: '05_execution_timeline.json',
    output: '06_classification.json',
  },
  {
    num: 7,
    name: 'Forensic Report Generator',
    description: 'PDF generation, CVSS scoring, IOC extraction, JSON serialization',
    input: '06_classification.json',
    output: '07_forensic_report.pdf',
  },
];

export const JSON_ANALYZER_URL = 'https://memforensics.netlify.app';
