export interface EngineProgress {
  engineNum: number;
  name: string;
  status: 'pending' | 'running' | 'done' | 'failed';
  percent: number;
  message: string;
  metrics: string;
  startTime?: number;
  endTime?: number;
  error?: string;
}

export interface LogLine {
  id: string;
  timestamp: string;
  engineNum?: number;
  text: string;
  level: 'info' | 'success' | 'error' | 'warning';
}

export interface Artifact {
  filename: string;
  engineNum: number;
  sizeBytes: number;
  ready: boolean;
  path: string;
}

export interface PipelineRun {
  id: string;
  filename: string;
  engines: number[];
  status: 'done' | 'failed';
  startedAt: string;
  duration: number;
}

export interface ReportMetadata {
  caseId: string;
  analysisDate: string;
  memoryImage: string;
  malwareFamily: string;
  cvssScore: number;
  cvssRating: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  infectedProcesses: number;
  c2Server: string;
  injectionTechnique: string;
  mitreIds: string[];
  enginesRun: number[];
}

export interface EngineConfig {
  num: number;
  name: string;
  description: string;
  input: string;
  output: string;
}
