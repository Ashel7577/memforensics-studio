import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import type { EngineProgress, LogLine, Artifact, PipelineRun } from './types';

interface AppStore {
  filePath: string | null;
  fileName: string | null;
  fileSize: number | null;
  fileMD5: string | null;

  selectedEngines: number[];
  limit: number;
  verbose: boolean;

  activePipelineId: string | null;
  pipelineStatus: 'idle' | 'queued' | 'running' | 'done' | 'failed';
  engineProgress: EngineProgress[];
  logs: LogLine[];
  artifacts: Artifact[];

  history: PipelineRun[];

  setFile: (path: string | null, name: string | null, size: number | null, md5: string | null) => void;
  setEngines: (engines: number[]) => void;
  toggleEngine: (num: number) => void;
  setLimit: (limit: number) => void;
  setVerbose: (verbose: boolean) => void;
  setPipelineStatus: (status: AppStore['pipelineStatus']) => void;
  setActivePipelineId: (id: string | null) => void;
  appendLog: (log: LogLine) => void;
  clearLogs: () => void;
  updateEngineProgress: (progress: EngineProgress) => void;
  addArtifact: (artifact: Artifact) => void;
  resetPipeline: () => void;
  loadHistory: (history: PipelineRun[]) => void;
  addHistory: (run: PipelineRun) => void;
}

const defaultEngines = [1, 2, 3, 4, 5, 6, 7];

export const useStore = create<AppStore>()(
  persist(
    (set, get) => ({
      filePath: null,
      fileName: null,
      fileSize: null,
      fileMD5: null,

      selectedEngines: defaultEngines,
      limit: 10,
      verbose: false,

      activePipelineId: null,
      pipelineStatus: 'idle',
      engineProgress: [],
      logs: [],
      artifacts: [],

      history: [],

      setFile: (path, name, size, md5) =>
        set({ filePath: path, fileName: name, fileSize: size, fileMD5: md5 }),
      setEngines: (engines) => set({ selectedEngines: engines }),
      toggleEngine: (num) =>
        set((state) => {
          const exists = state.selectedEngines.includes(num);
          return {
            selectedEngines: exists
              ? state.selectedEngines.filter((n) => n !== num)
              : [...state.selectedEngines, num],
          };
        }),
      setLimit: (limit) => set({ limit }),
      setVerbose: (verbose) => set({ verbose }),
      setPipelineStatus: (status) => set({ pipelineStatus: status }),
      setActivePipelineId: (id) => set({ activePipelineId: id }),
      appendLog: (log) => set((state) => ({ logs: [...state.logs, log] })),
      clearLogs: () => set({ logs: [] }),
      updateEngineProgress: (progress) =>
        set((state) => {
          const idx = state.engineProgress.findIndex((e) => e.engineNum === progress.engineNum);
          if (idx >= 0) {
            const next = [...state.engineProgress];
            next[idx] = progress;
            return { engineProgress: next };
          }
          return { engineProgress: [...state.engineProgress, progress] };
        }),
      addArtifact: (artifact) =>
        set((state) => ({ artifacts: [...state.artifacts, artifact] })),
      resetPipeline: () =>
        set({
          activePipelineId: null,
          pipelineStatus: 'idle',
          engineProgress: [],
          logs: [],
          artifacts: [],
        }),
      loadHistory: (history) => set({ history }),
      addHistory: (run) =>
        set((state) => ({ history: [run, ...state.history] })),
    }),
    {
      name: 'memforensics-store-v2',
      version: 1,
      migrate: (persistedState: any) => {
        if (persistedState && typeof persistedState === 'object') {
          return {
            ...persistedState,
            filePath: null,
            fileName: null,
            fileSize: null,
            fileMD5: null,
            activePipelineId: null,
            pipelineStatus: 'idle',
            engineProgress: [],
            logs: [],
            artifacts: [],
          };
        }
        return persistedState;
      },
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        history: state.history,
      }),
    }
  )
);
