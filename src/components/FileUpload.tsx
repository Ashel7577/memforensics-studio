import { useCallback, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { UploadCloud, FileCheck, ShieldCheck, HardDrive, Lock, Crosshair } from 'lucide-react';
import { useStore } from '../store';

export default function FileUpload() {
  const { fileName, fileMD5, filePath, setFile } = useStore();
  const [dialogError, setDialogError] = useState<string | null>(null);

  const handleFile = useCallback(async () => {
    try {
      const result = await invoke<string>('open_file_dialog');
      if (result) {
        // Windows separates with '\\', POSIX with '/' — split on both so the
        // card shows a file name rather than the whole path.
        const name = result.split(/[\\/]/).pop() || result;
        setFile(result, name, 0, 'Hash computed by engine');
      }
    } catch (err) {
      // A cancelled picker rejects too, so only surface real failures.
      const msg = String(err);
      if (!msg.includes('No file selected')) {
        console.error('Dialog error:', err);
        setDialogError(msg);
      }
    }
  }, [setFile]);

  // The webview strips real paths off dropped files (and WebView2 swallows the
  // drop outright), and the engines need a path on disk, not a File object —
  // so a drop just opens the picker.
  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    handleFile();
  }, [handleFile]);

  return (
    <div>
      <div
        onDrop={handleDrop}
        onDragOver={e => e.preventDefault()}
        onClick={handleFile}
        className={`group/cmd relative overflow-hidden rounded-xl cursor-pointer transition-all duration-300 ${
          fileName
            ? 'border border-green/30 bg-green/[0.03] hover:border-green/60'
            : 'border-2 border-dashed border-border hover:border-blue hover:shadow-[0_0_0_3px_rgba(88,166,255,0.15)]'
        }`}
      >
        <span className="absolute inset-0 cmd-grid opacity-30 pointer-events-none" aria-hidden="true" />
        <span className="cmd-sheen" aria-hidden="true" />

        {/* acquisition reticle */}
        <span
          className="cmd-corner left-3 top-3 border-l border-t"
          style={{ borderColor: fileName ? 'rgba(63,185,80,0.6)' : undefined }}
          aria-hidden="true"
        />
        <span
          className="cmd-corner right-3 top-3 border-r border-t"
          style={{ borderColor: fileName ? 'rgba(63,185,80,0.6)' : undefined }}
          aria-hidden="true"
        />
        <span
          className="cmd-corner left-3 bottom-3 border-l border-b"
          style={{ borderColor: fileName ? 'rgba(63,185,80,0.6)' : undefined }}
          aria-hidden="true"
        />
        <span
          className="cmd-corner right-3 bottom-3 border-r border-b"
          style={{ borderColor: fileName ? 'rgba(63,185,80,0.6)' : undefined }}
          aria-hidden="true"
        />

        <div className="relative z-10 p-10 text-center">
          {fileName ? (
            <div className="flex flex-col items-center gap-2">
              <div className="relative">
                <div className="absolute inset-0 rounded-full bg-green/20 blur-xl" aria-hidden="true" />
                <FileCheck className="relative w-12 h-12 text-green" />
              </div>
              <p className="text-primary font-semibold text-lg">{fileName}</p>
              <p className="flex items-center gap-1.5 text-green text-xs font-mono uppercase tracking-[0.2em]">
                <span className="w-1.5 h-1.5 rounded-full bg-green arm-led" />
                Evidence loaded · ready for analysis
              </p>
              <p className="text-muted/60 text-[10px] font-mono">click to select a different image</p>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-2">
              <div className="relative">
                <Crosshair
                  className="absolute -inset-3 w-[72px] h-[72px] text-blue/20 animate-spin-slow"
                  style={{ animationDuration: '9s' }}
                  aria-hidden="true"
                />
                <UploadCloud className="relative w-12 h-12 text-muted group-hover/cmd:text-blue transition-colors" />
              </div>
              <p className="text-primary font-medium mt-1">Drop memory image for acquisition</p>
              <p className="text-muted text-xs font-mono tracking-wider">.dmp · .raw · .mem</p>
              <p className="text-blue text-xs font-mono border-b border-blue/40">or click to browse evidence</p>
            </div>
          )}
        </div>
      </div>

      {dialogError && (
        <p className="mt-2 text-[11px] font-mono text-red">
          Could not open the file picker: {dialogError}
        </p>
      )}

      {fileName && (
        <div className="mt-3 rounded-xl border border-border bg-card overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-[#0a0e14]">
            <ShieldCheck className="w-3.5 h-3.5 text-green" />
            <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-muted">
              Chain of Custody
            </span>
            <span className="ml-auto text-[9px] font-mono text-green uppercase tracking-wider">
              read-only · source unmodified
            </span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 divide-x divide-border">
            <Field icon={<HardDrive className="w-3 h-3" />} label="Evidence File" value={fileName} />
            <Field icon={<Lock className="w-3 h-3" />} label="MD5" value={fileMD5 || 'Computed by engine'} />
            <Field icon={<ShieldCheck className="w-3 h-3" />} label="Acquisition" value="VM snapshot" />
            <Field
              icon={<Crosshair className="w-3 h-3" />}
              label="Source Path"
              value={filePath || '—'}
              title={filePath ?? undefined}
            />
          </div>
        </div>
      )}
    </div>
  );
}

function Field({
  icon,
  label,
  value,
  title,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  title?: string;
}) {
  return (
    <div className="px-4 py-3 min-w-0">
      <span className="flex items-center gap-1 text-muted text-[9px] font-mono uppercase tracking-[0.16em]">
        {icon}
        {label}
      </span>
      <span className="block text-primary text-[11px] font-mono truncate mt-0.5" title={title ?? value}>
        {value}
      </span>
    </div>
  );
}
