import { useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { UploadCloud, FileCheck } from 'lucide-react';
import { useStore } from '../store';

export default function FileUpload() {
  const { fileName, fileMD5, setFile } = useStore();

  const handleFile = useCallback(async () => {
    try {
      const result = await invoke<string>('open_file_dialog');
      if (result) {
        const name = result.split('/').pop() || result;
        setFile(result, name, 0, 'Hash computed by engine');
      }
    } catch (err) {
      console.error('Dialog error:', err);
    }
  }, [setFile]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) {
      const path = (file as any).path;
      if (path) {
        setFile(path, file.name, file.size, 'Hash computed by engine');
      } else {
        handleFile();
      }
    }
  }, [setFile, handleFile]);

  return (
    <div>
      <div
        onDrop={handleDrop}
        onDragOver={e => e.preventDefault()}
        onClick={handleFile}
        className="border-2 border-dashed border-border rounded-xl p-12 text-center cursor-pointer hover:border-blue transition-all duration-200 hover:shadow-[0_0_0_3px_rgba(88,166,255,0.15)]"
      >
        {fileName ? (
          <div className="flex flex-col items-center gap-2">
            <FileCheck className="w-12 h-12 text-green" />
            <p className="text-primary font-medium">{fileName}</p>
            <p className="text-green text-sm">Ready for analysis</p>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-2">
            <UploadCloud className="w-12 h-12 text-muted" />
            <p className="text-primary">Drop memory dump here</p>
            <p className="text-muted text-sm">.dmp · .raw · .mem</p>
            <p className="text-blue text-sm underline">or click to browse</p>
          </div>
        )}
      </div>

      {fileName && (
        <div className="mt-3 bg-card border border-border rounded-xl p-4 grid grid-cols-2 gap-3">
          <div>
            <span className="text-muted text-xs block">FILENAME</span>
            <span className="text-primary text-xs font-mono">{fileName}</span>
          </div>
          <div>
            <span className="text-muted text-xs block">MD5</span>
            <span className="text-primary text-xs font-mono">{fileMD5 || 'Computed by engine'}</span>
          </div>
        </div>
      )}
    </div>
  );
}
