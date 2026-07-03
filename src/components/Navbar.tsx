import { Link, useLocation } from 'react-router-dom';
import { History, ExternalLink } from 'lucide-react';
import { useStore } from '../store';
import { JSON_ANALYZER_URL } from '../lib/constants';
import { invoke } from '@tauri-apps/api/core';

export default function Navbar() {
  const { fileName } = useStore();
  const location = useLocation();

  const openAnalyzer = () => {
    invoke('open_url', { url: JSON_ANALYZER_URL });
  };

  return (
    <nav className="sticky top-0 z-50 h-14 bg-card border-b border-border flex items-center justify-between px-4 shrink-0">
      <Link to="/" className="flex items-center gap-2">
        <span className="text-lg font-bold bg-gradient-to-r from-purple to-blue bg-clip-text text-transparent">
          MemForensics Studio
        </span>
        <span className="text-[10px] text-muted bg-cardalt px-1.5 py-0.5 rounded font-mono">
          v1.0
        </span>
      </Link>

      <div className="flex items-center gap-4">
        {fileName && (
          <span className="hidden md:inline text-xs text-muted font-mono truncate max-w-[200px]">
            {fileName}
          </span>
        )}

        <Link
          to="/history"
          className={`flex items-center gap-1.5 text-sm font-medium transition-colors ${
            location.pathname === '/history' ? 'text-blue' : 'text-muted hover:text-primary'
          }`}
        >
          <History className="w-4 h-4" />
          History
        </Link>

        <button
          onClick={openAnalyzer}
          className="flex items-center gap-1.5 text-sm font-medium text-blue border border-blue/30 rounded-lg px-3 py-1.5 hover:bg-blue/10 transition-colors"
        >
          JSON Analyzer
          <ExternalLink className="w-3.5 h-3.5" />
        </button>
      </div>
    </nav>
  );
}
