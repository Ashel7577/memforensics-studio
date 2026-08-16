import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import './index.css';

createRoot(document.getElementById('root')!).render(<App />);

/* The native window is created hidden so the compositor never shows a bright
 * empty frame before the webview has content. Reveal it once React has
 * committed and the browser has actually painted — two rAFs, because the first
 * fires before paint. */
requestAnimationFrame(() => {
  requestAnimationFrame(() => {
    import('@tauri-apps/api/core')
      .then(({ invoke }) => invoke('show_main_window'))
      .catch(() => {
        /* running in a plain browser — nothing to reveal */
      });
  });
});
