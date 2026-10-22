import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import { ErrorBoundary } from './components/ui/error-boundary';
import { reloadForStaleChunk } from './lib/stale-chunk';
import './styles/globals.css';

// A deploy replaces the JS bundles while a tab can still be open. Vite fires
// this when a lazy preload fails (the chunk from the previous build is gone);
// reload once so the new entry and its hashed chunks load together instead of
// surfacing "does not provide an export named …" to the operator.
window.addEventListener('vite:preloadError', (event) => {
  event.preventDefault();
  reloadForStaleChunk('failed to fetch dynamically imported module');
});
window.addEventListener('unhandledrejection', (event) => {
  reloadForStaleChunk(event.reason);
});

const rootEl = document.getElementById('v2-root');
if (rootEl) {
  ReactDOM.createRoot(rootEl).render(
    <React.StrictMode>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </React.StrictMode>,
  );
}
