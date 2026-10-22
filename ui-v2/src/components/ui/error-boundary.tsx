import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react';
import { reloadForStaleChunk } from '@/lib/stale-chunk';

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Last-resort render boundary. Without one, a single thrown render (a bad
 * `res.map` on an object payload, a null deref in a table cell) unmounts the
 * entire React root and leaves the operator staring at a blank console with
 * no way back. Each workspace is expensive to rebuild, so we keep the shell
 * alive and offer a reset instead of failing the whole page.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Console only: the CSP and audit trail already capture server failures,
    // and shipping stacks to a third party is not acceptable for this app.
    console.error('Admin UI V2 render error', error, info.componentStack);
    // A deploy can leave this tab holding the previous entry while its lazy
    // chunks have been replaced. Reload once to pick up the new build rather
    // than showing a module-export error the operator cannot act on.
    reloadForStaleChunk(error);
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div className="flex min-h-screen items-center justify-center bg-bg p-6">
        <div className="w-full max-w-lg rounded-xl border border-sig-crit/30 bg-bg-card p-6">
          <div className="flex items-center gap-2 text-sig-crit">
            <AlertTriangle className="h-5 w-5" />
            <h1 className="text-sm font-semibold">This workspace failed to render</h1>
          </div>
          <p className="mt-2 text-xs text-text-dim">
            The rest of the console is still running. Reloading re-fetches the page data; the error
            message below is what the browser caught.
          </p>
          <pre className="mt-3 max-h-40 overflow-auto rounded-lg border border-border bg-bg-panel p-3 font-mono text-[11px] text-text-dim">
            {error.message}
          </pre>
          <div className="mt-4 flex gap-2">
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-hover"
            >
              Reload console
            </button>
            <a
              href="/admin"
              className="rounded-lg border border-border px-3 py-1.5 text-xs font-semibold text-text-dim hover:text-text"
            >
              Back to classic UI
            </a>
          </div>
        </div>
      </div>
    );
  }
}
