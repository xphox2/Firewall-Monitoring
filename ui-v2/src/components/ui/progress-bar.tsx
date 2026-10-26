import { useEffect, useState } from 'react';
import { cn } from '@/lib/utils';
import { formatElapsed } from '@/lib/motion';
import { Spinner } from './spinner';

export interface ProgressBarProps {
  /** 0-100. */
  value: number;
  className?: string;
}

/**
 * The progress bar itself.
 *
 * Ports V1's `.fwmon-flows-progress` / `.fwmon-flows-progress-bar`
 * (cmd/api/static/css/admin-flows.css:957-969): a 6px track with an accent
 * fill that eases to its new width.
 */
export function ProgressBar({ value, className }: ProgressBarProps) {
  const pct = Math.max(0, Math.min(100, value));
  return (
    <div
      className={cn('mt-2 h-1.5 overflow-hidden rounded-full bg-bg-panel', className)}
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(pct)}
    >
      <div
        className="h-full rounded-full bg-accent transition-[width] duration-300 ease-out"
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

/** V1's elapsed format lives in lib/motion so it can be tested. */
export interface LongOpStatusProps {
  /** What the operation is doing, e.g. "Flow statistics for the last 24h". */
  title: string;
  /** The current step, e.g. "Scanning partitions…". */
  step?: string;
  /** Progress in percent, or undefined when the operation reports no total. */
  progress?: number;
  /** True while the operation is running. */
  active: boolean;
  /** Called when the operator cancels. */
  onCancel?: () => void;
  /** After this many seconds, say that the wait may be long. */
  slowAfterSeconds?: number;
  className?: string;
}

/**
 * The long-running-operation row.
 *
 * Ports V1's `showLoading()` / `updateLoading()` (cmd/api/static/js/admin-flows.js:
 * 720-758) and the block it drove (admin-flows.css:919-1010).
 *
 * V1's version was a title, a step, an elapsed counter, a bar and a note that
 * appeared after a minute. The bar alone loses the point: the operator needs
 * to know WHAT is taking time, not just that something is.
 *
 * The note after a minute matters because the report has no time limit - a
 * long wait should read as working, not as stuck.
 */
export function LongOpStatus({
  title,
  step,
  progress,
  active,
  onCancel,
  slowAfterSeconds = 60,
  className,
}: LongOpStatusProps) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (!active) {
      setElapsed(0);
      return;
    }
    const started = Date.now();
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => clearInterval(id);
  }, [active]);

  if (!active) return null;

  return (
    <div
      className={cn('rounded-xl border border-border bg-bg-card p-3 text-text-dim', className)}
      role="status"
    >
      <div className="flex flex-wrap items-center gap-2">
        <Spinner />
        <span className="min-w-0 flex-1 font-semibold break-words text-text">{title}</span>
        <span className="font-mono tabular-nums text-text-faint">{formatElapsed(elapsed)}</span>
        {onCancel ? (
          <button
            type="button"
            onMouseDown={(event) => event.preventDefault()}
            onClick={onCancel}
            className="rounded-md border border-border bg-bg-panel px-2.5 py-1 text-xs font-medium text-text-dim transition-colors hover:text-text"
          >
            Cancel
          </button>
        ) : null}
      </div>

      {/*
        The bar is always rendered. V1's showLoading() set the bar to 0% and
        left it there until the first progress event, so the row showed its
        shape from the start rather than appearing when the first tick
        arrived.
        */}
      <ProgressBar value={progress ?? 0} />

      {step ? <div className="mt-1 text-xs text-text-faint">{step}</div> : null}

      {elapsed >= slowAfterSeconds ? (
        <div className="mt-1 text-xs text-text-dim">
          Still working — a large range can take several minutes.
        </div>
      ) : null}
    </div>
  );
}
