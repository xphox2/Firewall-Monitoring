import { cn } from '@/lib/utils';

export interface SkeletonProps {
  /** How many placeholder bars to draw. */
  rows?: number;
  className?: string;
}

/**
 * The shape-preserving placeholder.
 *
 * Ports V1's `.dash-skeleton` (cmd/api/static/css/admin-design-system.css:
 * 1392-1405). V1's comment says it best: module bodies show their SHAPE while
 * the first payload is still in flight, rather than the whole grid collapsing
 * to one centred spinner. The second and third bars are narrower and start
 * later, so the block reads as content rather than as a progress indicator.
 */
export function Skeleton({ rows = 3, className }: SkeletonProps) {
  return (
    <div className={cn('dash-skeleton', className)} aria-hidden="true">
      {Array.from({ length: Math.max(1, rows) }, (_, i) => (
        <span key={i} />
      ))}
    </div>
  );
}

/**
 * The table-row placeholder.
 *
 * This is what `<ResponsiveDataView>` already rendered - five 40px rows with
 * a border - extracted so the loading state has one definition instead of an
 * inline block that only one component knew about.
 */
export function SkeletonRows({ rows = 5, className }: SkeletonProps) {
  return (
    <div className={cn('space-y-3', className)} aria-hidden="true">
      {Array.from({ length: Math.max(1, rows) }, (_, i) => (
        <div key={i} className="h-10 rounded-md border border-border/50 bg-bg-panel animate-pulse motion-reduce:animate-none" />
      ))}
    </div>
  );
}

/**
 * The stat-tile placeholder: a small label bar over a wide value bar.
 */
export function SkeletonStat({ className }: { className?: string }) {
  return (
    <div className={cn('space-y-2', className)} aria-hidden="true">
      <div className="h-2.5 w-16 rounded bg-bg-panel animate-pulse motion-reduce:animate-none" />
      <div className="h-6 w-20 rounded bg-bg-panel animate-pulse motion-reduce:animate-none" />
    </div>
  );
}

/**
 * The chart-area placeholder: a block the same height as the chart it stands
 * in for, so the page does not jump when the real chart arrives.
 */
export function SkeletonChart({ height = 220, className }: { height?: number; className?: string }) {
  return (
    <div
      className={cn(
        'flex items-center justify-center rounded-lg border border-border bg-bg-panel',
        className,
      )}
      style={{ height }}
      aria-hidden="true"
    >
      <Skeleton rows={3} className="w-full max-w-xs px-4" />
    </div>
  );
}

/**
 * The placeholder for a single NUMBER.
 *
 * A metric that renders `?? 0` while its query is in flight is not a
 * cosmetic problem: a tile reading "0 devices online" is a fact, and the
 * operator cannot tell it from the truth. This renders a bar of the same
 * height instead, so the tile shows that a value is coming.
 */
export function SkeletonValue({
  loading,
  width = 'w-16',
  height = '1.5rem',
  className,
}: {
  loading: boolean;
  width?: string;
  /**
   * Match the height of the number it stands in for, so the tile does not
   * jump when the real value lands. The Overview vitals use `text-2xl`
   * (2rem), the smaller stat cards `text-xl` (1.5rem).
   */
  height?: string;
  className?: string;
}) {
  if (!loading) return null;
  return (
    <span
      className={cn('inline-block rounded bg-bg-panel align-middle animate-pulse motion-reduce:animate-none', width, className)}
      style={{ height }}
      aria-hidden="true"
    />
  );
}
