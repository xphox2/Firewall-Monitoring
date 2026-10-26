/**
 * The pure parts of the motion layer.
 *
 * These live apart from the components so they can be tested without a DOM:
 * the V2 test environment is node-only (no jsdom, no testing-library), so
 * anything worth asserting on has to be a function.
 */

/** V1 showed the overlay only after this long, so a fast load never flashes. */
export const OVERLAY_DELAY_MS = 250;

/**
 * Elapsed whole seconds since a start timestamp.
 *
 * `startedAt` is the moment the LOAD began, not the moment the overlay
 * appeared - the elapsed count has to be honest about the whole wait.
 */
export function elapsedSeconds(startedAt: number | null, now: number): number {
  if (startedAt == null) return 0;
  return Math.max(0, Math.floor((now - startedAt) / 1000));
}

/**
 * V1's elapsed format: seconds under a minute, then minutes and seconds.
 *
 * The report has no time limit, so the operator needs to see that the clock
 * is running rather than watching a frozen number.
 */
export function formatElapsed(seconds: number): string {
  const secs = Math.max(0, Math.round(seconds));
  if (secs < 60) return `${secs} s`;
  return `${Math.floor(secs / 60)} min ${secs % 60} s`;
}

/**
 * The gauge's fill percentage.
 *
 * V1's `createGauge` (cmd/api/static/js/admin-connection-detail.js:104-128)
 * computed this in JavaScript; the CSS only carried the arc's presentation.
 */
export function gaugePercent(value: number, max: number): number {
  if (!(max > 0)) return 0;
  return Math.min((value / max) * 100, 100);
}

/**
 * The gauge's stroke colour, from V1's thresholds.
 *
 * The colour is a `var()` so a Day/Night flip re-resolves instantly: SVG
 * presentation attributes cannot take `var()`, but an inline style can.
 */
export function gaugeStrokeColour(percent: number): string {
  if (percent >= 90) return 'var(--fwmon-sig-crit)';
  if (percent >= 70) return 'var(--fwmon-sig-warn)';
  return 'var(--fwmon-sig-ok)';
}

/**
 * The traffic particles' colour.
 *
 * V1 coloured particles by the connection type, from a 12-entry palette. V2's
 * edge model does not carry the type, so the colour is the edge's own role: a
 * tunnel is the accent, a declared link is the healthy green.
 */
export function particleColourForKind(kind: string): string {
  return kind === 'tunnel' ? 'var(--fwmon-accent)' : 'var(--fwmon-sig-ok)';
}

/**
 * Whether the overlay should be showing yet.
 *
 * A load that answers inside the delay must not flash an overlay at all.
 */
export function overlayShouldShow(
  active: boolean,
  startedAt: number | null,
  now: number,
  delayMs: number = OVERLAY_DELAY_MS,
): boolean {
  if (!active || startedAt == null) return false;
  return now - startedAt >= delayMs;
}
