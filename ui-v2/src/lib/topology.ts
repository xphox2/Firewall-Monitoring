export type LinkState = 'up' | 'down' | 'unknown';

/**
 * One classification for both edge colour and the KPI counters. Connection
 * statuses default to "unknown" and the poller emits "stale"; neither is a
 * failure, so they must not inflate the "down" count.
 */
export function linkState(status: string | null | undefined): LinkState {
  const value = String(status ?? '')
    .trim()
    .toLowerCase();
  if (!value) return 'unknown';
  if (/\b(up|online|active|ok|healthy|established)\b/.test(value)) return 'up';
  if (/\b(down|offline|failed|error|critical)\b/.test(value)) return 'down';
  return 'unknown';
}

export function linkColour(status: string | null | undefined): string {
  switch (linkState(status)) {
    case 'up':
      return '#4ade80';
    case 'down':
      return '#f87171';
    default:
      return '#94a3b8';
  }
}
