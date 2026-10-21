export interface AlertFilters {
  deviceId: string;
  siteId: string;
  severity: string;
  alertType: string;
  includeSnoozed: boolean;
}

export const EMPTY_ALERT_FILTERS: AlertFilters = {
  deviceId: '',
  siteId: '',
  severity: '',
  alertType: '',
  includeSnoozed: false,
};

export const ALERT_RANGES = [
  { value: '1h', hours: 1 },
  { value: '6h', hours: 6 },
  { value: '12h', hours: 12 },
  { value: '24h', hours: 24 },
  { value: '7d', hours: 168 },
  { value: '30d', hours: 720 },
] as const;

/** Query string for GET /api/alerts (the list has no time-window param). */
export function buildAlertQuery(opts: {
  acknowledged: boolean;
  filters: AlertFilters;
  offset: number;
  limit?: number;
}): string {
  const params = new URLSearchParams({
    acknowledged: opts.acknowledged ? 'true' : 'false',
    limit: String(opts.limit ?? 50),
    offset: String(Math.max(0, opts.offset)),
  });
  if (opts.filters.deviceId) params.set('device_id', opts.filters.deviceId);
  if (opts.filters.siteId) params.set('site_id', opts.filters.siteId);
  if (opts.filters.severity) params.set('severity', opts.filters.severity);
  if (opts.filters.alertType) params.set('alert_type', opts.filters.alertType);
  if (opts.filters.includeSnoozed) params.set('include_snoozed', 'true');
  return params.toString();
}

export type AlertState = 'resolved' | 'acknowledged' | 'snoozed' | 'open';

export function alertState(
  alert: {
    acknowledged?: boolean;
    snoozed_until?: string | null;
    resolved_at?: string | null;
  },
  now: number = Date.now(),
): AlertState {
  if (alert.resolved_at) return 'resolved';
  if (alert.acknowledged) return 'acknowledged';
  if (alert.snoozed_until) {
    const until = new Date(alert.snoozed_until).getTime();
    if (Number.isFinite(until) && until > now) return 'snoozed';
  }
  return 'open';
}

/** "1–50 of 123" (or "0 of 0"). */
export function pageRange(offset: number, count: number, total: number): string {
  if (total === 0 || count === 0) return `0 of ${total}`;
  return `${offset + 1}–${offset + count} of ${total}`;
}

/** Compact label for a stats bucket ("2026-10-20 14:00" → "14:00"). */
export function compactBucket(bucket: string): string {
  const value = String(bucket ?? '');
  const time = value.match(/(\d{2}):(\d{2})(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$/);
  if (time) return `${time[1]}:${time[2]}`;
  const date = value.match(/(\d{4})-(\d{2})-(\d{2})/);
  if (date) return `${date[2]}-${date[3]}`;
  return value;
}

/**
 * Last N trend buckets for the compact bar list. The stats endpoint always
 * buckets by hour, so multi-day windows are aggregated per day here — twelve
 * hourly bars would otherwise all read "14:00" and cover only half a day.
 */
export function trendBars(
  buckets: Array<{ bucket: string; count: number }> | undefined,
  maxBars = 12,
  groupByDay = false,
): Array<{ label: string; count: number }> {
  const rows = buckets ?? [];
  if (!groupByDay) {
    return rows.slice(-maxBars).map((b) => ({
      label: compactBucket(b.bucket),
      count: Number(b.count) || 0,
    }));
  }
  const byDay = new Map<string, number>();
  for (const row of rows) {
    const day = String(row.bucket ?? '').slice(0, 10);
    if (!day) continue;
    byDay.set(day, (byDay.get(day) ?? 0) + (Number(row.count) || 0));
  }
  return Array.from(byDay.entries())
    .slice(-maxBars)
    .map(([day, count]) => ({ label: compactBucket(day), count }));
}
