import { bucketToMs } from './time-buckets';

// Mirrors internal/normalize/enums.go (TestEnumsJSMirror keeps the classic
// console's enums.js in lockstep; V2 carries only the labels it displays).
export const CLASS_NAMES: Record<number, string> = {
  4001: 'Network',
  2004: 'Finding',
  3002: 'Auth',
  5019: 'Config change',
  4014: 'VPN session',
  5001: 'Device health',
};

export const ACTIVITY_NAMES: Record<number, string> = {
  1: 'Open',
  2: 'Close',
  3: 'Traffic',
  4: 'HTTP',
  5: 'DNS',
  6: 'Packet',
  7: 'DHCP',
  10: 'Detect',
  20: 'Logon',
  21: 'Logoff',
  22: 'Connect',
  23: 'Disconnect',
  24: 'Roam',
  30: 'Create',
  31: 'Update',
  32: 'Delete',
  40: 'Tunnel up',
  41: 'Tunnel down',
  42: 'Client connect',
  43: 'Client disconnect',
  44: 'Tunnel stats',
  50: 'WAN down',
  51: 'WAN up',
  52: 'Latency',
  53: 'Packet loss',
  54: 'HA state',
  55: 'Device offline',
  56: 'Device online',
  57: 'Resource',
  58: 'Failover',
  59: 'Software',
};

export const ACTION_NAMES: Record<number, string> = {
  0: 'Unknown',
  1: 'Allow',
  2: 'Deny',
  3: 'Reject',
  4: 'Timeout close',
  99: 'Other',
};

export const DIRECTION_NAMES: Record<number, string> = {
  0: 'Unknown',
  1: 'Inbound',
  2: 'Outbound',
  3: 'Internal',
  4: 'External',
};

// CEF severity, 0-10: the normalized store's scale (info→2, low→3,
// medium/warning→5, high→7, critical→9). Not OCSF — the class ids follow OCSF,
// severity does not.
export const SEVERITY_NAMES: Record<number, string> = {
  0: 'Unknown',
  1: 'Info',
  2: 'Info',
  3: 'Low',
  4: 'Medium',
  5: 'Medium',
  6: 'High',
  7: 'High',
  8: 'Critical',
  9: 'Critical',
  10: 'Critical',
};

function label(map: Record<number, string>, value: number | null | undefined, raw = 'Unknown'): string {
  if (value === null || value === undefined) return raw;
  return map[value] ?? String(value);
}

export function classLabel(value: number | null | undefined): string {
  return label(CLASS_NAMES, value, '—');
}

export function activityLabel(value: number | null | undefined): string {
  return label(ACTIVITY_NAMES, value, '—');
}

export function actionLabel(value: number | null | undefined): string {
  return label(ACTION_NAMES, value, '—');
}

export function directionLabel(value: number | null | undefined): string {
  return label(DIRECTION_NAMES, value, '—');
}

export function severityLabel(value: number | null | undefined): string {
  return label(SEVERITY_NAMES, value, '—');
}

export interface EventBucket {
  hour?: string;
  day?: string;
  hits?: number;
  bytes_in?: number;
  bytes_out?: number;
}

function bucketTime(row: EventBucket): number | null {
  return bucketToMs(row.hour ?? row.day ?? '');
}

/** {hour|day, bytes_in, bytes_out} → bits per second (both directions). */
export function eventBytesSeries(
  rows: EventBucket[] | undefined,
  seconds: number,
): { timestamps: number[]; values: number[] } {
  const width = Number.isFinite(seconds) && seconds > 0 ? seconds : 0;
  const points: Array<{ ts: number; bps: number }> = [];
  for (const row of rows ?? []) {
    const ts = bucketTime(row);
    if (ts == null) continue;
    const bytes = (Number(row.bytes_in) || 0) + (Number(row.bytes_out) || 0);
    points.push({ ts, bps: width > 0 ? (bytes * 8) / width : 0 });
  }
  points.sort((a, b) => a.ts - b.ts);
  return { timestamps: points.map((p) => p.ts), values: points.map((p) => p.bps) };
}

/** Generic stats TimeBucket {bucket,count} → counts (syslog/trap/alerts). */
export function timeBucketSeries(
  buckets: Array<{ bucket: string; count: number }> | undefined,
): { timestamps: number[]; values: number[] } {
  const points: Array<{ ts: number; count: number }> = [];
  for (const bucket of buckets ?? []) {
    const ts = bucketToMs(bucket.bucket);
    if (ts == null) continue;
    points.push({ ts, count: Number(bucket.count) || 0 });
  }
  points.sort((a, b) => a.ts - b.ts);
  return { timestamps: points.map((p) => p.ts), values: points.map((p) => p.count) };
}

/** {hour|day, hits} → event counts. */
export function eventHitsSeries(rows: EventBucket[] | undefined): {
  timestamps: number[];
  values: number[];
} {
  const points: Array<{ ts: number; hits: number }> = [];
  for (const row of rows ?? []) {
    const ts = bucketTime(row);
    if (ts == null) continue;
    points.push({ ts, hits: Number(row.hits) || 0 });
  }
  points.sort((a, b) => a.ts - b.ts);
  return { timestamps: points.map((p) => p.ts), values: points.map((p) => p.hits) };
}


/**
 * One day-bucketed count from the security-event analytics.
 *
 * The server's `SecEventDayCount` is `{ day, count }` — a DATE string and
 * a count, not the `{ hits }` bucket the net-event analytics uses.
 */
export interface SecDayCount {
  day: string;
  count: number;
}

/**
 * A day-bucketed series for the chart.
 *
 * The day is a UTC calendar date, so it is parsed as UTC midnight. The
 * points are sorted oldest-first, because the chart draws them in order.
 */
export function secDayCountSeries(rows: SecDayCount[] | undefined): {
  timestamps: number[];
  values: number[];
} {
  const points: Array<{ ts: number; count: number }> = [];
  for (const row of rows ?? []) {
    const ts = Date.parse(`${row.day}T00:00:00Z`);
    if (!Number.isFinite(ts)) continue;
    points.push({ ts: ts / 1000, count: Number(row.count) || 0 });
  }
  points.sort((a, b) => a.ts - b.ts);
  return { timestamps: points.map((p) => p.ts), values: points.map((p) => p.count) };
}
