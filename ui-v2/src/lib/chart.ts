export interface ChartSeries {
  label: string;
  color: string;
  values: Array<number | null>;
}

export type ChartKind = 'percent' | 'bps' | 'bytes' | 'count';

/** Median gap between buckets, in seconds. 0 when the series is too short. */
export function bucketSeconds(timestamps: number[]): number {
  if (timestamps.length < 2) return 0;
  const diffs: number[] = [];
  for (let i = 1; i < timestamps.length; i += 1) diffs.push(timestamps[i]! - timestamps[i - 1]!);
  diffs.sort((a, b) => a - b);
  const median = diffs[Math.floor(diffs.length / 2)] ?? 0;
  return median > 0 ? median / 1000 : 0;
}

/**
 * Interface/VPN buckets carry the bytes moved IN each bucket, not a rate.
 * Divide by the bucket span so the chart shows throughput at every range
 * (a 5-minute bucket and a 1-day bucket then share the same y unit).
 */
export function toBitsPerSecond(
  values: Array<number | null>,
  seconds: number,
): Array<number | null> {
  if (!seconds) return values.map(() => null);
  return values.map((v) => (v == null ? null : (v * 8) / seconds));
}

/**
 * Interface charts carry CUMULATIVE octet counters averaged per bucket, not
 * per-bucket deltas. Throughput is the consecutive-bucket delta (clamped at 0
 * across counter resets/wraps) over the actual interval — the same rule the
 * classic console uses. Using the raw value plots a rising staircase.
 */
export function counterDeltasToBps(
  values: Array<number | null>,
  timestampsMs: number[],
): Array<number | null> {
  const out: Array<number | null> = [];
  for (let i = 0; i < values.length; i += 1) {
    const current = values[i];
    const previous = i > 0 ? values[i - 1] : null;
    if (i === 0 || current == null || previous == null) {
      out.push(null);
      continue;
    }
    const seconds = (timestampsMs[i]! - timestampsMs[i - 1]!) / 1000;
    if (!(seconds > 0)) {
      out.push(null);
      continue;
    }
    const delta = Math.max(0, current - previous);
    out.push((delta * 8) / seconds);
  }
  return out;
}

export function formatBitsPerSecond(value: number): string {
  if (!Number.isFinite(value)) return '—';
  if (value >= 1e12) return `${(value / 1e12).toFixed(2)} Tbps`;
  if (value >= 1e9) return `${(value / 1e9).toFixed(1)} Gbps`;
  if (value >= 1e6) return `${(value / 1e6).toFixed(1)} Mbps`;
  if (value >= 1e3) return `${(value / 1e3).toFixed(1)} Kbps`;
  return `${Math.round(value)} bps`;
}

export function formatAxisValue(value: number, kind: ChartKind): string {
  if (!Number.isFinite(value)) return '';
  if (kind === 'percent') return `${Math.round(value)}%`;
  if (kind === 'count') {
    if (Math.abs(value) >= 1e6) return `${(value / 1e6).toFixed(1)}M`;
    if (Math.abs(value) >= 1e3) return `${(value / 1e3).toFixed(0)}K`;
    return String(Math.round(value));
  }
  if (kind === 'bps') {
    if (Math.abs(value) >= 1e12) return `${(value / 1e12).toFixed(2)}T`;
    if (Math.abs(value) >= 1e9) return `${(value / 1e9).toFixed(1)}G`;
    if (Math.abs(value) >= 1e6) return `${(value / 1e6).toFixed(0)}M`;
    if (Math.abs(value) >= 1e3) return `${(value / 1e3).toFixed(0)}K`;
    return `${Math.round(value)}`;
  }
  if (Math.abs(value) >= 1e12) return `${(value / 1e12).toFixed(2)}TB`;
  if (Math.abs(value) >= 1e9) return `${(value / 1e9).toFixed(1)}GB`;
  if (Math.abs(value) >= 1e6) return `${(value / 1e6).toFixed(0)}MB`;
  if (Math.abs(value) >= 1e3) return `${(value / 1e3).toFixed(0)}KB`;
  return `${Math.round(value)}B`;
}

export function formatValue(value: number | null, kind: ChartKind): string {
  if (value == null || !Number.isFinite(value)) return '—';
  if (kind === 'percent') return `${value.toFixed(1)}%`;
  if (kind === 'count') return `${Math.round(value)}`;
  if (kind === 'bps') return formatBitsPerSecond(value);
  return formatAxisValue(value, 'bytes');
}

/** Numeric coercion for JSON values that may be null/strings. */
export function numOrNull(value: unknown): number | null {
  if (value == null || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}
