/**
 * Dialect time-bucket → epoch ms. Buckets are emitted as
 * "YYYY-MM-DD HH:MM[:SS]" (hour) or "YYYY-MM-DD" (day) in UTC, and as ISO on
 * drivers that format timestamps that way. Day-only strings are not valid ISO
 * with a Z suffix, so build midnight explicitly.
 */
export function bucketToMs(bucket: string): number | null {
  const raw = String(bucket ?? '').trim();
  if (!raw) return null;
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) return Date.parse(`${raw}T00:00:00Z`);
  let iso = raw.includes('T') ? raw : raw.replace(' ', 'T');
  if (!/(?:Z|[+-]\d{2}:?\d{2})$/.test(iso)) iso += 'Z';
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : null;
}
