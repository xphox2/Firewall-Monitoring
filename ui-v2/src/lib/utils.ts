import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number | null | undefined, decimals = 1): string {
  if (bytes === null || bytes === undefined || isNaN(bytes)) return '—';
  if (bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  const i = Math.min(Math.floor(Math.log(Math.abs(bytes)) / Math.log(k)), sizes.length - 1);
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

export function formatBps(bps: number | null | undefined, decimals = 1): string {
  if (bps === null || bps === undefined || isNaN(bps)) return '—';
  if (bps === 0) return '0 bps';
  const k = 1000;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
  const i = Math.min(Math.floor(Math.log(Math.abs(bps)) / Math.log(k)), sizes.length - 1);
  return `${parseFloat((bps / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

export function formatNumber(n: number | null | undefined): string {
  if (n === null || n === undefined || isNaN(n)) return '—';
  return new Intl.NumberFormat('en-US').format(n);
}

export function formatCompactNumber(n: number | null | undefined): string {
  if (n === null || n === undefined || isNaN(n)) return '—';
  if (Math.abs(n) < 1000) return String(n);
  return new Intl.NumberFormat('en-US', {
    notation: 'compact',
    maximumFractionDigits: 1,
  }).format(n);
}

export function formatRelativeTime(iso: string | null | undefined): string {
  if (!iso) return 'Never';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  const diffSec = Math.round((Date.now() - d.getTime()) / 1000);
  if (diffSec < 5) return 'just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ${diffMin % 60}m ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}

// Display timezone: shared app state, not a per-render localStorage read. The
// V1 console hydrated this and then re-rendered; V2 read localStorage in
// formatDateTime but nothing ever wrote it, so the setting was inert and
// timestamps never followed a change.
const TZ_STORAGE_KEY = 'display_timezone';
let tzVersion = 0;
const tzSubscribers = new Set<() => void>();

export function setDisplayTimezone(tz: string | null | undefined) {
  try {
    if (tz) localStorage.setItem(TZ_STORAGE_KEY, tz);
    else localStorage.removeItem(TZ_STORAGE_KEY);
  } catch {
    // storage blocked: keep the in-memory version bump so the UI still follows
  }
  tzVersion += 1;
  tzSubscribers.forEach((fn) => fn());
}

export function subscribeDisplayTimezone(fn: () => void): () => void {
  tzSubscribers.add(fn);
  return () => {
    tzSubscribers.delete(fn);
  };
}

export function getDisplayTimezoneVersion(): number {
  return tzVersion;
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  let tz: string | undefined;
  try {
    tz = localStorage.getItem(TZ_STORAGE_KEY) || undefined;
  } catch {
    tz = undefined;
  }
  try {
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
      ...(tz && tz !== 'local' ? { timeZone: tz } : {}),
    }).format(d);
  } catch {
    return d.toLocaleString();
  }
}

/** Date-only variant of formatDateTime (same display timezone, no time). */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  let tz: string | undefined;
  try {
    tz = localStorage.getItem(TZ_STORAGE_KEY) || undefined;
  } catch {
    tz = undefined;
  }
  try {
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      ...(tz && tz !== 'local' ? { timeZone: tz } : {}),
    }).format(d);
  } catch {
    return d.toLocaleDateString();
  }
}

export function countryCodeToFlag(cc: string | null | undefined): string {
  if (!cc || cc.length !== 2) return '';
  const upper = cc.toUpperCase();
  const c0 = upper.charCodeAt(0);
  const c1 = upper.charCodeAt(1);
  if (c0 < 65 || c0 > 90 || c1 < 65 || c1 > 90) return '';
  return String.fromCodePoint(0x1f1e6 + (c0 - 65), 0x1f1e6 + (c1 - 65));
}
