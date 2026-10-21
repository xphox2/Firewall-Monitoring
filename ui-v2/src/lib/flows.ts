import { bucketToMs } from './time-buckets';

export { bucketToMs } from './time-buckets';

export interface FlowFilters {
  deviceId: string;
  protocol: string;
  src: string;
  dst: string;
  dstPort: string;
  flowSource: string;
  firewallEvent: string;
}

export const EMPTY_FLOW_FILTERS: FlowFilters = {
  deviceId: '',
  protocol: '',
  src: '',
  dst: '',
  dstPort: '',
  flowSource: '',
  firewallEvent: '',
};

export const FLOW_RANGES = [
  { value: '1h', hours: 1 },
  { value: '6h', hours: 6 },
  { value: '12h', hours: 12 },
  { value: '24h', hours: 24 },
  { value: '7d', hours: 168 },
  { value: '30d', hours: 720 },
  { value: '90d', hours: 2160 },
] as const;

export type FlowRange = (typeof FLOW_RANGES)[number]['value'];

export const PROTOCOL_OPTIONS = [
  { value: '6', label: 'TCP' },
  { value: '17', label: 'UDP' },
  { value: '1', label: 'ICMP' },
  { value: '47', label: 'GRE' },
  { value: '50', label: 'ESP' },
  { value: '132', label: 'SCTP' },
];

export const FLOW_SOURCE_OPTIONS = [
  { value: '0', label: 'sFlow' },
  { value: '1', label: 'NetFlow v5' },
  { value: '2', label: 'NetFlow v9' },
  { value: '3', label: 'IPFIX' },
];

export const FIREWALL_EVENT_OPTIONS = [
  { value: '1', label: 'Created' },
  { value: '2', label: 'Deleted' },
  { value: '3', label: 'Denied' },
  { value: '4', label: 'Alert' },
  { value: '5', label: 'Update' },
];

/** The server silently ignores an out-of-range/malformed dst_port. */
export function isValidDstPort(value: string): boolean {
  const text = value.trim();
  if (!text) return true;
  if (!/^\d+$/.test(text)) return false;
  const port = Number(text);
  return port >= 1 && port <= 65535;
}

/**
 * Permissive address/CIDR check. The server's ipFilterClause silently drops a
 * value it cannot parse, so the UI must not claim the filter is applied when
 * the value is obviously malformed (letters, spaces, multiple slashes).
 */
export function isLikelyAddress(value: string): boolean {
  const text = value.trim();
  if (!text) return true;
  if (!/^[0-9a-fA-F:.\/]+$/.test(text)) return false;
  if ((text.match(/\//g) ?? []).length > 1) return false;

  const [addr, maskText] = text.split('/');
  if (!addr) return false;
  const v4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(addr);
  const v6 = addr.includes(':');
  if (!v4 && !v6) return false;
  if (v4 && !addr.split('.').every((octet) => Number(octet) <= 255)) return false;
  if (maskText !== undefined) {
    if (!/^\d+$/.test(maskText)) return false;
    const mask = Number(maskText);
    // A mask the server cannot parse becomes a literal string comparison and
    // silently matches nothing.
    if (v4 && mask > 32) return false;
    if (v6 && mask > 128) return false;
  }
  return true;
}

/** Query string shared by /flows/stats and /flows (samples). */
export function buildFlowQuery(
  filters: FlowFilters,
  hours: number,
  opts: { limit?: number; offset?: number } = {},
): string {
  const params = new URLSearchParams({ hours: String(hours) });
  if (opts.limit != null) params.set('limit', String(opts.limit));
  if (opts.offset != null) params.set('offset', String(Math.max(0, opts.offset)));
  if (filters.deviceId) params.set('device_id', filters.deviceId);
  if (filters.protocol) params.set('protocol', filters.protocol);
  // Only send values the server will actually honour; otherwise the filter
  // row would claim a constraint that is not applied.
  if (filters.src.trim() && isLikelyAddress(filters.src)) params.set('src_addr', filters.src.trim());
  if (filters.dst.trim() && isLikelyAddress(filters.dst)) params.set('dst_addr', filters.dst.trim());
  if (filters.dstPort.trim() && isValidDstPort(filters.dstPort)) {
    params.set('dst_port', filters.dstPort.trim());
  }
  if (filters.flowSource) params.set('flow_source', filters.flowSource);
  if (filters.firewallEvent) params.set('firewall_event', filters.firewallEvent);
  return params.toString();
}

export interface BytesPoint {
  ts: number;
  bps: number;
}

/** bytes-per-bucket → bits per second using the server's bucket width. */
export function bytesToBpsPoints(
  buckets: Array<{ bucket: string; count: number }> | undefined,
  bucketSeconds: number,
): { timestamps: number[]; values: number[] } {
  const seconds = Number.isFinite(bucketSeconds) && bucketSeconds > 0 ? bucketSeconds : 0;
  const points: BytesPoint[] = [];
  for (const bucket of buckets ?? []) {
    const ts = bucketToMs(bucket.bucket);
    if (ts == null) continue;
    const bytes = Number(bucket.count) || 0;
    points.push({ ts, bps: seconds > 0 ? (bytes * 8) / seconds : 0 });
  }
  points.sort((a, b) => a.ts - b.ts);
  return {
    timestamps: points.map((p) => p.ts),
    values: points.map((p) => p.bps),
  };
}

const CSV_COLUMNS: Array<{ key: string; label: string }> = [
  { key: 'timestamp', label: 'timestamp' },
  { key: 'device_id', label: 'device_id' },
  { key: 'src_addr', label: 'src_addr' },
  { key: 'src_port', label: 'src_port' },
  { key: 'dst_addr', label: 'dst_addr' },
  { key: 'dst_port', label: 'dst_port' },
  { key: 'service_port', label: 'service_port' },
  { key: 'protocol', label: 'protocol' },
  { key: 'bytes', label: 'bytes' },
  { key: 'packets', label: 'packets' },
  { key: 'tcp_flags', label: 'tcp_flags' },
  { key: 'sampling_rate', label: 'sampling_rate' },
  { key: 'flow_source', label: 'flow_source' },
  { key: 'firewall_event', label: 'firewall_event' },
  { key: 'app_category', label: 'app_category' },
  { key: 'direction', label: 'direction' },
  { key: 'dst_country', label: 'dst_country' },
  { key: 'dst_asn', label: 'dst_asn' },
];

function csvCell(value: unknown): string {
  if (value == null) return '';
  let text = String(value);
  // Spreadsheet formula injection: a leading = + - @ is executed by Excel and
  // Sheets, which also strip a leading tab/newline first, so neutralise both.
  if (/^[\t\r\n]*[=+\-@]/.test(text)) text = `'${text}`;
  if (/[",\n\r]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

/** RFC-4180 CSV for the current (filtered) sample set, capped by the caller. */
export function exportFlowsCsv(rows: Array<Record<string, unknown>>): string {
  const lines = [CSV_COLUMNS.map((c) => c.label).join(',')];
  for (const row of rows) {
    lines.push(CSV_COLUMNS.map((c) => csvCell(row[c.key])).join(','));
  }
  return lines.join('\r\n');
}
