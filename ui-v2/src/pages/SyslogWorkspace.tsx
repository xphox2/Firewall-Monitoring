import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ScrollText, Search, Filter } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';
import { timeBucketSeries } from '@/lib/events';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { BarList } from '@/components/ui/bar-list';
import { DetailSection } from '@/components/ui/detail-section';
import { TimeSeriesChart } from '@/components/charts/time-series-chart';
import { ColumnDef } from '@tanstack/react-table';

interface SyslogRow {
  id: number;
  timestamp: string;
  device_id?: number;
  probe_id?: number;
  hostname?: string;
  app_name?: string;
  process_id?: string;
  message_id?: string;
  structured_data?: string;
  source_ip?: string;
  severity: number;
  facility?: number;
  priority?: number;
  message: string;
}

interface SyslogStats {
  total?: number;
  by_severity?: Array<{ key: string; count: number }>;
  over_time?: Array<{ bucket: string; count: number }>;
}

const SEVERITY_NAMES: Record<number, { label: string; badgeClass: string }> = {
  0: { label: '0 Emerg', badgeClass: 'bg-sig-crit/20 text-sig-crit' },
  1: { label: '1 Alert', badgeClass: 'bg-sig-crit/20 text-sig-crit' },
  2: { label: '2 Crit', badgeClass: 'bg-sig-crit/15 text-sig-crit' },
  3: { label: '3 Error', badgeClass: 'bg-sig-warn/20 text-sig-warn' },
  4: { label: '4 Warn', badgeClass: 'bg-sig-warn/15 text-sig-warn' },
  5: { label: '5 Notice', badgeClass: 'bg-accent/15 text-accent' },
  6: { label: '6 Info', badgeClass: 'bg-bg-panel text-text-dim' },
  7: { label: '7 Debug', badgeClass: 'bg-bg-panel text-text-faint' },
};

const FACILITIES: Record<number, string> = {
  0: 'kern',
  1: 'user',
  2: 'mail',
  3: 'daemon',
  4: 'auth',
  5: 'syslog',
  6: 'lpr',
  7: 'news',
  8: 'uucp',
  9: 'cron',
  10: 'authpriv',
  11: 'ftp',
  12: 'ntp',
  13: 'audit',
  14: 'alert',
  15: 'clock',
  16: 'local0',
  17: 'local1',
  18: 'local2',
  19: 'local3',
  20: 'local4',
  21: 'local5',
  22: 'local6',
  23: 'local7',
};

const RANGES = [
  { value: '1h', hours: 1 },
  { value: '24h', hours: 24 },
  { value: '7d', hours: 168 },
  { value: '30d', hours: 720 },
] as const;

type Range = (typeof RANGES)[number]['value'];

export function SyslogWorkspace() {
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [range, setRange] = useState<Range>('24h');
  const [selectedId, setSelectedId] = useState<number | null>(null);
  // Full-text search is a LIKE scan over the retention window (the handler says
  // so itself). Debounce so typing "severity" does not fire eight scans.
  const [debouncedSearch, setDebouncedSearch] = useState('');
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(searchQuery), 350);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  const hours = RANGES.find((r) => r.value === range)?.hours ?? 24;

  const { data: syslogRes, isLoading } = useQuery({
    queryKey: ['raw-syslog', hours, severityFilter, debouncedSearch],
    queryFn: () => {
      const params = new URLSearchParams({ limit: '100', hours: String(hours) });
      if (severityFilter !== '') params.set('severity', severityFilter);
      if (debouncedSearch.trim()) params.set('search', debouncedSearch.trim());
      return apiFetch<any>(`/admin/api/syslog?${params.toString()}`);
    },
    refetchInterval: 15_000,
  });

  const { data: stats, isError: statsError } = useQuery({
    queryKey: ['syslog-stats', hours],
    queryFn: () => apiFetch<SyslogStats>(`/admin/api/syslog/stats?hours=${hours}`),
    refetchInterval: 30_000,
  });

  const { data: detail } = useQuery({
    queryKey: ['syslog-detail', selectedId],
    queryFn: () => apiFetch<SyslogRow>(`/admin/api/syslog/${selectedId}`),
    enabled: Boolean(selectedId),
  });

  const messages: SyslogRow[] = Array.isArray(syslogRes)
    ? syslogRes
    : syslogRes?.messages ?? syslogRes?.items ?? syslogRes?.data ?? [];

  const chart = useMemo(() => timeBucketSeries(stats?.over_time), [stats]);
  // by_severity keys are display names ("Emergency", "Critical", …) from the
  // stats meter, not numeric ids.
  const severityRows = (stats?.by_severity ?? []).map((row) => ({
    key: row.key || 'Unknown',
    value: row.count,
  }));

  const columns = useMemo<ColumnDef<SyslogRow, unknown>[]>(
    () => [
      {
        accessorKey: 'timestamp',
        header: 'Time',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim whitespace-nowrap">
            {formatRelativeTime(row.original.timestamp)}
          </span>
        ),
      },
      {
        accessorKey: 'severity',
        header: 'Severity',
        cell: ({ row }) => {
          const sev = SEVERITY_NAMES[row.original.severity] ?? SEVERITY_NAMES[6];
          return (
            <span
              className={cn(
                'rounded px-2 py-0.5 font-mono text-[10px] font-semibold uppercase',
                sev.badgeClass,
              )}
            >
              {sev.label}
            </span>
          );
        },
      },
      {
        accessorKey: 'hostname',
        header: 'Source',
        cell: ({ row }) => (
          <div>
            <div className="font-mono text-xs text-text">
              {row.original.hostname || row.original.source_ip || `Dev #${row.original.device_id ?? '?'}`}
            </div>
            {row.original.app_name && (
              <div className="text-[10px] text-text-faint">{row.original.app_name}</div>
            )}
          </div>
        ),
      },
      {
        accessorKey: 'message',
        header: 'Raw Syslog Payload',
        cell: ({ row }) => (
          <div className="font-mono text-xs text-text truncate max-w-2xl">
            {row.original.message}
          </div>
        ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-border pb-3">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <ScrollText className="h-3.5 w-3.5" />
            Telemetry / Raw Syslog Explorer
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            Raw Syslog Stream & RFC5424/3164 Inspector
          </h1>
        </div>

        <div className="flex items-center gap-0.5 rounded-lg border border-border bg-bg-panel p-1">
          {RANGES.map((r) => (
            <button
              key={r.value}
              type="button"
              onClick={() => setRange(r.value)}
              className={cn(
                'rounded px-2 py-1 font-mono text-[11px] font-medium',
                range === r.value ? 'bg-accent text-white' : 'text-text-dim hover:text-text',
              )}
            >
              {r.value}
            </button>
          ))}
        </div>
      </div>

      {statsError && (
        <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit">
          Could not load syslog statistics.
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
        <div className="rounded-xl border border-border bg-bg-card p-4 xl:col-span-2">
          <TimeSeriesChart
            title={`Syslog volume — ${range}`}
            timestamps={chart.timestamps}
            series={[{ label: 'Messages', color: '#7DD3FC', values: chart.values }]}
            kind="count"
            emptyMessage="No syslog messages in this window."
          />
        </div>
        <div className="space-y-3">
          <div className="rounded-xl border border-border bg-bg-card p-3.5">
            <div className="text-[10px] uppercase text-text-faint">Messages in {range}</div>
            <div className="mt-0.5 font-mono text-lg font-bold text-text">{stats?.total ?? 0}</div>
          </div>
          <BarList title="Severity" rows={severityRows} empty="No severity data." />
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-bg-card p-2.5">
        <Filter className="h-3.5 w-3.5 text-text-faint ml-1" />
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          aria-label="Filter by syslog severity"
          className="rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text"
        >
          <option value="">All Severities (0-7)</option>
          {Object.entries(SEVERITY_NAMES).map(([k, v]) => (
            <option key={k} value={k}>
              {v.label}
            </option>
          ))}
        </select>

        <div className="relative flex-1 min-w-[200px]">
          <Search className="h-3.5 w-3.5 text-text-faint absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Full-text search raw syslog messages..."
            className="w-full rounded border border-border bg-bg-panel pl-8 pr-3 py-1 text-xs font-mono text-text focus:border-accent focus:outline-hidden"
          />
        </div>
      </div>

      <ResponsiveDataView
        data={messages}
        columns={columns}
        isLoading={isLoading}
        onRowClick={(row) => setSelectedId(row.id)}
        emptyTitle="No raw syslog messages matching filter."
        renderMobileCard={(msg) => (
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-semibold text-accent">
                {msg.hostname || msg.source_ip}
              </span>
              <span className="font-mono text-[11px] text-text-dim">
                {formatRelativeTime(msg.timestamp)}
              </span>
            </div>
            <div className="font-mono text-xs text-text line-clamp-2 break-all">{msg.message}</div>
          </div>
        )}
      />

      <SlideOverDrawer
        open={Boolean(selectedId)}
        onOpenChange={(open) => {
          if (!open) setSelectedId(null);
        }}
        title={`Syslog Message #${selectedId ?? ''}`}
        subtitle="RFC5424/3164 header and the raw payload."
        size="lg"
      >
        {!detail ? (
          <p className="p-6 text-center text-xs text-text-dim">Loading message…</p>
        ) : (
          <div className="space-y-4">
            <DetailSection
              title="Message"
              fields={[
                ['When', detail.timestamp ? new Date(detail.timestamp).toLocaleString() : '—'],
                ['Hostname', detail.hostname],
                ['Source IP', detail.source_ip],
                ['Device', detail.device_id ? `#${detail.device_id}` : ''],
                ['App', detail.app_name],
                ['Process', detail.process_id],
                ['Message ID', detail.message_id],
              ]}
            />
            <DetailSection
              title="Priority"
              fields={[
                ['Severity', SEVERITY_NAMES[detail.severity]?.label ?? String(detail.severity)],
                [
                  'Facility',
                  detail.facility !== undefined
                    ? `${detail.facility}${
                        FACILITIES[detail.facility] ? ` (${FACILITIES[detail.facility]})` : ''
                      }`
                    : '',
                ],
                [
                  'Priority',
                  detail.priority !== undefined ? String(detail.priority) : '',
                ],
              ]}
            />
            <DetailSection
              title="Structured data"
              fields={[['SD', detail.structured_data]]}
            />
            <div>
              <h4 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-text-faint">
                Raw payload
              </h4>
              <pre className="max-h-72 overflow-auto rounded-lg border border-border bg-bg-panel p-3 font-mono text-[11px] text-text whitespace-pre-wrap break-all">
                {detail.message}
              </pre>
            </div>
            <details className="rounded-lg border border-border bg-bg-card p-3">
              <summary className="cursor-pointer text-xs font-semibold text-text">
                Raw JSON
              </summary>
              <pre className="mt-2 max-h-64 overflow-auto rounded border border-border bg-bg-panel p-2 font-mono text-[10px] text-text-dim">
                {JSON.stringify(detail, null, 2)}
              </pre>
            </details>
          </div>
        )}
      </SlideOverDrawer>
    </div>
  );
}
