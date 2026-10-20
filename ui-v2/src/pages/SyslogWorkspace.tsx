import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ScrollText, Search, Filter } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { ColumnDef } from '@tanstack/react-table';

interface SyslogRow {
  id: number;
  timestamp: string;
  device_id?: number;
  device_name?: string;
  source_ip?: string;
  severity: number;
  facility?: number;
  message: string;
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

export function SyslogWorkspace() {
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const { data: syslogRes, isLoading } = useQuery({
    queryKey: ['raw-syslog', severityFilter, searchQuery],
    queryFn: () => {
      const params = new URLSearchParams({ limit: '100' });
      if (severityFilter !== '') params.set('severity', severityFilter);
      if (searchQuery.trim()) params.set('search', searchQuery.trim());
      return apiFetch<any>(`/admin/api/syslog?${params.toString()}`);
    },
    refetchInterval: 15_000,
  });

  const { data: detail } = useQuery({
    queryKey: ['syslog-detail', selectedId],
    queryFn: () => apiFetch<any>(`/admin/api/syslog/${selectedId}`),
    enabled: Boolean(selectedId),
  });

  const messages: SyslogRow[] = Array.isArray(syslogRes)
    ? syslogRes
    : syslogRes?.messages ?? syslogRes?.items ?? syslogRes?.data ?? [];

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
            <span className={cn('rounded px-2 py-0.5 font-mono text-[10px] font-semibold uppercase', sev.badgeClass)}>
              {sev.label}
            </span>
          );
        },
      },
      {
        accessorKey: 'device_name',
        header: 'Source',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text">
            {row.original.device_name || row.original.source_ip || `Dev #${row.original.device_id ?? '?'}`}
          </span>
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
    []
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
            className="w-full rounded border border-border bg-bg-panel pl-8 pr-3 py-1 text-xs font-mono text-text focus:border-accent focus:outline-none"
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
                {msg.device_name || msg.source_ip}
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
      >
        <pre className="rounded-lg border border-border bg-bg-panel p-3 font-mono text-xs text-text overflow-x-auto whitespace-pre-wrap">
          {JSON.stringify(detail ?? {}, null, 2)}
        </pre>
      </SlideOverDrawer>
    </div>
  );
}
