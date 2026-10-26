import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { RadioTower, Search, Filter } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';
import { timeBucketSeries } from '@/lib/events';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { SkeletonValue } from '@/components/ui/skeleton';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { BarList } from '@/components/ui/bar-list';
import { DetailSection } from '@/components/ui/detail-section';
import { TimeSeriesChart } from '@/components/charts/time-series-chart';
import { ColumnDef } from '@tanstack/react-table';

interface TrapRow {
  id: number;
  timestamp: string;
  device_id?: number;
  probe_id?: number;
  source_ip?: string;
  trap_oid: string;
  trap_type?: string;
  severity?: string;
  message?: string;
  processed?: boolean;
}

interface TrapStats {
  total?: number;
  by_severity?: Array<{ key: string; count: number }>;
  by_type?: Array<{ key: string; count: number }>;
  over_time?: Array<{ bucket: string; count: number }>;
}

const RANGES = [
  { value: '1h', hours: 1 },
  { value: '24h', hours: 24 },
  { value: '7d', hours: 168 },
  { value: '30d', hours: 720 },
] as const;

type Range = (typeof RANGES)[number]['value'];

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-sig-crit/15 text-sig-crit',
  high: 'bg-sig-crit/15 text-sig-crit',
  warning: 'bg-sig-warn/15 text-sig-warn',
  error: 'bg-sig-warn/15 text-sig-warn',
  info: 'bg-accent/15 text-accent',
};

export function TrapsWorkspace() {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [range, setRange] = useState<Range>('24h');
  const [selectedTrap, setSelectedTrap] = useState<TrapRow | null>(null);

  const hours = RANGES.find((r) => r.value === range)?.hours ?? 24;

  const { data: trapsRes, isLoading } = useQuery({
    // GetTraps filters by device_id/severity/trap_type/hours; `search` is
    // client-side over the loaded page (the server ignores it).
    queryKey: ['snmp-traps', hours, severityFilter],
    queryFn: () => {
      const params = new URLSearchParams({ limit: '100', hours: String(hours) });
      if (severityFilter) params.set('severity', severityFilter);
      return apiFetch<any>(`/admin/api/traps?${params.toString()}`);
    },
    refetchInterval: 15_000,
  });

  const { data: stats, isError: statsError, isLoading: statsLoading } = useQuery({
    queryKey: ['trap-stats', hours],
    queryFn: () => apiFetch<TrapStats>(`/admin/api/traps/stats?hours=${hours}`),
    refetchInterval: 30_000,
  });

  const allTraps: TrapRow[] = Array.isArray(trapsRes)
    ? trapsRes
    : trapsRes?.traps ?? trapsRes?.items ?? trapsRes?.data ?? [];

  const needle = searchQuery.trim().toLowerCase();
  const traps = needle
    ? allTraps.filter((t) =>
        [t.trap_oid, t.trap_type, t.source_ip, t.severity, t.message]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(needle)),
      )
    : allTraps;

  const chart = useMemo(() => timeBucketSeries(stats?.over_time), [stats]);
  const severityOptions = (stats?.by_severity ?? [])
    .map((row) => row.key)
    .filter((key) => key !== '');
  const severityRows = (stats?.by_severity ?? []).map((row) => ({
    key: row.key || 'unknown',
    value: row.count,
  }));
  const typeRows = (stats?.by_type ?? []).map((row) => ({ key: row.key, value: row.count }));

  const columns = useMemo<ColumnDef<TrapRow, unknown>[]>(
    () => [
      {
        accessorKey: 'timestamp',
        header: 'Time',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {formatRelativeTime(row.original.timestamp)}
          </span>
        ),
      },
      {
        accessorKey: 'source_ip',
        header: 'Source Device',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text">
            {row.original.source_ip || `Dev #${row.original.device_id ?? '?'}`}
          </span>
        ),
      },
      {
        accessorKey: 'trap_type',
        header: 'Trap Type / OID',
        cell: ({ row }) => (
          <div>
            <div className="font-semibold text-xs text-text">
              {row.original.trap_type || 'SNMP Trap'}
            </div>
            <div className="font-mono text-[11px] text-accent">{row.original.trap_oid}</div>
          </div>
        ),
      },
      {
        accessorKey: 'severity',
        header: 'Severity',
        cell: ({ row }) => (
          <span
            className={cn(
              'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
              SEVERITY_STYLE[(row.original.severity ?? '').toLowerCase()] ??
                'bg-bg-panel text-text-dim',
            )}
          >
            {row.original.severity || '—'}
          </span>
        ),
      },
      {
        accessorKey: 'message',
        header: 'Message',
        cell: ({ row }) => (
          <span className="line-clamp-2 max-w-xl text-[11px] text-text-dim">
            {row.original.message || '—'}
          </span>
        ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3 border-b border-border pb-3">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <RadioTower className="h-3.5 w-3.5" />
            Telemetry / SNMP Traps Explorer
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            Real-Time SNMPv2c / v3 Trap Stream & VarBind Inspector
          </h1>
        </div>

        <div className="flex flex-wrap items-center gap-2">
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
          <div className="relative w-full sm:w-64">
            <Search className="h-3.5 w-3.5 text-text-faint absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by OID or trap type..."
              className="w-full rounded border border-border bg-bg-card pl-8 pr-3 py-1.5 text-xs font-mono text-text focus:border-accent focus:outline-hidden"
            />
          </div>
        </div>
      </div>

      {statsError && (
        <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit">
          Could not load trap statistics.
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
        <div className="rounded-xl border border-border bg-bg-card p-4 xl:col-span-2">
          <TimeSeriesChart
            title={`Trap volume — ${range}`}
            timestamps={chart.timestamps}
            series={[{ label: 'Traps', color: '#FCD34D', values: chart.values }]}
            kind="count"
            emptyMessage="No traps in this window."
          />
        </div>
        <div className="space-y-3">
          <div className="rounded-xl border border-border bg-bg-card p-3.5">
            <div className="text-[10px] uppercase text-text-faint">Traps in {range}</div>
            <div className="mt-0.5 font-mono text-lg font-bold text-text">
              <SkeletonValue loading={statsLoading} width="w-12" height="1.25rem" />
              {statsLoading ? null : (stats?.total ?? 0)}
            </div>
          </div>
          <BarList title="Severity" rows={severityRows} empty="No severity data." />
        </div>
      </div>

      {typeRows.length > 0 && (
        <BarList title="Top trap types" rows={typeRows} empty="No trap type data." />
      )}

      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-bg-card p-2.5">
        <Filter className="h-3.5 w-3.5 text-text-faint ml-1" />
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          aria-label="Filter by trap severity"
          className="rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text"
        >
          <option value="">All severities</option>
          {severityOptions.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
        <button
          type="button"
          onClick={() => setSeverityFilter('')}
          className="ml-auto rounded border border-border bg-bg-panel px-2.5 py-1 text-[11px] text-text-dim hover:text-text"
        >
          Clear
        </button>
      </div>

      <ResponsiveDataView
        data={traps}
        columns={columns}
        isLoading={isLoading}
        onRowClick={(row) => setSelectedTrap(row)}
        emptyTitle="No SNMP traps received in this window."
        renderMobileCard={(t) => (
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs text-text">{t.trap_type || 'SNMP Trap'}</span>
              <span className="font-mono text-[11px] text-text-dim">
                {formatRelativeTime(t.timestamp)}
              </span>
            </div>
            <div className="font-mono text-xs text-accent break-all">{t.trap_oid}</div>
            {t.message && <div className="text-[11px] text-text-dim">{t.message}</div>}
          </div>
        )}
      />

      <SlideOverDrawer
        open={Boolean(selectedTrap)}
        onOpenChange={(open) => {
          if (!open) setSelectedTrap(null);
        }}
        title="SNMP Trap Inspector"
        subtitle={selectedTrap?.trap_oid}
        size="lg"
      >
        {selectedTrap && (
          <div className="space-y-4">
            <DetailSection
              title="Trap"
              fields={[
                [
                  'When',
                  selectedTrap.timestamp
                    ? new Date(selectedTrap.timestamp).toLocaleString()
                    : '—',
                ],
                ['OID', selectedTrap.trap_oid],
                ['Type', selectedTrap.trap_type],
                ['Severity', selectedTrap.severity],
              ]}
            />
            <DetailSection
              title="Source"
              fields={[
                ['Source IP', selectedTrap.source_ip],
                ['Device', selectedTrap.device_id ? `#${selectedTrap.device_id}` : ''],
                ['Probe', selectedTrap.probe_id ? `#${selectedTrap.probe_id}` : ''],
              ]}
            />
            <DetailSection title="Message" fields={[['Message', selectedTrap.message]]} />
            <details className="rounded-lg border border-border bg-bg-card p-3">
              <summary className="cursor-pointer text-xs font-semibold text-text">
                Raw JSON
              </summary>
              <pre className="mt-2 max-h-64 overflow-auto rounded border border-border bg-bg-panel p-2 font-mono text-[10px] text-text-dim">
                {JSON.stringify(selectedTrap, null, 2)}
              </pre>
            </details>
          </div>
        )}
      </SlideOverDrawer>
    </div>
  );
}
