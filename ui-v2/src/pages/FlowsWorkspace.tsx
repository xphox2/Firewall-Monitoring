import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ArrowRight, Check, Download, Filter, Waves } from 'lucide-react';
import { apiFetch, ApiError } from '@/lib/api';
import { cn, formatBytes, formatCompactNumber, formatRelativeTime } from '@/lib/utils';
import { formatBitsPerSecond } from '@/lib/chart';
import {
  EMPTY_FLOW_FILTERS,
  FIREWALL_EVENT_OPTIONS,
  FLOW_RANGES,
  FLOW_SOURCE_OPTIONS,
  PROTOCOL_OPTIONS,
  buildFlowQuery,
  bytesToBpsPoints,
  exportFlowsCsv,
  isLikelyAddress,
  isValidDstPort,
  type FlowFilters,
  type FlowRange,
} from '@/lib/flows';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { LongOpStatus } from '@/components/ui/progress-bar';
import { SkeletonChart } from '@/components/ui/skeleton';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { TimeSeriesChart } from '@/components/charts/time-series-chart';
import { useToast } from '@/components/ui/toast';
import { ColumnDef } from '@tanstack/react-table';

type FlowsTab = 'talkers' | 'conversations' | 'samples' | 'detections';

interface FlowKeyCount {
  key: string;
  count: number;
  records?: number;
}

interface FlowPortCount {
  key: string;
  port: number;
  count: number;
}

interface FlowConversation {
  src_addr: string;
  dst_addr: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  bytes: number;
  packets: number;
}

interface FlowStats {
  total_flows?: number;
  total_bytes?: number;
  total_packets?: number;
  bits_per_second?: number;
  unique_sources?: number;
  unique_dests?: number;
  protocol_count?: number;
  bucket_seconds?: number;
  avg_sampling_rate?: number;
  by_protocol?: FlowKeyCount[];
  by_category?: FlowKeyCount[];
  by_direction?: FlowKeyCount[];
  top_countries?: FlowKeyCount[];
  top_asns?: FlowKeyCount[];
  top_sources?: FlowKeyCount[];
  top_destinations?: FlowKeyCount[];
  top_services?: FlowPortCount[];
  top_conversations?: FlowConversation[];
  bytes_over_time?: Array<{ bucket: string; count: number }>;
  local_traffic?: { bytes?: number; packets?: number; flows?: number };
  mixed_source_devices?: string[];
  geo_enabled?: boolean;
  geo_source?: string;
  degraded?: boolean;
  degraded_blocks?: string[];
  partial_blocks?: string[];
  partial_reasons?: Record<string, string>;
  unique_approximate?: boolean;
  sampling_rate_min?: number;
  sampling_rate_max?: number;
}

interface FlowSample {
  id?: number;
  timestamp?: string;
  device_id?: number;
  src_addr?: string;
  src_port?: number;
  dst_addr?: string;
  dst_port?: number;
  protocol?: number | string;
  bytes?: number;
  packets?: number;
  tcp_flags?: number;
  sampling_rate?: number;
  flow_source?: number;
  firewall_event?: number;
  app_category?: number | string;
  direction?: number | string;
  dst_country?: string;
  dst_asn?: number;
  service_port?: number;
}

const BLOCK_LABELS: Record<string, string> = {
  totals: 'Totals',
  by_protocol: 'Protocols',
  by_category: 'Applications',
  by_direction: 'Directions',
  top_countries: 'Countries',
  top_asns: 'ASNs',
  top_sources: 'Top sources',
  top_destinations: 'Top destinations',
  top_conversations: 'Conversations',
  top_services: 'Services',
  bytes_over_time: 'Throughput',
  unique_src_addr: 'Unique sources',
  unique_dst_addr: 'Unique destinations',
  sampling: 'Sampling',
};

function blockLabel(block: string): string {
  return BLOCK_LABELS[block] ?? block.replace(/_/g, ' ');
}

function protocolLabel(value: number | string | undefined): string {
  if (value === undefined || value === null) return '—';
  const found = PROTOCOL_OPTIONS.find((p) => p.value === String(value));
  if (found) return found.label;
  return String(value);
}

function samplingLabel(stats: FlowStats | undefined): string {
  const min = stats?.sampling_rate_min ?? 0;
  const max = stats?.sampling_rate_max ?? stats?.avg_sampling_rate ?? 0;
  if (max <= 0) return 'unsampled';
  if (min <= 0 || Math.round(min) === Math.round(max)) return `1:${Math.round(max)}`;
  return `1:${Math.round(min)}–1:${Math.round(max)}`;
}

function rangeHours(range: FlowRange): number {
  return FLOW_RANGES.find((r) => r.value === range)?.hours ?? 1;
}

export function FlowsWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = (searchParams.get('tab') as FlowsTab) || 'talkers';
  const [range, setRange] = useState<FlowRange>('1h');
  const [filters, setFilters] = useState<FlowFilters>(EMPTY_FLOW_FILTERS);

  const hours = rangeHours(range);
  // Filter text inputs feed multi-query stats runs; committing on every
  // keystroke would fire a dozen expensive requests while a CIDR is typed.
  const [appliedFilters, setAppliedFilters] = useState(filters);
  useEffect(() => {
    const timer = setTimeout(() => setAppliedFilters(filters), 350);
    return () => clearTimeout(timer);
  }, [filters]);

  const { data: devices = [] } = useQuery({
    queryKey: ['flow-devices'],
    queryFn: () => apiFetch<Array<{ id: number; name: string }>>('/admin/api/devices'),
  });

  const {
    data: stats,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ['flow-stats', hours, appliedFilters],
    queryFn: () =>
      apiFetch<FlowStats>(`/admin/api/flows/stats?${buildFlowQuery(appliedFilters, hours)}`),
    refetchInterval: 20_000,
  });

  const setTab = useCallback(
    (tab: FlowsTab) => {
      setSearchParams({ tab }, { replace: true });
    },
    [setSearchParams],
  );

  const drillConversation = useCallback(
    (conversation: FlowConversation) => {
      const next = { ...filters, dst: conversation.dst_addr, dstPort: String(conversation.dst_port) };
      setFilters(next);
      // Bypass the debounce for a drill: the samples tab must not render the
      // pre-drill row set for the next 350 ms.
      setAppliedFilters(next);
      setTab('samples');
    },
    [filters, setTab],
  );

  const activeFilterCount = Object.entries(filters).filter(([, value]) =>
    typeof value === 'boolean' ? value : String(value).trim() !== '',
  ).length;

  return (
    <div className="space-y-4">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3 border-b border-border pb-3">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <Waves className="h-3.5 w-3.5" />
            Telemetry / Network Flows (sFlow & NetFlow)
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            Throughput, Top Talkers, Conversations & Detections
          </h1>
        </div>

        <div className="flex items-center gap-1 rounded-lg border border-border bg-bg-panel p-1">
          {(
            [
              { id: 'talkers', label: 'Traffic' },
              { id: 'conversations', label: 'Conversations' },
              { id: 'samples', label: 'Samples' },
              { id: 'detections', label: 'Detections' },
            ] as const
          ).map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={cn(
                'rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
                activeTab === t.id
                  ? 'bg-bg-card text-text shadow-xs border border-border'
                  : 'text-text-dim hover:text-text',
              )}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-2 rounded-lg border border-border bg-bg-card p-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-0.5 rounded-md border border-border bg-bg-panel p-0.5">
            {FLOW_RANGES.map((r) => (
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

          <Filter className="ml-1 h-3.5 w-3.5 text-text-faint" />
          <select
            value={filters.deviceId}
            onChange={(e) => setFilters((f) => ({ ...f, deviceId: e.target.value }))}
            aria-label="Filter by device"
            className="rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text"
          >
            <option value="">All devices</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name}
              </option>
            ))}
          </select>
          <select
            value={filters.protocol}
            onChange={(e) => setFilters((f) => ({ ...f, protocol: e.target.value }))}
            aria-label="Filter by protocol"
            className="rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text"
          >
            <option value="">All protocols</option>
            {PROTOCOL_OPTIONS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
          </select>
          <select
            value={filters.flowSource}
            onChange={(e) => setFilters((f) => ({ ...f, flowSource: e.target.value }))}
            aria-label="Filter by exporter"
            className="rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text"
          >
            <option value="">Any exporter</option>
            {FLOW_SOURCE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <select
            value={filters.firewallEvent}
            onChange={(e) => setFilters((f) => ({ ...f, firewallEvent: e.target.value }))}
            aria-label="Filter by firewall event"
            className="rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text"
          >
            <option value="">Any firewall event</option>
            {FIREWALL_EVENT_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            value={filters.src}
            onChange={(e) => setFilters((f) => ({ ...f, src: e.target.value }))}
            placeholder="src IP / CIDR"
            aria-label="Filter by source address"
            className="w-40 rounded border border-border bg-bg-panel px-2.5 py-1 font-mono text-xs text-text"
          />
          <input
            type="text"
            value={filters.dst}
            onChange={(e) => setFilters((f) => ({ ...f, dst: e.target.value }))}
            placeholder="dst IP / CIDR"
            aria-label="Filter by destination address"
            className="w-40 rounded border border-border bg-bg-panel px-2.5 py-1 font-mono text-xs text-text"
          />
          <input
            type="text"
            value={filters.dstPort}
            onChange={(e) => setFilters((f) => ({ ...f, dstPort: e.target.value }))}
            placeholder="dst port"
            inputMode="numeric"
            aria-label="Filter by destination port"
            className="w-24 rounded border border-border bg-bg-panel px-2.5 py-1 font-mono text-xs text-text"
          />
          <button
            type="button"
            onClick={() => {
              setFilters(EMPTY_FLOW_FILTERS);
              setAppliedFilters(EMPTY_FLOW_FILTERS);
            }}
            className="ml-auto rounded border border-border bg-bg-panel px-2.5 py-1 text-[11px] text-text-dim hover:text-text"
          >
            Clear ({activeFilterCount})
          </button>
        </div>

        {(!isValidDstPort(filters.dstPort) ||
          !isLikelyAddress(filters.src) ||
          !isLikelyAddress(filters.dst)) && (
          <p className="text-[10px] text-sig-warn">
            Ignored by the server:{' '}
            {[
              !isValidDstPort(filters.dstPort) ? 'dst port must be 1–65535' : null,
              !isLikelyAddress(filters.src) ? 'source must be an IP or CIDR' : null,
              !isLikelyAddress(filters.dst) ? 'destination must be an IP or CIDR' : null,
            ]
              .filter(Boolean)
              .join(' · ')}
          </p>
        )}
      </div>

      {isError && (
        <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit">
          Could not load flow statistics: {error instanceof Error ? error.message : 'request failed'}
        </div>
      )}

      {activeTab === 'talkers' && (
        <TrafficOverview stats={stats} isLoading={isLoading} range={range} />
      )}
      {activeTab === 'conversations' && (
        <ConversationsTab
          conversations={stats?.top_conversations ?? []}
          isLoading={isLoading}
          onDrill={drillConversation}
        />
      )}
      {activeTab === 'samples' && (
        <SamplesTab hours={hours} filters={appliedFilters} range={range} />
      )}
      {activeTab === 'detections' && <FlowDetectionsSubTab />}
    </div>
  );
}

function Tile({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-border bg-bg-card p-3">
      <div className="text-[10px] uppercase text-text-faint">{label}</div>
      <div className={cn('mt-0.5 font-mono text-lg font-bold', tone ?? 'text-text')}>{value}</div>
    </div>
  );
}

function FlowBars({
  title,
  rows,
  empty,
  subtitle,
  labelFor,
}: {
  title: string;
  rows: Array<{ key: string; count: number }> | undefined;
  empty: string;
  subtitle?: string;
  labelFor?: (row: { key: string; count: number }) => string;
}) {
  const items = (rows ?? []).slice(0, 8);
  const max = Math.max(1, ...items.map((r) => Number(r.count) || 0));
  return (
    <div className="rounded-xl border border-border bg-bg-card p-3.5">
      <div className="mb-2 flex items-baseline justify-between gap-2">
        <h3 className="text-xs font-semibold text-text">{title}</h3>
        {subtitle && <span className="text-[10px] text-text-faint">{subtitle}</span>}
      </div>
      {items.length === 0 ? (
        <p className="py-2 text-[11px] text-text-faint">{empty}</p>
      ) : (
        <div className="space-y-1.5">
          {items.map((row, idx) => (
            <div key={`${row.key}-${idx}`} className="space-y-0.5">
              <div className="flex items-center justify-between gap-2 font-mono text-[11px]">
                <span className="min-w-0 truncate text-text">
                  {labelFor ? labelFor(row) : row.key || '—'}
                </span>
                <span className="shrink-0 text-text-dim">{formatBytes(row.count ?? 0)}</span>
              </div>
              <div className="h-1 overflow-hidden rounded-full bg-bg-panel">
                <div
                  className="h-full rounded-full bg-accent/70"
                  style={{ width: `${Math.max(2, ((Number(row.count) || 0) / max) * 100)}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function TrafficOverview({
  stats,
  isLoading,
  range,
}: {
  stats: FlowStats | undefined;
  isLoading: boolean;
  range: FlowRange;
}) {
  const chart = useMemo(
    () => bytesToBpsPoints(stats?.bytes_over_time, stats?.bucket_seconds ?? 0),
    [stats],
  );

  if (isLoading && !stats) {
    return (
      <div className="space-y-3">
        {/*
          The long-running row. V1's flows page said what it was doing and
          how long it had been working, because the aggregate can take a
          minute on a large range and a spinner alone reads as "stuck".
        */}
        <LongOpStatus
          active
          title={`Flow statistics — ${range}`}
          step="Aggregating sFlow / NetFlow samples…"
        />
        {/*
          The shape-preserving placeholder. V1's dashboard modules showed
          their shape while the first payload was in flight rather than
          collapsing to one centred spinner.
        */}
        <SkeletonChart height={220} />
      </div>
    );
  }

  const local = stats?.local_traffic;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2.5">
        <Tile
          label="Throughput"
          value={formatBitsPerSecond(stats?.bits_per_second ?? 0)}
          tone="text-accent"
        />
        <Tile label="Flows" value={formatCompactNumber(stats?.total_flows ?? 0)} />
        <Tile label="Volume" value={formatBytes(stats?.total_bytes ?? 0)} />
        <Tile label="Packets" value={formatCompactNumber(stats?.total_packets ?? 0)} />
        <Tile
          label="Unique src → dst"
          value={`${formatCompactNumber(stats?.unique_sources ?? 0)} → ${formatCompactNumber(
            stats?.unique_dests ?? 0,
          )}${stats?.unique_approximate ? ' (approx.)' : ''}${
            stats?.degraded ? ' (partial)' : ''
          }`}
        />
        <Tile label="Sampling" value={samplingLabel(stats)} />
      </div>

      {stats?.degraded && (
        <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-[11px] text-sig-crit">
          <strong>Partial window.</strong> The rolled-up aggregates did not complete in time, so
          the figures cover less than the requested {range} — in the worst case only the last hour
          still held in raw samples. Affected panels:{' '}
          <span className="font-mono">
            {(stats.degraded_blocks ?? []).map(blockLabel).join(', ') || 'unknown'}
          </span>
          .
        </div>
      )}

      {(stats?.partial_blocks ?? []).length > 0 && (
        <div className="rounded-lg border border-sig-warn/40 bg-sig-warn/10 px-3 py-2 text-[11px] text-sig-warn">
          Incomplete panels:{' '}
          {(stats?.partial_blocks ?? [])
            .map(
              (block) =>
                `${blockLabel(block)} (${stats?.partial_reasons?.[block] ?? 'partial'})`,
            )
            .join('; ')}
          .
        </div>
      )}

      {((local?.flows ?? 0) > 0 || (stats?.mixed_source_devices ?? []).length > 0) && (
        <div className="space-y-1.5">
          {(local?.flows ?? 0) > 0 && (
            <div className="rounded-lg border border-border bg-bg-panel px-3 py-2 text-[11px] text-text-dim">
              Scope-local noise excluded from the rankings:{' '}
              <span className="font-mono text-text">{formatCompactNumber(local?.flows ?? 0)}</span>{' '}
              flows, <span className="font-mono text-text">{formatBytes(local?.bytes ?? 0)}</span>{' '}
              (link-local, multicast, broadcast, loopback).
            </div>
          )}
          {(stats?.mixed_source_devices ?? []).length > 0 && (
            <div className="rounded-lg border border-sig-warn/40 bg-sig-warn/10 px-3 py-2 text-[11px] text-sig-warn">
              Multiple exporters are metering the same traffic on:{' '}
              <span className="font-mono">{stats?.mixed_source_devices?.join(', ')}</span>. Bytes can
              be double-counted until one exporter is disabled.
            </div>
          )}
        </div>
      )}

      <div className="rounded-xl border border-border bg-bg-card p-4">
        <TimeSeriesChart
          title={`Throughput — ${range}${stats?.degraded ? ' (partial)' : ''}`}
          timestamps={chart.timestamps}
          series={[{ label: 'Throughput', color: '#7DD3FC', values: chart.values }]}
          kind="bps"
          isLoading={isLoading}
          emptyMessage="No flow buckets in this window."
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
        <FlowBars
          title="Top sources"
          rows={stats?.top_sources}
          empty="No source talkers."
          subtitle="by volume"
        />
        <FlowBars
          title="Top destinations"
          rows={stats?.top_destinations}
          empty="No destination talkers."
          subtitle="by volume"
        />
        <FlowBars
          title="Protocols"
          rows={stats?.by_protocol}
          empty="No protocol distribution."
          labelFor={(row) => protocolLabel(row.key)}
        />
        <FlowBars
          title="Applications"
          rows={stats?.by_category}
          empty="No application classification."
        />
        <FlowBars
          title="Directions"
          rows={stats?.by_direction}
          empty="No direction classification."
        />
        <FlowBars
          title="Services"
          rows={(stats?.top_services ?? []).map((s) => ({
            key: `${s.key}${s.port ? ` :${s.port}` : ''}`,
            count: s.count,
          }))}
          empty="No service ports."
        />
        {stats?.geo_enabled ? (
          <>
            <FlowBars title="Countries" rows={stats?.top_countries} empty="No geo data yet." />
            <FlowBars
              title="ASNs"
              rows={stats?.top_asns}
              empty="No ASN data yet."
              labelFor={(row) => (row.key.startsWith('AS') ? row.key : `AS${row.key}`)}
            />
          </>
        ) : (
          <div className="rounded-xl border border-border bg-bg-card p-3.5 text-[11px] text-text-faint">
            Geo/ASN enrichment is disabled on the server, so country and ASN rankings are not
            available.
          </div>
        )}
      </div>
    </div>
  );
}

function ConversationsTab({
  conversations,
  isLoading,
  onDrill,
}: {
  conversations: FlowConversation[];
  isLoading: boolean;
  onDrill: (conversation: FlowConversation) => void;
}) {
  const columns = useMemo<ColumnDef<FlowConversation, unknown>[]>(
    () => [
      {
        id: 'pair',
        header: 'Conversation Pair',
        cell: ({ row }) => (
          <div className="font-mono text-xs flex flex-wrap items-center gap-1.5">
            <span className="text-text">{row.original.src_addr}</span>
            <ArrowRight className="h-3 w-3 text-accent" />
            <span className="text-text">
              {row.original.dst_addr}:{row.original.dst_port}
            </span>
          </div>
        ),
      },
      {
        id: 'protocol',
        header: 'Protocol',
        cell: ({ row }) => (
          <span className="rounded bg-bg-panel px-1.5 py-0.5 font-mono text-[10px] uppercase text-text-dim">
            {protocolLabel(row.original.protocol)}
          </span>
        ),
      },
      {
        accessorKey: 'bytes',
        header: 'Volume',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-accent">
            {formatBytes(row.original.bytes ?? 0)}
          </span>
        ),
      },
      {
        accessorKey: 'packets',
        header: 'Packets',
        cell: ({ row }) => (
          <span className="font-mono text-[11px] text-text-dim">
            {formatCompactNumber(row.original.packets ?? 0)}
          </span>
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex justify-end">
            <button
              type="button"
              onClick={() => onDrill(row.original)}
              className="rounded border border-border bg-bg-panel px-2 py-1 text-[10px] font-semibold uppercase text-text-dim hover:text-text"
            >
              Samples
            </button>
          </div>
        ),
      },
    ],
    [onDrill],
  );

  return (
    <ResponsiveDataView
      data={conversations}
      columns={columns}
      isLoading={isLoading}
      emptyTitle="No flow conversations recorded in this window."
      emptyDescription="Widen the range or clear filters."
      renderMobileCard={(c) => (
        <div className="flex items-center justify-between font-mono text-xs">
          <span>
            {c.src_addr} → {c.dst_addr}:{c.dst_port}
          </span>
          <span className="text-accent">{formatBytes(c.bytes ?? 0)}</span>
        </div>
      )}
    />
  );
}

function SamplesTab({
  hours,
  filters,
  range,
}: {
  hours: number;
  filters: FlowFilters;
  range: FlowRange;
}) {
  const { toast } = useToast();
  const [selectedSample, setSelectedSample] = useState<FlowSample | null>(null);
  const [exporting, setExporting] = useState(false);

  const {
    data: flowsRes,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ['flow-samples', hours, filters],
    queryFn: () =>
      apiFetch<FlowSample[]>(`/admin/api/flows?${buildFlowQuery(filters, hours, { limit: 200 })}`),
    refetchInterval: 15_000,
  });

  const samples: FlowSample[] = Array.isArray(flowsRes) ? flowsRes : [];

  const exportCsv = async () => {
    setExporting(true);
    try {
      const rows = await apiFetch<FlowSample[]>(
        `/admin/api/flows?${buildFlowQuery(filters, hours, { limit: 5000 })}`,
      );
      const list = Array.isArray(rows) ? rows : [];
      const csv = exportFlowsCsv(list as unknown as Array<Record<string, unknown>>);
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `flows-${range}-${new Date().toISOString().slice(0, 10)}.csv`;
      // Safari will not download from a detached anchor, and revoking the URL
      // before the download starts aborts it in Firefox.
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 0);
      toast({
        title: `${list.length} flow samples exported`,
        description:
          list.length >= 5000
            ? 'Capped at 5,000 rows for the current filters.'
            : 'All matching samples in the current window.',
        variant: 'success',
      });
    } catch (err) {
      toast({
        title: 'Export failed',
        description: err instanceof ApiError ? err.message : 'Request failed',
        variant: 'error',
      });
    } finally {
      setExporting(false);
    }
  };

  const columns = useMemo<ColumnDef<FlowSample, unknown>[]>(
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
        accessorKey: 'src_addr',
        header: 'Source',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text">
            {row.original.src_addr}:{row.original.src_port}
          </span>
        ),
      },
      {
        accessorKey: 'dst_addr',
        header: 'Destination',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text">
            {row.original.dst_addr}:{row.original.dst_port}
          </span>
        ),
      },
      {
        id: 'protocol',
        header: 'Proto',
        cell: ({ row }) => (
          <span className="font-mono text-[11px] text-text-dim">
            {protocolLabel(row.original.protocol)}
          </span>
        ),
      },
      {
        accessorKey: 'bytes',
        header: 'Bytes',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {formatBytes(row.original.bytes ?? 0)}
          </span>
        ),
      },
      {
        accessorKey: 'packets',
        header: 'Packets',
        cell: ({ row }) => (
          <span className="font-mono text-[11px] text-text-dim">
            {formatCompactNumber(row.original.packets ?? 0)}
          </span>
        ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-[11px] text-text-dim">
          Newest {samples.length} samples for the current filters (the list caps at 200 live rows).
        </p>
        <button
          type="button"
          onClick={exportCsv}
          disabled={exporting}
          className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text disabled:opacity-50"
        >
          <Download className="h-3.5 w-3.5" />
          {exporting ? 'Exporting…' : 'Export CSV (5,000)'}
        </button>
      </div>

      {isError ? (
        <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit">
          Could not load flow samples: {error instanceof Error ? error.message : 'request failed'}
        </div>
      ) : (
        <ResponsiveDataView
          data={samples}
          columns={columns}
          isLoading={isLoading}
          onRowClick={(row) => setSelectedSample(row)}
          emptyTitle="No raw sFlow/NetFlow samples received for these filters."
          renderMobileCard={(s) => (
            <div className="space-y-1 font-mono text-xs">
              <div className="text-text">
                {s.src_addr}:{s.src_port} → {s.dst_addr}:{s.dst_port}
              </div>
              <div className="text-text-dim">
                {protocolLabel(s.protocol)} · {formatBytes(s.bytes ?? 0)}
              </div>
            </div>
          )}
        />
      )}

      <SlideOverDrawer
        open={Boolean(selectedSample)}
        onOpenChange={(open) => {
          if (!open) setSelectedSample(null);
        }}
        title="Flow Sample Inspector"
        subtitle={selectedSample ? formatRelativeTime(selectedSample.timestamp) : undefined}
        size="lg"
      >
        {selectedSample && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-2">
              {[
                ['Source', `${selectedSample.src_addr ?? '—'}:${selectedSample.src_port ?? '—'}`],
                [
                  'Destination',
                  `${selectedSample.dst_addr ?? '—'}:${selectedSample.dst_port ?? '—'}`,
                ],
                ['Protocol', protocolLabel(selectedSample.protocol)],
                ['Bytes', formatBytes(selectedSample.bytes ?? 0)],
                ['Packets', formatCompactNumber(selectedSample.packets ?? 0)],
                ['Sampling rate', selectedSample.sampling_rate ? `1:${selectedSample.sampling_rate}` : '—'],
                [
                  'Exporter',
                  FLOW_SOURCE_OPTIONS.find((o) => o.value === String(selectedSample.flow_source))
                    ?.label ?? '—',
                ],
                [
                  'Firewall event',
                  FIREWALL_EVENT_OPTIONS.find(
                    (o) => o.value === String(selectedSample.firewall_event),
                  )?.label ?? '—',
                ],
                ['Country', selectedSample.dst_country || '—'],
                ['ASN', selectedSample.dst_asn ? `AS${selectedSample.dst_asn}` : '—'],
                ['Device', selectedSample.device_id ? `#${selectedSample.device_id}` : '—'],
                ['TCP flags', selectedSample.tcp_flags ?? '—'],
              ].map(([label, value]) => (
                <div
                  key={label}
                  className="rounded-lg border border-border bg-bg-panel px-2.5 py-2"
                >
                  <div className="text-[10px] uppercase text-text-faint">{label}</div>
                  <div className="font-mono text-xs text-text">{value}</div>
                </div>
              ))}
            </div>
            <details className="rounded-lg border border-border bg-bg-card p-3">
              <summary className="cursor-pointer text-xs font-semibold text-text">
                Raw sample JSON
              </summary>
              <pre className="mt-2 max-h-64 overflow-auto rounded border border-border bg-bg-panel p-2 font-mono text-[10px] text-text-dim">
                {JSON.stringify(selectedSample, null, 2)}
              </pre>
            </details>
          </div>
        )}
      </SlideOverDrawer>
    </div>
  );
}

function FlowDetectionsSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: detectionsRes, isLoading } = useQuery({
    queryKey: ['flow-detections'],
    queryFn: () => apiFetch<any>('/admin/api/flows/detections?limit=100'),
  });

  const detections: any[] = Array.isArray(detectionsRes)
    ? detectionsRes
    : detectionsRes?.detections ?? detectionsRes?.items ?? [];

  const ackMutation = useMutation({
    mutationFn: async (id: number) =>
      apiFetch(`/admin/api/flows/detections/${id}/ack`, { method: 'POST' }),
    onSuccess: () => {
      toast({ title: 'Flow detection acknowledged', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['flow-detections'] });
    },
  });

  const columns = useMemo<ColumnDef<any, unknown>[]>(
    () => [
      {
        accessorKey: 'detected_at',
        header: 'Detected',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {formatRelativeTime(row.original.detected_at || row.original.timestamp)}
          </span>
        ),
      },
      {
        accessorKey: 'detector',
        header: 'Detector',
        cell: ({ row }) => (
          <span className="rounded bg-sig-warn/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-sig-warn">
            {row.original.detector || 'Anomaly'}
          </span>
        ),
      },
      {
        accessorKey: 'src_addr',
        header: 'Subject IP',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text">{row.original.src_addr || '—'}</span>
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex justify-end">
            {!row.original.acknowledged && (
              <button
                type="button"
                onClick={() => ackMutation.mutate(row.original.id)}
                className="flex items-center gap-1 rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text hover:bg-bg-hover"
              >
                <Check className="h-3 w-3 text-sig-ok" /> Ack
              </button>
            )}
          </div>
        ),
      },
    ],
    [ackMutation],
  );

  return (
    <ResponsiveDataView
      data={detections}
      columns={columns}
      isLoading={isLoading}
      emptyTitle="No sFlow anomaly detections triggered."
      renderMobileCard={(d) => (
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-sig-warn">{d.detector || 'Anomaly'}</span>
          <span className="font-mono text-text">{d.src_addr}</span>
        </div>
      )}
    />
  );
}
