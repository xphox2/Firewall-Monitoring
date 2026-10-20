import { useState, useMemo } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  BarChart3,
  ShieldAlert,
  Search,
  Filter,
} from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatBytes, formatRelativeTime, countryCodeToFlag } from '@/lib/utils';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { ColumnDef } from '@tanstack/react-table';

type EventsTab = 'stream' | 'analytics' | 'security';
type TimeWindow = '1h' | '6h' | '12h' | '24h' | '7d' | '30d';

interface NetEventRow {
  id: number;
  ts?: string;
  timestamp?: string;
  device_id: number;
  device_name?: string;
  action?: number | string;
  src_ip?: string | null;
  src_port?: number | null;
  src_country?: string | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  dst_country?: string | null;
  proto?: number | string | null;
  app?: string | null;
  app_cat?: string | null;
  policy_id?: string | number | null;
  policy_name?: string | null;
  bytes_in?: number | null;
  bytes_out?: number | null;
  bytes_sent?: number | null;
  bytes_rcvd?: number | null;
}

interface SecEventRow {
  id: number;
  ts?: string;
  timestamp?: string;
  device_id: number;
  device_name?: string;
  class?: string | number;
  event_class?: string;
  severity?: number | string;
  action?: number | string;
  src_ip?: string | null;
  dst_ip?: string | null;
  sig_name?: string | null;
  signature?: string | null;
  user_name?: string | null;
  message?: string | null;
}

const TIME_WINDOWS: TimeWindow[] = ['1h', '6h', '12h', '24h', '7d', '30d'];

function windowToHours(w: TimeWindow): number {
  switch (w) {
    case '1h':
      return 1;
    case '6h':
      return 6;
    case '12h':
      return 12;
    case '24h':
      return 24;
    case '7d':
      return 168;
    case '30d':
      return 720;
  }
}

function formatNetAction(raw: number | string | undefined): { label: string; isDeny: boolean } {
  if (typeof raw === 'number') {
    if (raw === 1) return { label: 'allow', isDeny: false };
    if (raw === 2) return { label: 'deny', isDeny: true };
    if (raw === 3) return { label: 'close', isDeny: false };
    return { label: `act(${raw})`, isDeny: false };
  }
  const s = String(raw || 'allow').toLowerCase();
  const isDeny = s.includes('deny') || s.includes('drop') || s.includes('block') || s === '2';
  return { label: s, isDeny };
}

function formatProto(proto: number | string | null | undefined): string {
  if (proto === null || proto === undefined || proto === '') return '—';
  if (typeof proto === 'number') {
    if (proto === 6) return 'TCP';
    if (proto === 17) return 'UDP';
    if (proto === 1) return 'ICMP';
    if (proto === 58) return 'ICMPv6';
    return String(proto);
  }
  return String(proto).toUpperCase();
}

export function EventsWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = (searchParams.get('tab') as EventsTab) || 'stream';
  const [windowRange, setWindowRange] = useState<TimeWindow>('1h');

  const setTab = (tab: EventsTab) => {
    setSearchParams({ tab }, { replace: true });
  };

  return (
    <div className="space-y-4">
      {/* Compact Header so the Event Stream table sits immediately above the fold (y < 380px) */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3 border-b border-border pb-3">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <Activity className="h-3.5 w-3.5" />
            Telemetry / Normalized Firewall Events
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            Normalized Event Stream, Policy Analytics & IPS/UTM Security
          </h1>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Range Pills */}
          <div className="flex items-center gap-0.5 rounded-lg bg-bg-panel p-1 border border-border">
            {TIME_WINDOWS.map((w) => (
              <button
                key={w}
                type="button"
                onClick={() => setWindowRange(w)}
                className={cn(
                  'rounded px-2 py-1 text-xs font-mono font-medium transition-colors',
                  windowRange === w
                    ? 'bg-accent text-white'
                    : 'text-text-dim hover:text-text'
                )}
              >
                {w}
              </button>
            ))}
          </div>

          {/* Sub-Tabs */}
          <div className="flex items-center gap-1 rounded-lg bg-bg-panel p-1 border border-border">
            <button
              type="button"
              onClick={() => setTab('stream')}
              className={cn(
                'flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-medium transition-colors',
                activeTab === 'stream'
                  ? 'bg-bg-card text-text shadow-sm border border-border'
                  : 'text-text-dim hover:text-text'
              )}
            >
              <Activity className="h-3.5 w-3.5 text-accent" />
              Event Stream
            </button>
            <button
              type="button"
              onClick={() => setTab('analytics')}
              className={cn(
                'flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-medium transition-colors',
                activeTab === 'analytics'
                  ? 'bg-bg-card text-text shadow-sm border border-border'
                  : 'text-text-dim hover:text-text'
              )}
            >
              <BarChart3 className="h-3.5 w-3.5 text-accent" />
              Policy & Geo Analytics
            </button>
            <button
              type="button"
              onClick={() => setTab('security')}
              className={cn(
                'flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-medium transition-colors',
                activeTab === 'security'
                  ? 'bg-bg-card text-text shadow-sm border border-border'
                  : 'text-text-dim hover:text-text'
              )}
            >
              <ShieldAlert className="h-3.5 w-3.5 text-accent" />
              Security Events
            </button>
          </div>
        </div>
      </div>

      {activeTab === 'stream' && <EventStreamSubTab windowRange={windowRange} />}
      {activeTab === 'analytics' && <EventAnalyticsSubTab windowRange={windowRange} />}
      {activeTab === 'security' && <SecurityEventsSubTab windowRange={windowRange} />}
    </div>
  );
}

// ============================================================================
// SUB-TAB 1: EVENT STREAM (ABOVE THE FOLD!)
// ============================================================================
function EventStreamSubTab({ windowRange }: { windowRange: TimeWindow }) {
  const [actionFilter, setActionFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEventId, setSelectedEventId] = useState<number | null>(null);
  const hours = windowToHours(windowRange);

  const { data: eventsRes, isLoading } = useQuery({
    queryKey: ['net-events', hours, actionFilter, searchQuery],
    queryFn: () => {
      const params = new URLSearchParams({ hours: String(hours), limit: '100' });
      if (actionFilter) params.set('action', actionFilter);
      if (searchQuery.trim()) params.set('src_ip', searchQuery.trim());
      return apiFetch<any>(`/admin/api/events?${params.toString()}`);
    },
    refetchInterval: 15_000,
  });

  const { data: eventDetail } = useQuery({
    queryKey: ['net-event-detail', selectedEventId],
    queryFn: () => apiFetch<any>(`/admin/api/events/${selectedEventId}`),
    enabled: Boolean(selectedEventId),
  });

  const events: NetEventRow[] = Array.isArray(eventsRes)
    ? eventsRes
    : eventsRes?.events ?? eventsRes?.rows ?? eventsRes?.items ?? eventsRes?.data ?? [];

  const columns = useMemo<ColumnDef<NetEventRow, unknown>[]>(
    () => [
      {
        id: 'time',
        header: 'Time',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {formatRelativeTime(row.original.ts || row.original.timestamp)}
          </span>
        ),
      },
      {
        id: 'action',
        header: 'Action',
        cell: ({ row }) => {
          const { label, isDeny } = formatNetAction(row.original.action);
          return (
            <span
              className={cn(
                'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
                isDeny ? 'bg-sig-crit/15 text-sig-crit' : 'bg-sig-ok/15 text-sig-ok'
              )}
            >
              {label}
            </span>
          );
        },
      },
      {
        accessorKey: 'src_ip',
        header: 'Source',
        cell: ({ row }) => (
          <div className="font-mono text-xs">
            {row.original.src_country && (
              <span className="fwmon-flag mr-1">{countryCodeToFlag(row.original.src_country)}</span>
            )}
            <span className="text-text">{row.original.src_ip || '—'}</span>
            {row.original.src_port ? <span className="text-text-faint">:{row.original.src_port}</span> : null}
          </div>
        ),
      },
      {
        accessorKey: 'dst_ip',
        header: 'Destination',
        cell: ({ row }) => (
          <div className="font-mono text-xs">
            {row.original.dst_country && (
              <span className="fwmon-flag mr-1">{countryCodeToFlag(row.original.dst_country)}</span>
            )}
            <span className="text-text">{row.original.dst_ip || '—'}</span>
            {row.original.dst_port ? <span className="text-text-faint">:{row.original.dst_port}</span> : null}
          </div>
        ),
      },
      {
        id: 'proto',
        header: 'Proto / App',
        cell: ({ row }) => (
          <div className="text-xs">
            <span className="font-mono uppercase text-text">{formatProto(row.original.proto)}</span>
            {row.original.app && <span className="text-text-dim ml-1.5">({row.original.app})</span>}
          </div>
        ),
      },
      {
        id: 'device',
        header: 'Device / Policy',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {row.original.device_name ||
              row.original.policy_name ||
              (row.original.policy_id ? `#${row.original.policy_id}` : `Dev #${row.original.device_id}`)}
          </span>
        ),
      },
      {
        id: 'bytes',
        header: 'Traffic',
        cell: ({ row }) => {
          const totalBytes =
            (row.original.bytes_in ?? row.original.bytes_rcvd ?? 0) +
            (row.original.bytes_out ?? row.original.bytes_sent ?? 0);
          return <span className="font-mono text-xs text-text-dim">{formatBytes(totalBytes)}</span>;
        },
      },
    ],
    []
  );

  return (
    <div className="space-y-3">
      {/* Compact single-row filter bar so the table starts at y < 380px */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-bg-card p-2.5">
        <Filter className="h-3.5 w-3.5 text-text-faint ml-1" />
        <select
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          aria-label="Filter by firewall action"
          className="rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text"
        >
          <option value="">All Actions</option>
          <option value="1">Accept / Allow (1)</option>
          <option value="2">Deny / Drop (2)</option>
          <option value="3">Close / Reset (3)</option>
        </select>

        <div className="relative flex-1 min-w-[200px]">
          <Search className="h-3.5 w-3.5 text-text-faint absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter by source IP prefix..."
            className="w-full rounded border border-border bg-bg-panel pl-8 pr-3 py-1 text-xs font-mono text-text focus:border-accent focus:outline-none"
          />
        </div>
      </div>

      <ResponsiveDataView
        data={events}
        columns={columns}
        isLoading={isLoading}
        onRowClick={(row) => setSelectedEventId(row.id)}
        emptyTitle="No normalized firewall events in this window."
        renderMobileCard={(ev) => {
          const { label, isDeny } = formatNetAction(ev.action);
          return (
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span
                  className={cn(
                    'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
                    isDeny ? 'bg-sig-crit/15 text-sig-crit' : 'bg-sig-ok/15 text-sig-ok'
                  )}
                >
                  {label}
                </span>
                <span className="font-mono text-[11px] text-text-dim">
                  {formatRelativeTime(ev.ts || ev.timestamp)}
                </span>
              </div>
              <div className="font-mono text-xs text-text">
                {ev.src_ip}:{ev.src_port} → {ev.dst_ip}:{ev.dst_port} ({formatProto(ev.proto)})
              </div>
            </div>
          );
        }}
      />

      <SlideOverDrawer
        open={Boolean(selectedEventId)}
        onOpenChange={(open) => {
          if (!open) setSelectedEventId(null);
        }}
        title={`Normalized Event #${selectedEventId ?? ''}`}
        subtitle="Full normalized fields and underlying raw syslog reference."
      >
        <pre className="rounded-lg border border-border bg-bg-panel p-3 font-mono text-xs text-text overflow-x-auto whitespace-pre-wrap">
          {JSON.stringify(eventDetail ?? {}, null, 2)}
        </pre>
      </SlideOverDrawer>
    </div>
  );
}

// ============================================================================
// SUB-TAB 2: POLICY & GEO ANALYTICS (SEPARATED FROM STREAM!)
// ============================================================================
function EventAnalyticsSubTab({ windowRange }: { windowRange: TimeWindow }) {
  const hours = windowToHours(windowRange);

  const { data: analytics, isLoading } = useQuery({
    queryKey: ['net-event-analytics', hours],
    queryFn: () => apiFetch<any>(`/admin/api/events/analytics?hours=${hours}`),
  });

  const { data: rollups } = useQuery({
    queryKey: ['net-event-rollups', hours],
    queryFn: () => apiFetch<any>(`/admin/api/events/rollups?hours=${hours}`),
  });

  if (isLoading) {
    return (
      <div className="rounded-xl border border-border bg-bg-card p-8 text-center text-sm text-text-dim">
        Loading event analytics & rollups…
      </div>
    );
  }

  const topPolicies: any[] =
    rollups?.top_rules ??
    rollups?.policies ??
    analytics?.top_policies ??
    analytics?.policies ??
    [];
  const topCountries: any[] =
    analytics?.geo_dst ??
    analytics?.top_countries ??
    analytics?.countries ??
    [];
  const topApps: any[] =
    analytics?.apps ??
    analytics?.top_apps ??
    analytics?.app_categories ??
    [];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
        <h2 className="text-sm font-semibold text-text">Top Firewall Policies ({windowRange})</h2>
        {topPolicies.length === 0 ? (
          <p className="text-xs text-text-dim">No policy rollup data in this window.</p>
        ) : (
          <div className="space-y-2">
            {topPolicies.slice(0, 8).map((p: any, i: number) => (
              <div key={i} className="flex items-center justify-between text-xs font-mono">
                <span className="text-text truncate">
                  {p.rule_key || p.policy_name || p.policy_id || 'Default'}
                </span>
                <span className="text-text-dim">{p.hits ?? p.events ?? p.count ?? 0} hits</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
        <h2 className="text-sm font-semibold text-text">Top Destination Countries</h2>
        {topCountries.length === 0 ? (
          <p className="text-xs text-text-dim">No country breakdown in this window.</p>
        ) : (
          <div className="space-y-2">
            {topCountries.slice(0, 8).map((c: any, i: number) => (
              <div key={i} className="flex items-center justify-between text-xs font-mono">
                <span className="text-text">
                  <span className="fwmon-flag mr-1.5">{countryCodeToFlag(c.country || c.cc)}</span>
                  {c.country || c.cc || 'Unknown'}
                </span>
                <span className="text-text-dim">{c.count ?? c.events ?? 0}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
        <h2 className="text-sm font-semibold text-text">Top Applications & Services</h2>
        {topApps.length === 0 ? (
          <p className="text-xs text-text-dim">No application telemetry in this window.</p>
        ) : (
          <div className="space-y-2">
            {topApps.slice(0, 8).map((a: any, i: number) => (
              <div key={i} className="flex items-center justify-between text-xs font-mono">
                <span className="text-text truncate">{a.app || a.category || a.service || 'Unknown'}</span>
                <span className="text-text-dim">{formatBytes(a.bytes ?? a.total_bytes ?? 0)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// SUB-TAB 3: SECURITY EVENTS (IPS / AV / WEB FILTER / AUTH)
// ============================================================================
function SecurityEventsSubTab({ windowRange }: { windowRange: TimeWindow }) {
  const [selectedSecId, setSelectedSecId] = useState<number | null>(null);
  const hours = windowToHours(windowRange);

  const { data: secRes, isLoading } = useQuery({
    queryKey: ['sec-events', hours],
    queryFn: () => apiFetch<any>(`/admin/api/security-events?hours=${hours}&limit=100`),
  });

  const { data: secDetail } = useQuery({
    queryKey: ['sec-event-detail', selectedSecId],
    queryFn: () => apiFetch<any>(`/admin/api/security-events/${selectedSecId}`),
    enabled: Boolean(selectedSecId),
  });

  const secEvents: SecEventRow[] = Array.isArray(secRes)
    ? secRes
    : secRes?.events ?? secRes?.rows ?? secRes?.items ?? secRes?.data ?? [];

  const columns = useMemo<ColumnDef<SecEventRow, unknown>[]>(
    () => [
      {
        id: 'time',
        header: 'When',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {formatRelativeTime(row.original.ts || row.original.timestamp)}
          </span>
        ),
      },
      {
        id: 'class',
        header: 'Class',
        cell: ({ row }) => (
          <span className="rounded bg-accent/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-accent">
            {String(row.original.class ?? row.original.event_class ?? 'security')}
          </span>
        ),
      },
      {
        id: 'severity',
        header: 'Severity',
        cell: ({ row }) => (
          <span className="rounded bg-sig-crit/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-sig-crit">
            {String(row.original.severity ?? 'warning')}
          </span>
        ),
      },
      {
        id: 'signature',
        header: 'Signature / Summary',
        cell: ({ row }) => (
          <span className="text-xs text-text">
            {row.original.sig_name || row.original.signature || row.original.message || 'Security event'}
          </span>
        ),
      },
    ],
    []
  );

  return (
    <div className="space-y-4">
      <ResponsiveDataView
        data={secEvents}
        columns={columns}
        isLoading={isLoading}
        onRowClick={(row) => setSelectedSecId(row.id)}
        emptyTitle="No IPS, AV, or authentication security events in this window."
        renderMobileCard={(ev) => (
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs uppercase text-accent">
                {String(ev.class ?? ev.event_class ?? 'security')}
              </span>
              <span className="font-mono text-[11px] text-text-dim">
                {formatRelativeTime(ev.ts || ev.timestamp)}
              </span>
            </div>
            <div className="text-xs text-text">
              {ev.sig_name || ev.signature || ev.message}
            </div>
          </div>
        )}
      />

      <SlideOverDrawer
        open={Boolean(selectedSecId)}
        onOpenChange={(open) => {
          if (!open) setSelectedSecId(null);
        }}
        title={`Security Event #${selectedSecId ?? ''}`}
      >
        <pre className="rounded-lg border border-border bg-bg-panel p-3 font-mono text-xs text-text overflow-x-auto whitespace-pre-wrap">
          {JSON.stringify(secDetail ?? {}, null, 2)}
        </pre>
      </SlideOverDrawer>
    </div>
  );
}
