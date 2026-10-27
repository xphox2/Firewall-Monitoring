import { useEffect, useState, useMemo } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  BarChart3,
  ShieldAlert,
} from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatBytes, formatCompactNumber, formatRelativeTime, countryCodeToFlag } from '@/lib/utils';
import {
  actionLabel,
  activityLabel,
  classLabel,
  directionLabel,
  eventBytesSeries,
  eventHitsSeries,
  severityLabel,
} from '@/lib/events';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { RefreshButton } from '@/components/ui/refresh-button';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { BarList } from '@/components/ui/bar-list';
import { DetailSection } from '@/components/ui/detail-section';
import { TimeSeriesChart } from '@/components/charts/time-series-chart';
import { ColumnDef } from '@tanstack/react-table';
import { Select } from '@/components/ui/input';
import { EventFilterBar, EventSearchBox } from '@/components/events/event-filter-bar';
import { EventPager } from '@/components/events/event-pager';
import { secDayCountSeries, type SecDayCount } from '@/lib/events';
import { buildNetEventQuery, buildSecEventQuery, EVENT_PAGE_SIZE, type EventFilters } from '@/lib/event-filters';

type EventsTab = 'stream' | 'analytics' | 'security' | 'security-analytics';
type TimeWindow = '1h' | '6h' | '12h' | '24h' | '7d' | '30d';

interface NetEventRow {
  id: number;
  ts?: string;
  timestamp?: string;
  device_id: number;
  device_name?: string;
  activity?: number | null;
  action?: number | string;
  direction?: number | null;
  src_ip?: string | null;
  src_port?: number | null;
  src_country?: string | null;
  src_mac?: string | null;
  src_if?: string | null;
  src_zone?: string | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  dst_country?: string | null;
  dst_mac?: string | null;
  dst_if?: string | null;
  dst_zone?: string | null;
  proto?: number | string | null;
  app?: string | null;
  app_cat?: string | null;
  app_risk?: number | null;
  policy_id?: string | number | null;
  policy_name?: string | null;
  rule_key?: string | null;
  rule_uid?: string | null;
  rule_name?: string | null;
  rule_index?: number | null;
  ruleset?: string | null;
  user_name?: string | null;
  user_group?: string | null;
  src_hostname?: string | null;
  dev_type?: string | null;
  os_name?: string | null;
  bytes_in?: number | null;
  bytes_out?: number | null;
  bytes_sent?: number | null;
  bytes_rcvd?: number | null;
  pkts_in?: number | null;
  pkts_out?: number | null;
  duration_ms?: number | null;
  session_id?: string | null;
  nat_src_ip?: string | null;
  nat_src_port?: number | null;
  nat_dst_ip?: string | null;
  nat_dst_port?: number | null;
  threat_flag?: number | null;
  url_host?: string | null;
  url_path?: string | null;
  dns_qname?: string | null;
  dns_qtype?: number | null;
  web_cat?: string | null;
}

interface SecEventRow {
  id: number;
  ts?: string;
  timestamp?: string;
  device_id: number;
  device_name?: string;
  class?: number | null;
  event_class?: string;
  activity?: number | null;
  severity?: number | null;
  action?: number | null;
  src_ip?: string | null;
  src_port?: number | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  proto?: number | null;
  user_name?: string | null;
  src_hostname?: string | null;
  admin_user?: string | null;
  admin_src_ip?: string | null;
  admin_method?: string | null;
  sig_id?: string | null;
  sig_name?: string | null;
  signature?: string | null;
  threat_cat?: string | null;
  file_hash?: string | null;
  url_host?: string | null;
  tunnel_name?: string | null;
  tunnel_type?: string | null;
  tunnel_peer?: string | null;
  config_path?: string | null;
  config_obj?: string | null;
  config_old?: string | null;
  config_new?: string | null;
  wan_name?: string | null;
  metric_name?: string | null;
  metric_value?: number | null;
  message?: string | null;
  raw_id?: number | null;
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

// GetNetEvents only accepts a full IP or CIDR (validIPOrCIDR); a partial
// prefix like "10.0" returns 400 and blanks the stream. Keep this at least as
// strict as netip: no empty prefix, no leading zeros, no malformed IPv6.
function isIpOrCidr(value: string): boolean {
  if (!value) return false;
  const parts = value.split('/');
  if (parts.length > 2) return false;
  const addr = parts[0] ?? '';
  const prefix = parts[1];

  const v4 = (() => {
    const octets = addr.split('.');
    return (
      octets.length === 4 &&
      octets.every((o) => /^(0|[1-9]\d{0,2})$/.test(o) && Number(o) <= 255)
    );
  })();

  const v6 = (() => {
    if (!addr.includes(':')) return false;
    if (!/^[0-9a-fA-F:]+$/.test(addr)) return false;
    if ((addr.match(/::/g) || []).length > 1) return false;
    const groups = addr.split(':').filter((g) => g !== '');
    return addr.includes('::') ? groups.length <= 7 : groups.length === 8;
  })();

  if (!v4 && !v6) return false;
  if (prefix === undefined) return true;
  if (!/^(0|[1-9]\d{0,2})$/.test(prefix)) return false;
  return Number(prefix) <= (v4 ? 32 : 128);
}

function formatNetAction(raw: number | string | undefined): { label: string; isDeny: boolean } {
  if (typeof raw === 'number') {
    // normalize.Action: 1 allow, 2 deny, 3 reject, 4 timeout_close, 99 other.
    return { label: actionLabel(raw).toLowerCase(), isDeny: raw === 2 || raw === 3 };
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
                  ? 'bg-bg-card text-text shadow-xs border border-border'
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
                  ? 'bg-bg-card text-text shadow-xs border border-border'
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
                  ? 'bg-bg-card text-text shadow-xs border border-border'
                  : 'text-text-dim hover:text-text'
              )}
            >
              <ShieldAlert className="h-3.5 w-3.5 text-accent" />
              Security Events
            </button>
            <button
              type="button"
              onClick={() => setTab('security-analytics')}
              className={cn(
                'flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-medium transition-colors',
                activeTab === 'security-analytics'
                  ? 'bg-bg-card text-text shadow-xs border border-border'
                  : 'text-text-dim hover:text-text'
              )}
            >
              <BarChart3 className="h-3.5 w-3.5 text-accent" />
              Security Analytics
            </button>
          </div>
        </div>
      </div>

      {activeTab === 'stream' && <EventStreamSubTab windowRange={windowRange} />}
      {activeTab === 'analytics' && <EventAnalyticsSubTab windowRange={windowRange} />}
      {activeTab === 'security' && <SecurityEventsSubTab windowRange={windowRange} />}
      {activeTab === 'security-analytics' && <SecurityAnalyticsSubTab windowRange={windowRange} />}
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
  const [filters, setFilters] = useState<EventFilters>({});
  const [page, setPage] = useState(0);
  const hours = windowToHours(windowRange);
  const offset = page * EVENT_PAGE_SIZE;

  const [debouncedSearch, setDebouncedSearch] = useState('');
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(searchQuery), 350);
    return () => clearTimeout(timer);
  }, [searchQuery]);
  const srcFilter = isIpOrCidr(debouncedSearch.trim()) ? debouncedSearch.trim() : '';

  /*
   * The server's filters for `GET /admin/api/events`: device_id, probe_id,
   * site_id, activity, action, src_ip, dst_ip and rule_key. The console
   * offered only the action and the source address.
   */
  const netFilters: EventFilters = useMemo(
    () => ({ ...filters, action: actionFilter, srcIp: srcFilter }),
    [filters, actionFilter, srcFilter],
  );

  const { data: eventsRes, isLoading } = useQuery({
    queryKey: ['net-events', hours, netFilters, page],
    queryFn: () => {
      const params = buildNetEventQuery(netFilters, hours, EVENT_PAGE_SIZE, offset);
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
  // The server reports the total and whether it was CAPPED (the count is
  // only computed up to a limit, so a capped total is a lower bound).
  const eventsTotal: number | undefined = Array.isArray(eventsRes) ? undefined : eventsRes?.total;
  const eventsCapped: boolean = !Array.isArray(eventsRes) && Boolean(eventsRes?.total_capped);

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
      <EventFilterBar
        filters={filters}
        onChange={(next) => {
          setFilters(next);
          setPage(0);
        }}
        // The action and the source address live in their own state, so
        // "Clear" has to reset them as well or the operator is left with a
        // filter they cannot see.
        onClear={() => {
          setActionFilter('');
          setSearchQuery('');
          setPage(0);
        }}
        withSite
        withRuleKey
        withDestination
        withActivity
      >
        <Select
          className="px-2.5 py-1"
          value={actionFilter}
          onChange={(e) => {
            setActionFilter(e.target.value);
            setPage(0);
          }}
          aria-label="Filter by firewall action"
        >
          <option value="">All Actions</option>
          <option value="1">Accept / Allow (1)</option>
          <option value="2">Deny / Drop (2)</option>
          <option value="3">Reject / Reset (3)</option>
        </Select>

        <EventSearchBox
          value={searchQuery}
          onChange={(next) => {
            setSearchQuery(next);
            setPage(0);
          }}
          placeholder="Filter by exact source IP or CIDR..."
        />
        <RefreshButton
          queryKeys={[['net-events'], ['net-event-analytics'], ['net-event-rollups']]}
          label="Refresh"
        />
      </EventFilterBar>

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

      <EventPager
        page={page}
        total={eventsTotal}
        pageSize={EVENT_PAGE_SIZE}
        onChange={setPage}
        capped={eventsCapped}
      />

      <SlideOverDrawer
        open={Boolean(selectedEventId)}
        onOpenChange={(open) => {
          if (!open) setSelectedEventId(null);
        }}
        title={`Normalized Event #${selectedEventId ?? ''}`}
        subtitle="Full normalized fields and underlying raw syslog reference."
      >
        <NetEventInspector event={eventDetail} />
      </SlideOverDrawer>
    </div>
  );
}

// ============================================================================
// SUB-TAB 2: POLICY & GEO ANALYTICS (SEPARATED FROM STREAM!)
// ============================================================================
function windowToDays(w: TimeWindow): number {
  // GetNetEventRollups only reads `days` (1..365, default 30), so the hour
  // ranges have to be expressed as whole days or the pills did nothing.
  return Math.min(365, Math.max(1, Math.ceil(windowToHours(w) / 24)));
}

function NetEventInspector({ event }: { event: NetEventRow | undefined }) {
  if (!event) {
    return <p className="p-6 text-center text-xs text-text-dim">Loading event…</p>;
  }
  const action = formatNetAction(event.action);
  const totalBytes =
    (event.bytes_in ?? event.bytes_rcvd ?? 0) + (event.bytes_out ?? event.bytes_sent ?? 0);
  const endpoint = (ip?: string | null, port?: number | null) =>
    ip ? `${ip}${port ? `:${port}` : ''}` : '';

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={cn(
            'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
            action.isDeny ? 'bg-sig-crit/15 text-sig-crit' : 'bg-sig-ok/15 text-sig-ok',
          )}
        >
          {action.label}
        </span>
        <span className="rounded bg-bg-panel px-2 py-0.5 text-[10px] uppercase text-text-dim">
          {activityLabel(event.activity)}
        </span>
        <span className="rounded bg-bg-panel px-2 py-0.5 text-[10px] uppercase text-text-dim">
          {directionLabel(event.direction)}
        </span>
        {event.threat_flag ? (
          <span className="rounded bg-sig-crit/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-sig-crit">
            threat-intel match
          </span>
        ) : null}
      </div>

      <DetailSection
        title="Event"
        fields={[
          ['When', event.ts ? new Date(event.ts).toLocaleString() : '—'],
          ['Device', event.device_name || `#${event.device_id}`],
          ['Session', event.session_id],
          ['Activity', activityLabel(event.activity)],
          ['Action', action.label],
          ['Direction', directionLabel(event.direction)],
        ]}
      />

      <DetailSection
        title="Rule & policy"
        fields={[
          ['Policy', event.policy_name || event.policy_id],
          ['Rule', event.rule_name || event.rule_key],
          ['Rule UID', event.rule_uid],
          [
            'Rule index',
            event.rule_index !== null && event.rule_index !== undefined
              ? String(event.rule_index)
              : '',
          ],
          ['Ruleset', event.ruleset],
        ]}
      />

      <DetailSection
        title="Endpoints"
        fields={[
          ['Source', endpoint(event.src_ip, event.src_port)],
          ['Source zone / if', [event.src_zone, event.src_if].filter(Boolean).join(' / ')],
          ['Source MAC', event.src_mac],
          ['Source country', event.src_country],
          ['Destination', endpoint(event.dst_ip, event.dst_port)],
          ['Destination zone / if', [event.dst_zone, event.dst_if].filter(Boolean).join(' / ')],
          ['Destination MAC', event.dst_mac],
          ['Destination country', event.dst_country],
          ['Protocol', formatProto(event.proto)],
        ]}
      />

      <DetailSection
        title="Identity & application"
        fields={[
          ['User', event.user_name],
          ['Group', event.user_group],
          ['Hostname', event.src_hostname],
          ['OS', event.os_name],
          ['Device type', event.dev_type],
          ['Application', event.app],
          ['Category', event.app_cat],
          [
            'App risk',
            event.app_risk !== null && event.app_risk !== undefined ? String(event.app_risk) : '',
          ],
        ]}
      />

      <DetailSection
        title="Traffic"
        fields={[
          ['Bytes in', event.bytes_in !== null && event.bytes_in !== undefined ? formatBytes(event.bytes_in) : ''],
          ['Bytes out', event.bytes_out !== null && event.bytes_out !== undefined ? formatBytes(event.bytes_out) : ''],
          ['Total', totalBytes > 0 ? formatBytes(totalBytes) : ''],
          ['Packets in', event.pkts_in !== null && event.pkts_in !== undefined ? formatCompactNumber(event.pkts_in) : ''],
          ['Packets out', event.pkts_out !== null && event.pkts_out !== undefined ? formatCompactNumber(event.pkts_out) : ''],
          [
            'Duration',
            event.duration_ms !== null && event.duration_ms !== undefined
              ? `${event.duration_ms} ms`
              : '',
          ],
        ]}
      />

      <DetailSection
        title="NAT"
        fields={[
          ['Translated source', endpoint(event.nat_src_ip, event.nat_src_port)],
          ['Translated destination', endpoint(event.nat_dst_ip, event.nat_dst_port)],
        ]}
      />

      <DetailSection
        title="Web & DNS"
        fields={[
          ['URL host', event.url_host],
          ['URL path', event.url_path],
          ['Web category', event.web_cat],
          ['DNS query', event.dns_qname],
          [
            'DNS type',
            event.dns_qtype !== null && event.dns_qtype !== undefined
              ? String(event.dns_qtype)
              : '',
          ],
        ]}
      />

      <details className="rounded-lg border border-border bg-bg-card p-3">
        <summary className="cursor-pointer text-xs font-semibold text-text">
          Raw normalized JSON
        </summary>
        <pre className="mt-2 max-h-72 overflow-auto rounded border border-border bg-bg-panel p-2 font-mono text-[10px] text-text-dim">
          {JSON.stringify(event, null, 2)}
        </pre>
      </details>
    </div>
  );
}

function EventAnalyticsSubTab({ windowRange }: { windowRange: TimeWindow }) {
  const hours = windowToHours(windowRange);
  const days = windowToDays(windowRange);

  const {
    data: analytics,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ['net-event-analytics', hours],
    queryFn: () => apiFetch<any>(`/admin/api/events/analytics?hours=${hours}`),
  });

  const { data: rollups } = useQuery({
    queryKey: ['net-event-rollups', days],
    queryFn: () => apiFetch<any>(`/admin/api/events/rollups?days=${days}`),
  });

  const hourlyBytes = eventBytesSeries(analytics?.policy_bytes_hourly, 3600);
  const hourlyDeny = eventHitsSeries(analytics?.deny_hourly);
  const dailyBytes = eventBytesSeries(rollups?.policy_bytes, 86_400);
  const dailyDeny = eventHitsSeries(rollups?.deny);

  if (isLoading) {
    return (
      <div className="rounded-xl border border-border bg-bg-card p-8 text-center text-sm text-text-dim">
        Loading event analytics & rollups…
      </div>
    );
  }

  const keyRows = (rows: Array<{ key: string; count: number }> | undefined) =>
    (rows ?? []).map((row) => ({ key: row.key, value: row.count ?? 0 }));

  const policies = (rollups?.policy_hits ?? []).map((p: any) => ({
    key: p.rule_key || 'Default',
    value: p.hits ?? 0,
  }));
  const directions = (rollups?.directions ?? []).map((d: any) => ({
    key: directionLabel(d.direction),
    value: d.hits ?? 0,
  }));
  const geoDst = (analytics?.geo_dst ?? []).map((g: any) => ({
    key: g.country || 'Unknown',
    value: g.hits ?? 0,
  }));
  const geoSrc = (analytics?.geo_src ?? []).map((g: any) => ({
    key: g.country || 'Unknown',
    value: g.hits ?? 0,
  }));
  const identity = (analytics?.identity ?? []).map((row: any) => ({
    key: row.src_ip || row.src_mac || 'Unknown',
    value: row.hits ?? 0,
  }));
  const nat: Array<{ src_ip?: string; dst_ip?: string; hits?: number }> = analytics?.nat ?? [];

  return (
    <div className="space-y-4">
      {isError && (
        <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit" role="alert">
          Could not load event analytics: {error instanceof Error ? error.message : 'request failed'}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        {hours <= 24 && (
          <div className="rounded-xl border border-border bg-bg-card p-4">
            <TimeSeriesChart
              title={`Policy throughput — hourly (${windowRange})`}
              timestamps={hourlyBytes.timestamps}
              series={[{ label: 'Throughput', color: 'var(--fwmon-series-1)', values: hourlyBytes.values }]}
              kind="bps"
              emptyMessage="No policy byte telemetry in this window."
            />
          </div>
        )}
        {hours <= 24 && (
          <div className="rounded-xl border border-border bg-bg-card p-4">
            <TimeSeriesChart
              title={`Denied events — hourly (${windowRange})`}
              timestamps={hourlyDeny.timestamps}
              series={[{ label: 'Denies', color: 'var(--fwmon-series-2)', values: hourlyDeny.values }]}
              kind="count"
              emptyMessage="No denied events in this window."
            />
          </div>
        )}
        {days > 1 && (
          <>
            <div className="rounded-xl border border-border bg-bg-card p-4">
              <TimeSeriesChart
                title={`Policy throughput — daily rollup (${days}d)`}
                timestamps={dailyBytes.timestamps}
                series={[{ label: 'Throughput', color: 'var(--fwmon-series-1)', values: dailyBytes.values }]}
                kind="bps"
                emptyMessage="No rolled-up policy bytes in this window."
              />
            </div>
            <div className="rounded-xl border border-border bg-bg-card p-4">
              <TimeSeriesChart
                title={`Denied events — daily rollup (${days}d)`}
                timestamps={dailyDeny.timestamps}
                series={[{ label: 'Denies', color: 'var(--fwmon-series-2)', values: dailyDeny.values }]}
                kind="count"
                emptyMessage="No rolled-up denies in this window."
              />
            </div>
          </>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        <BarList
          title={`Top firewall policies (${days === 1 ? '24h' : `${days}d`} rollup)`}
          rows={policies}
          empty="No policy rollup data."
        />
        <BarList title="Top destination countries" rows={geoDst} flag empty="No geo data." />
        <BarList title="Top source countries" rows={geoSrc} flag empty="No geo data." />
        <BarList title="Applications" rows={keyRows(analytics?.apps)} empty="No app telemetry." />
        <BarList
          title="Application categories"
          rows={keyRows(analytics?.app_categories)}
          empty="No category telemetry."
        />
        <BarList
          title="Web categories"
          rows={keyRows(analytics?.web_categories)}
          empty="No web-category telemetry."
        />
        <BarList title="DNS queries" rows={keyRows(analytics?.dns)} empty="No DNS telemetry." />
        <BarList title="Users" rows={keyRows(analytics?.users)} empty="No user telemetry." />
        <BarList title="Identity (source)" rows={identity} empty="No identity telemetry." />
        <BarList title="Directions (rollup)" rows={directions} empty="No direction rollup." />
        <BarList
          title="Rulesets (rollup)"
          rows={keyRows(rollups?.rulesets)}
          empty="No ruleset rollup."
        />
        <BarList
          title="Rollup application categories"
          rows={keyRows(rollups?.app_categories)}
          empty="No rollup categories."
        />
      </div>

      {nat.length > 0 && (
        <div className="rounded-xl border border-border bg-bg-card p-4">
          <h3 className="mb-2 text-xs font-semibold text-text">NAT translations</h3>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-faint">
                  <th scope="col" className="px-2 py-1.5">Translated source</th>
                  <th scope="col" className="px-2 py-1.5">Destination</th>
                  <th scope="col" className="px-2 py-1.5 text-right">Hits</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60 font-mono text-[11px]">
                {nat.slice(0, 12).map((row, idx) => (
                  <tr key={`${row.src_ip}-${idx}`}>
                    <td className="px-2 py-1.5 text-text">{row.src_ip || '—'}</td>
                    <td className="px-2 py-1.5 text-text-dim">{row.dst_ip || '—'}</td>
                    <td className="px-2 py-1.5 text-right text-text-dim">{row.hits ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// SUB-TAB 3: SECURITY EVENTS (IPS / AV / WEB FILTER / AUTH)
// ============================================================================
const SEC_CLASSES = [
  { value: '2004', label: 'Finding (IPS / AV)' },
  { value: '3002', label: 'Authentication' },
  { value: '4001', label: 'Network' },
  { value: '4014', label: 'VPN session' },
  { value: '5001', label: 'Device health' },
  { value: '5019', label: 'Config change' },
];

// CEF 0-10. The normalizer maps words to 2/3/5/7/9 but passes a numeric CEF
// header through as-is, so 1/4/6/8/10 also occur; the filter is an exact
// match, so every value must be selectable.
const SEC_SEVERITIES = [
  { value: '0', label: '0 — Unknown' },
  { value: '1', label: '1 — Info' },
  { value: '2', label: '2 — Info' },
  { value: '3', label: '3 — Low' },
  { value: '4', label: '4 — Medium' },
  { value: '5', label: '5 — Medium' },
  { value: '6', label: '6 — High' },
  { value: '7', label: '7 — High' },
  { value: '8', label: '8 — Critical' },
  { value: '9', label: '9 — Critical' },
  { value: '10', label: '10 — Critical' },
];

function severityTone(value: number | null | undefined): string {
  // CEF thresholds: >=7 critical, >=4 warning (matches the classic console).
  const v = value ?? 0;
  if (v >= 7) return 'bg-sig-crit/15 text-sig-crit';
  if (v >= 4) return 'bg-sig-warn/15 text-sig-warn';
  return 'bg-accent/15 text-accent';
}

function SecEventInspector({ event }: { event: SecEventRow | undefined }) {
  if (!event) {
    return <p className="p-6 text-center text-xs text-text-dim">Loading event…</p>;
  }
  const endpoint = (ip?: string | null, port?: number | null) =>
    ip ? `${ip}${port ? `:${port}` : ''}` : '';
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded bg-accent/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-accent">
          {classLabel(event.class)}
        </span>
        <span className="rounded bg-bg-panel px-2 py-0.5 text-[10px] uppercase text-text-dim">
          {activityLabel(event.activity)}
        </span>
        <span
          className={cn(
            'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
            severityTone(event.severity),
          )}
        >
          {severityLabel(event.severity)}
        </span>
        <span className="rounded bg-bg-panel px-2 py-0.5 text-[10px] uppercase text-text-dim">
          {actionLabel(event.action)}
        </span>
      </div>

      <DetailSection
        title="Event"
        fields={[
          ['When', event.ts ? new Date(event.ts).toLocaleString() : '—'],
          ['Device', event.device_name || `#${event.device_id}`],
          ['Class', classLabel(event.class)],
          ['Activity', activityLabel(event.activity)],
          ['Action', actionLabel(event.action)],
          ['Severity', severityLabel(event.severity)],
        ]}
      />

      <DetailSection
        title="Network"
        fields={[
          ['Source', endpoint(event.src_ip, event.src_port)],
          ['Destination', endpoint(event.dst_ip, event.dst_port)],
          ['Protocol', formatProto(event.proto)],
          ['User', event.user_name],
          ['Hostname', event.src_hostname],
        ]}
      />

      <DetailSection
        title="Finding"
        fields={[
          ['Signature ID', event.sig_id],
          ['Signature', event.sig_name || event.signature],
          ['Threat category', event.threat_cat],
          ['File hash', event.file_hash],
          ['URL host', event.url_host],
        ]}
      />

      <DetailSection
        title="Administrative action"
        fields={[
          ['Admin', event.admin_user],
          ['Source IP', event.admin_src_ip],
          ['Method', event.admin_method],
          ['Config path', event.config_path],
          ['Object', event.config_obj],
          ['Old value', event.config_old],
          ['New value', event.config_new],
        ]}
      />

      <DetailSection
        title="Tunnel & health"
        fields={[
          ['Tunnel', event.tunnel_name],
          ['Tunnel type', event.tunnel_type],
          ['Peer', event.tunnel_peer],
          ['WAN', event.wan_name],
          ['Metric', event.metric_name],
          [
            'Value',
            event.metric_value !== null && event.metric_value !== undefined
              ? String(event.metric_value)
              : '',
          ],
        ]}
      />

      <DetailSection
        title="Message"
        fields={[
          ['Summary', event.message],
          ['Raw syslog id', event.raw_id !== null && event.raw_id !== undefined ? String(event.raw_id) : ''],
        ]}
      />

      <details className="rounded-lg border border-border bg-bg-card p-3">
        <summary className="cursor-pointer text-xs font-semibold text-text">
          Raw normalized JSON
        </summary>
        <pre className="mt-2 max-h-72 overflow-auto rounded border border-border bg-bg-panel p-2 font-mono text-[10px] text-text-dim">
          {JSON.stringify(event, null, 2)}
        </pre>
      </details>
    </div>
  );
}

// ============================================================================
// SUB-TAB 4: SECURITY ANALYTICS
// ============================================================================
/**
 * The security-event analytics.
 *
 * `GET /admin/api/security-events/analytics` is implemented on the server and
 * was never called by the console: the Security tab was a list and nothing
 * else. It carries the findings trend, the admin-login and config-change
 * trends, the VPN-session trend, the top-N rankings and the WAN health.
 */
function SecurityAnalyticsSubTab({ windowRange }: { windowRange: TimeWindow }) {
  const hours = windowToHours(windowRange);
  const days = windowToDays(windowRange);

  /*
   * The window.
   *
   * The endpoint takes `days` OR `hours`, and the server gives `days`
   * PRECEDENCE whenever it is set. So sending both made every sub-24h pill
   * show the same "since UTC midnight" window - the 1h, 6h, 12h and 24h
   * pills were all the same. So the sub-24h windows send `hours` and only
   * the multi-day ones send `days`.
   */
  const isLongWindow = windowRange === '7d' || windowRange === '30d';
  const windowParams = isLongWindow ? `days=${days}` : `hours=${hours}`;

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['sec-event-analytics', windowParams],
    queryFn: () =>
      apiFetch<any>(`/admin/api/security-events/analytics?${windowParams}`),
  });

  if (isLoading) {
    return (
      <div className="rounded-xl border border-border bg-bg-card p-8 text-center text-sm text-text-dim">
        Loading security analytics…
      </div>
    );
  }

  if (isError) {
    return (
      <div
        role="alert"
        className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit"
      >
        Could not load security analytics:{' '}
        {error instanceof Error ? error.message : 'request failed'}
      </div>
    );
  }

  const findings = secDayCountSeries(data?.findings as SecDayCount[] | undefined);
  const adminLogins = secDayCountSeries(data?.admin_logins as SecDayCount[] | undefined);
  const configChanges = secDayCountSeries(data?.config_changes as SecDayCount[] | undefined);
  const vpnSessions = secDayCountSeries(data?.vpn_sessions as SecDayCount[] | undefined);

  const keyRows = (rows: Array<{ key: string; count: number }> | undefined) =>
    (rows ?? []).map((row) => ({ key: row.key, value: Number(row.count) || 0 }));

  const wanHealth = (data?.wan_health ?? []) as Array<{
    day: string;
    wan_name: string;
    avg: number;
    last: number;
  }>;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <TimeSeriesChart
          title="Security findings over time"
          kind="count"
          timestamps={findings.timestamps}
          series={[{ label: 'Findings', color: 'var(--fwmon-series-2)', values: findings.values }]}
          emptyMessage="No security findings in this window."
        />
        <TimeSeriesChart
          title="Admin logins over time"
          kind="count"
          timestamps={adminLogins.timestamps}
          series={[{ label: 'Admin logins', color: 'var(--fwmon-series-1)', values: adminLogins.values }]}
          emptyMessage="No admin logins in this window."
        />
        <TimeSeriesChart
          title="Configuration changes over time"
          kind="count"
          timestamps={configChanges.timestamps}
          series={[{ label: 'Config changes', color: 'var(--fwmon-series-3)', values: configChanges.values }]}
          emptyMessage="No configuration changes in this window."
        />
        <TimeSeriesChart
          title="VPN sessions over time"
          kind="count"
          timestamps={vpnSessions.timestamps}
          series={[{ label: 'VPN sessions', color: 'var(--fwmon-series-4)', values: vpnSessions.values }]}
          emptyMessage="No VPN sessions in this window."
        />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
        <BarList
          title="Top signatures"
          rows={(data?.top_signatures ?? []).map((r: any) => ({
            key: r.sig_name || 'Unknown',
            value: Number(r.count) || 0,
          }))}
          empty="No signatures in this window."
        />
        <BarList
          title="Top admin users"
          rows={keyRows(data?.top_admin_users)}
          empty="No admin activity in this window."
        />
        <BarList
          title="Top admin source addresses"
          rows={keyRows(data?.top_admin_src_ips)}
          empty="No admin activity in this window."
        />
        <BarList
          title="Top configuration paths"
          rows={keyRows(data?.top_config_paths)}
          empty="No configuration changes in this window."
        />
        <BarList
          title="Top configuration admins"
          rows={keyRows(data?.top_config_admins)}
          empty="No configuration changes in this window."
        />
        <BarList
          title="Top tunnels"
          rows={keyRows(data?.top_tunnels)}
          empty="No tunnel activity in this window."
        />
        <BarList
          title="Top tunnel peers"
          rows={keyRows(data?.top_tunnel_peers)}
          empty="No tunnel activity in this window."
        />
      </div>

      <div className="rounded-xl border border-border bg-bg-card p-4">
        <h3 className="mb-2 text-xs font-semibold text-text">WAN health</h3>
        {wanHealth.length === 0 ? (
          <p className="text-[11px] text-text-faint">No WAN health readings in this window.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-faint">
                  <th scope="col" className="px-2 py-1.5">Day</th>
                  <th scope="col" className="px-2 py-1.5">WAN</th>
                  <th scope="col" className="px-2 py-1.5 text-right">Average</th>
                  <th scope="col" className="px-2 py-1.5 text-right">Latest</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {wanHealth.map((w, i) => (
                  <tr key={`${w.day}-${w.wan_name}-${i}`}>
                    <td className="px-2 py-1.5 font-mono text-text-dim">{w.day}</td>
                    <td className="px-2 py-1.5 font-mono text-text">{w.wan_name}</td>
                    <td className="px-2 py-1.5 text-right font-mono text-text-dim">
                      {Number(w.avg).toFixed(2)}
                    </td>
                    <td className="px-2 py-1.5 text-right font-mono text-text">
                      {Number(w.last).toFixed(2)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function SecurityEventsSubTab({ windowRange }: { windowRange: TimeWindow }) {
  const [selectedSecId, setSelectedSecId] = useState<number | null>(null);
  const [classFilter, setClassFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [filters, setFilters] = useState<EventFilters>({});
  const [page, setPage] = useState(0);
  const hours = windowToHours(windowRange);
  const PAGE_SIZE = 50;
  const offset = page * PAGE_SIZE;

  /*
   * The server's filters for `GET /admin/api/security-events`: device_id,
   * probe_id, class, activity, action, severity, admin_user, sig_name,
   * tunnel_name and wan_name. The console offered only the class and the
   * severity. There is NO site_id on this endpoint — the security events
   * are filtered by device or probe, not by site.
   */
  const secFilters: EventFilters = useMemo(
    () => ({ ...filters, class: classFilter, severity: severityFilter }),
    [filters, classFilter, severityFilter],
  );

  const {
    data: secRes,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ['sec-events', hours, secFilters, page],
    queryFn: () => {
      const params = buildSecEventQuery(secFilters, hours, PAGE_SIZE, offset);
      return apiFetch<any>(`/admin/api/security-events?${params.toString()}`);
    },
  });

  const { data: secDetail } = useQuery({
    queryKey: ['sec-event-detail', selectedSecId],
    queryFn: () => apiFetch<SecEventRow>(`/admin/api/security-events/${selectedSecId}`),
    enabled: Boolean(selectedSecId),
  });

  const secEvents: SecEventRow[] = Array.isArray(secRes)
    ? secRes
    : secRes?.events ?? secRes?.rows ?? secRes?.items ?? secRes?.data ?? [];
  // The server reports the total and whether it was CAPPED (the count is
  // only computed up to a limit, so a capped total is a lower bound).
  const secTotal: number | undefined = Array.isArray(secRes) ? undefined : secRes?.total;
  const secCapped: boolean = !Array.isArray(secRes) && Boolean(secRes?.total_capped);

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
            {classLabel(row.original.class)}
          </span>
        ),
      },
      {
        id: 'activity',
        header: 'Activity',
        cell: ({ row }) => (
          <span className="font-mono text-[11px] text-text-dim">
            {activityLabel(row.original.activity)}
          </span>
        ),
      },
      {
        id: 'action',
        header: 'Action',
        cell: ({ row }) => (
          <span className="font-mono text-[11px] text-text-dim">
            {actionLabel(row.original.action)}
          </span>
        ),
      },
      {
        id: 'severity',
        header: 'Severity',
        cell: ({ row }) => (
          <span
            className={cn(
              'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
              severityTone(row.original.severity),
            )}
          >
            {severityLabel(row.original.severity)}
          </span>
        ),
      },
      {
        id: 'signature',
        header: 'Signature / Summary',
        cell: ({ row }) => (
          <span className="text-xs text-text">
            {row.original.sig_name ||
              row.original.signature ||
              row.original.message ||
              'Security event'}
          </span>
        ),
      },
      {
        id: 'flow',
        header: 'Source → Destination',
        cell: ({ row }) => (
          <span className="font-mono text-[11px] text-text-dim">
            {row.original.src_ip || '—'}
            {row.original.dst_ip ? ` → ${row.original.dst_ip}` : ''}
          </span>
        ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-3">
      {isError && (
        <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit" role="alert">
          Could not load security events: {error instanceof Error ? error.message : 'request failed'}
        </div>
      )}

      <EventFilterBar
        filters={filters}
        onChange={(next) => {
          setFilters(next);
          setPage(0);
        }}
        // The class and the severity live in their own state.
        onClear={() => {
          setClassFilter('');
          setSeverityFilter('');
          setPage(0);
        }}
        withSecText
        withActivity
      >
        <Select
          className="px-2.5 py-1"
          value={classFilter}
          onChange={(e) => {
            setClassFilter(e.target.value);
            setPage(0);
          }}
          aria-label="Filter by event class"
        >
          <option value="">All classes</option>
          {SEC_CLASSES.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </Select>
        <Select
          className="px-2.5 py-1"
          value={severityFilter}
          onChange={(e) => {
            setSeverityFilter(e.target.value);
            setPage(0);
          }}
          aria-label="Filter by severity"
        >
          <option value="">All severities</option>
          {SEC_SEVERITIES.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </Select>
        <RefreshButton
          queryKeys={[['sec-events'], ['sec-event-analytics']]}
          label="Refresh"
        />
      </EventFilterBar>

      <ResponsiveDataView
        data={secEvents}
        columns={columns}
        isLoading={isLoading}
        onRowClick={(row) => setSelectedSecId(row.id)}
        emptyTitle="No security events in this window."
        emptyDescription="Adjust the class/severity filters or widen the window."
        renderMobileCard={(ev) => (
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs uppercase text-accent">
                {classLabel(ev.class)}
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

      <EventPager
        page={page}
        total={secTotal}
        pageSize={PAGE_SIZE}
        onChange={setPage}
        capped={secCapped}
      />


      <SlideOverDrawer
        open={Boolean(selectedSecId)}
        onOpenChange={(open) => {
          if (!open) setSelectedSecId(null);
        }}
        title={`Security Event #${selectedSecId ?? ''}`}
        subtitle="Normalized finding, endpoint, identity and administrative context."
        size="lg"
      >
        <SecEventInspector event={secDetail} />
      </SlideOverDrawer>
    </div>
  );
}
