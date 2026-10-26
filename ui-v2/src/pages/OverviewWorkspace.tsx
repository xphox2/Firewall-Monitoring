import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  Server,
  Radio,
  Terminal,
  BellRing,
  HardDrive,
  Sliders,
  ArrowRight,
  CheckCircle2,
  Sparkles,
  Tv,
  Maximize2,
  Cpu,
} from 'lucide-react';
import { apiFetch, type DashboardSummary, type SystemHealthSnapshot } from '@/lib/api';
import { cn, formatBytes, formatCompactNumber, formatRelativeTime } from '@/lib/utils';
import { formatBitsPerSecond } from '@/lib/chart';
import { bucketToMs } from '@/lib/time-buckets';
import { TimeSeriesChart } from '@/components/charts/time-series-chart';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { SkeletonStat, SkeletonValue } from '@/components/ui/skeleton';
import { mergeFeed } from '@/lib/noc';

type OverviewTab = 'health' | 'noc';

export function OverviewWorkspace() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = (searchParams.get('tab') as OverviewTab) || 'health';

  const setTab = (tab: OverviewTab) => {
    setSearchParams({ tab }, { replace: true });
  };

  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['dashboard-summary'],
    queryFn: () => apiFetch<DashboardSummary>('/admin/api/dashboard/summary'),
    refetchInterval: 30_000,
  });

  const { data: sysHealth, isLoading: sysHealthLoading } = useQuery({
    queryKey: ['system-health'],
    queryFn: () => apiFetch<SystemHealthSnapshot>('/admin/api/system'),
    refetchInterval: 30_000,
  });

  const online = summary?.device_counts?.online ?? 0;
  const total = summary?.device_counts?.total ?? 0;
  const offline = summary?.device_counts?.offline ?? 0;
  const probes = summary?.probe_count_active ?? 0;
  const syslog24 = summary?.syslog_24h ?? 0;
  const traps24 = summary?.trap_24h ?? 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-accent" />
            <h1 className="font-display text-lg sm:text-xl font-bold text-text">
              Command Overview & Live NOC Wallboard
            </h1>
          </div>
          <p className="text-xs text-text-faint mt-0.5">
            Unified NOC console across Desktop, Tablet, and Mobile viewports.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 rounded-lg bg-bg-panel p-1 border border-border">
            <button
              type="button"
              onClick={() => setTab('health')}
              className={cn(
                'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
                activeTab === 'health'
                  ? 'bg-bg-card text-text shadow-xs border border-border'
                  : 'text-text-dim hover:text-text'
              )}
            >
              <Activity className="h-3.5 w-3.5 text-accent" />
              System Health
            </button>
            <button
              type="button"
              onClick={() => setTab('noc')}
              className={cn(
                'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
                activeTab === 'noc'
                  ? 'bg-bg-card text-text shadow-xs border border-border'
                  : 'text-text-dim hover:text-text'
              )}
            >
              <Tv className="h-3.5 w-3.5 text-sig-ok" />
              Live NOC Stream
            </button>
          </div>
        </div>
      </div>

      {activeTab === 'noc' ? (
        <LiveNocWallboard />
      ) : (
        <>
          {/* KPI Vitals Grid */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
            <div
              onClick={() => navigate('/devices')}
              className="cursor-pointer rounded-lg border border-border bg-bg-card p-4 hover:border-border-strong transition-colors"
            >
              <div className="flex items-center justify-between text-xs text-text-faint">
                <span>Firewalls Online</span>
                <Server className="h-4 w-4 text-sig-ok" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <SkeletonValue loading={summaryLoading} width="w-14" height="2rem" />
                {summaryLoading ? null : (
                  <span className="font-display text-2xl font-bold text-sig-ok tabular-nums">{online}</span>
                )}
                <span className="font-mono text-xs text-text-mute">
                  {summaryLoading ? '' : `/ ${total} total`}
                </span>
              </div>
              <div className="mt-1 text-[11px] text-text-faint">
                {summaryLoading ? (
                  ''
                ) : offline > 0 ? (
                  <span className="text-sig-crit font-medium">{offline} offline</span>
                ) : (
                  'All monitored firewalls reachable'
                )}
              </div>
            </div>

            <div
              onClick={() => navigate('/collectors')}
              className="cursor-pointer rounded-lg border border-border bg-bg-card p-4 hover:border-border-strong transition-colors"
            >
              <div className="flex items-center justify-between text-xs text-text-faint">
                <span>Active Collectors</span>
                <Radio className="h-4 w-4 text-accent" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <SkeletonValue loading={summaryLoading} width="w-14" height="2rem" />
                {summaryLoading ? null : (
                  <span className="font-display text-2xl font-bold text-text tabular-nums">{probes}</span>
                )}
                <span className="font-mono text-xs text-text-mute">online</span>
              </div>
              <div className="mt-1 text-[11px] text-text-faint">
                {summary?.probe_count_pending
                  ? `${summary.probe_count_pending} awaiting approval`
                  : 'Relay heartbeat nominal'}
              </div>
            </div>

            <div
              onClick={() => navigate('/syslog')}
              className="cursor-pointer rounded-lg border border-border bg-bg-card p-4 hover:border-border-strong transition-colors"
            >
              <div className="flex items-center justify-between text-xs text-text-faint">
                <span>24h Syslog Ingest</span>
                <Terminal className="h-4 w-4 text-accent" />
              </div>
              <div className="mt-2 font-display text-2xl font-bold text-text tabular-nums">
                <SkeletonValue loading={summaryLoading} width="w-20" height="2rem" />
                {summaryLoading ? null : formatCompactNumber(syslog24)}
              </div>
              <div className="mt-1 text-[11px] text-text-faint">Messages ingested (last 24h)</div>
            </div>

            <div
              onClick={() => navigate('/traps')}
              className="cursor-pointer rounded-lg border border-border bg-bg-card p-4 hover:border-border-strong transition-colors"
            >
              <div className="flex items-center justify-between text-xs text-text-faint">
                <span>24h SNMP Traps</span>
                <BellRing className="h-4 w-4 text-sig-warn" />
              </div>
              <div className="mt-2 font-display text-2xl font-bold text-text tabular-nums">
                <SkeletonValue loading={summaryLoading} width="w-20" height="2rem" />
                {summaryLoading ? null : formatCompactNumber(traps24)}
              </div>
              <div className="mt-1 text-[11px] text-text-faint">Trap events received (last 24h)</div>
            </div>
          </div>

          {/* Primary Server Runtime Telemetry */}
          {sysHealthLoading && !sysHealth ? (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {[0, 1, 2, 3].map((n) => (
                <div key={n} className="rounded-lg border border-border bg-bg-card p-3.5">
                  <SkeletonStat />
                </div>
              ))}
            </div>
          ) : sysHealth ? (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="rounded-lg border border-border bg-bg-card p-3.5">
                <div className="text-[11px] text-text-faint flex items-center gap-1.5">
                  <Cpu className="h-3.5 w-3.5 text-accent" /> Go Runtime Goroutines
                </div>
                <div className="mt-1 font-mono text-lg font-bold text-text">
                  {sysHealth.runtime?.goroutines ?? sysHealth.goroutines ?? 0}
                </div>
              </div>
              <div className="rounded-lg border border-border bg-bg-card p-3.5">
                <div className="text-[11px] text-text-faint">Heap Memory Allocated</div>
                <div className="mt-1 font-mono text-lg font-bold text-text">
                  {sysHealth.runtime?.heap_alloc_mb !== undefined
                    ? `${sysHealth.runtime.heap_alloc_mb.toFixed(1)} MB`
                    : formatBytes(sysHealth.memory_alloc_bytes ?? 0)}
                </div>
              </div>
              <div className="rounded-lg border border-border bg-bg-card p-3.5">
                <div className="text-[11px] text-text-faint">PostgreSQL DB Size</div>
                <div className="mt-1 font-mono text-lg font-bold text-accent">
                  {formatBytes(sysHealth.db?.size_bytes ?? sysHealth.db_size_bytes ?? 0)}
                </div>
              </div>
              <div className="rounded-lg border border-border bg-bg-card p-3.5">
                <div className="text-[11px] text-text-faint">Open DB Connections</div>
                <div className="mt-1 font-mono text-lg font-bold text-text">
                  {sysHealth.db?.pool?.open ?? sysHealth.db_open_connections ?? 0}
                </div>
              </div>
            </div>
          ) : null}

          <ServerTrend />

          {/* V2 Workspace Quick-Launch Cards */}
          <section className="rounded-lg border border-border bg-bg-card p-5 space-y-4">
            <div className="flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-accent" />
              <h2 className="font-display text-sm font-bold text-text">
                Redesigned V2 Workspaces — Complete 5-Workspace Architecture
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
              <div
                onClick={() => navigate('/configuration/storage')}
                className="cursor-pointer rounded-lg border border-accent/40 bg-accent/5 p-4 hover:bg-accent/10 transition-colors flex flex-col justify-between gap-3"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-1.5 font-display text-xs font-bold text-accent">
                      <HardDrive className="h-4 w-4" />
                      Storage, Retention & Archive
                    </span>
                    <span className="inline-flex items-center gap-1 rounded bg-sig-ok/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-sig-ok">
                      <CheckCircle2 className="h-3 w-3" />
                      LIVE
                    </span>
                  </div>
                  <p className="text-xs text-text-dim mt-1.5">
                    Replaces the 9,589px Settings → Retention scroll-wall with a 3-tab matrix, live volume projections, and universal sticky save bar.
                  </p>
                </div>
                <div className="inline-flex items-center gap-1 text-xs font-semibold text-accent">
                  <span>Open Storage & Archive Matrix</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </div>
              </div>

              <div
                onClick={() => navigate('/configuration/alerting')}
                className="cursor-pointer rounded-lg border border-border bg-bg-panel/40 p-4 hover:border-border-strong transition-colors flex flex-col justify-between gap-3"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-1.5 font-display text-xs font-bold text-text">
                      <BellRing className="h-4 w-4 text-sig-warn" />
                      Unified Alerting & Detection
                    </span>
                    <span className="inline-flex items-center gap-1 rounded bg-sig-ok/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-sig-ok">
                      <CheckCircle2 className="h-3 w-3" />
                      LIVE
                    </span>
                  </div>
                  <p className="text-xs text-text-faint mt-1.5">
                    Consolidates Global Thresholds, sFlow/Deny Anomaly Detection, Event Profiles & Rules, and Notification Profiles.
                  </p>
                </div>
                <div className="inline-flex items-center gap-1 text-xs font-medium text-text-dim">
                  <span>Open Alerting & Rules</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </div>
              </div>

              <div
                onClick={() => navigate('/configuration/system')}
                className="cursor-pointer rounded-lg border border-border bg-bg-panel/40 p-4 hover:border-border-strong transition-colors flex flex-col justify-between gap-3"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-1.5 font-display text-xs font-bold text-text">
                      <Sliders className="h-4 w-4 text-accent" />
                      System, Users & Access
                    </span>
                    <span className="inline-flex items-center gap-1 rounded bg-sig-ok/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-sig-ok">
                      <CheckCircle2 className="h-3 w-3" />
                      LIVE
                    </span>
                  </div>
                  <p className="text-xs text-text-faint mt-1.5">
                    Users & RBAC, Scoped API Tokens, Display & Timezone, Scheduled Reports, Audit Log, and WebAuthn Passkeys.
                  </p>
                </div>
                <div className="inline-flex items-center gap-1 text-xs font-medium text-text-dim">
                  <span>Open System & Access</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </div>
              </div>
            </div>
          </section>

          {/* Monitored Firewall Fleet Quick List */}
          {summary?.devices && summary.devices.length > 0 && (
            <section className="rounded-lg border border-border bg-bg-card overflow-hidden">
              <div className="border-b border-border bg-bg-panel/50 px-4 py-3 flex items-center justify-between">
                <h2 className="font-display text-sm font-bold text-text">
                  Monitored Firewalls ({summary.devices.length})
                </h2>
                <button
                  type="button"
                  onClick={() => navigate('/devices')}
                  className="text-xs font-medium text-accent hover:underline"
                >
                  View All Firewalls →
                </button>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 p-4">
                {summary.devices.slice(0, 12).map((dev) => (
                  <div
                    key={dev.id}
                    onClick={() => navigate(`/devices/${dev.id}`)}
                    className="cursor-pointer rounded-md border border-border bg-bg-panel/40 px-3.5 py-2.5 flex items-center justify-between gap-2 hover:border-border-strong transition-colors"
                  >
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-text truncate">{dev.name}</div>
                      <div className="text-[11px] text-text-faint">
                        Polled {formatRelativeTime(dev.last_polled)}
                      </div>
                    </div>
                    <span
                      className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase ${
                        dev.status === 'online'
                          ? 'bg-sig-ok/15 text-sig-ok'
                          : 'bg-sig-crit/15 text-sig-crit'
                      }`}
                    >
                      {dev.status}
                    </span>
                  </div>
                ))}
              </div>
            </section>
          )}
        </>
      )}
    </div>
  );
}

// ============================================================================
// SERVER RESOURCE TREND (GET /admin/api/system/metrics/chart)
// ============================================================================
interface ServerMetricBucket {
  bucket: string;
  cpu_percent?: number;
  mem_percent?: number;
  load1?: number;
  root_disk_percent?: number;
  data_disk_percent?: number | null;
}

const SERVER_TREND_RANGES = [
  { value: '1h', label: '1h' },
  { value: '6h', label: '6h' },
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
  { value: '30d', label: '30d' },
] as const;

function ServerTrend() {
  const [range, setRange] = useState<(typeof SERVER_TREND_RANGES)[number]['value']>('24h');

  const { data, isLoading, isError } = useQuery({
    queryKey: ['server-metric-chart', range],
    queryFn: () =>
      apiFetch<ServerMetricBucket[]>(`/admin/api/system/metrics/chart?range=${range}`),
    refetchInterval: 60_000,
  });

  const rows = Array.isArray(data) ? data : [];

  const chart = useMemo(() => {
    const points = rows
      .map((row) => ({ ts: bucketToMs(row.bucket), row }))
      .filter((point): point is { ts: number; row: ServerMetricBucket } => point.ts != null)
      .sort((a, b) => a.ts - b.ts);
    return {
      timestamps: points.map((point) => point.ts),
      cpu: points.map((point) => point.row.cpu_percent ?? null),
      mem: points.map((point) => point.row.mem_percent ?? null),
      root: points.map((point) => point.row.root_disk_percent ?? null),
      // A bucket where the volume could not be probed is unknown, not 0%.
      data: points.map((point) =>
        point.row.data_disk_percent == null ? null : point.row.data_disk_percent,
      ),
    };
  }, [rows]);

  return (
    <section className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-text">Server resource trend</h2>
          <p className="text-[11px] text-text-faint">
            Host CPU, memory and disk usage — 5-minute sampling. A gap means the volume could not
            be probed.
          </p>
        </div>
        <div className="flex items-center gap-0.5 rounded-lg border border-border bg-bg-panel p-1">
          {SERVER_TREND_RANGES.map((option) => (
            <button
              key={option.value}
              type="button"
              aria-pressed={range === option.value}
              onClick={() => setRange(option.value)}
              className={cn(
                'rounded px-2 py-1 font-mono text-[11px] font-medium',
                range === option.value ? 'bg-accent text-white' : 'text-text-dim hover:text-text',
              )}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {isError ? (
        <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit" role="alert">
          Could not load the server resource history.
        </div>
      ) : (
        <TimeSeriesChart
          timestamps={chart.timestamps}
          series={[
            { label: 'CPU', color: 'var(--fwmon-series-1)', values: chart.cpu },
            { label: 'Memory', color: 'var(--fwmon-series-5)', values: chart.mem },
            { label: 'Root disk', color: 'var(--fwmon-series-4)', values: chart.root },
            { label: 'DB volume', color: 'var(--fwmon-series-7)', values: chart.data },
          ]}
          kind="percent"
          isLoading={isLoading}
          emptyMessage="No server metric samples in this window."
          spanGaps={false}
        />
      )}
    </section>
  );
}

// ============================================================================
// LIVE NOC WALLBOARD (SSE /admin/api/noc/stream + /admin/api/noc/snapshot)
// ============================================================================
interface NocDeviceRow {
  id: number;
  name: string;
  ip?: string;
  status?: string;
  worst_severity?: string;
  bits_per_second?: number;
  last_polled?: string;
}

interface NocSite {
  site_id?: number | null;
  site_name: string;
  worst_severity?: string;
  devices_online?: number;
  devices_offline?: number;
  alerts_critical?: number;
  alerts_warning?: number;
  probe_offline?: boolean;
  bits_per_second?: number;
  threat_flows?: number;
  devices?: NocDeviceRow[];
}

interface NocFeedItem {
  kind?: string;
  id: number;
  at?: string;
  last_seen?: string;
  repeat?: number;
  severity?: string;
  type?: string;
  category?: string;
  device_id?: number;
  device_name?: string;
  site_name?: string;
  message?: string;
  acknowledged?: boolean;
  dedup_key?: string;
}

interface NocFeed {
  generated_at?: string;
  alerts?: NocFeedItem[];
  detections?: NocFeedItem[];
  silenced?: NocFeedItem[];
  silenced_total?: number;
}

interface NocThreatEntry {
  addr: string;
  requests?: number;
  bytes?: number;
  service?: number;
  protocol?: number;
  internal_hosts?: string[];
  internal_count?: number;
  devices?: number;
  inferred?: boolean;
  ip_match?: boolean;
  blocked?: number;
}

interface NocSnapshot {
  generated_at?: string;
  window_seconds?: number;
  total_flows?: number;
  total_bytes?: number;
  bits_per_second?: number;
  unique_sources?: number;
  unique_dests?: number;
  threat_flows?: number;
  probes_online?: number;
  probes_offline?: number;
  devices_online?: number;
  devices_offline?: number;
  active_threat_intel?: number;
  sites?: NocSite[];
  feed?: NocFeed;
  threat_top?: {
    window_seconds?: number;
    summary?: {
      inbound?: number;
      outbound?: number;
      unclassified?: number;
      other?: number;
      blocked?: number;
    };
    outbound?: NocThreatEntry[];
    inbound?: NocThreatEntry[];
  };
}

type FeedKind = 'all' | 'alerts' | 'detections' | 'silenced';

const severityBadge: Record<string, string> = {
  ok: 'bg-sig-ok/15 text-sig-ok',
  critical: 'bg-sig-crit/15 text-sig-crit',
  warning: 'bg-sig-warn/15 text-sig-warn',
  info: 'bg-accent/15 text-accent',
};

function severityBorder(severity?: string): string {
  if (severity === 'critical') return 'border-sig-crit/50';
  if (severity === 'warning') return 'border-sig-warn/50';
  return 'border-border';
}

function FeedRow({ item, list }: { item: NocFeedItem; list: string }) {
  const at = item.last_seen || item.at;
  return (
    <div className="flex items-start gap-2 border-b border-border/50 px-2 py-1.5 last:border-0">
      <span
        className={cn(
          'mt-0.5 shrink-0 rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
          severityBadge[item.severity ?? 'info'] ?? severityBadge.info,
        )}
      >
        {item.severity || list}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-1.5 text-[11px]">
          <span className="font-semibold text-text">{item.type || item.kind || 'event'}</span>
          {(item.repeat ?? 1) > 1 && (
            <span className="font-mono text-[10px] text-text-faint">×{item.repeat}</span>
          )}
          {list === 'silenced' && (
            <span className="rounded bg-bg-panel px-1 text-[9px] uppercase text-text-faint">
              silenced
            </span>
          )}
          {item.device_name && (
            <span className="font-mono text-[10px] text-text-dim">{item.device_name}</span>
          )}
          {item.site_name && (
            <span className="font-mono text-[10px] text-text-faint">{item.site_name}</span>
          )}
        </div>
        <div className="line-clamp-2 text-[11px] text-text-dim">{item.message}</div>
      </div>
      <span className="shrink-0 font-mono text-[10px] text-text-faint">
        {formatRelativeTime(at)}
      </span>
    </div>
  );
}

function LiveNocWallboard() {
  const navigate = useNavigate();
  const [sseConnected, setSseConnected] = useState(false);
  const [everConnected, setEverConnected] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [snapshot, setSnapshot] = useState<NocSnapshot | null>(null);
  const [feed, setFeed] = useState<NocFeed | null>(null);
  const [feedKind, setFeedKind] = useState<FeedKind>('all');
  const [feedCount, setFeedCount] = useState(20);
  const [view, setView] = useState<'site' | 'device'>('site');
  const [manualPause, setManualPause] = useState(false);
  const [hoveringFeed, setHoveringFeed] = useState(false);
  const [drillSite, setDrillSite] = useState<NocSite | null>(null);
  // Pausing only holds the feed; vitals keep streaming. Hovering the feed also
  // holds it so a row can be read without it being re-sorted away.
  // Touch devices can synthesize mouseenter without a matching mouseleave;
  // only honour hover-hold where hovering is a real input.
  const hoverCapable =
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia('(hover: hover)').matches
      : false;
  const paused = manualPause || (hoverCapable && hoveringFeed);
  const pausedRef = useRef(false);
  const pendingFeedRef = useRef<NocFeed | null>(null);

  useEffect(() => {
    pausedRef.current = paused;
    if (!paused && pendingFeedRef.current) {
      setFeed(pendingFeedRef.current);
      pendingFeedRef.current = null;
    }
  }, [paused]);

  const { data: initialSnapshot } = useQuery({
    queryKey: ['noc-snapshot'],
    queryFn: () => apiFetch<NocSnapshot>('/admin/api/noc/snapshot'),
  });

  useEffect(() => {
    if (initialSnapshot) {
      setSnapshot((current) => current ?? initialSnapshot);
      if (initialSnapshot.feed && !pausedRef.current) {
        setFeed((current) => current ?? initialSnapshot.feed ?? null);
      }
    }
  }, [initialSnapshot]);

  useEffect(() => {
    const es = new EventSource('/admin/api/noc/stream');
    es.onopen = () => {
      setSseConnected(true);
      setEverConnected(true);
    };
    es.onmessage = (ev) => {
      try {
        const parsed = JSON.parse(ev.data) as NocSnapshot;
        setSnapshot(parsed);
        // The one-shot carries the feed inline; the stream normally sends it
        // as a named event, but accept it here too.
        if (parsed.feed) {
          if (pausedRef.current) pendingFeedRef.current = parsed.feed;
          else setFeed(parsed.feed);
        }
      } catch {
        // keepalive comment
      }
    };
    // v0.11.269: the live alert/detection ticker arrives as a named event.
    const onFeed = (ev: MessageEvent) => {
      try {
        const parsed = JSON.parse(ev.data) as NocFeed;
        if (pausedRef.current) pendingFeedRef.current = parsed;
        else setFeed(parsed);
      } catch {
        // ignore malformed frame
      }
    };
    es.addEventListener('feed', onFeed as EventListener);
    es.onerror = () => setSseConnected(false);
    return () => {
      es.removeEventListener('feed', onFeed as EventListener);
      es.close();
    };
  }, []);

  useEffect(() => {
    const onChange = () => setIsFullscreen(Boolean(document.fullscreenElement));
    document.addEventListener('fullscreenchange', onChange);
    return () => document.removeEventListener('fullscreenchange', onChange);
  }, []);

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  };

  const sites = snapshot?.sites ?? [];
  const devices: Array<NocDeviceRow & { site_name?: string }> = sites.flatMap((site) =>
    (site.devices ?? []).map((d) => ({ ...d, site_name: site.site_name })),
  );

  const feedItems = useMemo(() => mergeFeed(feed, feedKind, feedCount), [feed, feedKind, feedCount]);

  const threats = snapshot?.threat_top;
  const summary = threats?.summary;

  if (!snapshot) {
    return (
      <div className="rounded-xl border border-border bg-bg-card p-8 text-center text-sm text-text-dim">
        Connecting to the NOC stream…
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-border bg-bg-card px-4 py-3">
        <div className="flex items-center gap-2.5">
          <span
            className={cn(
              'h-2.5 w-2.5 rounded-full',
              sseConnected ? 'bg-sig-ok animate-pulse motion-reduce:animate-none' : 'bg-sig-warn',
            )}
          />
          <span className="text-xs font-semibold text-text">
            {sseConnected
              ? 'Live NOC stream connected'
              : everConnected
                ? 'Stream reconnecting…'
                : 'Connecting to stream…'}
          </span>
          <span className="font-mono text-[10px] text-text-faint">
            updated {formatRelativeTime(snapshot.generated_at)}
          </span>
        </div>
        <button
          type="button"
          onClick={toggleFullscreen}
          className="flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:bg-bg-hover"
        >
          <Maximize2 className="h-3.5 w-3.5 text-accent" />
          {isFullscreen ? 'Exit fullscreen' : 'Fullscreen wallboard'}
        </button>
      </div>

      {/* Vitals */}
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 gap-2.5">
        {[
          {
            label: 'Throughput',
            value: formatBitsPerSecond(snapshot.bits_per_second ?? 0),
            tone: 'text-accent',
          },
          {
            label: `Flows (${Math.max(1, Math.round((snapshot.window_seconds ?? 300) / 60))}m)`,
            value: formatCompactNumber(snapshot.total_flows ?? 0),
          },
          {
            label: 'Unique src → dst',
            value: `${formatCompactNumber(snapshot.unique_sources ?? 0)} → ${formatCompactNumber(
              snapshot.unique_dests ?? 0,
            )}`,
          },
          {
            label: 'Threat flows',
            value: formatCompactNumber(snapshot.threat_flows ?? 0),
            tone: (snapshot.threat_flows ?? 0) > 0 ? 'text-sig-crit' : 'text-text',
          },
          {
            label: 'Probes',
            value: `${snapshot.probes_online ?? 0} up · ${snapshot.probes_offline ?? 0} down`,
            tone: (snapshot.probes_offline ?? 0) > 0 ? 'text-sig-warn' : 'text-text',
          },
          {
            label: 'Devices',
            value: `${snapshot.devices_online ?? 0} up · ${snapshot.devices_offline ?? 0} down`,
            tone: (snapshot.devices_offline ?? 0) > 0 ? 'text-sig-warn' : 'text-text',
          },
          {
            label: 'Threat intel IOCs',
            value: formatCompactNumber(snapshot.active_threat_intel ?? 0),
          },
        ].map((tile) => (
          <div key={tile.label} className="rounded-lg border border-border bg-bg-card p-3">
            <div className="text-[10px] uppercase text-text-faint">{tile.label}</div>
            <div className={cn('mt-0.5 font-mono text-sm font-bold', tile.tone ?? 'text-text')}>
              {tile.value}
            </div>
          </div>
        ))}
      </div>

      {/* Site / device health */}
      <div className="rounded-xl border border-border bg-bg-card p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-text">
            {view === 'site' ? `Site health (${sites.length})` : `Devices (${devices.length})`}
          </h2>
          <div className="flex items-center gap-1 rounded-lg border border-border bg-bg-panel p-1">
            {(['site', 'device'] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setView(mode)}
                className={cn(
                  'rounded px-2.5 py-1 text-[11px] font-medium',
                  view === mode ? 'bg-bg-card text-text shadow-xs' : 'text-text-dim hover:text-text',
                )}
              >
                By {mode}
              </button>
            ))}
          </div>
        </div>

        {sites.length === 0 ? (
          <p className="p-4 text-center text-xs text-text-faint">No sites or devices reported.</p>
        ) : view === 'site' ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-2.5">
            {sites.map((site, idx) => (
              <div
                key={site.site_id ?? `unassigned-${idx}`}
                onClick={() => {
                  if (site.site_id) setDrillSite(site);
                }}
                role={site.site_id ? 'button' : undefined}
                tabIndex={site.site_id ? 0 : undefined}
                onKeyDown={(event) => {
                  if (site.site_id && (event.key === 'Enter' || event.key === ' ')) {
                    event.preventDefault();
                    setDrillSite(site);
                  }
                }}
                className={cn(
                  'rounded-lg border bg-bg-panel p-3 space-y-1.5',
                  severityBorder(site.worst_severity),
                  site.site_id && 'cursor-pointer hover:border-accent/60',
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-text">{site.site_name}</span>
                  <span
                    className={cn(
                      'rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
                      severityBadge[site.worst_severity ?? 'ok'] ?? severityBadge.ok,
                    )}
                  >
                    {site.worst_severity || 'ok'}
                  </span>
                </div>
                <div className="flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-[10px] text-text-dim">
                  <span>
                    {site.devices_online ?? 0} up · {site.devices_offline ?? 0} down
                  </span>
                  <span>{formatBitsPerSecond(site.bits_per_second ?? 0)}</span>
                  {(site.alerts_critical ?? 0) + (site.alerts_warning ?? 0) > 0 && (
                    <span className="text-sig-warn">
                      {site.alerts_critical ?? 0} crit · {site.alerts_warning ?? 0} warn
                    </span>
                  )}
                  {site.probe_offline && <span className="text-sig-crit">probe offline</span>}
                  {(site.threat_flows ?? 0) > 0 && (
                    <span className="text-sig-crit">{site.threat_flows} threat flows</span>
                  )}
                </div>
                {(site.devices ?? []).length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-0.5">
                    {(site.devices ?? []).slice(0, 6).map((d) => (
                      <button
                        key={d.id}
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/devices/${d.id}`);
                        }}
                        className={cn(
                          'rounded px-1.5 py-0.5 text-[10px] font-mono',
                          d.status === 'online'
                            ? 'bg-sig-ok/10 text-sig-ok'
                            : 'bg-sig-crit/10 text-sig-crit',
                        )}
                        title={d.ip}
                      >
                        {d.name}
                      </button>
                    ))}
                    {(site.devices ?? []).length > 6 && (
                      <span className="self-center text-[10px] text-text-faint">
                        +{(site.devices ?? []).length - 6}
                      </span>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-faint">
                  <th scope="col" className="px-2 py-1.5">Device</th>
                  <th scope="col" className="px-2 py-1.5">Site</th>
                  <th scope="col" className="px-2 py-1.5">Status</th>
                  <th scope="col" className="px-2 py-1.5">Severity</th>
                  <th scope="col" className="px-2 py-1.5 text-right">Throughput</th>
                  <th scope="col" className="px-2 py-1.5 text-right">Last polled</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {devices.map((d) => (
                  <tr
                    key={`${d.site_name}-${d.id}`}
                    className="hover:bg-bg-hover"
                    onClick={() => navigate(`/devices/${d.id}`)}
                  >
                    <td className="px-2 py-1.5 font-semibold text-text">
                      {/*
                        The device name is the link. The ROW used to carry
                        role="button", which gives a table row no computed
                        accessible name at all - its content is spread across
                        the cells - so a screen reader announced "button" and
                        nothing else.
                      */}
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/devices/${d.id}`);
                        }}
                        className="text-left font-semibold text-text underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
                      >
                        {d.name}
                      </button>
                    </td>
                    <td className="px-2 py-1.5 text-[11px] text-text-dim">{d.site_name}</td>
                    <td className="px-2 py-1.5">
                      <span
                        className={cn(
                          'rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
                          d.status === 'online'
                            ? 'bg-sig-ok/15 text-sig-ok'
                            : 'bg-sig-crit/15 text-sig-crit',
                        )}
                      >
                        {d.status || 'unknown'}
                      </span>
                    </td>
                    <td className="px-2 py-1.5">
                      <span
                        className={cn(
                          'rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
                          severityBadge[d.worst_severity ?? 'ok'] ?? severityBadge.ok,
                        )}
                      >
                        {d.worst_severity || 'ok'}
                      </span>
                    </td>
                    <td className="px-2 py-1.5 text-right font-mono text-[11px]">
                      {formatBitsPerSecond(d.bits_per_second ?? 0)}
                    </td>
                    <td className="px-2 py-1.5 text-right font-mono text-[10px] text-text-faint">
                      {!d.last_polled || new Date(d.last_polled).getFullYear() <= 1
                        ? 'Never'
                        : formatRelativeTime(d.last_polled)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        {/* Live feed */}
        <div className="rounded-xl border border-border bg-bg-card overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border bg-bg-panel/40 px-3 py-2">
            <h2 className="text-sm font-semibold text-text">
              Live feed
              {feed?.silenced_total ? (
                <span className="ml-2 font-mono text-[10px] text-text-faint">
                  {feed.silenced_total} silenced
                </span>
              ) : null}
              {paused && (
                <span className="ml-2 rounded bg-sig-warn/15 px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase text-sig-warn">
                  {manualPause ? 'paused' : 'held'}
                </span>
              )}
            </h2>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                aria-pressed={manualPause}
                onClick={() => setManualPause((value) => !value)}
                className={cn(
                  'rounded border px-2 py-1 text-[10px] font-semibold uppercase',
                  manualPause
                    ? 'border-sig-warn/40 bg-sig-warn/10 text-sig-warn'
                    : 'border-border bg-bg-panel text-text-dim hover:text-text',
                )}
              >
                {manualPause ? 'Resume' : 'Pause'}
              </button>
              <select
                value={feedKind}
                onChange={(e) => setFeedKind(e.target.value as FeedKind)}
                aria-label="Feed kind"
                className="rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text"
              >
                <option value="all">All events</option>
                <option value="alerts">Alerts</option>
                <option value="detections">Detections</option>
                <option value="silenced">Silenced</option>
              </select>
              <select
                value={feedCount}
                onChange={(e) => setFeedCount(Number(e.target.value))}
                aria-label="Feed length"
                className="rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text"
              >
                {[10, 20, 50].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div
            className="max-h-[420px] overflow-y-auto"
            onMouseEnter={() => setHoveringFeed(true)}
            onMouseLeave={() => setHoveringFeed(false)}
          >
            {feedItems.length === 0 ? (
              <p className="p-6 text-center text-xs text-text-faint">
                Nothing in the feed for this filter.
              </p>
            ) : (
              feedItems.map(({ item, list }) => (
                <FeedRow
                  key={item.dedup_key ?? `${list}-${item.id}`}
                  item={item}
                  list={list}
                />
              ))
            )}
          </div>
        </div>

        {/* Threats last 60s */}
        <div className="rounded-xl border border-border bg-bg-card overflow-hidden">
          <div className="border-b border-border bg-bg-panel/40 px-3 py-2">
            <h2 className="text-sm font-semibold text-text">
              Threats — last {threats?.window_seconds ?? 60}s
            </h2>
            {summary && (
              <div className="mt-1 flex flex-wrap gap-x-3 font-mono text-[10px] text-text-dim">
                <span>outbound {summary.outbound ?? 0}</span>
                <span>inbound {summary.inbound ?? 0}</span>
                <span>blocked {summary.blocked ?? 0}</span>
                <span>unclassified {summary.unclassified ?? 0}</span>
              </div>
            )}
          </div>
          {!threats || ((threats.outbound ?? []).length === 0 && (threats.inbound ?? []).length === 0) ? (
            <p className="p-6 text-center text-xs text-text-faint">
              No threat-intel traffic in the last minute.
            </p>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 divide-y sm:divide-y-0 sm:divide-x divide-border">
              {(
                [
                  { title: 'Outbound', entries: threats.outbound ?? [] },
                  { title: 'Inbound', entries: threats.inbound ?? [] },
                ] as const
              ).map((column) => (
                <div key={column.title} className="p-2">
                  <div className="px-1 pb-1 text-[10px] font-semibold uppercase text-text-faint">
                    {column.title}
                  </div>
                  {column.entries.length === 0 ? (
                    <p className="px-1 py-2 text-[11px] text-text-faint">None.</p>
                  ) : (
                    column.entries.slice(0, 6).map((entry) => (
                      <div
                        key={`${column.title}-${entry.addr}-${entry.service}`}
                        className="rounded px-1 py-1 hover:bg-bg-hover"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-[11px] text-text">{entry.addr}</span>
                          <span className="font-mono text-[10px] text-text-faint">
                            :{entry.service}
                          </span>
                        </div>
                        <div className="flex flex-wrap gap-x-2 font-mono text-[10px] text-text-dim">
                          <span>{entry.requests ?? 0} req</span>
                          <span>{formatBytes(entry.bytes ?? 0)}</span>
                          {entry.ip_match ? (
                            <span className="text-sig-crit">IP match</span>
                          ) : (
                            <span className="text-sig-warn">ASN match</span>
                          )}
                          {entry.inferred && <span className="text-text-faint">inferred</span>}
                          {(entry.blocked ?? 0) > 0 && (
                            <span className="text-sig-ok">{entry.blocked} blocked</span>
                          )}
                        </div>
                        {(entry.internal_hosts ?? []).length > 0 && (
                          <div className="truncate font-mono text-[10px] text-text-faint">
                            {entry.internal_hosts?.join(', ')}
                            {(entry.internal_count ?? 0) > (entry.internal_hosts?.length ?? 0)
                              ? ` +${(entry.internal_count ?? 0) - (entry.internal_hosts?.length ?? 0)}`
                              : ''}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <SiteDrilldown
        site={drillSite}
        onClose={() => setDrillSite(null)}
        onOpenDevice={(id) => navigate(`/devices/${id}`)}
      />
    </div>
  );
}

function SiteDrilldown({
  site,
  onClose,
  onOpenDevice,
}: {
  site: NocSite | null;
  onClose: () => void;
  onOpenDevice: (deviceId: number) => void;
}) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['noc-site-drilldown', site?.site_id],
    queryFn: () =>
      apiFetch<NocSnapshot>(`/admin/api/noc/snapshot?site_id=${site?.site_id}`),
    enabled: site?.site_id != null,
    refetchInterval: 30_000,
  });
  const filtered = data?.sites?.[0];

  return (
    <SlideOverDrawer
      open={Boolean(site)}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={`Site drill-down — ${site?.site_name ?? ''}`}
      subtitle="Filtered snapshot, refreshed every 30 seconds"
      size="lg"
    >
      {isLoading ? (
        <p className="p-6 text-center text-xs text-text-dim">Loading site snapshot…</p>
      ) : isError ? (
        <p className="p-6 text-center text-xs text-sig-crit" role="alert">
          Could not load this site's snapshot.
        </p>
      ) : !filtered ? (
        <p className="p-6 text-center text-xs text-text-faint">
          No snapshot data for this site.
        </p>
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-2">
            {(
              [
                ['Throughput', formatBitsPerSecond(filtered.bits_per_second ?? 0)],
                [
                  'Devices',
                  `${filtered.devices_online ?? 0} up · ${filtered.devices_offline ?? 0} down`,
                ],
                [
                  'Alerts',
                  `${filtered.alerts_critical ?? 0} crit · ${filtered.alerts_warning ?? 0} warn`,
                ],
                ['Threat flows', formatCompactNumber(filtered.threat_flows ?? 0)],
              ] as const
            ).map(([label, value]) => (
              <div key={label} className="rounded-lg border border-border bg-bg-panel p-2.5">
                <div className="text-[10px] uppercase text-text-faint">{label}</div>
                <div className="mt-0.5 font-mono text-sm font-bold text-text">{value}</div>
              </div>
            ))}
          </div>

          {filtered.probe_offline && (
            <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-[11px] text-sig-crit">
              The site probe is offline — device status may be stale.
            </div>
          )}

          {(filtered.devices ?? []).length === 0 ? (
            <p className="text-[11px] text-text-faint">No devices in this site.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-faint">
                    <th scope="col" className="px-2 py-1.5">Device</th>
                    <th scope="col" className="px-2 py-1.5">Status</th>
                    <th scope="col" className="px-2 py-1.5">Severity</th>
                    <th scope="col" className="px-2 py-1.5 text-right">Throughput</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {(filtered.devices ?? []).map((device) => (
                    <tr
                      key={device.id}
                      className="hover:bg-bg-hover"
                      onClick={() => onOpenDevice(device.id)}
                    >
                      <td className="px-2 py-1.5">
                        {/*
                          The device name is the control. The ROW used to
                          carry role="button", which gives a table row no
                          computed accessible name - its content is spread
                          across the cells.
                        */}
                        <button
                          type="button"
                          onClick={(event) => {
                            event.stopPropagation();
                            onOpenDevice(device.id);
                          }}
                          className="text-left font-semibold text-text underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
                        >
                          {device.name}
                        </button>
                        <div className="font-mono text-[10px] text-text-faint">{device.ip}</div>
                      </td>
                      <td className="px-2 py-1.5">
                        <span
                          className={
                            device.status === 'online'
                              ? 'rounded bg-sig-ok/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-sig-ok'
                              : 'rounded bg-sig-crit/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-sig-crit'
                          }
                        >
                          {device.status || 'unknown'}
                        </span>
                      </td>
                      <td className="px-2 py-1.5">
                        <span
                          className={
                            device.worst_severity === 'critical'
                              ? 'rounded bg-sig-crit/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-sig-crit'
                              : device.worst_severity === 'warning'
                                ? 'rounded bg-sig-warn/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-sig-warn'
                                : 'rounded bg-sig-ok/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-sig-ok'
                          }
                        >
                          {device.worst_severity || 'ok'}
                        </span>
                      </td>
                      <td className="px-2 py-1.5 text-right font-mono text-[11px] text-text-dim">
                        {formatBitsPerSecond(device.bits_per_second ?? 0)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </SlideOverDrawer>
  );
}
