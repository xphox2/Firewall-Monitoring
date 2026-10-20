import { useState, useEffect } from 'react';
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

type OverviewTab = 'health' | 'noc';

export function OverviewWorkspace() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = (searchParams.get('tab') as OverviewTab) || 'health';

  const setTab = (tab: OverviewTab) => {
    setSearchParams({ tab }, { replace: true });
  };

  const { data: summary } = useQuery({
    queryKey: ['dashboard-summary'],
    queryFn: () => apiFetch<DashboardSummary>('/admin/api/dashboard/summary'),
    refetchInterval: 30_000,
  });

  const { data: sysHealth } = useQuery({
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
                  ? 'bg-bg-card text-text shadow-sm border border-border'
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
                  ? 'bg-bg-card text-text shadow-sm border border-border'
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
                <span className="font-display text-2xl font-bold text-sig-ok tabular-nums">
                  {online}
                </span>
                <span className="font-mono text-xs text-text-mute">/ {total} total</span>
              </div>
              <div className="mt-1 text-[11px] text-text-faint">
                {offline > 0 ? (
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
                <span className="font-display text-2xl font-bold text-text tabular-nums">{probes}</span>
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
                {formatCompactNumber(syslog24)}
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
                {formatCompactNumber(traps24)}
              </div>
              <div className="mt-1 text-[11px] text-text-faint">Trap events received (last 24h)</div>
            </div>
          </div>

          {/* Primary Server Runtime Telemetry */}
          {sysHealth && (
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
          )}

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
// LIVE NOC WALLBOARD (SSE /admin/api/noc/stream + /admin/api/noc/snapshot)
// ============================================================================
function LiveNocWallboard() {
  const [sseConnected, setSseConnected] = useState(false);
  const [liveSnapshot, setLiveSnapshot] = useState<any>(null);

  const { data: initialSnapshot } = useQuery({
    queryKey: ['noc-snapshot'],
    queryFn: () => apiFetch<any>('/admin/api/noc/snapshot'),
  });

  useEffect(() => {
    const es = new EventSource('/admin/api/noc/stream');
    es.onopen = () => setSseConnected(true);
    es.onmessage = (ev) => {
      try {
        const parsed = JSON.parse(ev.data);
        setLiveSnapshot(parsed);
      } catch {
        // Ignore keepalive comments
      }
    };
    es.onerror = () => setSseConnected(false);
    return () => es.close();
  }, []);

  const data = liveSnapshot || initialSnapshot || {};

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between rounded-xl border border-border bg-bg-card px-4 py-3">
        <div className="flex items-center gap-2.5">
          <span
            className={cn(
              'h-2.5 w-2.5 rounded-full',
              sseConnected ? 'bg-sig-ok animate-pulse' : 'bg-sig-warn'
            )}
          />
          <span className="text-xs font-semibold text-text">
            {sseConnected ? 'Live NOC SSE Stream Connected' : 'Polling NOC Snapshot'}
          </span>
        </div>
        <button
          type="button"
          onClick={toggleFullscreen}
          className="flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:bg-bg-hover"
        >
          <Maximize2 className="h-3.5 w-3.5 text-accent" />
          Fullscreen Wallboard
        </button>
      </div>

      <div className="rounded-xl border border-border bg-bg-card p-4">
        <h2 className="text-sm font-semibold text-text mb-2">Real-Time NOC Telemetry Feed</h2>
        <pre className="rounded-lg border border-border bg-bg-panel p-3 font-mono text-xs text-text overflow-x-auto max-h-96">
          {JSON.stringify(data, null, 2)}
        </pre>
      </div>
    </div>
  );
}
