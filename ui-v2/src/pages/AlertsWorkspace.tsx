import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Bell,
  Flame,
  History,
  Check,
  Clock,
  Sparkles,
  CheckCheck,
  BellOff,
  Filter,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatCompactNumber, formatRelativeTime } from '@/lib/utils';
import {
  ALERT_RANGES,
  EMPTY_ALERT_FILTERS,
  alertState,
  buildAlertQuery,
  pageRange,
  trendBars,
  type AlertFilters,
} from '@/lib/alerts';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { BarList } from '@/components/ui/bar-list';
import { SkeletonValue } from '@/components/ui/skeleton';
import { ParsedSyslogFields } from '@/components/alerts/parsed-syslog-fields';
import { isSyslogAlertType } from '@/lib/syslog-parse';
import { useToast } from '@/components/ui/toast';
import { ColumnDef } from '@tanstack/react-table';

type AlertsTab = 'open' | 'incidents' | 'history';

const PAGE_SIZE = 50;

interface AlertRow {
  id: number;
  device_id?: number;
  site_id?: number | null;
  device_name?: string;
  alert_type: string;
  severity: string;
  title?: string;
  message: string;
  metric_name?: string;
  threshold?: number;
  current_value?: number;
  acknowledged: boolean;
  acknowledged_at?: string | null;
  resolved_at?: string | null;
  snoozed_until?: string | null;
  snoozed_reason?: string;
  notes?: string;
  source_addr?: string;
  timestamp?: string;
  created_at?: string;
}

interface LinkedDetection {
  id: number;
  detected_at?: string;
  detector?: string;
  category?: string;
  severity?: string;
  src_addr?: string;
  dst_addr?: string;
  dst_port?: number;
  score?: number;
  message?: string;
  acknowledged?: boolean;
}

interface AlertStats {
  total: number;
  by_severity?: Array<{ key: string; count: number }>;
  by_type?: Array<{ key: string; count: number }>;
  over_time?: Array<{ bucket: string; count: number }>;
}

interface IncidentRow {
  id: number;
  title: string;
  severity: string;
  alert_count: number;
  started_at: string;
  resolved_at?: string | null;
  updated_at?: string;
}

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-sig-crit/15 text-sig-crit',
  warning: 'bg-sig-warn/15 text-sig-warn',
  info: 'bg-accent/15 text-accent',
};

const STATE_STYLE: Record<string, string> = {
  open: 'bg-sig-crit/15 text-sig-crit',
  acknowledged: 'bg-sig-ok/15 text-sig-ok',
  snoozed: 'bg-accent/15 text-accent',
  resolved: 'bg-bg-panel text-text-faint',
};

export function AlertsWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = (searchParams.get('tab') as AlertsTab) || 'open';

  const setTab = (tab: AlertsTab) => {
    setSearchParams({ tab }, { replace: true });
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-border pb-3">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <Bell className="h-3.5 w-3.5" />
            Security & Alerts / Incident Response
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            Alert Queue, Storm Incidents & History
          </h1>
        </div>

        <div className="flex items-center gap-1 rounded-lg border border-border bg-bg-panel p-1">
          <button
            type="button"
            onClick={() => setTab('open')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'open'
                ? 'bg-bg-card text-text shadow-xs border border-border'
                : 'text-text-dim hover:text-text',
            )}
          >
            <Bell className="h-3.5 w-3.5 text-accent" />
            Open Alerts
          </button>
          <button
            type="button"
            onClick={() => setTab('incidents')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'incidents'
                ? 'bg-bg-card text-text shadow-xs border border-border'
                : 'text-text-dim hover:text-text',
            )}
          >
            <Flame className="h-3.5 w-3.5 text-sig-warn" />
            Storm Incidents
          </button>
          <button
            type="button"
            onClick={() => setTab('history')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'history'
                ? 'bg-bg-card text-text shadow-xs border border-border'
                : 'text-text-dim hover:text-text',
            )}
          >
            <History className="h-3.5 w-3.5 text-accent" />
            Alert History
          </button>
        </div>
      </div>

      {activeTab === 'open' && <AlertsQueue acknowledged={false} />}
      {activeTab === 'incidents' && <StormIncidentsSubTab />}
      {activeTab === 'history' && <AlertsQueue acknowledged={true} />}
    </div>
  );
}

function AlertsQueue({ acknowledged }: { acknowledged: boolean }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [range, setRange] = useState('24h');
  const [trendType, setTrendType] = useState('');
  const [filters, setFilters] = useState<AlertFilters>(EMPTY_ALERT_FILTERS);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [detail, setDetail] = useState<AlertRow | null>(null);
  const [notesDraft, setNotesDraft] = useState('');
  const [snoozeHours, setSnoozeHours] = useState('1');
  const [bulkSnoozeOpen, setBulkSnoozeOpen] = useState(false);
  const [bulkHours, setBulkHours] = useState('1');
  const [bulkReason, setBulkReason] = useState('');
  const [suggestedRule, setSuggestedRule] = useState<any>(null);

  const hours = ALERT_RANGES.find((r) => r.value === range)?.hours ?? 24;

  const { data: devices = [] } = useQuery({
    queryKey: ['alert-devices'],
    queryFn: () => apiFetch<Array<{ id: number; name: string }>>('/admin/api/devices'),
  });
  const { data: sites = [] } = useQuery({
    queryKey: ['alert-sites'],
    queryFn: () => apiFetch<Array<{ id: number; name: string }>>('/admin/api/sites'),
  });

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['alert-stats', hours, filters.deviceId],
    queryFn: () =>
      apiFetch<AlertStats>(
        `/admin/api/alerts/stats?hours=${hours}${filters.deviceId ? `&device_id=${filters.deviceId}` : ''}`,
      ),
    refetchInterval: 30_000,
  });

  const { data: typeStats, isFetching: typeStatsLoading } = useQuery({
    queryKey: ['alert-stats-type', hours, filters.deviceId, trendType],
    queryFn: () =>
      apiFetch<AlertStats>(
        `/admin/api/alerts/stats?hours=${hours}&alert_type=${encodeURIComponent(trendType)}${
          filters.deviceId ? `&device_id=${filters.deviceId}` : ''
        }`,
      ),
    enabled: Boolean(trendType),
    refetchInterval: 30_000,
    placeholderData: (previous) => previous,
  });

  // The volume card, total and severity tiles follow the selected type; the
  // by-type distribution always stays fleet-wide.
  const activeStats = trendType ? typeStats : stats;

  const offset = page * PAGE_SIZE;
  const { data: listRes, isLoading } = useQuery({
    queryKey: ['alerts-list', acknowledged, filters, page],
    queryFn: () =>
      apiFetch<{ alerts?: AlertRow[]; total?: number }>(
        `/admin/api/alerts?${buildAlertQuery({ acknowledged, filters, offset, limit: PAGE_SIZE })}`,
      ),
    refetchInterval: 15_000,
  });

  const alerts = listRes?.alerts ?? [];
  const total = listRes?.total ?? 0;

  // The detail endpoint joins the flow detections behind this alert.
  const {
    data: alertDetailData,
    isPending: alertDetailLoading,
    isError: alertDetailError,
  } = useQuery({
    queryKey: ['alert-detail', detail?.id],
    queryFn: () =>
      apiFetch<{ alert?: AlertRow; detections?: LinkedDetection[] }>(
        `/admin/api/alerts/${detail?.id}`,
      ),
    enabled: Boolean(detail?.id),
  });
  const linkedDetections = alertDetailData?.detections ?? [];
  const sourceAddr = alertDetailData?.alert?.source_addr;

  const updateFilters = (patch: Partial<AlertFilters>) => {
    // Reset synchronously with the filter change: an effect would render once
    // with the new filters and the stale offset and fire a wasted request.
    setFilters((current) => ({ ...current, ...patch }));
    setPage(0);
    setSelected(new Set());
  };

  useEffect(() => {
    setNotesDraft(detail?.notes ?? '');
    setSnoozeHours('1');
    setSuggestedRule(null);
  }, [detail]);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['alerts-list'] });
    queryClient.invalidateQueries({ queryKey: ['alert-stats'] });
  };

  const bulkAck = useMutation({
    mutationFn: async () =>
      apiFetch('/admin/api/alerts/bulk-acknowledge', {
        method: 'POST',
        body: { ids: Array.from(selected) },
      }),
    onSuccess: () => {
      toast({ title: `Acknowledged ${selected.size} alert(s)`, variant: 'success' });
      setSelected(new Set());
      invalidate();
    },
    onError: (err: Error) =>
      toast({ title: 'Bulk acknowledge failed', description: err.message, variant: 'error' }),
  });

  const bulkSnooze = useMutation({
    mutationFn: async () =>
      apiFetch('/admin/api/alerts/bulk-snooze', {
        method: 'POST',
        body: {
          ids: Array.from(selected),
          hours: Math.max(1, Number(bulkHours) || 1),
          reason: bulkReason.trim(),
        },
      }),
    onSuccess: () => {
      toast({ title: `Snoozed ${selected.size} alert(s)`, variant: 'info' });
      setSelected(new Set());
      setBulkSnoozeOpen(false);
      setBulkReason('');
      setBulkHours('1');
      invalidate();
    },
    onError: (err: Error) =>
      toast({ title: 'Bulk snooze failed', description: err.message, variant: 'error' }),
  });

  const ackOne = useMutation({
    mutationFn: async (id: number) =>
      apiFetch(`/admin/api/alerts/${id}/acknowledge`, { method: 'POST', body: { notes: notesDraft } }),
    onSuccess: () => {
      toast({ title: 'Alert acknowledged', variant: 'success' });
      setDetail(null);
      invalidate();
    },
    onError: (err: Error) =>
      toast({ title: 'Acknowledge failed', description: err.message, variant: 'error' }),
  });

  const snoozeOne = useMutation({
    mutationFn: async (id: number) =>
      apiFetch(`/admin/api/alerts/${id}/snooze`, {
        method: 'POST',
        body: { hours: Math.max(1, Number(snoozeHours) || 1) },
      }),
    onSuccess: () => {
      toast({ title: 'Alert snoozed', variant: 'info' });
      setDetail(null);
      invalidate();
    },
    onError: (err: Error) =>
      toast({ title: 'Snooze failed', description: err.message, variant: 'error' }),
  });

  const unsnooze = useMutation({
    mutationFn: async (id: number) =>
      apiFetch(`/admin/api/alerts/${id}/unsnooze`, { method: 'POST' }),
    onSuccess: () => {
      toast({ title: 'Snooze cleared', variant: 'info' });
      setDetail(null);
      invalidate();
    },
    onError: (err: Error) =>
      toast({ title: 'Unsnooze failed', description: err.message, variant: 'error' }),
  });

  const saveNotes = useMutation({
    mutationFn: async () => {
      if (!detail) return;
      return apiFetch(`/admin/api/alerts/${detail.id}/notes`, {
        method: 'POST',
        body: { notes: notesDraft },
      });
    },
    onSuccess: () => {
      toast({ title: 'Operator notes saved', variant: 'success' });
      invalidate();
    },
    onError: (err: Error) =>
      toast({ title: 'Save notes failed', description: err.message, variant: 'error' }),
  });

  const loadSuggestedRule = async (alertId: number) => {
    try {
      const res = await apiFetch<any>(`/admin/api/alerts/${alertId}/suggested-rule`);
      setSuggestedRule(res);
    } catch (err) {
      toast({
        title: 'Suggested rule unavailable',
        description: err instanceof Error ? err.message : 'Unable to build rule suggestion',
        variant: 'error',
      });
    }
  };

  const createSuggestedRule = useMutation({
    mutationFn: async () => {
      const rule = suggestedRule?.rule;
      if (!rule) throw new Error('No suggested rule to create');
      const { suggested_name: suggestedName, expires_hours: expiresHours, profile_name, ...rest } =
        rule;
      void profile_name;
      const expiresAt =
        typeof expiresHours === 'number' && expiresHours > 0
          ? new Date(Date.now() + expiresHours * 3600_000).toISOString()
          : undefined;
      return apiFetch('/admin/api/event-rules', {
        method: 'POST',
        body: {
          ...rest,
          name: suggestedName || 'Suppress similar alerts',
          enabled: true,
          ...(expiresAt ? { expires_at: expiresAt } : {}),
        },
      });
    },
    onSuccess: () => {
      toast({ title: 'Suppression rule created', variant: 'success' });
      setSuggestedRule(null);
      if (detail) {
        void apiFetch(`/admin/api/alerts/${detail.id}/acknowledge`, {
          method: 'POST',
          body: { notes: 'Suppressed via Event Rule' },
        }).catch(() => {});
      }
      invalidate();
    },
    onError: (err: Error) =>
      toast({ title: 'Rule creation failed', description: err.message, variant: 'error' }),
  });

  const toggleSelected = (id: number) => {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const pageIds = alerts.map((a) => a.id);
  const allPageSelected = pageIds.length > 0 && pageIds.every((id) => selected.has(id));

  const columns = useMemo<ColumnDef<AlertRow, unknown>[]>(
    () => [
      {
        id: 'select',
        header: () => (
          <input
            type="checkbox"
            aria-label="Select all alerts on this page"
            checked={allPageSelected}
            onChange={() => {
              setSelected((current) => {
                const next = new Set(current);
                if (allPageSelected) pageIds.forEach((id) => next.delete(id));
                else pageIds.forEach((id) => next.add(id));
                return next;
              });
            }}
          />
        ),
        cell: ({ row }) => (
          <input
            type="checkbox"
            aria-label={`Select alert ${row.original.id}`}
            checked={selected.has(row.original.id)}
            onClick={(e) => e.stopPropagation()}
            onChange={() => toggleSelected(row.original.id)}
          />
        ),
      },
      {
        accessorKey: 'timestamp',
        header: 'Triggered',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {formatRelativeTime(row.original.timestamp || row.original.created_at)}
          </span>
        ),
      },
      {
        accessorKey: 'severity',
        header: 'Severity',
        cell: ({ row }) => (
          <span
            className={cn(
              'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
              SEVERITY_STYLE[row.original.severity] ?? 'bg-bg-panel text-text-dim',
            )}
          >
            {row.original.severity}
          </span>
        ),
      },
      {
        accessorKey: 'alert_type',
        header: 'Type / Message',
        cell: ({ row }) => (
          <div className="min-w-[190px]">
            <div className="text-xs font-semibold text-text">
              {row.original.alert_type || 'Alert'}
            </div>
            <div className="line-clamp-2 text-[11px] text-text-dim">{row.original.message}</div>
          </div>
        ),
      },
      {
        id: 'device',
        header: 'Device',
        cell: ({ row }) => (
          <span className="font-mono text-[11px] text-text-dim">
            {row.original.device_name || (row.original.device_id ? `#${row.original.device_id}` : '—')}
          </span>
        ),
      },
      {
        id: 'state',
        header: 'State',
        cell: ({ row }) => {
          const state = alertState(row.original);
          return (
            <span
              className={cn(
                'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
                STATE_STYLE[state],
              )}
            >
              {state}
            </span>
          );
        },
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
            {!row.original.acknowledged && !row.original.resolved_at && (
              <button
                type="button"
                onClick={() => ackOne.mutate(row.original.id)}
                className="flex items-center gap-1 rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text hover:bg-bg-hover"
              >
                <Check className="h-3 w-3 text-sig-ok" /> Ack
              </button>
            )}
          </div>
        ),
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [selected, allPageSelected, alerts, ackOne],
  );

  const severityCounts = useMemo(() => {
    const map = new Map((activeStats?.by_severity ?? []).map((s) => [s.key, s.count]));
    return {
      critical: map.get('critical') ?? 0,
      warning: map.get('warning') ?? 0,
      info: map.get('info') ?? 0,
    };
  }, [activeStats]);
  const bars = useMemo(
    () => trendBars(activeStats?.over_time, 12, hours > 48),
    [activeStats, hours],
  );
  const maxBar = Math.max(1, ...bars.map((b) => b.count));
  const alertTypes = useMemo(
    () => (stats?.by_type ?? []).map((t) => t.key).filter(Boolean),
    [stats],
  );

  // A range/device change can drop the selected type from the window; leaving
  // the state set would render a controlled select with no matching option.
  useEffect(() => {
    if (trendType && alertTypes.length > 0 && !alertTypes.includes(trendType)) {
      setTrendType('');
    }
  }, [alertTypes, trendType]);

  return (
    <div className="space-y-4">
      {/* Stats for the selected window */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="rounded-xl border border-border bg-bg-card p-3.5">
          <div className="text-[10px] uppercase text-text-faint">Alerts in {range}</div>
          <div className="mt-0.5 font-mono text-xl font-bold text-text">
            <SkeletonValue loading={statsLoading} width="w-12" />
            {statsLoading ? null : (activeStats?.total ?? 0)}
          </div>
        </div>
        <div className="rounded-xl border border-border bg-bg-card p-3.5">
          <div className="text-[10px] uppercase text-text-faint">Critical</div>
          <div className="mt-0.5 font-mono text-xl font-bold text-sig-crit">
            <SkeletonValue loading={statsLoading} width="w-10" />
            {statsLoading ? null : severityCounts.critical}
          </div>
        </div>
        <div className="rounded-xl border border-border bg-bg-card p-3.5">
          <div className="text-[10px] uppercase text-text-faint">Warning</div>
          <div className="mt-0.5 font-mono text-xl font-bold text-sig-warn">
            <SkeletonValue loading={statsLoading} width="w-10" />
            {statsLoading ? null : severityCounts.warning}
          </div>
        </div>
        <div className="rounded-xl border border-border bg-bg-card p-3.5">
          <div className="text-[10px] uppercase text-text-faint">Info</div>
          <div className="mt-0.5 font-mono text-xl font-bold text-accent">
            <SkeletonValue loading={statsLoading} width="w-10" />
            {statsLoading ? null : severityCounts.info}
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-bg-card p-3.5">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-xs font-semibold text-text">
            Alert volume{trendType ? ` — ${trendType}` : ''}
            {trendType && typeStatsLoading ? (
              <span className="ml-1.5 font-mono text-[10px] text-text-faint">loading…</span>
            ) : null}
          </h2>
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={trendType}
              onChange={(e) => setTrendType(e.target.value)}
              aria-label="Alert type for the volume trend"
              className="max-w-[220px] rounded border border-border bg-bg-panel px-2 py-1 font-mono text-[11px] text-text"
            >
              <option value="">All types</option>
              {alertTypes.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
            <div className="flex items-center gap-0.5 rounded-lg border border-border bg-bg-panel p-1">
              {ALERT_RANGES.map((r) => (
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
        </div>
        {bars.length === 0 ? (
          <p className="py-3 text-center text-[11px] text-text-faint">No alerts in this window.</p>
        ) : (
          <div className="flex items-end gap-1.5 overflow-x-auto pb-1" style={{ height: 90 }}>
            {bars.map((bar, idx) => (
              <div key={`${bar.label}-${idx}`} className="flex min-w-[28px] flex-1 flex-col items-center gap-1">
                <div className="text-[9px] font-mono text-text-faint">{bar.count}</div>
                <div
                  className="w-full rounded-t bg-accent/70"
                  style={{ height: `${Math.max(2, (bar.count / maxBar) * 52)}px` }}
                  title={`${bar.label}: ${bar.count}`}
                />
                <div className="font-mono text-[9px] text-text-faint">{bar.label}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div>
        <BarList
          title={`Alerts by type — ${range}`}
          rows={(stats?.by_type ?? []).map((row) => ({ key: row.key, value: row.count }))}
          empty="No alerts in this window."
          footer={
            (stats?.by_type ?? []).length > 8
              ? `+${(stats?.by_type ?? []).length - 8} more type(s) not shown`
              : undefined
          }
        />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-bg-card p-2.5">
        <Filter className="ml-1 h-3.5 w-3.5 text-text-faint" />
        <select
          value={filters.deviceId}
          onChange={(e) => updateFilters({ deviceId: e.target.value })}
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
          value={filters.siteId}
          onChange={(e) => updateFilters({ siteId: e.target.value })}
          aria-label="Filter by site"
          className="rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text"
        >
          <option value="">All sites</option>
          <option value="unassigned">Unassigned</option>
          {sites.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </select>
        <select
          value={filters.severity}
          onChange={(e) => updateFilters({ severity: e.target.value })}
          aria-label="Filter by severity"
          className="rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text"
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="warning">Warning</option>
          <option value="info">Info</option>
        </select>
        <select
          value={filters.alertType}
          onChange={(e) => updateFilters({ alertType: e.target.value })}
          aria-label="Filter by alert type"
          className="max-w-[220px] rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text"
        >
          <option value="">All types</option>
          {alertTypes.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
        <label className="inline-flex items-center gap-1.5 text-[11px] text-text-dim">
          <input
            type="checkbox"
            checked={filters.includeSnoozed}
            onChange={(e) => updateFilters({ includeSnoozed: e.target.checked })}
          />
          Include snoozed
        </label>
        <button
          type="button"
          onClick={() => {
            setFilters(EMPTY_ALERT_FILTERS);
            setPage(0);
            setSelected(new Set());
          }}
          className="ml-auto rounded border border-border bg-bg-panel px-2.5 py-1 text-[11px] text-text-dim hover:text-text"
        >
          Clear
        </button>
      </div>

      {selected.size > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-accent/40 bg-accent/10 px-3 py-2">
          <span className="text-xs font-semibold text-text">{selected.size} selected</span>
          <button
            type="button"
            onClick={() => bulkAck.mutate()}
            disabled={bulkAck.isPending}
            className="flex items-center gap-1 rounded bg-sig-ok px-2.5 py-1 text-[11px] font-semibold text-white disabled:opacity-50"
          >
            <CheckCheck className="h-3 w-3" /> Acknowledge
          </button>
          <button
            type="button"
            onClick={() => setBulkSnoozeOpen(true)}
            className="flex items-center gap-1 rounded border border-border bg-bg-panel px-2.5 py-1 text-[11px] font-semibold text-text"
          >
            <BellOff className="h-3 w-3" /> Snooze
          </button>
          <button
            type="button"
            onClick={() => setSelected(new Set())}
            className="ml-auto text-[11px] text-text-dim hover:text-text"
          >
            Clear selection
          </button>
        </div>
      )}

      <ResponsiveDataView
        data={alerts}
        columns={columns}
        isLoading={isLoading}
        getRowId={(row) => String(row.id)}
        onRowClick={(row) => setDetail(row)}
        emptyTitle={acknowledged ? 'No acknowledged alerts.' : 'No open alerts.'}
        emptyDescription="Adjust the filters or widen the stats window."
        renderMobileCard={(a) => (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-semibold text-text">{a.alert_type}</span>
              <span
                className={cn(
                  'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
                  SEVERITY_STYLE[a.severity] ?? 'bg-bg-panel text-text-dim',
                )}
              >
                {a.severity}
              </span>
            </div>
            <p className="line-clamp-2 text-[11px] text-text-dim">{a.message}</p>
            <div className="flex items-center justify-between font-mono text-[10px] text-text-faint">
              <span>{a.device_name || `#${a.device_id ?? '?'}`}</span>
              <span>{formatRelativeTime(a.timestamp || a.created_at)}</span>
            </div>
          </div>
        )}
      />

      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[11px] text-text-dim">
          {pageRange(offset, alerts.length, total)}
        </span>
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            disabled={page === 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            className="inline-flex items-center gap-1 rounded border border-border bg-bg-panel px-2.5 py-1 text-[11px] text-text disabled:opacity-40"
          >
            <ChevronLeft className="h-3 w-3" /> Prev
          </button>
          <button
            type="button"
            disabled={offset + alerts.length >= total}
            onClick={() => setPage((p) => p + 1)}
            className="inline-flex items-center gap-1 rounded border border-border bg-bg-panel px-2.5 py-1 text-[11px] text-text disabled:opacity-40"
          >
            Next <ChevronRight className="h-3 w-3" />
          </button>
        </div>
      </div>

      {/* Detail drawer */}
      <SlideOverDrawer
        open={Boolean(detail)}
        onOpenChange={(open) => {
          if (!open) setDetail(null);
        }}
        title={detail ? `${detail.alert_type} — ${detail.severity}` : 'Alert detail'}
        subtitle={detail ? formatRelativeTime(detail.timestamp || detail.created_at) : undefined}
        size="lg"
      >
        {detail && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={cn(
                  'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
                  STATE_STYLE[alertState(detail)],
                )}
              >
                {alertState(detail)}
              </span>
              {detail.device_name && (
                <span className="font-mono text-[11px] text-text-dim">{detail.device_name}</span>
              )}
              {detail.snoozed_until && (
                <span className="text-[11px] text-accent">
                  snoozed until {new Date(detail.snoozed_until).toLocaleString()}
                </span>
              )}
              {sourceAddr && (
                <span className="rounded bg-sig-crit/15 px-1.5 py-0.5 font-mono text-[10px] text-sig-crit">
                  source {sourceAddr}
                </span>
              )}
            </div>

            {isSyslogAlertType(detail.alert_type) && <ParsedSyslogFields raw={detail.message} />}

            <p className="rounded-lg border border-border bg-bg-panel p-3 text-xs text-text">
              {detail.message}
            </p>

            {detail.metric_name && (
              <div className="grid grid-cols-3 gap-2">
                <div className="rounded-lg border border-border bg-bg-panel p-2.5">
                  <div className="text-[10px] uppercase text-text-faint">Metric</div>
                  <div className="font-mono text-xs text-text">{detail.metric_name || '—'}</div>
                </div>
                <div className="rounded-lg border border-border bg-bg-panel p-2.5">
                  <div className="text-[10px] uppercase text-text-faint">Threshold</div>
                  <div className="font-mono text-xs text-text">
                    {detail.threshold != null ? detail.threshold : '—'}
                  </div>
                </div>
                <div className="rounded-lg border border-border bg-bg-panel p-2.5">
                  <div className="text-[10px] uppercase text-text-faint">Current</div>
                  <div className="font-mono text-xs text-text">
                    {detail.current_value != null ? detail.current_value : '—'}
                  </div>
                </div>
              </div>
            )}

            <div>
              <h3 className="mb-1.5 text-xs font-semibold text-text">
                Linked flow detections ({linkedDetections.length})
              </h3>
              {alertDetailLoading ? (
                <p className="text-[11px] text-text-dim">Loading linked detections…</p>
              ) : alertDetailError ? (
                <p className="text-[11px] text-sig-crit">Could not load linked detections.</p>
              ) : linkedDetections.length === 0 ? (
                <p className="text-[11px] text-text-faint">No linked flow detections.</p>
              ) : (
                <div className="space-y-1.5">
                  {linkedDetections.map((detection) => (
                    <div
                      key={detection.id}
                      className="rounded-lg border border-border bg-bg-panel px-2.5 py-2"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span
                            className={cn(
                              'rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
                              SEVERITY_STYLE[detection.severity ?? 'info'] ?? SEVERITY_STYLE['info'],
                            )}
                          >
                            {detection.severity || 'info'}
                          </span>
                          <span className="font-mono text-[11px] text-text">
                            {detection.detector || 'detector'}
                          </span>
                          {detection.category && (
                            <span className="text-[10px] text-text-faint">{detection.category}</span>
                          )}
                        </div>
                        <span className="font-mono text-[10px] text-text-faint">
                          {formatRelativeTime(detection.detected_at)}
                        </span>
                      </div>
                      <div className="mt-1 font-mono text-[11px] text-text-dim">
                        {detection.src_addr || '—'} → {detection.dst_addr || '—'}
                        {detection.dst_port ? `:${detection.dst_port}` : ''}
                      </div>
                      {detection.message && (
                        <div className="text-[11px] text-text-dim">{detection.message}</div>
                      )}
                      {detection.score != null && (
                        <div className="font-mono text-[10px] text-text-faint">
                          score {formatCompactNumber(detection.score)}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div>
              <label className="mb-1 block text-xs font-medium text-text-dim">Operator notes</label>
              <textarea
                rows={3}
                maxLength={4000}
                value={notesDraft}
                onChange={(e) => setNotesDraft(e.target.value)}
                className="w-full rounded-md border border-border bg-bg-panel p-2.5 text-xs text-text"
              />
              <button
                type="button"
                onClick={() => saveNotes.mutate()}
                disabled={saveNotes.isPending}
                className="mt-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text disabled:opacity-50"
              >
                Save notes
              </button>
            </div>

            <div className="flex flex-wrap items-center gap-2 border-t border-border pt-3">
              {!detail.acknowledged && !detail.resolved_at && (
                <button
                  type="button"
                  onClick={() => ackOne.mutate(detail.id)}
                  className="inline-flex items-center gap-1.5 rounded-md bg-sig-ok px-3 py-1.5 text-xs font-semibold text-white"
                >
                  <Check className="h-3.5 w-3.5" /> Acknowledge
                </button>
              )}
              <div className="flex items-center gap-1.5">
                <input
                  type="number"
                  min={1}
                  value={snoozeHours}
                  onChange={(e) => setSnoozeHours(e.target.value)}
                  aria-label="Snooze hours"
                  className="w-16 rounded border border-border bg-bg-panel px-2 py-1.5 font-mono text-xs text-text"
                />
                <button
                  type="button"
                  onClick={() => snoozeOne.mutate(detail.id)}
                  className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text"
                >
                  <Clock className="h-3.5 w-3.5" /> Snooze hours
                </button>
              </div>
              {detail.snoozed_until && (
                <button
                  type="button"
                  onClick={() => unsnooze.mutate(detail.id)}
                  className="inline-flex items-center gap-1.5 rounded-md border border-sig-warn/40 bg-sig-warn/10 px-3 py-1.5 text-xs font-medium text-sig-warn"
                >
                  <BellOff className="h-3.5 w-3.5" /> Unsnooze
                </button>
              )}
            </div>

            <div className="rounded-lg border border-border bg-bg-card p-3">
              <div className="flex items-center justify-between gap-2">
                <div>
                  <div className="text-xs font-semibold text-text">Suggest a suppression rule</div>
                  <div className="text-[11px] text-text-dim">
                    Pre-fill a rule for this alert&apos;s source and type.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => loadSuggestedRule(detail.id)}
                  className="inline-flex items-center gap-1 rounded-md border border-border bg-bg-panel px-2.5 py-1.5 text-[11px] font-medium text-text"
                >
                  <Sparkles className="h-3 w-3 text-accent" /> Suggest
                </button>
              </div>
              {suggestedRule && (
                <div className="mt-2 space-y-2">
                  <pre className="max-h-48 overflow-auto rounded border border-border bg-bg-panel p-2 font-mono text-[10px] text-text-dim">
                    {JSON.stringify(suggestedRule?.rule ?? suggestedRule, null, 2)}
                  </pre>
                  <button
                    type="button"
                    disabled={!suggestedRule?.rule || createSuggestedRule.isPending}
                    onClick={() => createSuggestedRule.mutate()}
                    className="w-full rounded bg-accent px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
                  >
                    Create rule and acknowledge
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </SlideOverDrawer>

      {/* Bulk snooze */}
      <SlideOverDrawer
        open={bulkSnoozeOpen}
        onOpenChange={setBulkSnoozeOpen}
        title={`Snooze ${selected.size} alert(s)`}
        size="md"
        footer={
          <div className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => setBulkSnoozeOpen(false)}
              className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text-dim"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => bulkSnooze.mutate()}
              disabled={bulkSnooze.isPending}
              className="rounded-md bg-accent px-3.5 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
            >
              Snooze
            </button>
          </div>
        }
      >
        <div className="space-y-3">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">Hours</span>
            <input
              type="number"
              min={1}
              value={bulkHours}
              onChange={(e) => setBulkHours(e.target.value)}
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 font-mono text-xs text-text"
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">Reason (optional)</span>
            <input
              type="text"
              value={bulkReason}
              onChange={(e) => setBulkReason(e.target.value)}
              placeholder="Change window / known maintenance"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            />
          </label>
        </div>
      </SlideOverDrawer>
    </div>
  );
}

function StormIncidentsSubTab() {
  const { data: incidentsRes, isLoading } = useQuery({
    queryKey: ['storm-incidents'],
    queryFn: () => apiFetch<any>('/admin/api/incidents'),
  });

  const incidents: IncidentRow[] = Array.isArray(incidentsRes)
    ? incidentsRes
    : incidentsRes?.incidents ?? incidentsRes?.items ?? [];

  const columns = useMemo<ColumnDef<IncidentRow, unknown>[]>(
    () => [
      {
        accessorKey: 'title',
        header: 'Incident',
        cell: ({ row }) => (
          <div>
            <div className="text-xs font-semibold text-text">{row.original.title}</div>
            <div className="text-[11px] text-text-dim">
              {row.original.alert_count ?? 0} linked alerts
            </div>
          </div>
        ),
      },
      {
        accessorKey: 'severity',
        header: 'Severity',
        cell: ({ row }) => (
          <span
            className={cn(
              'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
              SEVERITY_STYLE[row.original.severity] ?? 'bg-bg-panel text-text-dim',
            )}
          >
            {row.original.severity}
          </span>
        ),
      },
      {
        id: 'status',
        header: 'Status',
        cell: ({ row }) => (
          <span className="font-mono text-[11px] uppercase text-text-dim">
            {row.original.resolved_at ? 'resolved' : 'open'}
          </span>
        ),
      },
      {
        accessorKey: 'started_at',
        header: 'Started',
        cell: ({ row }) => (
          <span className="font-mono text-[11px] text-text-dim">
            {formatRelativeTime(row.original.started_at)}
          </span>
        ),
      },
    ],
    [],
  );

  return (
    <ResponsiveDataView
      data={incidents}
      columns={columns}
      isLoading={isLoading}
      emptyTitle="No storm incidents."
      emptyDescription="Bursts that cross the digest threshold are grouped here."
      renderMobileCard={(i) => (
        <div className="space-y-1">
          <div className="text-xs font-semibold text-text">{i.title}</div>
          <div className="text-[11px] text-text-dim">
            {i.severity} · {i.resolved_at ? 'resolved' : 'open'} · {i.alert_count ?? 0} alerts
          </div>
        </div>
      )}
    />
  );
}
