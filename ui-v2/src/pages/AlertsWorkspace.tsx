import { useState, useMemo } from 'react';
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
} from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { ClassicFallback } from '@/components/ui/classic-fallback';
import { useToast } from '@/components/ui/toast';
import { ColumnDef } from '@tanstack/react-table';

type AlertsTab = 'open' | 'incidents' | 'history';

interface AlertRow {
  id: number;
  device_id?: number;
  device_name?: string;
  alert_type: string;
  severity: string;
  title?: string;
  message: string;
  acknowledged: boolean;
  snoozed_until?: string | null;
  notes?: string;
  timestamp?: string;
  created_at?: string;
}

interface IncidentRow {
  id: number;
  title: string;
  status: string;
  severity: string;
  alert_count: number;
  started_at: string;
  updated_at?: string;
}

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
            Security & Alerts / Triage Queue
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            Active Alerts, Storm Incidents & Triage Queue
          </h1>
          <p className="text-xs text-text-dim mt-0.5">
            Acknowledge, snooze, or generate a 1-click Suppress/Customize Event Rule from any noisy alert.
          </p>
        </div>

        <div className="flex items-center gap-1 rounded-lg bg-bg-panel p-1 border border-border self-start">
          <button
            type="button"
            onClick={() => setTab('open')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'open'
                ? 'bg-bg-card text-text shadow-sm border border-border'
                : 'text-text-dim hover:text-text'
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
                ? 'bg-bg-card text-text shadow-sm border border-border'
                : 'text-text-dim hover:text-text'
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
                ? 'bg-bg-card text-text shadow-sm border border-border'
                : 'text-text-dim hover:text-text'
            )}
          >
            <History className="h-3.5 w-3.5 text-accent" />
            Alert History
          </button>
        </div>
      </div>

      <ClassicFallback
        title="Alert filters, analytics and full triage are still in the classic console"
        description="The preview supports acknowledge, snooze, notes and incidents. Range pills, stat tiles, charts, device/site/type/severity filters, the snoozed toggle, paging, bulk selection and linked detections are not rebuilt yet."
        href="/admin/alerts"
        label="Open full alerts"
      />

      {activeTab === 'open' && <AlertsQueueSubTab acknowledged={false} />}
      {activeTab === 'incidents' && <StormIncidentsSubTab />}
      {activeTab === 'history' && <AlertsQueueSubTab acknowledged={true} />}
    </div>
  );
}

function AlertsQueueSubTab({ acknowledged }: { acknowledged: boolean }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [selectedAlert, setSelectedAlert] = useState<AlertRow | null>(null);
  const [notesDraft, setNotesDraft] = useState('');
  const [suggestedRule, setSuggestedRule] = useState<any>(null);

  const { data: alertsRes, isLoading } = useQuery({
    queryKey: ['alerts-list', acknowledged],
    queryFn: () =>
      apiFetch<any>(`/admin/api/alerts?acknowledged=${acknowledged ? 'true' : 'false'}&limit=100`),
    refetchInterval: 15_000,
  });

  const alerts: AlertRow[] = Array.isArray(alertsRes)
    ? alertsRes
    : alertsRes?.alerts ?? alertsRes?.items ?? alertsRes?.data ?? [];

  const ackMutation = useMutation({
    mutationFn: async (id: number) => apiFetch(`/admin/api/alerts/${id}/acknowledge`, { method: 'POST' }),
    onSuccess: () => {
      toast({ title: 'Alert acknowledged', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['alerts-list'] });
    },
  });

  const snoozeMutation = useMutation({
    mutationFn: async ({ id, minutes }: { id: number; minutes: number }) =>
      // SnoozeAlert binds `hours`; duration_minutes was ignored and the server
      // fell back to its 1h clamp, so any other duration silently snoozed 1h.
      apiFetch(`/admin/api/alerts/${id}/snooze`, {
        method: 'POST',
        body: { hours: Math.max(1, Math.round(minutes / 60)) },
      }),
    onSuccess: () => {
      toast({ title: 'Alert snoozed', variant: 'info' });
      queryClient.invalidateQueries({ queryKey: ['alerts-list'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Snooze failed', description: err.message, variant: 'error' });
    },
  });

  const bulkAckMutation = useMutation({
    mutationFn: async () =>
      apiFetch('/admin/api/alerts/bulk-acknowledge', {
        method: 'POST',
        // BulkAcknowledgeAlerts binds `ids`; alert_ids made every call 400.
        body: { ids: alerts.map((a) => a.id) },
      }),
    onSuccess: () => {
      toast({ title: 'All visible alerts acknowledged', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['alerts-list'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Bulk acknowledge failed', description: err.message, variant: 'error' });
    },
  });

  const saveNotesMutation = useMutation({
    mutationFn: async () => {
      if (!selectedAlert) return;
      return apiFetch(`/admin/api/alerts/${selectedAlert.id}/notes`, {
        method: 'POST',
        body: { notes: notesDraft },
      });
    },
    onSuccess: () => {
      toast({ title: 'Operator notes saved', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['alerts-list'] });
    },
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

  const createSuggestedRuleMutation = useMutation({
    mutationFn: async () => {
      // The endpoint returns SuggestResult {supported, rule, …}; posting the
      // envelope (or rule.suggested_name) to CreateEventRule failed binding
      // because EventRule requires `name`.
      const rule = suggestedRule?.rule;
      if (!rule) throw new Error('No suggested rule to create');
      // expires_hours/profile_name are suggestion metadata, not EventRule
      // columns: EventRule takes an absolute expires_at. Leaving expires_hours
      // in the body silently turned a 24h mute into a permanent one.
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
          // GORM omits the false zero value on INSERT and the table default is
          // true, but CreateEventRule force-disables when Enabled is false —
          // so an omitted field produced a rule that never fires.
          enabled: true,
          ...(expiresAt ? { expires_at: expiresAt } : {}),
        },
      });
    },
    onSuccess: () => {
      toast({ title: 'Suppression rule created from alert', variant: 'success' });
      setSuggestedRule(null);
    },
    onError: (err: Error) => {
      toast({ title: 'Rule creation failed', description: err.message, variant: 'error' });
    },
  });

  const columns = useMemo<ColumnDef<AlertRow, unknown>[]>(
    () => [
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
        cell: ({ row }) => {
          const sev = (row.original.severity || 'warning').toLowerCase();
          return (
            <span
              className={cn(
                'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
                sev === 'critical'
                  ? 'bg-sig-crit/15 text-sig-crit'
                  : sev === 'warning'
                    ? 'bg-sig-warn/15 text-sig-warn'
                    : 'bg-accent/15 text-accent'
              )}
            >
              {row.original.severity}
            </span>
          );
        },
      },
      {
        accessorKey: 'device_name',
        header: 'Device',
        cell: ({ row }) => (
          <span className="font-semibold text-xs text-text">
            {row.original.device_name || (row.original.device_id ? `Dev #${row.original.device_id}` : 'System')}
          </span>
        ),
      },
      {
        accessorKey: 'alert_type',
        header: 'Type & Message',
        cell: ({ row }) => (
          <div>
            <span className="font-mono text-[11px] font-semibold text-accent mr-2">
              {row.original.alert_type}
            </span>
            <span className="text-xs text-text">{row.original.message}</span>
          </div>
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
            {!row.original.acknowledged && (
              <>
                <button
                  type="button"
                  onClick={() => ackMutation.mutate(row.original.id)}
                  className="flex items-center gap-1 rounded border border-sig-ok/40 bg-sig-ok/10 px-2 py-1 text-[11px] font-semibold text-sig-ok"
                >
                  <Check className="h-3 w-3" /> Ack
                </button>
                <button
                  type="button"
                  onClick={() => snoozeMutation.mutate({ id: row.original.id, minutes: 60 })}
                  className="flex items-center gap-1 rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text-dim hover:text-text"
                >
                  <Clock className="h-3 w-3" /> 1h
                </button>
              </>
            )}
          </div>
        ),
      },
    ],
    [ackMutation, snoozeMutation]
  );

  return (
    <div className="space-y-3">
      {!acknowledged && alerts.length > 0 && (
        <div className="flex items-center justify-between rounded-lg border border-border bg-bg-card px-3.5 py-2">
          <span className="text-xs text-text-dim">
            Showing <strong className="text-text">{alerts.length}</strong> open unacknowledged alerts
          </span>
          <button
            type="button"
            disabled={bulkAckMutation.isPending}
            onClick={() => bulkAckMutation.mutate()}
            className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1 text-xs font-semibold text-white hover:opacity-90"
          >
            <CheckCheck className="h-3.5 w-3.5" />
            Acknowledge All Visible
          </button>
        </div>
      )}

      <ResponsiveDataView
        data={alerts}
        columns={columns}
        isLoading={isLoading}
        onRowClick={(row) => {
          setSelectedAlert(row);
          setNotesDraft(row.notes || '');
          setSuggestedRule(null);
        }}
        emptyTitle={acknowledged ? 'No historical alerts.' : 'Zero open alerts — fleet is healthy.'}
        renderMobileCard={(a) => (
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-semibold text-accent">{a.alert_type}</span>
              <span className="font-mono text-[11px] text-text-dim">
                {formatRelativeTime(a.timestamp || a.created_at)}
              </span>
            </div>
            <div className="text-xs text-text">{a.message}</div>
          </div>
        )}
      />

      <SlideOverDrawer
        open={Boolean(selectedAlert)}
        onOpenChange={(open) => {
          if (!open) setSelectedAlert(null);
        }}
        title={`Alert #${selectedAlert?.id ?? ''}: ${selectedAlert?.alert_type ?? ''}`}
        subtitle={selectedAlert?.device_name || 'Alert Triage & Rule Suggestion'}
      >
        {selectedAlert && (
          <div className="space-y-4">
            <div className="rounded-lg border border-border bg-bg-panel p-3 text-xs text-text">
              {selectedAlert.message}
            </div>

            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">Operator Investigation Notes</label>
              <textarea
                rows={3}
                value={notesDraft}
                onChange={(e) => setNotesDraft(e.target.value)}
                placeholder="Add incident ticket or root-cause notes..."
                className="w-full rounded-md border border-border bg-bg-panel p-2.5 text-xs text-text"
              />
              <div className="mt-2 flex justify-end">
                <button
                  type="button"
                  onClick={() => saveNotesMutation.mutate()}
                  className="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white"
                >
                  Save Notes
                </button>
              </div>
            </div>

            <div className="pt-3 border-t border-border space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-text">Silence or Customize Future Occurrences</div>
                  <div className="text-[11px] text-text-dim">
                    Generate a pre-filled Event Rule matching this alert's source and type.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => loadSuggestedRule(selectedAlert.id)}
                  className="flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:bg-bg-hover"
                >
                  <Sparkles className="h-3.5 w-3.5 text-accent" />
                  Suggest Rule
                </button>
              </div>

              {suggestedRule && (
                <div className="space-y-2">
                  <pre className="rounded-lg border border-border bg-bg-panel p-3 font-mono text-[11px] text-text overflow-x-auto">
                    {JSON.stringify(suggestedRule?.rule ?? suggestedRule, null, 2)}
                  </pre>
                  <button
                    type="button"
                    disabled={!suggestedRule?.rule || createSuggestedRuleMutation.isPending}
                    onClick={() => createSuggestedRuleMutation.mutate()}
                    className="w-full rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
                  >
                    Create Event Rule
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
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
        header: 'Incident Group',
        cell: ({ row }) => <span className="font-semibold text-text">{row.original.title}</span>,
      },
      {
        accessorKey: 'alert_count',
        header: 'Correlated Alerts',
        cell: ({ row }) => (
          <span className="rounded bg-sig-warn/15 px-2 py-0.5 font-mono text-xs font-semibold text-sig-warn">
            {row.original.alert_count}
          </span>
        ),
      },
      {
        accessorKey: 'started_at',
        header: 'Started',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">{formatRelativeTime(row.original.started_at)}</span>
        ),
      },
    ],
    []
  );

  return (
    <ResponsiveDataView
      data={incidents}
      columns={columns}
      isLoading={isLoading}
      emptyTitle="No active alert storm incidents."
      renderMobileCard={(inc) => (
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-text">{inc.title}</span>
          <span className="font-mono text-sig-warn">{inc.alert_count} alerts</span>
        </div>
      )}
    />
  );
}
