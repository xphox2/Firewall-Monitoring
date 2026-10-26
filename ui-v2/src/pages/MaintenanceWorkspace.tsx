import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { CalendarClock, Plus, Trash2, Edit3, AlertCircle } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatDateTime } from '@/lib/utils';
import {
  RECUR_RULES,
  WEEKDAYS,
  normalizeRecurDays,
  parseRecurDays,
  recurrenceLabel,
  recurrenceValidation,
} from '@/lib/maintenance';
import { fromLocalInput, toLocalInput } from '@/lib/datetime';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { useToast } from '@/components/ui/toast';
import { ColumnDef } from '@tanstack/react-table';

interface MaintenanceWindow {
  id: number;
  name: string;
  notes?: string;
  description?: string;
  device_id?: number | null;
  site_id?: number | null;
  start_time: string;
  end_time: string;
  suppress_all?: boolean;
  suppress_alerts?: boolean;
  alert_types?: string;
  recurring?: boolean;
  recur_rule?: string;
  recur_days?: string;
  created_by?: string;
}

export function MaintenanceWorkspace() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: windowsList, isLoading } = useQuery({
    queryKey: ['maintenance-windows'],
    queryFn: () => apiFetch<MaintenanceWindow[]>('/admin/api/maintenance-windows'),
  });

  const { data: activeList } = useQuery({
    queryKey: ['maintenance-windows-active'],
    queryFn: () => apiFetch<MaintenanceWindow[]>('/admin/api/maintenance-windows/active'),
    refetchInterval: 30_000,
  });

  const windows = windowsList ?? [];
  const activeWindows = activeList ?? [];

  const { data: devices = [] } = useQuery({
    queryKey: ['maint-devices'],
    queryFn: () => apiFetch<Array<{ id: number; name: string }>>('/admin/api/devices'),
  });
  const { data: sites = [] } = useQuery({
    queryKey: ['maint-sites'],
    queryFn: () => apiFetch<Array<{ id: number; name: string }>>('/admin/api/sites'),
  });
  const { data: alertTypes = [] } = useQuery({
    queryKey: ['alert-types'],
    queryFn: () =>
      apiFetch<Array<{ type: string; family: string; description: string }>>(
        '/admin/api/alert-types',
      ),
  });
  const groupedAlertTypes = useMemo(() => {
    const map = new Map<string, Array<{ type: string; description: string }>>();
    for (const info of alertTypes) {
      const list = map.get(info.family) ?? [];
      list.push({ type: info.type, description: info.description });
      map.set(info.family, list);
    }
    return Array.from(map.entries());
  }, [alertTypes]);

  const [drawerOpen, setDrawerOpen] = useState(false);
  // Scope is an explicit mode, not inferred from the pointer: a selected scope
  // with no id yet must still render its picker.
  const [scopeMode, setScopeMode] = useState<'all' | 'device' | 'site'>('all');
  const [editing, setEditing] = useState<Partial<MaintenanceWindow>>({
    name: '',
    notes: '',
    start_time: toLocalInput(),
    end_time: toLocalInput(new Date(Date.now() + 2 * 3600_000).toISOString()),
    suppress_all: true,
    recurring: false,
    recur_rule: '',
    recur_days: '',
  });

  const saveMutation = useMutation({
    mutationFn: async () => {
      const startIso = fromLocalInput(editing.start_time);
      const endIso = fromLocalInput(editing.end_time);
      if (!startIso || !endIso) {
        throw new Error('Start and end times are required');
      }
      if (new Date(endIso) <= new Date(startIso)) {
        throw new Error('End time must be after the start time');
      }
      const recurError = recurrenceValidation(
        editing.recurring,
        editing.recur_rule,
        editing.recur_days,
      );
      if (recurError) throw new Error(recurError);
      const recurring = Boolean(editing.recurring);
      const recurRule = recurring ? String(editing.recur_rule || 'weekly') : '';
      const recurDays =
        recurring && recurRule === 'weekly'
          ? normalizeRecurDays(parseRecurDays(editing.recur_days))
          : '';
      const hasSelectedTypes = (editing.alert_types ?? '')
        .split(',')
        .some((t) => t.trim());
      // A legacy row with suppress_all off and no type list already suppresses
      // everything server-side; allow unrelated edits without forcing the
      // operator to re-express that choice.
      const legacySuppressAll = Boolean(editing.id) && editing.suppress_all === false && !hasSelectedTypes;
      if (scopeMode === 'device' && !editing.device_id) {
        throw new Error('Select a device for this window (or switch the scope to all devices & sites)');
      }
      if (scopeMode === 'site' && !editing.site_id) {
        throw new Error('Select a site for this window (or switch the scope to all devices & sites)');
      }
      if (editing.suppress_all === false && !hasSelectedTypes && !legacySuppressAll) {
        // The server skips the type filter when alert_types is empty, so
        // "suppress_all off + no types" suppresses EVERYTHING — the opposite
        // of what an empty list looks like. Refuse it.
        throw new Error(
          'Select at least one alert type (or enable "suppress all") — an empty list would suppress every alert',
        );
      }
      const payload = {
        ...editing,
        notes: editing.notes ?? editing.description ?? '',
        suppress_all: editing.suppress_all ?? editing.suppress_alerts ?? true,
        // Only the active scope's id is sent; the inactive one stays in the
        // draft so switching modes back does not lose the selection.
        device_id: scopeMode === 'device' ? (editing.device_id ?? null) : null,
        site_id: scopeMode === 'site' ? (editing.site_id ?? null) : null,
        start_time: startIso,
        end_time: endIso,
        recurring,
        recur_rule: recurRule,
        recur_days: recurDays,
      };
      if (editing.id) {
        return apiFetch(`/admin/api/maintenance-windows/${editing.id}`, {
          method: 'PUT',
          body: payload,
        });
      }
      return apiFetch('/admin/api/maintenance-windows', {
        method: 'POST',
        body: payload,
      });
    },
    onSuccess: () => {
      toast({
        title: editing.id ? 'Maintenance window updated' : 'Maintenance window scheduled',
        variant: 'success',
      });
      setDrawerOpen(false);
      queryClient.invalidateQueries({ queryKey: ['maintenance-windows'] });
      queryClient.invalidateQueries({ queryKey: ['maintenance-windows-active'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to save maintenance window', description: err.message, variant: 'error' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: number) =>
      apiFetch(`/admin/api/maintenance-windows/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      toast({ title: 'Maintenance window deleted', variant: 'info' });
      queryClient.invalidateQueries({ queryKey: ['maintenance-windows'] });
      queryClient.invalidateQueries({ queryKey: ['maintenance-windows-active'] });
    },
    onError: (err: Error) => {
      toast({
        title: 'Could not delete the maintenance window',
        description: err.message,
        variant: 'error',
      });
    },
  });

  const selectedTypes = new Set(
    (editing.alert_types ?? '')
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean),
  );

  const toggleAlertType = (type: string) => {
    setEditing((p) => {
      const next = new Set(
        (p.alert_types ?? '')
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean),
      );
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return { ...p, alert_types: Array.from(next).join(',') };
    });
  };

  const selectedRecurDays = new Set(parseRecurDays(editing.recur_days));
  const toggleWeekday = (day: string) => {
    setEditing((prev) => {
      const next = new Set(parseRecurDays(prev.recur_days));
      if (next.has(day)) next.delete(day);
      else next.add(day);
      return { ...prev, recur_days: normalizeRecurDays(next) };
    });
  };

  const columns = useMemo<ColumnDef<MaintenanceWindow, unknown>[]>(
    () => [
      {
        accessorKey: 'name',
        header: 'Window Name',
        cell: ({ row }) => {
          const notes = row.original.notes || row.original.description;
          return (
            <div>
              <div className="font-semibold text-text">{row.original.name}</div>
              {notes && <div className="text-[11px] text-text-dim">{notes}</div>}
            </div>
          );
        },
      },
      {
        accessorKey: 'start_time',
        header: 'Start',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {formatDateTime(row.original.start_time)}
          </span>
        ),
      },
      {
        accessorKey: 'end_time',
        header: 'End',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {formatDateTime(row.original.end_time)}
          </span>
        ),
      },
      {
        id: 'schedule',
        header: 'Schedule',
        cell: ({ row }) => {
          const recurring = Boolean(row.original.recurring);
          return (
            <span
              className={cn(
                'rounded px-2 py-0.5 text-[10px] font-semibold',
                recurring ? 'bg-accent/15 text-accent' : 'bg-bg-panel text-text-faint',
              )}
            >
              {recurrenceLabel(
                row.original.recurring,
                row.original.recur_rule,
                row.original.recur_days,
              )}
            </span>
          );
        },
      },
      {
        id: 'scope',
        header: 'Scope',
        cell: ({ row }) => {
          const w = row.original;
          if (w.device_id) {
            return (
              <span className="font-mono text-[11px] text-text">
                {devices.find((d) => d.id === w.device_id)?.name ?? `Device #${w.device_id}`}
              </span>
            );
          }
          if (w.site_id) {
            return (
              <span className="font-mono text-[11px] text-text">
                Site: {sites.find((s) => s.id === w.site_id)?.name ?? `#${w.site_id}`}
              </span>
            );
          }
          return <span className="text-[11px] text-text-dim">All devices & sites</span>;
        },
      },
      {
        accessorKey: 'suppress_all',
        header: 'Alert Suppression',
        cell: ({ row }) => {
          const suppress = row.original.suppress_all ?? row.original.suppress_alerts ?? true;
          if (suppress) {
            return (
              <span className="rounded bg-sig-warn/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-sig-warn">
                All notifications
              </span>
            );
          }
          const types = (row.original.alert_types ?? '')
            .split(',')
            .map((t) => t.trim())
            .filter(Boolean);
          if (types.length === 0) {
            // Legacy row: suppress_all off with no type filter suppresses all.
            return (
              <span className="rounded bg-sig-warn/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-sig-warn">
                All (no type filter)
              </span>
            );
          }
          return (
            <span
              className="rounded bg-bg-panel px-2 py-0.5 text-[10px] font-semibold uppercase text-text-dim"
              title={types.join(', ')}
            >
              {types.length} alert type(s)
            </span>
          );
        },
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex items-center justify-end gap-1.5">
            <button
              type="button"
              onClick={() => {
                setScopeMode(
                  row.original.site_id ? 'site' : row.original.device_id ? 'device' : 'all',
                );
                setEditing({
                  ...row.original,
                  notes: row.original.notes ?? row.original.description ?? '',
                  suppress_all: row.original.suppress_all ?? row.original.suppress_alerts ?? true,
                  start_time: toLocalInput(row.original.start_time),
                  end_time: toLocalInput(row.original.end_time),
                });
                setDrawerOpen(true);
              }}
              className="rounded border border-border bg-bg-panel p-1 text-text-dim hover:text-text"
            >
              <Edit3 className="h-3.5 w-3.5" />
            </button>
            <button
              type="button"
              onClick={() => deleteMutation.mutate(row.original.id)}
              className="rounded border border-sig-crit/30 bg-sig-crit/10 p-1 text-sig-crit"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          </div>
        ),
      },
    ],
    [deleteMutation, devices, sites]
  );

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <CalendarClock className="h-3.5 w-3.5" />
            Infrastructure / Maintenance Windows
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            Scheduled Maintenance & Alert Suppression
          </h1>
          <p className="text-xs text-text-dim mt-0.5">
            Schedule device, site, or global maintenance windows to suppress paging during firmware upgrades or circuit work.
          </p>
        </div>

        <button
          type="button"
          onClick={() => {
            setScopeMode('all');
            setEditing({
              name: '',
              notes: '',
              start_time: toLocalInput(),
              end_time: toLocalInput(new Date(Date.now() + 2 * 3600_000).toISOString()),
              suppress_all: true,
              recurring: false,
              recur_rule: '',
              recur_days: '',
            });
            setDrawerOpen(true);
          }}
          className="flex items-center gap-1.5 rounded-md bg-accent px-3.5 py-2 text-xs font-semibold text-white hover:opacity-90 self-start"
        >
          <Plus className="h-4 w-4" />
          Schedule Window
        </button>
      </div>

      {activeWindows.length > 0 && (
        <div className="rounded-xl border border-sig-warn/40 bg-sig-warn/10 p-3.5 flex items-center gap-2.5 text-xs text-sig-warn">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <div>
            <span className="font-semibold">{activeWindows.length} active maintenance window(s)</span> currently suppressing outbound notifications.
          </div>
        </div>
      )}

      <ResponsiveDataView
        data={windows}
        columns={columns}
        isLoading={isLoading}
        emptyTitle="No maintenance windows scheduled."
        renderMobileCard={(w) => (
          <div className="space-y-1">
            <div className="font-semibold text-sm text-text">{w.name}</div>
            <div className="text-xs font-mono text-text-dim">
              {formatDateTime(w.start_time)} → {formatDateTime(w.end_time)}
            </div>
            {w.recurring && (
              <div className="text-[11px] text-accent">
                {recurrenceLabel(w.recurring, w.recur_rule, w.recur_days)}
              </div>
            )}
            <div className="text-[11px] text-text-faint">
              {w.device_id
                ? devices.find((d) => d.id === w.device_id)?.name ?? `Device #${w.device_id}`
                : w.site_id
                  ? `Site: ${sites.find((s) => s.id === w.site_id)?.name ?? `#${w.site_id}`}`
                  : 'All devices & sites'}
            </div>
          </div>
        )}
      />

      <SlideOverDrawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        title={editing.id ? `Edit Window: ${editing.name}` : 'Schedule Maintenance Window'}
        footer={
          <div className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => setDrawerOpen(false)}
              className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text-dim"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={!editing.name?.trim() || saveMutation.isPending}
              onClick={() => saveMutation.mutate()}
              className="rounded-md bg-accent px-4 py-1.5 text-xs font-semibold text-white hover:opacity-90"
            >
              Save Window
            </button>
          </div>
        }
      >
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Window Name</label>
            <input
              type="text"
              value={editing.name ?? ''}
              onChange={(e) => setEditing((p) => ({ ...p, name: e.target.value }))}
              placeholder="FortiOS 7.4 Patch Window"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">Start Time</label>
              <input
                type="datetime-local"
                value={editing.start_time ?? ''}
                onChange={(e) => setEditing((p) => ({ ...p, start_time: e.target.value }))}
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">End Time</label>
              <input
                type="datetime-local"
                value={editing.end_time ?? ''}
                onChange={(e) => setEditing((p) => ({ ...p, end_time: e.target.value }))}
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
              />
            </div>
          </div>

          <div className="space-y-2 rounded-lg border border-border bg-bg-panel/40 p-3">
            <label className="flex items-center gap-2 text-xs text-text">
              <input
                type="checkbox"
                checked={editing.recurring ?? false}
                onChange={(e) =>
                  setEditing((p) => ({
                    ...p,
                    recurring: e.target.checked,
                    recur_rule: e.target.checked ? p.recur_rule || 'weekly' : p.recur_rule,
                    recur_days: e.target.checked ? p.recur_days ?? '' : '',
                  }))
                }
                className="h-4 w-4 rounded accent-accent"
              />
              Repeat this window
            </label>
            {editing.recurring && (
              <>
                <div>
                  <label className="mb-1 block text-xs font-medium text-text-dim">Frequency</label>
                  <select
                    value={editing.recur_rule || 'weekly'}
                    onChange={(e) => setEditing((p) => ({ ...p, recur_rule: e.target.value }))}
                    aria-label="Repeat frequency"
                    className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
                  >
                    {RECUR_RULES.map((rule) => (
                      <option key={rule.value} value={rule.value}>
                        {rule.label}
                      </option>
                    ))}
                  </select>
                </div>
                {(editing.recur_rule || 'weekly') === 'weekly' && (
                  <div>
                    <span className="mb-1 block text-xs font-medium text-text-dim">Days</span>
                    <div className="flex flex-wrap gap-1.5">
                      {WEEKDAYS.map((day) => {
                        const active = selectedRecurDays.has(day.value);
                        return (
                          <label
                            key={day.value}
                            className={cn(
                              'inline-flex cursor-pointer items-center rounded border px-2 py-1 text-[11px] font-medium',
                              active
                                ? 'border-accent/40 bg-accent/15 text-accent'
                                : 'border-border bg-bg-panel text-text-dim',
                            )}
                          >
                            <input
                              type="checkbox"
                              checked={active}
                              onChange={() => toggleWeekday(day.value)}
                              className="sr-only"
                            />
                            {day.label}
                          </label>
                        );
                      })}
                    </div>
                  </div>
                )}
                <p className="text-[10px] leading-relaxed text-text-faint">
                  Repeats at the start clock time; the end time sets the duration. Occurrences use
                  the server&apos;s timezone, and the first occurrence is the start time above.
                </p>
              </>
            )}
          </div>

          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Notes / Ticket Reference</label>
            <textarea
              rows={3}
              value={editing.notes ?? editing.description ?? ''}
              onChange={(e) => setEditing((p) => ({ ...p, notes: e.target.value }))}
              className="w-full rounded-md border border-border bg-bg-panel p-2.5 text-xs text-text"
            />
          </div>
          <div className="space-y-2">
            <span className="block text-xs font-medium text-text-dim">Scope</span>
            <div className="flex flex-wrap items-center gap-4 text-xs text-text">
              {(
                [
                  { id: 'all', label: 'All devices & sites' },
                  { id: 'device', label: 'One device' },
                  { id: 'site', label: 'One site' },
                ] as const
              ).map((opt) => (
                <label key={opt.id} className="inline-flex items-center gap-1.5">
                  <input
                    type="radio"
                    name="maint-scope"
                    checked={scopeMode === opt.id}
                    onChange={() => setScopeMode(opt.id)}
                  />
                  {opt.label}
                </label>
              ))}
            </div>
            {scopeMode === 'device' && (
              <select
                value={editing.device_id ?? ''}
                onChange={(e) =>
                  setEditing((p) => ({
                    ...p,
                    device_id: e.target.value ? Number(e.target.value) : null,
                  }))
                }
                aria-label="Maintenance window device"
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
              >
                <option value="">Select a device…</option>
                {devices.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name}
                  </option>
                ))}
              </select>
            )}
            {scopeMode === 'site' && (
              <select
                value={editing.site_id ?? ''}
                onChange={(e) =>
                  setEditing((p) => ({
                    ...p,
                    site_id: e.target.value ? Number(e.target.value) : null,
                  }))
                }
                aria-label="Maintenance window site"
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
              >
                <option value="">Select a site…</option>
                {sites.map((site) => (
                  <option key={site.id} value={site.id}>
                    {site.name}
                  </option>
                ))}
              </select>
            )}
          </div>

          <label className="flex items-center gap-2 text-xs text-text">
            <input
              type="checkbox"
              checked={editing.suppress_all !== false}
              onChange={(e) => setEditing((p) => ({ ...p, suppress_all: e.target.checked }))}
              className="h-4 w-4 rounded accent-accent"
            />
            Suppress all outbound alert notifications during the window
          </label>

          {editing.suppress_all === false && (
            <div className="rounded-lg border border-border bg-bg-panel/40">
              <div className="border-b border-border px-3 py-2 text-[11px] text-text-dim">
                Suppress only these alert types ({selectedTypes.size} selected). At least one is
                required: the server treats an empty list as “all types”.
                {Boolean(editing.id) && selectedTypes.size === 0 && (
                  <span className="mt-1 block text-sig-warn">
                    This existing window has no type filter, so it suppresses every alert type.
                    Selecting a type narrows it.
                  </span>
                )}
              </div>
              <div className="max-h-64 overflow-y-auto p-2 space-y-2">
                {groupedAlertTypes.map(([family, types]) => (
                  <div key={family}>
                    <div className="px-1 py-1 text-[10px] font-semibold uppercase tracking-wider text-text-faint">
                      {family}
                    </div>
                    {types.map((t) => (
                      <label
                        key={t.type}
                        className="flex items-start gap-2 rounded px-1 py-1 text-[11px] text-text hover:bg-bg-hover"
                      >
                        <input
                          type="checkbox"
                          checked={selectedTypes.has(t.type)}
                          onChange={() => toggleAlertType(t.type)}
                          className="mt-0.5 h-3.5 w-3.5 rounded accent-accent"
                        />
                        <span>
                          <span className="font-mono">{t.type}</span>
                          <span className="ml-1.5 text-text-faint">{t.description}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                ))}
                {alertTypes.length === 0 && (
                  <p className="p-2 text-[11px] text-text-faint">Alert types unavailable.</p>
                )}
              </div>
            </div>
          )}
        </div>
      </SlideOverDrawer>
    </div>
  );
}
