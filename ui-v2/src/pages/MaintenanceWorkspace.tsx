import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { CalendarClock, Plus, Trash2, Edit3, AlertCircle } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { formatDateTime } from '@/lib/utils';
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
  recurring?: boolean;
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

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<Partial<MaintenanceWindow>>({
    name: '',
    notes: '',
    start_time: toLocalInput(),
    end_time: toLocalInput(new Date(Date.now() + 2 * 3600_000).toISOString()),
    suppress_all: true,
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
      const payload = {
        ...editing,
        notes: editing.notes ?? editing.description ?? '',
        suppress_all: editing.suppress_all ?? editing.suppress_alerts ?? true,
        start_time: startIso,
        end_time: endIso,
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
  });

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
        accessorKey: 'suppress_all',
        header: 'Alert Suppression',
        cell: ({ row }) => {
          const suppress = row.original.suppress_all ?? row.original.suppress_alerts ?? true;
          return (
            <span className="rounded bg-sig-warn/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-sig-warn">
              {suppress ? 'Suppress Notifications' : 'Log Only'}
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
    [deleteMutation]
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
            setEditing({
              name: '',
              notes: '',
              start_time: toLocalInput(),
              end_time: toLocalInput(new Date(Date.now() + 2 * 3600_000).toISOString()),
              suppress_all: true,
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
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Notes / Ticket Reference</label>
            <textarea
              rows={3}
              value={editing.notes ?? editing.description ?? ''}
              onChange={(e) => setEditing((p) => ({ ...p, notes: e.target.value }))}
              className="w-full rounded-md border border-border bg-bg-panel p-2.5 text-xs text-text"
            />
          </div>
          <label className="flex items-center gap-2 text-xs text-text">
            <input
              type="checkbox"
              checked={editing.suppress_all !== false}
              onChange={(e) => setEditing((p) => ({ ...p, suppress_all: e.target.checked }))}
              className="h-4 w-4 rounded accent-accent"
            />
            Suppress outbound alert notifications during window
          </label>
        </div>
      </SlideOverDrawer>
    </div>
  );
}
