import { useEffect, useMemo, useState } from 'react';
import { apiFetch } from '@/lib/api';
import { cn } from '@/lib/utils';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { useToast } from '@/components/ui/toast';

export interface ConnectionDevice {
  id: number;
  name: string;
  ip_address?: string;
  retired_at?: string | null;
}

export interface ConnectionRecord {
  id: number;
  name: string;
  source_device_id: number;
  source_device_name?: string;
  dest_device_id: number;
  dest_device_name?: string;
  connection_type: string;
  status: string;
  notes?: string;
}

/**
 * The connection types the server accepts.
 *
 * internal/api/handlers/handlers_connections.go:30-35 — the allowlist is the
 * server's, and it is also the AUDIT-184 guard: connection_type is rendered
 * by the badge helpers, so anything outside the list is rejected.
 */
export const CONNECTION_TYPES = [
  'ipsec',
  'ssl',
  'gre',
  'tunnel',
  'vxlan',
  'l3ipvlan',
  'ethernet',
  'lag',
  'l2vlan',
  'bridge',
  'wan',
  'offnet',
] as const;

/** The statuses the server accepts on an edit. */
const CONNECTION_STATUSES = ['unknown', 'up', 'down'] as const;

export interface ConnectionEditorProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The connection being edited; null means "create". */
  connection: ConnectionRecord | null;
  /** Every device, for the endpoint pickers. */
  devices: ConnectionDevice[];
  onSaved?: (connection: ConnectionRecord) => void;
}

interface FormState {
  name: string;
  source_device_id: string;
  dest_device_id: string;
  connection_type: string;
  notes: string;
  status: string;
}

const EMPTY: FormState = {
  name: '',
  source_device_id: '',
  dest_device_id: '',
  connection_type: 'ipsec',
  notes: '',
  status: 'unknown',
};

/**
 * Create or edit a device connection.
 *
 * The V2 console could only DELETE a connection — the server's create and
 * update endpoints were live and unused, so a link between two devices could
 * not be declared or corrected from the V2 console at all.
 *
 * The server owns several fields and this form does not send them: `id`,
 * `match_method`, `auto_detected` and, on create, `status` (the server forces
 * "unknown" — a new link has not been observed yet). On an edit the server
 * accepts only name, source_device_id, dest_device_id, connection_type,
 * notes and status.
 *
 * There is deliberately no Description field: `models.DeviceConnection` has
 * no such column (only Notes), so a body carrying one was silently dropped
 * on create and produced a 500 on every update.
 */
export function ConnectionEditor({
  open,
  onOpenChange,
  connection,
  devices,
  onSaved,
}: ConnectionEditorProps) {
  const { toast } = useToast();
  const [form, setForm] = useState<FormState>(EMPTY);
  const [saving, setSaving] = useState(false);

  // A retired device cannot be a connection endpoint — the server rejects it
  // with "Source device is retired" — so it is not offered in the pickers.
  const selectable = useMemo(
    () => devices.filter((device) => !device.retired_at),
    [devices],
  );

  useEffect(() => {
    if (!open) return;
    setForm(
      connection
        ? {
            name: connection.name ?? '',
            source_device_id: String(connection.source_device_id ?? ''),
            dest_device_id: String(connection.dest_device_id ?? ''),
            connection_type: connection.connection_type || 'ipsec',
            notes: connection.notes ?? '',
            status: connection.status || 'unknown',
          }
        : EMPTY,
    );
  }, [open, connection]);

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }));

  const sameDevice =
    form.source_device_id !== '' &&
    form.source_device_id === form.dest_device_id;
  const missingEndpoints = form.source_device_id === '' || form.dest_device_id === '';
  const canSave = !sameDevice && !missingEndpoints && !saving;

  const save = async () => {
    if (!canSave) return;
    setSaving(true);
    try {
      const body: Record<string, unknown> = {
        name: form.name.trim(),
        source_device_id: Number(form.source_device_id),
        dest_device_id: Number(form.dest_device_id),
        connection_type: form.connection_type,
        notes: form.notes.trim(),
      };
      // `status` is server-owned on create (it forces "unknown": a new link
      // has not been observed yet), and the create handler ignores it anyway.
      if (connection) body.status = form.status;

      const saved = await apiFetch<ConnectionRecord>(
        connection ? `/admin/api/connections/${connection.id}` : '/admin/api/connections',
        { method: connection ? 'PUT' : 'POST', body },
      );
      toast({
        title: connection ? 'Connection updated' : 'Connection created',
        variant: 'success',
      });
      onOpenChange(false);
      onSaved?.(saved);
    } catch (err) {
      toast({
        title: connection ? 'Could not update the connection' : 'Could not create the connection',
        description: err instanceof Error ? err.message : 'request failed',
        variant: 'error',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <SlideOverDrawer
      open={open}
      onOpenChange={onOpenChange}
      title={connection ? `Edit ${connection.name || 'connection'}` : 'New connection'}
      subtitle={
        connection
          ? 'Change the endpoints, type, or notes for this declared link.'
          : 'Declare a link between two monitored devices.'
      }
      size="lg"
      footer={
        <>
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text-dim hover:text-text"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={save}
            disabled={!canSave}
            className="rounded-md bg-accent px-3.5 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
          >
            {saving ? 'Saving…' : connection ? 'Save changes' : 'Create connection'}
          </button>
        </>
      }
    >
      <div className="space-y-4">
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-text-dim">Name</span>
          <input
            type="text"
            value={form.name}
            onChange={(e) => set('name', e.target.value)}
            placeholder="e.g. HQ to DR site"
            className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
          />
        </label>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">Source device</span>
            <select
              value={form.source_device_id}
              onChange={(e) => set('source_device_id', e.target.value)}
              aria-label="Source device"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            >
              <option value="">Select a device…</option>
              {selectable.map((device) => (
                <option key={device.id} value={device.id}>
                  {device.name}
                  {device.ip_address ? ` (${device.ip_address})` : ''}
                </option>
              ))}
            </select>
          </label>

          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">Destination device</span>
            <select
              value={form.dest_device_id}
              onChange={(e) => set('dest_device_id', e.target.value)}
              aria-label="Destination device"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            >
              <option value="">Select a device…</option>
              {selectable.map((device) => (
                <option key={device.id} value={device.id}>
                  {device.name}
                  {device.ip_address ? ` (${device.ip_address})` : ''}
                </option>
              ))}
            </select>
          </label>
        </div>

        {sameDevice && (
          <div
            className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit"
            role="alert"
          >
            The source and destination cannot be the same device.
          </div>
        )}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">Connection type</span>
            <select
              value={form.connection_type}
              onChange={(e) => set('connection_type', e.target.value)}
              aria-label="Connection type"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            >
              {CONNECTION_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </label>

          {connection ? (
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">Status</span>
              <select
                value={form.status}
                onChange={(e) => set('status', e.target.value)}
                aria-label="Connection status"
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
              >
                {CONNECTION_STATUSES.map((status) => (
                  <option key={status} value={status}>
                    {status}
                  </option>
                ))}
              </select>
            </label>
          ) : null}
        </div>

        <label className="block">
          <span className="mb-1 block text-xs font-medium text-text-dim">Notes</span>
          <textarea
            rows={3}
            value={form.notes}
            onChange={(e) => set('notes', e.target.value)}
            className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
          />
        </label>

        {devices.length > selectable.length && (
          <p className="text-[11px] text-text-faint">
            {devices.length - selectable.length} retired device
            {devices.length - selectable.length === 1 ? '' : 's'} hidden — a retired
            device cannot be a connection endpoint.
          </p>
        )}

        {connection && (
          <p className={cn('text-[11px] text-text-faint')}>
            A connection whose endpoint has been retired cannot be edited; delete it
            instead.
          </p>
        )}
      </div>
    </SlideOverDrawer>
  );
}
