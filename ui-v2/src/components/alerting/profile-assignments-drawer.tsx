import { useEffect, useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, X } from 'lucide-react';
import { apiFetch, ApiError } from '@/lib/api';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { useToast } from '@/components/ui/toast';

interface Assignment {
  id: number;
  name: string;
}

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  profile: { id: number; name: string } | null;
  onSaved: () => void;
}

function errorText(err: unknown): string {
  return err instanceof ApiError || err instanceof Error ? err.message : 'Request failed';
}

export function ProfileAssignmentsDrawer({ open, onOpenChange, profile, onSaved }: Props) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [siteToAdd, setSiteToAdd] = useState('');
  const [deviceToAdd, setDeviceToAdd] = useState('');

  // The drawer instance survives profile switches and close/reopen; a pending
  // selection made for profile A must never be submittable against profile B.
  useEffect(() => {
    setSiteToAdd('');
    setDeviceToAdd('');
  }, [profile?.id, open]);

  const { data: assignments, isLoading } = useQuery({
    queryKey: ['profile-assignments', profile?.id],
    queryFn: () =>
      apiFetch<{ sites?: Assignment[]; devices?: Assignment[] }>(
        `/admin/api/event-rule-profiles/${profile?.id}/assignments`,
      ),
    enabled: open && !!profile?.id,
  });

  const { data: allSites = [] } = useQuery({
    queryKey: ['assign-sites'],
    queryFn: () => apiFetch<Assignment[]>('/admin/api/sites'),
    enabled: open,
  });
  const { data: allDevices = [] } = useQuery({
    queryKey: ['assign-devices'],
    queryFn: () => apiFetch<Assignment[]>('/admin/api/devices'),
    enabled: open,
  });

  const sites = assignments?.sites ?? [];
  const devices = assignments?.devices ?? [];

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['profile-assignments', profile?.id] });
    queryClient.invalidateQueries({ queryKey: ['event-rule-profiles'] });
    queryClient.invalidateQueries({ queryKey: ['alert-config-overview'] });
    onSaved();
  };

  const fail = (title: string) => (err: unknown) =>
    toast({ title, description: errorText(err), variant: 'error' });

  const add = useMutation({
    mutationFn: async (body: { site_ids?: number[]; device_ids?: number[] }) =>
      apiFetch(`/admin/api/event-rule-profiles/${profile?.id}/assignments`, {
        method: 'PUT',
        body,
      }),
    onSuccess: () => {
      setSiteToAdd('');
      setDeviceToAdd('');
      refresh();
    },
    onError: fail('Could not assign'),
  });

  const unassignSite = useMutation({
    mutationFn: async (siteId: number) =>
      apiFetch(`/admin/api/sites/${siteId}/event-profile`, {
        method: 'PUT',
        body: { profile_id: null },
      }),
    onSuccess: refresh,
    onError: fail('Could not unassign site'),
  });

  const unassignDevice = useMutation({
    mutationFn: async (deviceId: number) =>
      apiFetch(`/admin/api/devices/${deviceId}/event-profile`, {
        method: 'PUT',
        body: { profile_id: null },
      }),
    onSuccess: refresh,
    onError: fail('Could not unassign device'),
  });

  const assignedSiteIds = useMemo(() => new Set(sites.map((s) => s.id)), [sites]);
  const assignedDeviceIds = useMemo(() => new Set(devices.map((d) => d.id)), [devices]);
  const availableSites = allSites.filter((s) => !assignedSiteIds.has(s.id));
  const availableDevices = allDevices.filter((d) => !assignedDeviceIds.has(d.id));

  const busy =
    add.isPending || unassignSite.isPending || unassignDevice.isPending;
  // Only a value present in the current options is submittable: a stale value
  // renders as a blank select but would otherwise still enable Add.
  const canAddSite =
    Boolean(siteToAdd) && availableSites.some((site) => String(site.id) === siteToAdd);
  const canAddDevice =
    Boolean(deviceToAdd) && availableDevices.some((device) => String(device.id) === deviceToAdd);

  return (
    <SlideOverDrawer
      open={open}
      onOpenChange={onOpenChange}
      title={profile ? `Assignments — ${profile.name}` : 'Assignments'}
      subtitle="Devices resolve Default → Site → Device; a device-level assignment overrides its site."
      size="lg"
    >
      <div className="space-y-5">
        <div className="rounded-lg border border-border bg-bg-panel px-3 py-2 text-[11px] text-text-dim">
          Assigning only touches the listed sites/devices, and moves an entity that already has a
          different profile. Removing an assignment sends that entity back to the next layer (a
          device without its own profile inherits its site&apos;s, then Default).
        </div>

        <section className="space-y-2">
          <h3 className="text-xs font-semibold text-text">
            Sites {isLoading ? '' : `(${sites.length})`}
          </h3>
          {isLoading ? (
            <p className="text-[11px] text-text-dim">Loading assignments…</p>
          ) : sites.length === 0 ? (
            <p className="text-[11px] text-text-faint">No sites assigned.</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {sites.map((site) => (
                <span
                  key={site.id}
                  className="inline-flex items-center gap-1 rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text"
                >
                  {site.name}
                  <button
                    type="button"
                    aria-label={`Unassign site ${site.name}`}
                    disabled={busy}
                    onClick={() => unassignSite.mutate(site.id)}
                    className="text-text-faint hover:text-sig-crit disabled:opacity-40"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </span>
              ))}
            </div>
          )}
          <div className="flex items-center gap-2">
            <select
              value={siteToAdd}
              onChange={(e) => setSiteToAdd(e.target.value)}
              aria-label="Site to assign"
              className="flex-1 rounded-md border border-border bg-bg-panel px-2.5 py-1.5 text-xs text-text"
            >
              <option value="">Select a site…</option>
              {availableSites.map((site) => (
                <option key={site.id} value={site.id}>
                  {site.name}
                </option>
              ))}
            </select>
            <button
              type="button"
              disabled={!canAddSite || busy}
              onClick={() => add.mutate({ site_ids: [Number(siteToAdd)] })}
              className="inline-flex items-center gap-1 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40"
            >
              <Plus className="h-3.5 w-3.5" /> Add
            </button>
          </div>
        </section>

        <section className="space-y-2">
          <h3 className="text-xs font-semibold text-text">
            Devices {isLoading ? '' : `(${devices.length})`}
          </h3>
          {isLoading ? (
            <p className="text-[11px] text-text-dim">Loading assignments…</p>
          ) : devices.length === 0 ? (
            <p className="text-[11px] text-text-faint">No devices assigned.</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {devices.map((device) => (
                <span
                  key={device.id}
                  className="inline-flex items-center gap-1 rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text"
                >
                  {device.name}
                  <button
                    type="button"
                    aria-label={`Unassign device ${device.name}`}
                    disabled={busy}
                    onClick={() => unassignDevice.mutate(device.id)}
                    className="text-text-faint hover:text-sig-crit disabled:opacity-40"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </span>
              ))}
            </div>
          )}
          <div className="flex items-center gap-2">
            <select
              value={deviceToAdd}
              onChange={(e) => setDeviceToAdd(e.target.value)}
              aria-label="Device to assign"
              className="flex-1 rounded-md border border-border bg-bg-panel px-2.5 py-1.5 text-xs text-text"
            >
              <option value="">Select a device…</option>
              {availableDevices.map((device) => (
                <option key={device.id} value={device.id}>
                  {device.name}
                </option>
              ))}
            </select>
            <button
              type="button"
              disabled={!canAddDevice || busy}
              onClick={() => add.mutate({ device_ids: [Number(deviceToAdd)] })}
              className="inline-flex items-center gap-1 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40"
            >
              <Plus className="h-3.5 w-3.5" /> Add
            </button>
          </div>
        </section>
      </div>
    </SlideOverDrawer>
  );
}
