import { useState, useMemo } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Radio,
  MapPin,
  Plus,
  Check,
  X,
  Key,
  PowerOff,
  RotateCcw,
  ShieldAlert,
  Trash2,
  Edit3,
  Terminal,
} from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { useToast } from '@/components/ui/toast';
import { AlertConfigDrawer } from '@/components/devices/alert-config-drawer';
import { ColumnDef } from '@tanstack/react-table';

type CollectorsTab = 'probes' | 'sites';

// Wire shape of models.Probe. The previous approved/location/ip_address/
// last_heartbeat names do not exist on the JSON payload, so every probe
// rendered as "Pending Approval" with dead IP/heartbeat cells and the
// approve/reject buttons showed for already-approved collectors.
interface ProbeRecord {
  id: number;
  name: string;
  description?: string;
  listen_address?: string;
  status: string;
  approval_status: string;
  decommissioned_at?: string | null;
  agent_version?: string;
  last_seen?: string;
  registration_key?: string;
}

interface SiteRecord {
  id: number;
  name: string;
  region?: string;
  country?: string;
  address?: string;
  timezone?: string;
  description?: string;
  parent_site_id?: number | null;
  parent_site?: { id: number; name: string } | null;
  alert_policy_id?: number | null;
  event_profile_id?: number | null;
}

export function CollectorsWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = (searchParams.get('tab') as CollectorsTab) || 'probes';

  const setTab = (tab: CollectorsTab) => {
    setSearchParams({ tab }, { replace: true });
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <Radio className="h-3.5 w-3.5" />
            Infrastructure / Collectors & Sites
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            Remote Collector Probes & Site Hierarchy
          </h1>
          <p className="text-xs text-text-dim mt-0.5">
            Approve and monitor remote telemetry collectors (`fwmon-collector`) and organize sites with policy inheritance.
          </p>
        </div>

        <div className="flex items-center gap-1 rounded-lg bg-bg-panel p-1 border border-border self-start">
          <button
            type="button"
            onClick={() => setTab('probes')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'probes'
                ? 'bg-bg-card text-text shadow-xs border border-border'
                : 'text-text-dim hover:text-text'
            )}
          >
            <Radio className="h-3.5 w-3.5 text-accent" />
            Collector Probes
          </button>
          <button
            type="button"
            onClick={() => setTab('sites')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'sites'
                ? 'bg-bg-card text-text shadow-xs border border-border'
                : 'text-text-dim hover:text-text'
            )}
          >
            <MapPin className="h-3.5 w-3.5 text-accent" />
            Sites Hierarchy
          </button>
        </div>
      </div>

      {activeTab === 'probes' && <ProbesSubTab />}
      {activeTab === 'sites' && <SitesSubTab />}
    </div>
  );
}

function ProbesSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: probesList, isLoading } = useQuery({
    queryKey: ['probes'],
    queryFn: () => apiFetch<ProbeRecord[]>('/admin/api/probes'),
    refetchInterval: 15_000,
  });

  const probes = probesList ?? [];

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [probeName, setProbeName] = useState('');
  const [probeLocation, setProbeLocation] = useState('');
  const [mintedKey, setMintedKey] = useState<string | null>(null);
  // RejectProbe requires a reason; the old one-click POST sent an empty body
  // and always 400'd.
  const [rejectTarget, setRejectTarget] = useState<ProbeRecord | null>(null);
  const [rejectReason, setRejectReason] = useState('');

  const createProbeMutation = useMutation({
    mutationFn: async () =>
      apiFetch<ProbeRecord & { registration_key?: string }>('/admin/api/probes', {
        method: 'POST',
        // models.Probe has no `location` column; description is the free-text
        // field the register form is actually filling in.
        body: { name: probeName.trim(), description: probeLocation.trim() },
      }),
    onSuccess: (res) => {
      if (res?.registration_key) {
        setMintedKey(res.registration_key);
      }
      toast({ title: 'Collector probe registered', variant: 'success' });
      setDrawerOpen(false);
      setProbeName('');
      setProbeLocation('');
      queryClient.invalidateQueries({ queryKey: ['probes'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to create probe', description: err.message, variant: 'error' });
    },
  });

  const actionMutation = useMutation({
    mutationFn: async ({ id, action }: { id: number; action: string }) =>
      apiFetch<{ registration_key?: string }>(`/admin/api/probes/${id}/${action}`, {
        method: 'POST',
      }),
    onSuccess: (res, vars) => {
      if (res?.registration_key) {
        setMintedKey(res.registration_key);
      }
      toast({ title: `Collector ${vars.action} succeeded`, variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['probes'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Probe action failed', description: err.message, variant: 'error' });
    },
  });

  const rejectMutation = useMutation({
    mutationFn: async ({ id, reason }: { id: number; reason: string }) =>
      apiFetch(`/admin/api/probes/${id}/reject`, {
        method: 'POST',
        body: { reason },
      }),
    onSuccess: () => {
      toast({ title: 'Collector rejected', variant: 'info' });
      setRejectTarget(null);
      setRejectReason('');
      queryClient.invalidateQueries({ queryKey: ['probes'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Reject failed', description: err.message, variant: 'error' });
    },
  });

  const pingCommandMutation = useMutation({
    mutationFn: async (id: number) =>
      apiFetch(`/admin/api/probes/${id}/commands`, {
        method: 'POST',
        // CreateProbeCommand binds `type`; command_type was ignored and the
        // request 400'd with "Unsupported command type".
        body: { type: 'noop' },
      }),
    onSuccess: () => {
      toast({ title: 'Heartbeat noop command enqueued', variant: 'info' });
    },
    onError: (err: Error) => {
      toast({
        title: 'Could not enqueue the heartbeat command',
        description: err.message,
        variant: 'error',
      });
    },
  });

  const columns = useMemo<ColumnDef<ProbeRecord, unknown>[]>(
    () => [
      {
        accessorKey: 'name',
        header: 'Collector Probe',
        cell: ({ row }) => (
          <div>
            <div className="font-semibold text-text">{row.original.name}</div>
            <div className="text-[11px] font-mono text-text-dim">
              {row.original.listen_address || 'Awaiting heartbeat'} •{' '}
              {row.original.description || 'No description'}
            </div>
          </div>
        ),
      },
      {
        accessorKey: 'status',
        header: 'State',
        cell: ({ row }) => (
          <div className="flex items-center gap-1.5">
            <span
              className={cn(
                'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
                row.original.decommissioned_at
                  ? 'bg-bg-panel text-text-faint'
                  : row.original.approval_status !== 'approved'
                    ? 'bg-sig-warn/15 text-sig-warn'
                    : row.original.status === 'online' || row.original.status === 'active'
                      ? 'bg-sig-ok/15 text-sig-ok'
                      : 'bg-sig-crit/15 text-sig-crit'
              )}
            >
              {row.original.decommissioned_at
                ? 'Decommissioned'
                : row.original.approval_status !== 'approved'
                  ? row.original.approval_status || 'Pending Approval'
                  : row.original.status || 'offline'}
            </span>
          </div>
        ),
      },
      {
        accessorKey: 'last_seen',
        header: 'Last Heartbeat',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {formatRelativeTime(row.original.last_seen)}
          </span>
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex items-center justify-end gap-1.5">
            {row.original.approval_status !== 'approved' && !row.original.decommissioned_at && (
              <>
                <button
                  type="button"
                  onClick={() => actionMutation.mutate({ id: row.original.id, action: 'approve' })}
                  className="flex items-center gap-1 rounded border border-sig-ok/40 bg-sig-ok/10 px-2 py-1 text-[11px] font-semibold text-sig-ok"
                >
                  <Check className="h-3 w-3" /> Approve
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setRejectTarget(row.original);
                    setRejectReason('');
                  }}
                  className="flex items-center gap-1 rounded border border-sig-crit/40 bg-sig-crit/10 px-2 py-1 text-[11px] font-semibold text-sig-crit"
                >
                  <X className="h-3 w-3" /> Reject
                </button>
              </>
            )}
            <button
              type="button"
              onClick={() => pingCommandMutation.mutate(row.original.id)}
              className="rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text-dim hover:text-text"
              title="Test command channel"
            >
              <Terminal className="h-3 w-3 inline mr-1" />
              Noop
            </button>
            <button
              type="button"
              onClick={() => actionMutation.mutate({ id: row.original.id, action: 'regenerate-key' })}
              className="rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text-dim hover:text-text"
              title="Rotate registration key"
            >
              <Key className="h-3 w-3 inline mr-1" />
              Rotate Key
            </button>
            {row.original.decommissioned_at ? (
              <button
                type="button"
                onClick={() => actionMutation.mutate({ id: row.original.id, action: 'recommission' })}
                className="rounded border border-border bg-bg-panel p-1 text-text-dim hover:text-text"
                title="Recommission"
              >
                <RotateCcw className="h-3.5 w-3.5" />
              </button>
            ) : (
              <button
                type="button"
                onClick={() => actionMutation.mutate({ id: row.original.id, action: 'decommission' })}
                className="rounded border border-border bg-bg-panel p-1 text-text-dim hover:text-text"
                title="Decommission"
              >
                <PowerOff className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        ),
      },
    ],
    [actionMutation, pingCommandMutation]
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-text">Registered Collectors ({probes.length})</h2>
          <p className="text-xs text-text-dim">
            Collectors ingest Syslog, SNMP Traps, sFlow/NetFlow, and execute remote SNMP/SSH polling.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setDrawerOpen(true)}
          className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90"
        >
          <Plus className="h-3.5 w-3.5" />
          Register Collector
        </button>
      </div>

      {mintedKey && (
        <div className="rounded-lg border border-sig-ok/40 bg-sig-ok/10 p-3 text-xs">
          <div className="font-semibold text-sig-ok">One-Time Collector Registration Key:</div>
          <code className="block mt-1 font-mono text-text break-all">{mintedKey}</code>
        </div>
      )}

      <ResponsiveDataView
        data={probes}
        columns={columns}
        isLoading={isLoading}
        emptyTitle="No remote collectors registered."
        renderMobileCard={(p) => (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-sm text-text">{p.name}</span>
              <span className="rounded bg-bg-panel px-2 py-0.5 text-[10px] uppercase text-text-dim">
                {p.status}
              </span>
            </div>
            <div className="text-xs font-mono text-text-dim">
              {p.listen_address || 'No IP'} • Last seen: {formatRelativeTime(p.last_seen)}
            </div>
          </div>
        )}
      />

      <SlideOverDrawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        title="Register New Collector Probe"
        subtitle="Generates a one-time registration token for a new fwmon-collector instance."
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
              disabled={!probeName.trim() || createProbeMutation.isPending}
              onClick={() => createProbeMutation.mutate()}
              className="rounded-md bg-accent px-4 py-1.5 text-xs font-semibold text-white hover:opacity-90"
            >
              Create & Generate Key
            </button>
          </div>
        }
      >
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Collector Name</label>
            <input
              type="text"
              value={probeName}
              onChange={(e) => setProbeName(e.target.value)}
              placeholder="us-east-collector-01"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Location / Datacenter</label>
            <input
              type="text"
              value={probeLocation}
              onChange={(e) => setProbeLocation(e.target.value)}
              placeholder="Ashburn, VA (Equinix DC2)"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            />
          </div>
        </div>
      </SlideOverDrawer>

      <SlideOverDrawer
        open={!!rejectTarget}
        onOpenChange={(open) => {
          if (!open) setRejectTarget(null);
        }}
        title={`Reject collector: ${rejectTarget?.name ?? ''}`}
        subtitle="The rejection reason is stored on the probe and shown to operators."
        footer={
          <div className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => setRejectTarget(null)}
              className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text-dim"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={!rejectReason.trim() || rejectMutation.isPending}
              onClick={() =>
                rejectTarget &&
                rejectMutation.mutate({ id: rejectTarget.id, reason: rejectReason.trim() })
              }
              className="rounded-md bg-sig-crit px-4 py-1.5 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
            >
              Reject Collector
            </button>
          </div>
        }
      >
        <label className="block text-xs font-medium text-text-dim mb-1">Reason</label>
        <textarea
          rows={3}
          value={rejectReason}
          onChange={(e) => setRejectReason(e.target.value)}
          placeholder="Unknown host / failed change ticket CHG-1234"
          className="w-full rounded-md border border-border bg-bg-panel p-2.5 text-xs text-text"
        />
      </SlideOverDrawer>
    </div>
  );
}

function SitesSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: sitesList, isLoading } = useQuery({
    queryKey: ['sites'],
    queryFn: () => apiFetch<SiteRecord[]>('/admin/api/sites'),
  });

  const sites = sitesList ?? [];

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [siteToDelete, setSiteToDelete] = useState<SiteRecord | null>(null);
  const [alertConfigSite, setAlertConfigSite] = useState<SiteRecord | null>(null);
  const [editingSite, setEditingSite] = useState<Partial<SiteRecord>>({
    name: '',
    address: '',
    description: '',
  });

  const saveSiteMutation = useMutation({
    mutationFn: async () => {
      // Send only editable columns. The edit draft is the API row and carries
      // the nested parent_site object; echoing it would invite a GORM
      // association write (and the id belongs in the path, not the body).
      const payload = {
        name: editingSite.name?.trim() ?? '',
        region: editingSite.region ?? '',
        country: editingSite.country ?? '',
        address: editingSite.address ?? '',
        timezone: editingSite.timezone ?? '',
        description: editingSite.description ?? '',
        parent_site_id: editingSite.parent_site_id ?? null,
      };
      if (editingSite.id) {
        return apiFetch(`/admin/api/sites/${editingSite.id}`, {
          method: 'PUT',
          body: payload,
        });
      }
      return apiFetch('/admin/api/sites', {
        method: 'POST',
        body: payload,
      });
    },
    onSuccess: () => {
      toast({ title: editingSite.id ? 'Site updated' : 'Site created', variant: 'success' });
      setDrawerOpen(false);
      queryClient.invalidateQueries({ queryKey: ['sites'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to save site', description: err.message, variant: 'error' });
    },
  });

  const deleteSiteMutation = useMutation({
    mutationFn: async (id: number) => apiFetch(`/admin/api/sites/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      toast({ title: 'Site deleted', variant: 'info' });
      setSiteToDelete(null);
      queryClient.invalidateQueries({ queryKey: ['sites'] });
    },
    onError: (err: Error) => {
      // DeleteSite returns 409 when the site still has children or devices;
      // without this the trash click looked like it did nothing.
      toast({ title: 'Site was not deleted', description: err.message, variant: 'error' });
    },
  });

  const columns = useMemo<ColumnDef<SiteRecord, unknown>[]>(
    () => [
      {
        accessorKey: 'name',
        header: 'Site Name',
        cell: ({ row }) => <span className="font-semibold text-text">{row.original.name}</span>,
      },
      {
        id: 'region',
        header: 'Region / TZ',
        cell: ({ row }) => {
          const parts = [row.original.region, row.original.country, row.original.timezone].filter(
            Boolean,
          );
          return (
            <span className="font-mono text-[11px] text-text-dim">
              {parts.length > 0 ? parts.join(' · ') : '—'}
            </span>
          );
        },
      },
      {
        id: 'parent',
        header: 'Parent',
        cell: ({ row }) => (
          <span className="text-[11px] text-text-dim">
            {row.original.parent_site?.name || '—'}
          </span>
        ),
      },
      {
        accessorKey: 'address',
        header: 'Location',
        cell: ({ row }) => <span className="text-xs text-text-dim">{row.original.address || '—'}</span>,
      },
      {
        accessorKey: 'description',
        header: 'Description',
        cell: ({ row }) => <span className="text-xs text-text-dim">{row.original.description || '—'}</span>,
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex items-center justify-end gap-1.5">
            {/*
              The per-site alert override. The console had only the GLOBAL
              thresholds, so a noisy site could not be given its own numbers.
            */}
            <button
              type="button"
              onClick={() => setAlertConfigSite(row.original)}
              title="Alert thresholds & routing for this site"
              className="rounded border border-border bg-bg-panel p-1 text-text-dim hover:text-text"
            >
              <ShieldAlert className="h-3.5 w-3.5" />
            </button>
            <button
              type="button"
              onClick={() => {
                setEditingSite(row.original);
                setDrawerOpen(true);
              }}
              className="rounded border border-border bg-bg-panel p-1 text-text-dim hover:text-text"
            >
              <Edit3 className="h-3.5 w-3.5" />
            </button>
            <button
              type="button"
              onClick={() => setSiteToDelete(row.original)}
              className="rounded border border-sig-crit/30 bg-sig-crit/10 p-1 text-sig-crit"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          </div>
        ),
      },
    ],
    [deleteSiteMutation]
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-text">Sites Hierarchy ({sites.length})</h2>
          <p className="text-xs text-text-dim">
            Group firewalls by physical location or region for scoped alerting, maintenance windows, and NOC filtering.
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            setEditingSite({
              name: '',
              region: '',
              country: '',
              address: '',
              timezone: '',
              description: '',
              parent_site_id: null,
            });
            setDrawerOpen(true);
          }}
          className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90"
        >
          <Plus className="h-3.5 w-3.5" />
          Create Site
        </button>
      </div>

      <ResponsiveDataView
        data={sites}
        columns={columns}
        isLoading={isLoading}
        emptyTitle="No sites configured."
        renderMobileCard={(s) => (
          <div className="space-y-1">
            <div className="font-semibold text-sm text-text">{s.name}</div>
            <div className="text-xs text-text-dim">{s.address || s.description || 'No location'}</div>
            {(s.region || s.timezone || s.parent_site?.name) && (
              <div className="font-mono text-[11px] text-text-faint">
                {[s.region, s.country, s.timezone, s.parent_site?.name ? `parent: ${s.parent_site.name}` : '']
                  .filter(Boolean)
                  .join(' · ')}
              </div>
            )}
          </div>
        )}
      />

      <SlideOverDrawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        title={editingSite.id ? `Edit Site: ${editingSite.name}` : 'Create Site'}
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
              disabled={!editingSite.name?.trim() || saveSiteMutation.isPending}
              onClick={() => saveSiteMutation.mutate()}
              className="rounded-md bg-accent px-4 py-1.5 text-xs font-semibold text-white hover:opacity-90"
            >
              Save Site
            </button>
          </div>
        }
      >
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Site Name</label>
            <input
              type="text"
              value={editingSite.name ?? ''}
              onChange={(e) => setEditingSite((p) => ({ ...p, name: e.target.value }))}
              maxLength={255}
              placeholder="US-East HQ"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">Region</label>
              <input
                type="text"
                value={editingSite.region ?? ''}
                onChange={(e) => setEditingSite((p) => ({ ...p, region: e.target.value }))}
                maxLength={255}
                placeholder="us-east"
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">Country</label>
              <input
                type="text"
                value={editingSite.country ?? ''}
                onChange={(e) => setEditingSite((p) => ({ ...p, country: e.target.value }))}
                maxLength={255}
                placeholder="US"
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
              />
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Timezone</label>
            <input
              type="text"
              value={editingSite.timezone ?? ''}
              onChange={(e) => setEditingSite((p) => ({ ...p, timezone: e.target.value }))}
              maxLength={100}
              placeholder="America/New_York"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 font-mono text-xs text-text"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Parent site</label>
            <select
              value={editingSite.parent_site_id ?? ''}
              onChange={(e) =>
                setEditingSite((p) => ({
                  ...p,
                  parent_site_id: e.target.value ? Number(e.target.value) : null,
                }))
              }
              aria-label="Parent site"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            >
              <option value="">No parent (top level)</option>
              {sites
                .filter((site) => site.id !== editingSite.id)
                .map((site) => (
                  <option key={site.id} value={site.id}>
                    {site.name}
                  </option>
                ))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Geographic Location</label>
            <input
              type="text"
              value={editingSite.address ?? ''}
              onChange={(e) => setEditingSite((p) => ({ ...p, address: e.target.value }))}
              maxLength={500}
              placeholder="New York, NY"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Description</label>
            <textarea
              rows={3}
              value={editingSite.description ?? ''}
              onChange={(e) => setEditingSite((p) => ({ ...p, description: e.target.value }))}
              maxLength={1000}
              className="w-full rounded-md border border-border bg-bg-panel p-2.5 text-xs text-text"
            />
          </div>
        </div>
      </SlideOverDrawer>

      {/*
        The per-site alert override. The console had only the GLOBAL
        thresholds, so a noisy site could not be given its own numbers.
      */}
      <AlertConfigDrawer
        open={!!alertConfigSite}
        onOpenChange={(open) => {
          if (!open) setAlertConfigSite(null);
        }}
        scope="site"
        id={alertConfigSite?.id ?? 0}
        name={alertConfigSite?.name ?? ''}
      />

      <ConfirmDialog
        open={!!siteToDelete}
        onOpenChange={(open) => {
          if (!open) setSiteToDelete(null);
        }}
        title={`Delete site ${siteToDelete?.name ?? ''}?`}
        description="Devices and child sites must be moved first. This cannot be undone."
        confirmLabel="Delete site"
        destructive
        pending={deleteSiteMutation.isPending}
        onConfirm={() => siteToDelete && deleteSiteMutation.mutate(siteToDelete.id)}
      />
    </div>
  );
}
