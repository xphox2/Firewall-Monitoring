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
  Trash2,
  Edit3,
  Terminal,
} from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { useToast } from '@/components/ui/toast';
import { ColumnDef } from '@tanstack/react-table';

type CollectorsTab = 'probes' | 'sites';

interface ProbeRecord {
  id: number;
  name: string;
  location?: string;
  ip_address?: string;
  status: string;
  approved: boolean;
  decommissioned?: boolean;
  version?: string;
  last_heartbeat?: string;
  registration_key?: string;
}

interface SiteRecord {
  id: number;
  name: string;
  location?: string;
  description?: string;
  parent_site_id?: number | null;
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
                ? 'bg-bg-card text-text shadow-sm border border-border'
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
                ? 'bg-bg-card text-text shadow-sm border border-border'
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

  const createProbeMutation = useMutation({
    mutationFn: async () =>
      apiFetch<ProbeRecord & { registration_key?: string }>('/admin/api/probes', {
        method: 'POST',
        body: { name: probeName.trim(), location: probeLocation.trim() },
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

  const pingCommandMutation = useMutation({
    mutationFn: async (id: number) =>
      apiFetch(`/admin/api/probes/${id}/commands`, {
        method: 'POST',
        body: { command_type: 'noop' },
      }),
    onSuccess: () => {
      toast({ title: 'Heartbeat noop command enqueued', variant: 'info' });
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
              {row.original.ip_address || 'Awaiting heartbeat'} • {row.original.location || 'Global'}
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
                row.original.decommissioned
                  ? 'bg-bg-panel text-text-faint'
                  : !row.original.approved
                    ? 'bg-sig-warn/15 text-sig-warn'
                    : row.original.status === 'online' || row.original.status === 'active'
                      ? 'bg-sig-ok/15 text-sig-ok'
                      : 'bg-sig-crit/15 text-sig-crit'
              )}
            >
              {row.original.decommissioned
                ? 'Decommissioned'
                : !row.original.approved
                  ? 'Pending Approval'
                  : row.original.status || 'offline'}
            </span>
          </div>
        ),
      },
      {
        accessorKey: 'last_heartbeat',
        header: 'Last Heartbeat',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {formatRelativeTime(row.original.last_heartbeat)}
          </span>
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex items-center justify-end gap-1.5">
            {!row.original.approved && !row.original.decommissioned && (
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
                  onClick={() => actionMutation.mutate({ id: row.original.id, action: 'reject' })}
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
            {row.original.decommissioned ? (
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
              {p.ip_address || 'No IP'} • Last seen: {formatRelativeTime(p.last_heartbeat)}
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
  const [editingSite, setEditingSite] = useState<Partial<SiteRecord>>({
    name: '',
    location: '',
    description: '',
  });

  const saveSiteMutation = useMutation({
    mutationFn: async () => {
      if (editingSite.id) {
        return apiFetch(`/admin/api/sites/${editingSite.id}`, {
          method: 'PUT',
          body: editingSite,
        });
      }
      return apiFetch('/admin/api/sites', {
        method: 'POST',
        body: editingSite,
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
      queryClient.invalidateQueries({ queryKey: ['sites'] });
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
        accessorKey: 'location',
        header: 'Location',
        cell: ({ row }) => <span className="text-xs text-text-dim">{row.original.location || '—'}</span>,
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
              onClick={() => deleteSiteMutation.mutate(row.original.id)}
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
            setEditingSite({ name: '', location: '', description: '' });
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
            <div className="text-xs text-text-dim">{s.location || s.description || 'No location'}</div>
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
              placeholder="US-East HQ"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Geographic Location</label>
            <input
              type="text"
              value={editingSite.location ?? ''}
              onChange={(e) => setEditingSite((p) => ({ ...p, location: e.target.value }))}
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
              className="w-full rounded-md border border-border bg-bg-panel p-2.5 text-xs text-text"
            />
          </div>
        </div>
      </SlideOverDrawer>
    </div>
  );
}
