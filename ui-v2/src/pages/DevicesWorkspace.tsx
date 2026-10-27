import { useState, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Server,
  Plus,
  Search,
  Edit3,
  ArrowLeft,
  Activity,
  Shield,
  Cpu,
  Network,
  FileCode2,
  AlertTriangle,
  Play,
  Eye,
  Archive,
  RotateCcw,
  Trash2,
  CheckCircle2,
  Download,
} from 'lucide-react';
import { apiFetch, type MeResponse } from '@/lib/api';
import { cn, formatBytes, formatRelativeTime } from '@/lib/utils';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { StatusDot } from '@/components/ui/status-dot';
import { Gauge } from '@/components/ui/gauge';
import { DeviceCapabilitiesPanel } from '@/components/devices/capability-matrix';
import type { DeviceCapabilities } from '@/lib/device-capabilities';
import { SlideOverDrawer, DrawerTab } from '@/components/ui/slide-over-drawer';
import { StepUpAuthDialog } from '@/components/ui/step-up-auth-dialog';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { TimeSeriesChart } from '@/components/charts/time-series-chart';
import { ConfigDiffDrawer } from '@/components/devices/config-diff-drawer';
import {
  CoreCpuPanel,
  DiskUsagePanel,
  HAPanel,
  LicencePanel,
  LoadAveragePanel,
  PingSlaPanel,
  RecentAlertsPanel,
  SdwanPanel,
  SecurityStatsPanel,
} from '@/components/devices/device-ops-panels';
import type { RevisionMeta } from '@/lib/config-diff';
import {
  bucketSeconds,
  counterDeltasToBps,
  numOrNull,
  toBitsPerSecond,
  type ChartSeries,
} from '@/lib/chart';
import { useToast } from '@/components/ui/toast';
import { PurgeDeviceDialog, type PurgeJob } from '@/components/devices/purge-device-dialog';
import { AlertConfigDrawer } from '@/components/devices/alert-config-drawer';
import { PublicInterfaceToggle } from '@/components/devices/public-interface-toggle';
import { ColumnDef } from '@tanstack/react-table';
import { Input, Select } from '@/components/ui/input';
import { Field } from '@/components/ui/field';
import { Button } from '@/components/ui/button';

export interface DeviceRecord {
  id: number;
  name: string;
  ip_address: string;
  vendor?: string;
  model?: string;
  os_version?: string;
  serial_number?: string;
  status: string;
  site_id?: number | null;
  site_name?: string;
  probe_id?: number | null;
  snmp_version?: string;
  snmp_port?: number;
  snmp_community?: string;
  snmpv3_username?: string;
  snmpv3_auth_type?: string;
  snmpv3_priv_type?: string;
  // The credentials. The server masks them on read as "********" and treats a
  // masked or empty value on write as "leave unchanged", so the console must
  // never send the mask back.
  snmpv3_auth_pass?: string;
  snmpv3_priv_pass?: string;
  ssh_poll_enabled?: boolean;
  ssh_poll_interval?: number;
  ssh_port?: number;
  ssh_username?: string;
  ssh_password?: string;
  api_port?: number;
  api_token?: string;
  api_insecure_tls?: boolean;
  location?: string;
  /**
   * Whether the device appears on the UNAUTHENTICATED public dashboard.
   *
   * The column defaults to TRUE, so a device is published unless an operator
   * says otherwise - and until the console had a control for it, there was no
   * way to say otherwise at all.
   */
  public_visible?: boolean;
  enabled: boolean;
  retired_at?: string | null;
  last_polled?: string | null;
  cpu_usage?: number;
  memory_usage?: number;
  disk_usage?: number;
  active_sessions?: number;
  vpn_up?: number;
  vpn_total?: number;
}

/** The secret fields the editor can set. */
const SECRET_FIELDS = [
  'snmp_community',
  'snmpv3_auth_pass',
  'snmpv3_priv_pass',
  'ssh_password',
  'api_token',
] as const;

/** The server's mask for a stored secret. */
const SECRET_MASK = '********';

const CHART_RANGES = ['1h', '6h', '12h', '24h', '7d', '30d', '90d', '365d'] as const;

interface SiteOption {
  id: number;
  name: string;
}

interface ProbeOption {
  id: number;
  name: string;
}

export function DevicesWorkspace() {
  const { '*': splat } = useParams();
  const deviceId = splat && /^\d+$/.test(splat) ? Number(splat) : null;

  if (deviceId) {
    // Keyed so switching devices resets expanded rows and the chart range
    // instead of querying device B for device A's interface/tunnel.
    return <DeviceDetailView key={deviceId} deviceId={deviceId} />;
  }
  return <DeviceInventoryView />;
}

// ============================================================================
// DEVICE INVENTORY VIEW + TABBED SLIDE-OVER DEVICE EDITOR
// ============================================================================
function DeviceInventoryView() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [search, setSearch] = useState('');
  const [lifecycleFilter, setLifecycleFilter] = useState<'active' | 'retired' | 'all'>('active');

  const { data: devicesList, isLoading } = useQuery({
    queryKey: ['devices', lifecycleFilter],
    queryFn: () =>
      apiFetch<DeviceRecord[]>(
        `/admin/api/devices${lifecycleFilter !== 'active' ? `?include_retired=true` : ''}`
      ),
    refetchInterval: 15_000,
  });

  const { data: sitesList } = useQuery({
    queryKey: ['sites'],
    queryFn: () => apiFetch<SiteOption[]>('/admin/api/sites'),
  });

  const { data: probesList } = useQuery({
    queryKey: ['probes'],
    queryFn: () => apiFetch<ProbeOption[]>('/admin/api/probes'),
  });

  const filteredDevices = useMemo(() => {
    const raw = devicesList ?? [];
    return raw.filter((d) => {
      if (lifecycleFilter === 'active' && d.retired_at) return false;
      if (lifecycleFilter === 'retired' && !d.retired_at) return false;
      if (!search.trim()) return true;
      const q = search.toLowerCase();
      return (
        d.name.toLowerCase().includes(q) ||
        d.ip_address.toLowerCase().includes(q) ||
        (d.vendor || '').toLowerCase().includes(q) ||
        (d.model || '').toLowerCase().includes(q)
      );
    });
  }, [devicesList, lifecycleFilter, search]);

  // The operator's own role. Two device settings are ADMIN-ONLY on the
  // server (public_visible and api_insecure_tls), so the console has to know
  // the role to show the control at all — and to disable it with a reason
  // rather than hide it.
  const { data: me } = useQuery({
    queryKey: ['me'],
    queryFn: () => apiFetch<MeResponse>('/admin/api/me'),
  });
  const isAdmin = me?.role === 'admin';

  // Tabbed Device Editor Drawer State (replaces the 1,599px #device-modal)
  const [editorOpen, setEditorOpen] = useState(false);
  const [editorTab, setEditorTab] = useState<'general' | 'snmp' | 'credentials' | 'test'>('general');
  const [editingDevice, setEditingDevice] = useState<Partial<DeviceRecord>>({
    name: '',
    ip_address: '',
    vendor: 'generic',
    snmp_version: '2c',
    snmp_port: 161,
    snmp_community: '',
    ssh_poll_enabled: false,
    ssh_port: 22,
    enabled: true,
  });

  // Step-up secret reveal
  const [revealField, setRevealField] = useState<string | null>(null);
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, string>>({});
  const [testResult, setTestResult] = useState<{ success?: boolean; message?: string } | null>(null);

  const openCreateDrawer = () => {
    setEditingDevice({
      name: '',
      ip_address: '',
      vendor: 'generic',
      snmp_version: '2c',
      snmp_port: 161,
      snmp_community: '',
      ssh_poll_enabled: false,
      ssh_port: 22,
      enabled: true,
    });
    setRevealedSecrets({});
    setTestResult(null);
    setEditorTab('general');
    setEditorOpen(true);
  };

  const openEditDrawer = (dev: DeviceRecord) => {
    setEditingDevice({ ...dev });
    setRevealedSecrets({});
    setTestResult(null);
    setEditorTab('general');
    setEditorOpen(true);
  };

  /**
   * The body the server is sent.
   *
   * Two rules the server enforces and the console has to respect:
   *
   * - A secret the operator REVEALED and then edited lives in
   *   `revealedSecrets`, not in `editingDevice`. Without the merge, a
   *   revealed secret was silently dropped on save.
   * - A secret that is still the server's MASK ("********") means "leave it
   *   alone". Sending the mask back is harmless (the server drops it), but
   *   stripping it makes the intent explicit and keeps the mask out of the
   *   request.
   * - `public_visible` and `api_insecure_tls` are ADMIN-ONLY on the server,
   *   and the server gates on the PRESENCE of the key, not on a change
   *   (handlers_devices.go: "if _, has := updates["public_visible"]; has").
   *   The loaded record carries both, so spreading it would make EVERY
   *   device edit by a non-admin fail with a 403 — the control would be
   *   "gated" by breaking the whole save. They are sent only by an admin.
   */
  const buildSaveBody = (): Record<string, unknown> => {
    const body: Record<string, unknown> = { ...editingDevice, ...revealedSecrets };
    for (const field of SECRET_FIELDS) {
      if (body[field] === SECRET_MASK) delete body[field];
    }
    if (!isAdmin) {
      // An admin-only field in the body is rejected outright, and the whole
      // update with it. A non-admin's edit of an ordinary field must not
      // carry them.
      delete body.public_visible;
      delete body.api_insecure_tls;
    }
    return body;
  };

  const saveDeviceMutation = useMutation({
    mutationFn: async () => {
      if (editingDevice.id) {
        return apiFetch(`/admin/api/devices/${editingDevice.id}`, {
          method: 'PUT',
          body: buildSaveBody(),
        });
      }
      return apiFetch('/admin/api/devices', {
        method: 'POST',
        body: buildSaveBody(),
      });
    },
    onSuccess: () => {
      toast({
        title: editingDevice.id ? 'Device updated' : 'Device created',
        variant: 'success',
      });
      setEditorOpen(false);
      queryClient.invalidateQueries({ queryKey: ['devices'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to save device', description: err.message, variant: 'error' });
    },
  });

  const testConnectionMutation = useMutation({
    mutationFn: async () => {
      // The list/detail read paths mask snmp_community as "********", so testing
      // an existing device without revealing it dialed the literal mask and
      // always failed. Prefer the revealed value when the operator has it.
      const body = { ...editingDevice, ...revealedSecrets };
      if (body.snmp_community === '********') {
        throw new Error('Reveal the stored SNMP community first — testing with the mask always fails.');
      }
      return apiFetch<{ success: boolean; message: string }>('/admin/api/devices/test', {
        method: 'POST',
        body,
      });
    },
    onSuccess: (res) => {
      setTestResult(res);
      if (res?.success) {
        toast({ title: 'SNMP connection verified', description: res.message, variant: 'success' });
      } else {
        toast({ title: 'Connection test failed', description: res?.message, variant: 'error' });
      }
    },
    onError: (err: Error) => {
      setTestResult({ success: false, message: err.message });
    },
  });

  const columns = useMemo<ColumnDef<DeviceRecord, unknown>[]>(
    () => [
      {
        accessorKey: 'name',
        header: 'Firewall / Device',
        cell: ({ row }) => (
          <div>
            <div className="flex items-center gap-2">
              {/*
                The pulsing status dot. V1's device list had one
                (cmd/api/static/js/admin-main.js:533) and V2 had a flat dot
                that never moved.
                */}
              <StatusDot
                state={
                  row.original.retired_at
                    ? 'muted'
                    : row.original.status === 'online'
                      ? 'online'
                      : 'offline'
                }
                label={row.original.retired_at ? 'retired' : row.original.status || 'unknown'}
              />
              <span className="font-semibold text-text">{row.original.name}</span>
              {row.original.retired_at && (
                <span className="rounded bg-bg-panel px-1.5 py-0.5 text-[10px] uppercase text-text-faint">
                  Retired
                </span>
              )}
            </div>
            <div className="text-[11px] font-mono text-text-dim pl-4">
              {row.original.ip_address} {row.original.vendor ? `• ${row.original.vendor}` : ''}
            </div>
          </div>
        ),
      },
      {
        accessorKey: 'last_polled',
        header: 'Last Polled',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {formatRelativeTime(row.original.last_polled)}
          </span>
        ),
      },
      {
        accessorKey: 'public_visible',
        header: 'Public',
        cell: ({ row }) => {
          // The public dashboard is UNAUTHENTICATED, and the column defaults
          // to TRUE. A device that is published has to be visible as such in
          // the list, or "where did that device go from the public board?"
          // has no answer.
          if (row.original.retired_at) {
            return <span className="text-[10px] uppercase text-text-faint">Retired</span>;
          }
          const published = row.original.public_visible !== false;
          return (
            <span
              className={cn(
                'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
                published ? 'bg-sig-warn/15 text-sig-warn' : 'bg-bg-panel text-text-faint',
              )}
              title={
                published
                  ? 'Published on the unauthenticated public dashboard'
                  : 'Not published on the public dashboard'
              }
            >
              {published ? 'Public' : 'Private'}
            </span>
          );
        },
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
            <button
              type="button"
              onClick={() => navigate(`/devices/${row.original.id}`)}
              className="rounded border border-border bg-bg-panel px-2.5 py-1 text-xs font-medium text-text hover:bg-bg-hover"
            >
              Inspect
            </button>
            <button
              type="button"
              onClick={() => openEditDrawer(row.original)}
              className="rounded border border-border bg-bg-panel p-1.5 text-text-dim hover:text-text"
              title="Edit device"
            >
              <Edit3 className="h-3.5 w-3.5" />
            </button>
          </div>
        ),
      },
    ],
    [navigate]
  );

  const drawerTabs: DrawerTab[] = [
    { id: 'general', label: 'General & Site' },
    { id: 'snmp', label: 'SNMP Polling' },
    { id: 'credentials', label: 'SSH & API Keys' },
    { id: 'test', label: 'Test Connection' },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <Server className="h-3.5 w-3.5" />
            Infrastructure / Firewalls & Devices
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            Firewall & Network Device Fleet ({filteredDevices.length})
          </h1>
          <p className="text-xs text-text-dim mt-0.5">
            Click any device row to open the inline 7-tab telemetry, interface, VPN, and configuration diff workspace.
          </p>
        </div>

        <button
          type="button"
          onClick={openCreateDrawer}
          className="flex items-center gap-1.5 rounded-md bg-accent px-3.5 py-2 text-xs font-semibold text-on-accent hover:opacity-90 self-start"
        >
          <Plus className="h-4 w-4" />
          Add Firewall / Device
        </button>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="h-3.5 w-3.5 text-text-faint absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by hostname, IP, vendor, or model..."
            className="w-full rounded-md border border-border bg-bg-card pl-8 pr-3 py-1.5 text-xs text-text focus:border-accent focus:outline-hidden"
          />
        </div>

        <div className="flex items-center gap-1 rounded-lg bg-bg-panel p-1 border border-border self-start">
          {(['active', 'retired', 'all'] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => setLifecycleFilter(mode)}
              className={cn(
                'rounded-md px-3 py-1 text-xs font-medium capitalize transition-colors',
                lifecycleFilter === mode
                  ? 'bg-bg-card text-text shadow-xs border border-border'
                  : 'text-text-dim hover:text-text'
              )}
            >
              {mode}
            </button>
          ))}
        </div>
      </div>

      <PurgeJobsPanel isAdmin={isAdmin} />

      <ResponsiveDataView
        data={filteredDevices}
        columns={columns}
        isLoading={isLoading}
        onRowClick={(dev) => navigate(`/devices/${dev.id}`)}
        emptyTitle="No matching firewall devices."
        renderMobileCard={(dev) => (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span
                  className={cn(
                    'h-2.5 w-2.5 rounded-full',
                    dev.status === 'online' ? 'bg-sig-ok' : 'bg-sig-crit'
                  )}
                />
                <span className="font-semibold text-sm text-text">{dev.name}</span>
              </div>
              <span className="font-mono text-xs text-text-dim">{dev.ip_address}</span>
            </div>
            <div className="flex items-center justify-between text-xs text-text-dim">
              <span>
                {dev.vendor || 'generic'}
                {dev.retired_at ? ' • retired' : dev.status ? ` • ${dev.status}` : ''}
              </span>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  openEditDrawer(dev);
                }}
                className="rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text"
              >
                Edit
              </button>
            </div>
          </div>
        )}
      />

      {/* Tabbed Slide-Over Drawer (replaces the 1,599px #device-modal) */}
      <SlideOverDrawer
        open={editorOpen}
        onOpenChange={setEditorOpen}
        title={editingDevice.id ? `Edit Device: ${editingDevice.name}` : 'Add Firewall / Device'}
        subtitle="Tabbed device configuration with encrypted credential management."
        size="xl"
        tabs={drawerTabs}
        activeTab={editorTab}
        onTabChange={(id) => setEditorTab(id as typeof editorTab)}
        footer={
          <div className="flex items-center justify-between w-full">
            <button
              type="button"
              onClick={() => testConnectionMutation.mutate()}
              disabled={testConnectionMutation.isPending}
              className="flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:bg-bg-hover"
            >
              <Play className="h-3.5 w-3.5 text-accent" />
              {testConnectionMutation.isPending ? 'Testing…' : 'Test SNMP'}
            </button>
            <div className="flex items-center gap-2">
              <Button  variant="secondary"
                type="button"
                onClick={() => setEditorOpen(false)}
                
              >
                Cancel
              </Button>
              <Button  className="px-4"
                type="button"
                disabled={!editingDevice.name || !editingDevice.ip_address || saveDeviceMutation.isPending}
                onClick={() => saveDeviceMutation.mutate()}
                
              >
                {saveDeviceMutation.isPending ? 'Saving…' : 'Save Device'}
              </Button>
            </div>
          </div>
        }
      >
        {editorTab === 'general' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <Field label="Device Name / Hostname">
                  <Input
                    type="text"
                    value={editingDevice.name ?? ''}
                    onChange={(e) => setEditingDevice((p) => ({ ...p, name: e.target.value }))}
                    placeholder="fw-dc1-edge01"
                   
                  />
                </Field>
              </div>
              <div>
                <Field label="Management IP Address">
                  <Input mono
                    type="text"
                    value={editingDevice.ip_address ?? ''}
                    onChange={(e) => setEditingDevice((p) => ({ ...prevIp(p, e.target.value) }))}
                    placeholder="10.0.1.1"
                   
                  />
                </Field>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <Field label="Vendor Profile">
                  <Select
                    value={editingDevice.vendor ?? 'generic'}
                    onChange={(e) => setEditingDevice((p) => ({ ...p, vendor: e.target.value }))}
                   
                  >
                    <option value="generic">Generic / Auto-Detect (RFC1213)</option>
                    <option value="fortigate">Fortinet FortiGate</option>
                    <option value="paloalto">Palo Alto PAN-OS</option>
                    <option value="cisco_asa">Cisco ASA / Firepower</option>
                    <option value="pfsense">pfSense</option>
                    <option value="opnsense">OPNsense</option>
                    <option value="vyos">VyOS</option>
                    <option value="juniper_srx">Juniper SRX</option>
                    <option value="sonicwall">SonicWall</option>
                    <option value="checkpoint">Check Point</option>
                  </Select>
                </Field>
              </div>
              <div>
                <Field label="Site Assignment">
                  <Select
                    value={editingDevice.site_id ?? ''}
                    onChange={(e) =>
                      setEditingDevice((p) => ({
                        ...p,
                        site_id: e.target.value ? Number(e.target.value) : null,
                      }))
                    }
                   
                  >
                    <option value="">Unassigned (Global)</option>
                    {(sitesList ?? []).map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name}
                      </option>
                    ))}
                  </Select>
                </Field>
              </div>
              <div>
                <Field label="Collector Probe">
                  <Select
                    value={editingDevice.probe_id ?? ''}
                    onChange={(e) =>
                      setEditingDevice((p) => ({
                        ...p,
                        probe_id: e.target.value ? Number(e.target.value) : null,
                      }))
                    }
                   
                  >
                    <option value="">Direct (Primary Server)</option>
                    {(probesList ?? []).map((pr) => (
                      <option key={pr.id} value={pr.id}>
                        {pr.name}
                      </option>
                    ))}
                  </Select>
                </Field>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <Field label="Location">
                  <Input
                    type="text"
                    value={editingDevice.location ?? ''}
                    onChange={(e) => setEditingDevice((p) => ({ ...p, location: e.target.value }))}
                    placeholder="e.g. DC1 Rack 12"
                   
                  />
                </Field>
              </div>
            </div>

            {/*
              The public-dashboard visibility. The column DEFAULTS TO TRUE, so
              a device is published to the unauthenticated public dashboard
              unless an operator says otherwise - and until the console had a
              control for it, there was no way to say otherwise at all.
              Admin only on the server.
            */}
            <label
              className={cn(
                'flex items-start gap-2 text-xs',
                isAdmin ? 'text-text' : 'text-text-faint',
              )}
            >
              <input
                type="checkbox"
                checked={editingDevice.public_visible !== false}
                disabled={!isAdmin}
                onChange={(e) =>
                  setEditingDevice((p) => ({ ...p, public_visible: e.target.checked }))
                }
                className="mt-0.5 h-4 w-4 rounded accent-accent"
              />
              <span>
                Show on the public dashboard
                <span className="block text-[10px] text-text-faint">
                  The public dashboard is UNAUTHENTICATED. The device is published
                  unless this is cleared.
                  {!isAdmin ? ' Admin only.' : ''}
                </span>
              </span>
            </label>

            <label className="flex items-center gap-2 text-xs text-text pt-2">
              <input
                type="checkbox"
                checked={editingDevice.enabled !== false}
                onChange={(e) => setEditingDevice((p) => ({ ...p, enabled: e.target.checked }))}
                className="h-4 w-4 rounded accent-accent"
              />
              Enable active SNMP & telemetry polling for this device
            </label>
          </div>
        )}

        {editorTab === 'snmp' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <Field label="SNMP Version">
                  <Select
                    value={editingDevice.snmp_version ?? '2c'}
                    onChange={(e) => setEditingDevice((p) => ({ ...p, snmp_version: e.target.value }))}
                   
                  >
                    <option value="2c">SNMP v2c</option>
                    <option value="3">SNMP v3 (AuthPriv)</option>
                  </Select>
                </Field>
              </div>
              <div>
                <Field label="SNMP UDP Port">
                  <Input mono
                    type="number"
                    value={editingDevice.snmp_port ?? 161}
                    onChange={(e) => setEditingDevice((p) => ({ ...p, snmp_port: Number(e.target.value) }))}
                   
                  />
                </Field>
              </div>
            </div>

            {editingDevice.snmp_version !== '3' && editingDevice.snmp_version !== 'v3' ? (
              <div>
                <Field label="SNMP v2c Community String">
                  <div className="flex items-center gap-2">
                    <input
                      type={revealedSecrets.snmp_community ? 'text' : 'password'}
                      value={revealedSecrets.snmp_community ?? editingDevice.snmp_community ?? ''}
                      onChange={(e) =>
                        setEditingDevice((p) => ({ ...p, snmp_community: e.target.value }))
                      }
                      placeholder="Leave ******** to keep existing community"
                      className="flex-1 rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
                    />
                    {editingDevice.id && (
                      <button
                        type="button"
                        onClick={() => setRevealField('snmp_community')}
                        disabled={!isAdmin}
                        title={
                          isAdmin
                            ? 'Reveal the stored value (requires admin password verification)'
                            : 'Admin only — revealing a stored credential is an admin action'
                        }
                        className="flex items-center gap-1 rounded border border-border bg-bg-panel px-2.5 py-2 text-xs text-text-dim hover:text-text disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <Eye className="h-3.5 w-3.5" /> Reveal
                      </button>
                    )}
                  </div>
                </Field>
              </div>
            ) : (
              <div className="space-y-3">
                <div>
                  <Field label="SNMPv3 Username">
                    <Input mono
                      type="text"
                      value={editingDevice.snmpv3_username ?? ''}
                      onChange={(e) =>
                        setEditingDevice((p) => ({ ...p, snmpv3_username: e.target.value }))
                      }
                     
                    />
                  </Field>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <DeviceSecretField
                    label="Auth Password"
                    field="snmpv3_auth_pass"
                    editingDevice={editingDevice}
                    revealedSecrets={revealedSecrets}
                    onChange={(v) =>
                      setEditingDevice((p) => ({ ...p, snmpv3_auth_pass: v }))
                    }
                    onReveal={setRevealField}
                    canReveal={isAdmin}
                    hint="Required for SNMPv3 with an auth protocol."
                  />
                  <DeviceSecretField
                    label="Priv Password"
                    field="snmpv3_priv_pass"
                    editingDevice={editingDevice}
                    revealedSecrets={revealedSecrets}
                    onChange={(v) =>
                      setEditingDevice((p) => ({ ...p, snmpv3_priv_pass: v }))
                    }
                    onReveal={setRevealField}
                    canReveal={isAdmin}
                    hint="Required for SNMPv3 with a privacy protocol."
                  />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <Field label="Auth Protocol">
                      <Select
                        value={editingDevice.snmpv3_auth_type ?? 'SHA'}
                        onChange={(e) =>
                          setEditingDevice((p) => ({ ...p, snmpv3_auth_type: e.target.value }))
                        }
                       
                      >
                        <option value="SHA">SHA-1</option>
                        <option value="SHA256">SHA-256</option>
                        <option value="MD5">MD5</option>
                      </Select>
                    </Field>
                  </div>
                  <div>
                    <Field label="Priv Protocol">
                      <Select
                        value={editingDevice.snmpv3_priv_type ?? 'AES'}
                        onChange={(e) =>
                          setEditingDevice((p) => ({ ...p, snmpv3_priv_type: e.target.value }))
                        }
                       
                      >
                        <option value="AES">AES-128</option>
                        <option value="AES256">AES-256</option>
                        <option value="DES">DES</option>
                      </Select>
                    </Field>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {editorTab === 'credentials' && (
          <div className="space-y-4">
            <label className="flex items-center gap-2 text-xs text-text">
              <input
                type="checkbox"
                checked={Boolean(editingDevice.ssh_poll_enabled)}
                onChange={(e) => setEditingDevice((p) => ({ ...p, ssh_poll_enabled: e.target.checked }))}
                className="h-4 w-4 rounded accent-accent"
              />
              Enable SSH / REST API Configuration Backup & IPSec Provisioning
            </label>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <Field label="SSH Username">
                  <Input mono
                    type="text"
                    value={editingDevice.ssh_username ?? ''}
                    onChange={(e) => setEditingDevice((p) => ({ ...p, ssh_username: e.target.value }))}
                   
                  />
                </Field>
              </div>
              <div>
                <Field label="SSH Port">
                  <Input mono
                    type="number"
                    value={editingDevice.ssh_port ?? 22}
                    onChange={(e) => setEditingDevice((p) => ({ ...p, ssh_port: Number(e.target.value) }))}
                   
                  />
                </Field>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <DeviceSecretField
                label="SSH Password"
                field="ssh_password"
                editingDevice={editingDevice}
                revealedSecrets={revealedSecrets}
                onChange={(v) => setEditingDevice((p) => ({ ...p, ssh_password: v }))}
                onReveal={setRevealField}
                canReveal={isAdmin}
                hint="Used for the configuration backup and the IPSec provisioning path."
              />
              <div>
                <Field label="SSH Poll Interval (seconds)">
                  <Input mono
                    type="number"
                    min={0}
                    value={editingDevice.ssh_poll_interval ?? 900}
                    onChange={(e) =>
                      setEditingDevice((p) => ({ ...p, ssh_poll_interval: Number(e.target.value) }))
                    }
                   
                  />
                </Field>
                <p className="mt-1 text-[10px] text-text-faint">
                  0 disables the interval. The server default is 900.
                </p>
              </div>
            </div>

            <div className="border-t border-border pt-4 space-y-4">
              <div>
                <h3 className="text-xs font-semibold text-text">REST API</h3>
                <p className="text-[11px] text-text-faint">
                  The API token is what the IPSec provisioning and configuration
                  backup paths authenticate with. Without it a device can be
                  monitored but never configured.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <Field label="API Port">
                    <Input mono
                      type="number"
                      value={editingDevice.api_port ?? 443}
                      onChange={(e) => setEditingDevice((p) => ({ ...p, api_port: Number(e.target.value) }))}
                     
                    />
                  </Field>
                </div>
                <DeviceSecretField
                  label="API Token"
                  field="api_token"
                  editingDevice={editingDevice}
                  revealedSecrets={revealedSecrets}
                  onChange={(v) => setEditingDevice((p) => ({ ...p, api_token: v }))}
                  onReveal={setRevealField}
                  canReveal={isAdmin}
                  hint={
                    editingDevice.vendor === 'opnsense'
                      ? 'OPNsense stores a key and a secret in this ONE field, separated by a colon. Enter them as "key:secret".'
                      : undefined
                  }
                />
              </div>

              <label
                className={cn(
                  'flex items-start gap-2 text-xs',
                  isAdmin ? 'text-text' : 'text-text-faint',
                )}
              >
                <input
                  type="checkbox"
                  checked={Boolean(editingDevice.api_insecure_tls)}
                  disabled={!isAdmin}
                  onChange={(e) =>
                    setEditingDevice((p) => ({ ...p, api_insecure_tls: e.target.checked }))
                  }
                  className="mt-0.5 h-4 w-4 rounded accent-accent"
                />
                <span>
                  Allow a self-signed TLS certificate
                  {!isAdmin ? (
                    <span className="block text-[10px] text-text-faint">
                      Admin only.
                    </span>
                  ) : null}
                </span>
              </label>
            </div>
          </div>
        )}

        {editorTab === 'test' && (
          <div className="space-y-4">
            <p className="text-xs text-text-dim">
              Verify SNMP reachability and system OID response before saving changes.
            </p>
            <button
              type="button"
              onClick={() => testConnectionMutation.mutate()}
              disabled={testConnectionMutation.isPending}
              className="flex items-center gap-2 rounded-md bg-accent px-4 py-2 text-xs font-semibold text-on-accent hover:opacity-90"
            >
              <Play className="h-3.5 w-3.5" />
              {testConnectionMutation.isPending ? 'Dialing device…' : 'Run Live SNMP Check'}
            </button>
            {testResult && (
              <div
                className={cn(
                  'rounded-lg border p-3 text-xs flex items-start gap-2',
                  testResult.success
                    ? 'border-sig-ok/40 bg-sig-ok/10 text-sig-ok'
                    : 'border-sig-crit/40 bg-sig-crit/10 text-sig-crit'
                )}
              >
                {testResult.success ? (
                  <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" />
                ) : (
                  <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                )}
                <div>{testResult.message}</div>
              </div>
            )}
          </div>
        )}
      </SlideOverDrawer>

      {/* Step-Up Auth for Secret Reveal */}
      <StepUpAuthDialog
        open={Boolean(revealField)}
        onOpenChange={(open) => {
          if (!open) setRevealField(null);
        }}
        title="Reveal Stored Device Credential"
        description="Decrypting a stored device credential requires admin password verification and is recorded in the audit log."
        confirmLabel="Decrypt & Reveal"
        onConfirm={async ({ password, totp_code }) => {
          if (!editingDevice.id || !revealField) return;
          const res = await apiFetch<{ secret: string }>(
            `/admin/api/devices/${editingDevice.id}/reveal-secret`,
            {
              method: 'POST',
              body: { field: revealField, password, totp_code },
            }
          );
          if (res?.secret) {
            setRevealedSecrets((prev) => ({ ...prev, [revealField]: res.secret }));
          }
          setRevealField(null);
        }}
      />
    </div>
  );
}

/**
 * The purge jobs across the fleet.
 *
 * A purge runs in the BACKGROUND, so the job outlives the dialog that
 * started it. Without a list the operator had no way to see that a purge was
 * running, how far it had got, or that one had failed.
 */
function PurgeJobsPanel({ isAdmin }: { isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: jobs } = useQuery({
    queryKey: ['purge-jobs'],
    queryFn: () => apiFetch<PurgeJob[]>('/admin/api/purge-jobs'),
    refetchInterval: 10_000,
    // The purge endpoints are admin-only END TO END, the read-only job list
    // included. Firing them as an operator would be a 403 on every page
    // load, which is noise in the console and a false alarm.
    enabled: isAdmin,
  });

  const cancelMutation = useMutation({
    mutationFn: async (id: number) => apiFetch(`/admin/api/devices/${id}/purge/cancel`, { method: 'POST' }),
    onSuccess: () => {
      toast({ title: 'Purge cancellation requested', variant: 'info' });
      queryClient.invalidateQueries({ queryKey: ['purge-jobs'] });
    },
    onError: (err: Error) =>
      toast({ title: 'Could not cancel the purge', description: err.message, variant: 'error' }),
  });

  const rows = (jobs ?? []).filter((job) => job.status === 'pending' || job.status === 'running');
  if (rows.length === 0) return null;

  return (
    <div className="rounded-xl border border-sig-warn/40 bg-sig-warn/5 p-4">
      <h3 className="text-xs font-semibold text-sig-warn">
        {rows.length} purge job{rows.length === 1 ? '' : 's'} running
      </h3>
      <ul className="mt-2 space-y-1.5">
        {rows.map((job) => (
          <li key={job.id} className="flex flex-wrap items-center gap-2 text-[11px] text-text-dim">
            <span className="font-mono text-text">
              {job.device_name || `device ${job.device_id}`}
            </span>
            <span>
              {job.rows_deleted.toLocaleString()} row(s) · {job.tables_done}/{job.tables_total}{' '}
              table(s)
              {job.current_table ? ` · ${job.current_table}` : ''}
            </span>
            <button
              type="button"
              onClick={() => cancelMutation.mutate(job.device_id)}
              disabled={cancelMutation.isPending}
              className="rounded border border-sig-crit/40 bg-sig-crit/10 px-2 py-0.5 text-[10px] font-medium text-sig-crit disabled:opacity-50"
            >
              Cancel
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * The purge job for one device, with a cancel.
 *
 * A purge runs in the BACKGROUND: the POST only enqueues it, and the worker
 * deletes the rows table by table. Without this the operator had no way to
 * see that a purge was running, how far it had got, or to stop it.
 */
function PurgeJobPanel({ deviceId, isAdmin }: { deviceId: number; isAdmin: boolean }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: job } = useQuery({
    queryKey: ['device-purge-job', deviceId],
    queryFn: () => apiFetch<PurgeJob>(`/admin/api/devices/${deviceId}/purge`),
    retry: false,
    // Admin-only, like the rest of the purge surface.
    enabled: isAdmin,
    // Only while it is actually running; a finished job does not need a poll.
    refetchInterval: (query) => {
      const status = (query.state.data as PurgeJob | undefined)?.status;
      return status === 'pending' || status === 'running' ? 3000 : false;
    },
  });

  const cancelMutation = useMutation({
    mutationFn: async () => apiFetch(`/admin/api/devices/${deviceId}/purge/cancel`, { method: 'POST' }),
    onSuccess: () => {
      toast({ title: 'Purge cancellation requested', variant: 'info' });
      queryClient.invalidateQueries({ queryKey: ['device-purge-job', deviceId] });
    },
    onError: (err: Error) =>
      toast({ title: 'Could not cancel the purge', description: err.message, variant: 'error' }),
  });

  if (!job) return null;

  const running = job.status === 'pending' || job.status === 'running';
  return (
    <div className="rounded-xl border border-border bg-bg-card p-4 space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-xs font-semibold text-text">Purge job #{job.id}</h3>
        <span
          className={cn(
            'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
            running
              ? 'bg-sig-warn/15 text-sig-warn'
              : job.status === 'done'
                ? 'bg-sig-ok/15 text-sig-ok'
                : 'bg-sig-crit/15 text-sig-crit',
          )}
        >
          {job.status}
        </span>
      </div>
      <div className="text-[11px] text-text-dim">
        {job.rows_deleted.toLocaleString()} row(s) deleted · {job.tables_done}/
        {job.tables_total} table(s)
        {job.current_table ? ` · on ${job.current_table}` : ''}
      </div>
      <div className="text-[10px] text-text-faint">
        Requested by {job.requested_by || 'unknown'}
      </div>
      {job.error ? <div className="text-[11px] text-sig-crit">{job.error}</div> : null}
      {running ? (
        <button
          type="button"
          onClick={() => cancelMutation.mutate()}
          disabled={cancelMutation.isPending}
          className="rounded-md border border-sig-crit/40 bg-sig-crit/10 px-2.5 py-1 text-[11px] font-medium text-sig-crit disabled:opacity-50"
        >
          Cancel the purge
        </button>
      ) : null}
    </div>
  );
}

function prevIp(p: Partial<DeviceRecord>, ip: string): Partial<DeviceRecord> {
  return { ...p, ip_address: ip };
}

/**
 * One credential field: a masked input, a reveal button, and the rule that a
 * stored secret is never sent back.
 *
 * The server masks a stored secret as "********" and treats a masked or empty
 * value on write as "leave it unchanged", so the field shows the mask and the
 * operator types over it to replace it.
 */
function DeviceSecretField({
  label,
  field,
  editingDevice,
  revealedSecrets,
  onChange,
  onReveal,
  canReveal,
  hint,
  placeholder,
}: {
  label: string;
  field: string;
  editingDevice: Partial<DeviceRecord>;
  revealedSecrets: Record<string, string>;
  onChange: (value: string) => void;
  onReveal: (field: string) => void;
  /** False for an operator: revealing a stored credential is admin-only. */
  canReveal: boolean;
  hint?: string;
  placeholder?: string;
}) {
  const revealed = revealedSecrets[field];
  const stored = (editingDevice as Record<string, unknown>)[field];
  const masked = !revealed && stored === SECRET_MASK;
  return (
    <div>
      <Field label={label}>
        <div className="flex items-center gap-2">
          <input
            type={revealed ? 'text' : 'password'}
            value={revealed ?? (typeof stored === 'string' ? stored : '')}
            onChange={(e) => onChange(e.target.value)}
            placeholder={placeholder ?? (masked ? 'Unchanged' : '')}
            autoComplete="new-password"
            className="flex-1 rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
          />
          {editingDevice.id && (
            <button
              type="button"
              onClick={() => onReveal(field)}
              disabled={!canReveal}
              title={
                canReveal
                  ? 'Reveal the stored value (requires admin password verification)'
                  : 'Admin only — revealing a stored credential is an admin action'
              }
              className="flex items-center gap-1 rounded border border-border bg-bg-panel px-2.5 py-2 text-xs text-text-dim hover:text-text disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Eye className="h-3.5 w-3.5" /> Reveal
            </button>
          )}
        </div>
      </Field>
      {hint ? <p className="mt-1 text-[10px] text-text-faint">{hint}</p> : null}
    </div>
  );
}

// ============================================================================
// INLINE 7-TAB DEVICE DETAIL VIEW (/admin/v2/devices/:id)
// ============================================================================
type DetailTab =
  | 'interfaces'
  | 'vpn'
  | 'resources'
  | 'security'
  | 'diagnostics'
  | 'config'
  | 'lifecycle';

function DeviceDetailView({ deviceId }: { deviceId: number }) {
  const navigate = useNavigate();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<DetailTab>('interfaces');
  const [purgeDialogOpen, setPurgeDialogOpen] = useState(false);
  const [alertConfigOpen, setAlertConfigOpen] = useState(false);

  const { data: detail, isLoading } = useQuery({
    queryKey: ['device-detail', deviceId],
    queryFn: () => apiFetch<Record<string, any>>(`/admin/api/devices/${deviceId}/detail`),
    refetchInterval: 15_000,
  });

  // The operator's own account. The purge needs the TOTP code when the
  // account has 2FA, so the dialog has to know whether to ask for it.
  const { data: me } = useQuery({
    queryKey: ['me'],
    queryFn: () => apiFetch<MeResponse>('/admin/api/me'),
  });
  const isAdmin = me?.role === 'admin';

  // GetDeviceConfigHistory wraps the rows: {revisions, total_all, ...}. Typing
  // this as an array made `.map` throw and (before the ErrorBoundary) blanked
  // the whole console when the Config tab opened.
  const { data: configHistory } = useQuery({
    queryKey: ['device-config-history', deviceId],
    queryFn: () =>
      apiFetch<{
        revisions?: RevisionMeta[];
        total_all?: number;
      }>(`/admin/api/devices/${deviceId}/config-history`),
    enabled: activeTab === 'config',
  });
  const configRevs = configHistory?.revisions ?? [];
  const [revisionToView, setRevisionToView] = useState<number | null>(null);
  const {
    data: revisionData,
    isLoading: revisionLoading,
    error: revisionError,
  } = useQuery({
    queryKey: ['device-config-revision', deviceId, revisionToView],
    queryFn: () =>
      apiFetch<{
        revision?: { id: number; timestamp: string; checksum: string; config_text: string; length: number };
      }>(`/admin/api/devices/${deviceId}/config-history/${revisionToView}/view`),
    enabled: revisionToView != null,
  });
  const viewedRevision = revisionData?.revision;
  const [diffFrom, setDiffFrom] = useState<number | null>(null);
  const [diffTo, setDiffTo] = useState<number | null>(null);
  const [diffOpen, setDiffOpen] = useState(false);
  const [revisionToDelete, setRevisionToDelete] = useState<number | null>(null);
  const deleteRevisionMutation = useMutation({
    mutationFn: async (revId: number) =>
      apiFetch(`/admin/api/devices/${deviceId}/config-history/${revId}`, { method: 'DELETE' }),
    onSuccess: (_data, revId) => {
      toast({ title: `Revision #${revId} deleted`, variant: 'info' });
      setRevisionToDelete(null);
      if (revisionToView === revId) setRevisionToView(null);
      queryClient.invalidateQueries({ queryKey: ['device-config-history', deviceId] });
    },
    onError: (err: Error) =>
      toast({ title: 'Delete failed', description: err.message, variant: 'error' }),
  });

  const selectedFrom = configRevs.find((r) => r.id === diffFrom) ?? null;
  const selectedTo = configRevs.find((r) => r.id === diffTo) ?? null;

  const { data: capabilities, isLoading: capabilitiesLoading } = useQuery({
    queryKey: ['device-capabilities', deviceId],
    queryFn: () => apiFetch<DeviceCapabilities>(`/admin/api/devices/${deviceId}/capabilities`),
    enabled: activeTab === 'security',
  });

  const retireMutation = useMutation({
    mutationFn: async (action: 'retire' | 'restore') =>
      apiFetch(`/admin/api/devices/${deviceId}/${action}`, { method: 'POST' }),
    onSuccess: () => {
      toast({ title: 'Device lifecycle updated', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['device-detail', deviceId] });
      queryClient.invalidateQueries({ queryKey: ['devices'] });
    },
    onError: (err: Error) => {
      toast({
        title: 'Could not update the device lifecycle',
        description: err.message,
        variant: 'error',
      });
    },
  });

  const device: DeviceRecord | undefined = detail?.device;
  const interfaces: any[] = detail?.interfaces ?? [];
  const vpns: any[] = detail?.vpn_status ?? detail?.vpn_statuses ?? detail?.vpns ?? [];
  const sensors: any[] = detail?.hardware_sensors ?? [];
  const processorStats: any[] = detail?.processor_stats ?? [];
  const disks: any[] = detail?.disk_usage ?? [];
  const loadAverage: any = detail?.load_average ?? null;
  const recentAlerts: any[] = detail?.recent_alerts ?? [];
  const pingStats: any[] = detail?.ping_stats ?? [];
  const haStatus: any[] = detail?.ha_status ?? [];
  const securityStats: any = detail?.security_stats ?? null;
  const sdwanHealth: any[] = detail?.sdwan_health ?? [];
  const licenceInfo: any[] = detail?.license_info ?? [];
  const cpuUsage = detail?.system_status?.cpu_usage ?? device?.cpu_usage ?? 0;
  const memoryUsage = detail?.system_status?.memory_usage ?? device?.memory_usage ?? 0;

  const [chartRange, setChartRange] = useState<string>('24h');
  const [expandedIface, setExpandedIface] = useState<number | null>(null);
  const [expandedTunnel, setExpandedTunnel] = useState<string | null>(null);

  const { data: statusHistory, isLoading: statusLoading } = useQuery({
    queryKey: ['device-status-history', deviceId, chartRange],
    queryFn: () =>
      apiFetch<{ buckets?: any[] }>(
        `/admin/api/devices/${deviceId}/status-history?range=${chartRange}`,
      ),
    enabled: Boolean(deviceId) && activeTab === 'resources',
  });
  const buckets = statusHistory?.buckets ?? [];

  const chartSeries = useMemo(() => {
    const pct = (key: string) => buckets.map((b: any) => numOrNull(b[key]));
    return {
      timestamps: buckets.map((b: any) => Number(b.bucket_ms) || 0),
      overview: [
        { label: 'CPU', color: 'var(--fwmon-series-1)', values: pct('cpu_usage') },
        { label: 'Memory', color: 'var(--fwmon-series-5)', values: pct('memory_usage') },
        { label: 'Disk', color: 'var(--fwmon-series-4)', values: pct('disk_usage') },
      ] as ChartSeries[],
      // network_*_kbps is kilobits/s; the chart works in bits/s.
      network: [
        {
          label: 'In',
          color: 'var(--fwmon-series-1)',
          values: buckets.map((b: any) => {
            const v = numOrNull(b.network_in_kbps);
            return v == null ? null : v * 1000;
          }),
        },
        {
          label: 'Out',
          color: 'var(--fwmon-series-3)',
          values: buckets.map((b: any) => {
            const v = numOrNull(b.network_out_kbps);
            return v == null ? null : v * 1000;
          }),
        },
      ] as ChartSeries[],
      cpu: [
        { label: 'User', color: 'var(--fwmon-series-1)', values: pct('cpu_user') },
        { label: 'System', color: 'var(--fwmon-series-2)', values: pct('cpu_system') },
        { label: 'Nice', color: 'var(--fwmon-series-3)', values: pct('cpu_nice') },
        { label: 'IOWait', color: 'var(--fwmon-series-5)', values: pct('cpu_iowait') },
        { label: 'IRQ', color: 'var(--fwmon-series-6)', values: pct('cpu_irq') },
        { label: 'SoftIRQ', color: 'var(--fwmon-series-8)', values: pct('cpu_softirq') },
        { label: 'Idle', color: 'var(--fwmon-text-faint)', values: pct('cpu_idle') },
      ] as ChartSeries[],
    };
  }, [buckets]);

  const { data: ifaceChart, isLoading: ifaceLoading } = useQuery({
    queryKey: ['iface-chart', deviceId, expandedIface, chartRange],
    queryFn: async () => {
      const base = `/admin/api/devices/${deviceId}/interfaces/${expandedIface}`;
      const [sflow, snmp] = await Promise.all([
        apiFetch<any[]>(`${base}/sflow-chart?range=${chartRange}`).catch(() => []),
        apiFetch<any[]>(`${base}/chart?range=${chartRange}`).catch(() => []),
      ]);
      // Same freshness rule as the classic console: sFlow wins only when it is
      // at least as current as SNMP, so a stopped exporter cannot hide live
      // SNMP-measured traffic.
      const lastMs = (rows: any[]) =>
        rows && rows.length ? Number(rows[rows.length - 1]?.bucket_ms) || 0 : 0;
      const sflowOk = (sflow?.length ?? 0) >= 2;
      const snmpOk = (snmp?.length ?? 0) >= 2;
      if (sflowOk && (!snmpOk || lastMs(sflow) >= lastMs(snmp))) {
        return { rows: sflow, source: 'sFlow' };
      }
      if (snmpOk) return { rows: snmp, source: 'SNMP' };
      return { rows: [], source: '' };
    },
    enabled: Boolean(deviceId) && activeTab === 'interfaces' && expandedIface != null,
  });

  const ifaceSeries = useMemo(() => {
    const rows = ifaceChart?.rows ?? [];
    const ts = rows.map((r: any) => Number(r.bucket_ms) || 0);
    // Interface rows are cumulative counters; per-interval deltas (not a single
    // median span) are what the classic console plots.
    return {
      timestamps: ts,
      series: [
        {
          label: 'In',
          color: 'var(--fwmon-series-1)',
          values: counterDeltasToBps(
            rows.map((r: any) => numOrNull(r.in_bytes)),
            ts,
          ),
        },
        {
          label: 'Out',
          color: 'var(--fwmon-series-3)',
          values: counterDeltasToBps(
            rows.map((r: any) => numOrNull(r.out_bytes)),
            ts,
          ),
        },
      ] as ChartSeries[],
    };
  }, [ifaceChart]);

  const { data: tunnelChart, isLoading: tunnelLoading } = useQuery({
    queryKey: ['vpn-chart', deviceId, expandedTunnel, chartRange],
    queryFn: () => {
      // A logical tunnel is several vpn_status rows (provisioned name, dialup
      // counters, …). The group endpoint is the one that aggregates them, and
      // the group rides in the query string because names may contain '/'.
      const row = vpns.find((v: any) => v.tunnel_name === expandedTunnel);
      const group = row?.tunnel_group || row?.phase1_name || expandedTunnel || '';
      return apiFetch<any[]>(
        `/admin/api/devices/${deviceId}/vpn-group-chart?group=${encodeURIComponent(group)}&range=${chartRange}`,
      );
    },
    enabled: Boolean(deviceId) && activeTab === 'vpn' && expandedTunnel != null,
  });

  const tunnelSeries = useMemo(() => {
    const rows = Array.isArray(tunnelChart) ? tunnelChart : [];
    const ts = rows.map((r: any) => Number(r.bucket_ms) || 0);
    const seconds = bucketSeconds(ts);
    return {
      timestamps: ts,
      series: [
        {
          label: 'In',
          color: 'var(--fwmon-series-1)',
          values: toBitsPerSecond(
            rows.map((r: any) => numOrNull(r.in_bytes)),
            seconds,
          ),
        },
        {
          label: 'Out',
          color: 'var(--fwmon-series-3)',
          values: toBitsPerSecond(
            rows.map((r: any) => numOrNull(r.out_bytes)),
            seconds,
          ),
        },
      ] as ChartSeries[],
    };
  }, [tunnelChart]);

  const chartRangePills = (
    <div className="flex items-center gap-0.5 rounded-lg border border-border bg-bg-panel p-1">
      {CHART_RANGES.map((range) => (
        <button
          key={range}
          type="button"
          onClick={() => setChartRange(range)}
          className={cn(
            'rounded px-2 py-1 font-mono text-xs font-medium transition-colors',
            chartRange === range ? 'bg-accent text-on-accent' : 'text-text-dim hover:text-text',
          )}
        >
          {range}
        </button>
      ))}
    </div>
  );

  const tabs: { id: DetailTab; label: string; icon: typeof Activity }[] = [
    { id: 'interfaces', label: `Interfaces (${interfaces.length})`, icon: Network },
    { id: 'vpn', label: `VPN Tunnels (${vpns.length})`, icon: Shield },
    { id: 'resources', label: 'Resources & Sensors', icon: Cpu },
    { id: 'security', label: 'Security, HA & SD-WAN', icon: Shield },
    { id: 'diagnostics', label: 'Diagnostics & Ping', icon: Activity },
    { id: 'config', label: 'Config History & Diff', icon: FileCode2 },
    { id: 'lifecycle', label: 'Alerts & Lifecycle', icon: AlertTriangle },
  ];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3 border-b border-border pb-4">
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => navigate('/devices')}
            className="rounded-md border border-border bg-bg-panel p-2 text-text-dim hover:text-text"
            aria-label="Back to devices"
          >
            <ArrowLeft className="h-4 w-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-semibold text-text">
                {device?.name || `Device #${deviceId}`}
              </h1>
              <span
                className={cn(
                  'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
                  device?.status === 'online'
                    ? 'bg-sig-ok/15 text-sig-ok'
                    : 'bg-sig-crit/15 text-sig-crit'
                )}
              >
                {device?.status || 'unknown'}
              </span>
            </div>
            <div className="text-xs font-mono text-text-dim mt-0.5">
              {device?.ip_address} • {device?.vendor || 'Firewall'} {device?.model || ''}{' '}
              {device?.os_version ? `(${device.os_version})` : ''}
            </div>
          </div>
        </div>

        {/* 7-Tab Bar */}
        <div className="flex flex-wrap items-center gap-1 rounded-lg bg-bg-panel p-1 border border-border">
          {tabs.map((t) => {
            const Icon = t.icon;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setActiveTab(t.id)}
                className={cn(
                  'flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors',
                  activeTab === t.id
                    ? 'bg-bg-card text-text shadow-xs border border-border'
                    : 'text-text-dim hover:text-text'
                )}
              >
                <Icon className="h-3.5 w-3.5 text-accent" />
                {t.label}
              </button>
            );
          })}
        </div>
      </div>

      {isLoading ? (
        <div className="rounded-xl border border-border bg-bg-card p-8 text-center text-sm text-text-dim">
          Loading device telemetry…
        </div>
      ) : (
        <>
          {activeTab === 'interfaces' && (
            <div className="rounded-xl border border-border bg-bg-card p-4">
              <h2 className="text-sm font-semibold text-text mb-3">
                Physical & Logical Interfaces ({interfaces.length})
              </h2>
              {interfaces.length === 0 ? (
                <p className="text-xs text-text-dim">No interfaces reported yet.</p>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                  {interfaces.map((iface: any, idx: number) => (
                    <div
                      key={iface.index || iface.name || idx}
                      className="rounded-lg border border-border bg-bg-panel p-3 space-y-1.5"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono font-semibold text-xs text-text">
                          {iface.name || `ifIndex ${iface.index}`}
                        </span>
                        <div className="flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() =>
                              setExpandedIface(expandedIface === iface.index ? null : iface.index)
                            }
                            aria-expanded={expandedIface === iface.index}
                            className={cn(
                              'rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase transition-colors',
                              expandedIface === iface.index
                                ? 'border-accent/40 bg-accent/15 text-accent-text'
                                : 'border-border bg-bg-card text-text-dim hover:text-text',
                            )}
                          >
                            Chart
                          </button>
                          <span
                            className={cn(
                              'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
                              iface.status === 'up'
                                ? 'bg-sig-ok/15 text-sig-ok'
                                : 'bg-bg-card text-text-faint'
                            )}
                          >
                            {iface.status || 'down'}
                          </span>
                          {/*
                            The per-interface public-dashboard choice. It is
                            a DISPLAY SETTING holding the map for every
                            device, not the device's public_visible flag.
                          */}
                          {iface.name ? (
                            <PublicInterfaceToggle
                              deviceId={deviceId}
                              interfaceName={iface.name}
                              canEdit={isAdmin}
                            />
                          ) : null}
                        </div>
                      </div>
                      <div className="flex items-center justify-between text-[11px] font-mono text-text-dim">
                        <span>RX: {formatBytes(iface.in_bytes ?? 0)}</span>
                        <span>TX: {formatBytes(iface.out_bytes ?? 0)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {expandedIface != null && (
                <div className="mt-4 rounded-lg border border-border bg-bg-card p-4">
                  <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <h3 className="text-xs font-semibold text-text">
                        {interfaces.find((i: any) => i.index === expandedIface)?.name ||
                          `Interface ${expandedIface}`}{' '}
                        traffic
                      </h3>
                      {ifaceChart?.source && (
                        <span className="rounded bg-accent/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase text-accent-text">
                          {ifaceChart.source}
                        </span>
                      )}
                    </div>
                    {chartRangePills}
                  </div>
                  <TimeSeriesChart
                    timestamps={ifaceSeries.timestamps}
                    series={ifaceSeries.series}
                    kind="bps"
                    isLoading={ifaceLoading}
                    emptyMessage="Not enough history for this interface in this range."
                  />
                </div>
              )}
            </div>
          )}

          {activeTab === 'vpn' && (
            <div className="rounded-xl border border-border bg-bg-card p-4">
              <h2 className="text-sm font-semibold text-text mb-3">
                IPSec & SSL-VPN Tunnels ({vpns.length})
              </h2>
              {vpns.length === 0 ? (
                <p className="text-xs text-text-dim">No VPN tunnels reported for this device.</p>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {vpns.map((v: any, idx: number) => (
                    <div
                      key={v.tunnel_name || idx}
                      className="rounded-lg border border-border bg-bg-panel p-3 flex items-center justify-between"
                    >
                      <div>
                        <div className="font-semibold text-xs text-text">{v.tunnel_name}</div>
                        <div className="font-mono text-[11px] text-text-dim">
                          Remote: {v.remote_ip || '—'}
                        </div>
                      </div>
                      <div className="flex flex-col items-end gap-1.5">
                        <span
                          className={cn(
                            'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
                            v.status === 'up'
                              ? 'bg-sig-ok/15 text-sig-ok'
                              : 'bg-sig-crit/15 text-sig-crit'
                          )}
                        >
                          {v.status || 'down'}
                        </span>
                        <button
                          type="button"
                          onClick={() =>
                            setExpandedTunnel(
                              expandedTunnel === v.tunnel_name ? null : v.tunnel_name,
                            )
                          }
                          aria-expanded={expandedTunnel === v.tunnel_name}
                          className={cn(
                            'rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase transition-colors',
                            expandedTunnel === v.tunnel_name
                              ? 'border-accent/40 bg-accent/15 text-accent-text'
                              : 'border-border bg-bg-card text-text-dim hover:text-text',
                          )}
                        >
                          Chart
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {expandedTunnel != null && (
                <div className="mt-4 rounded-lg border border-border bg-bg-card p-4">
                  <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-xs font-semibold text-text">
                      {expandedTunnel} traffic
                    </h3>
                    {chartRangePills}
                  </div>
                  <TimeSeriesChart
                    timestamps={tunnelSeries.timestamps}
                    series={tunnelSeries.series}
                    kind="bps"
                    isLoading={tunnelLoading}
                    emptyMessage="Not enough history for this tunnel in this range."
                  />
                </div>
              )}
            </div>
          )}

          {activeTab === 'resources' && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-sm font-semibold text-text">Historical Telemetry</h2>
                {chartRangePills}
              </div>
              {/*
                The gauges. V1 drew a donut for CPU and memory
                (cmd/api/static/js/admin-device-detail.js:336-337) and V2 had
                plain numbers.
              */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="rounded-xl border border-border bg-bg-card p-4">
                <div className="text-xs text-text-dim">CPU Utilization</div>
                <div className="mt-1">
                  <Gauge value={cpuUsage} max={100} size={72} />
                </div>
              </div>
              <div className="rounded-xl border border-border bg-bg-card p-4">
                <div className="text-xs text-text-dim">Memory Utilization</div>
                <div className="mt-1">
                  <Gauge value={memoryUsage} max={100} size={72} />
                </div>
              </div>
              <div className="rounded-xl border border-border bg-bg-card p-4">
                <div className="text-xs text-text-dim">Hardware Sensors</div>
                <div className="text-2xl font-mono font-bold text-text mt-1">{sensors.length}</div>
              </div>
              </div>

              <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                <div className="rounded-xl border border-border bg-bg-card p-4">
                  <TimeSeriesChart
                    title="System Overview"
                    timestamps={chartSeries.timestamps}
                    series={chartSeries.overview}
                    kind="percent"
                    isLoading={statusLoading}
                    emptyMessage="No status history in this range."
                  />
                </div>
                <div className="rounded-xl border border-border bg-bg-card p-4">
                  <TimeSeriesChart
                    title="Network Throughput"
                    timestamps={chartSeries.timestamps}
                    series={chartSeries.network}
                    kind="bps"
                    isLoading={statusLoading}
                    emptyMessage="No network history in this range."
                  />
                </div>
              </div>

              <div className="rounded-xl border border-border bg-bg-card p-4">
                <TimeSeriesChart
                  title="CPU Breakdown"
                  timestamps={chartSeries.timestamps}
                  series={chartSeries.cpu}
                  kind="percent"
                  isLoading={statusLoading}
                  emptyMessage="This device does not report a CPU breakdown."
                />
              </div>

              {(processorStats.length > 0 || disks.length > 0 || loadAverage) && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <CoreCpuPanel processors={processorStats} />
                  <DiskUsagePanel disks={disks} />
                  {loadAverage && (
                    <div className="lg:col-span-2">
                      <LoadAveragePanel load={loadAverage} />
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === 'security' && (
            <div className="space-y-4">
              <SecurityStatsPanel stats={securityStats} />
              <LicencePanel licences={licenceInfo} />

              {/*
                The per-device alert override. The console had only the
                GLOBAL thresholds, so a noisy device could not be given its
                own numbers — every device in the fleet raised on the same
                ones.
              */}
              <div className="rounded-xl border border-border bg-bg-card p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-xs font-semibold text-text">
                      Alert thresholds & routing
                    </h3>
                    <p className="text-[11px] text-text-faint">
                      Override the global thresholds for this device only.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setAlertConfigOpen(true)}
                    className="rounded-md border border-border bg-bg-panel px-2.5 py-1.5 text-xs font-medium text-text-dim hover:text-text"
                  >
                    Alert overrides
                  </button>
                </div>
              </div>
              {!securityStats && licenceInfo.length === 0 && (
                <div className="rounded-xl border border-border bg-bg-card p-4 text-xs text-text-dim">
                  This device does not report security inspection counters or licences.
                </div>
              )}
              <div className="rounded-xl border border-border bg-bg-card p-4">
                <h2 className="text-sm font-semibold text-text">
                  Vendor telemetry capability matrix
                </h2>
                <p className="mt-0.5 text-[11px] text-text-faint">
                  Static vendor profile joined with the fields this device was observed sending.
                </p>
                <div className="mt-3">
                  <DeviceCapabilitiesPanel
                    capabilities={capabilities}
                    isLoading={capabilitiesLoading}
                  />
                </div>
              </div>
            </div>
          )}

          {activeTab === 'diagnostics' && (
            <div className="space-y-4">
              <div className="rounded-xl border border-border bg-bg-card p-4 space-y-2">
                <h2 className="text-sm font-semibold text-text">
                  Polling & Reachability Diagnostics
                </h2>
                <p className="text-xs text-text-dim">
                  Last polled: {formatRelativeTime(device?.last_polled)}
                </p>
              </div>
              <HAPanel rows={haStatus} />
              <SdwanPanel rows={sdwanHealth} />
              <PingSlaPanel rows={pingStats} />
              {haStatus.length === 0 && sdwanHealth.length === 0 && pingStats.length === 0 && (
                <div className="rounded-xl border border-border bg-bg-card p-4 text-xs text-text-dim">
                  This device does not report HA, SD-WAN or ping-SLA telemetry.
                </div>
              )}
            </div>
          )}

          {activeTab === 'config' && (
            <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h2 className="text-sm font-semibold text-text">
                    Configuration Revisions ({configRevs.length})
                  </h2>
                  <p className="text-[11px] text-text-faint">
                    Pick two revisions to compare. Volatile values (IV churn, save timestamps) are
                    normalised before diffing.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] text-text-dim">
                    {selectedFrom?.id ?? '—'} → {selectedTo?.id ?? '—'}
                  </span>
                  <button
                    type="button"
                    disabled={!selectedFrom || !selectedTo || selectedFrom.id === selectedTo.id}
                    onClick={() => setDiffOpen(true)}
                    className="rounded-md bg-accent px-3.5 py-1.5 text-xs font-semibold text-on-accent hover:opacity-90 disabled:opacity-40"
                  >
                    Compare revisions
                  </button>
                </div>
              </div>

              {configRevs.length === 0 ? (
                <p className="text-xs text-text-dim">No configuration backups archived yet.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse text-left text-xs">
                    <thead>
                      <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-faint">
                        <th className="px-2 py-2 text-center font-semibold">From</th>
                        <th className="px-2 py-2 text-center font-semibold">To</th>
                        <th className="px-3 py-2 font-semibold">Revision</th>
                        <th className="px-3 py-2 font-semibold">Trigger / Quality</th>
                        <th className="px-3 py-2 font-semibold">Changed by</th>
                        <th className="px-3 py-2 font-semibold">Checksum</th>
                        <th className="px-3 py-2" />
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/60">
                      {configRevs.map((rev) => (
                        <tr key={rev.id} className="hover:bg-bg-hover">
                          <td className="px-2 py-2 text-center">
                            <input
                              type="radio"
                              name="cfg-diff-from"
                              aria-label={`Use revision ${rev.id} as the diff base`}
                              checked={diffFrom === rev.id}
                              onChange={() => setDiffFrom(rev.id)}
                            />
                          </td>
                          <td className="px-2 py-2 text-center">
                            <input
                              type="radio"
                              name="cfg-diff-to"
                              aria-label={`Compare revision ${rev.id}`}
                              checked={diffTo === rev.id}
                              onChange={() => setDiffTo(rev.id)}
                            />
                          </td>
                          <td className="px-3 py-2">
                            <div className="font-mono text-text">#{rev.id}</div>
                            <div className="text-[11px] text-text-faint">
                              {formatRelativeTime(rev.timestamp)}
                            </div>
                          </td>
                          <td className="px-3 py-2 text-[11px] text-text-dim">
                            {rev.trigger_source || '—'}
                            {rev.backup_quality ? ` · ${rev.backup_quality}` : ''}
                          </td>
                          <td className="px-3 py-2 text-[11px] text-text-dim">
                            {rev.changed_by || (rev.attribution_checked ? 'out-of-band' : '—')}
                          </td>
                          <td className="px-3 py-2 font-mono text-[11px] text-text-faint">
                            {rev.checksum?.slice(0, 12)}
                          </td>
                          <td className="px-3 py-2 text-right">
                            <div className="inline-flex items-center gap-1">
                              <Button  variant="icon"
                                type="button"
                                onClick={() => setRevisionToView(rev.id)}
                                aria-label={`View revision ${rev.id}`}
                                title="View this revision"
                                
                              >
                                <Eye className="h-3.5 w-3.5" />
                              </Button>
                              <a
                                href={`/admin/api/devices/${deviceId}/config-history/${rev.id}`}
                              title="Download this revision"
                              className="inline-flex rounded border border-border bg-bg-panel p-1 text-text-dim hover:text-text"
                            >
                                <Download className="h-3.5 w-3.5" />
                              </a>
                              <Button  variant="danger-icon"
                                type="button"
                                onClick={() => setRevisionToDelete(rev.id)}
                                aria-label={`Delete revision ${rev.id}`}
                                title="Delete this revision"
                                
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                              </Button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              <ConfigDiffDrawer
                key={`${diffFrom ?? 0}:${diffTo ?? 0}`}
                open={diffOpen}
                onOpenChange={setDiffOpen}
                deviceId={Number(deviceId)}
                from={selectedFrom}
                to={selectedTo}
              />

              <SlideOverDrawer
                open={revisionToView != null}
                onOpenChange={(open) => {
                  if (!open) setRevisionToView(null);
                }}
                title={`Configuration revision #${revisionToView ?? ''}`}
                subtitle={
                  viewedRevision
                    ? `${new Date(viewedRevision.timestamp).toLocaleString()} · ${viewedRevision.length} bytes`
                    : undefined
                }
                size="2xl"
                footer={
                  <div className="flex w-full items-center justify-between gap-2">
                    <a
                      href={`/admin/api/devices/${deviceId}/config-history/${revisionToView ?? ''}`}
                      className="inline-flex items-center gap-1 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text-dim hover:text-text"
                    >
                      <Download className="h-3.5 w-3.5" />
                      Download
                    </a>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          const text = viewedRevision?.config_text;
                          if (!text) return;
                          if (!navigator.clipboard) {
                            toast({
                              title: 'Copy unavailable',
                              description: 'The clipboard API needs a secure context.',
                              variant: 'error',
                            });
                            return;
                          }
                          void navigator.clipboard
                            .writeText(text)
                            .then(() => toast({ title: 'Config copied', variant: 'success' }))
                            .catch(() => toast({ title: 'Copy failed', variant: 'error' }));
                        }}
                        className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text"
                      >
                        Copy config
                      </button>
                      <button
                        type="button"
                        onClick={() => setRevisionToView(null)}
                        className="rounded-md bg-accent px-4 py-1.5 text-xs font-semibold text-on-accent"
                      >
                        Close
                      </button>
                    </div>
                  </div>
                }
              >
                {revisionLoading ? (
                  <p className="p-6 text-center text-xs text-text-dim">Loading revision…</p>
                ) : revisionError ? (
                  <div className="m-4 rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit" role="alert">
                    Could not load the revision:{' '}
                    {revisionError instanceof Error ? revisionError.message : 'request failed'}
                  </div>
                ) : viewedRevision?.config_text ? (
                  <div className="space-y-2">
                    <div className="font-mono text-[11px] text-text-faint">
                      checksum {viewedRevision.checksum?.slice(0, 16)}
                    </div>
                    <pre className="max-h-[70vh] overflow-auto rounded-lg border border-border bg-bg-panel p-3 font-mono text-[11px] text-text whitespace-pre">
                      {viewedRevision.config_text}
                    </pre>
                  </div>
                ) : (
                  <p className="p-6 text-center text-xs text-text-faint">
                    This revision has no stored config text.
                  </p>
                )}
              </SlideOverDrawer>

              <ConfirmDialog
                open={revisionToDelete != null}
                onOpenChange={(open) => {
                  if (!open) setRevisionToDelete(null);
                }}
                title={`Delete revision #${revisionToDelete ?? ''}?`}
                description="The stored config snapshot is removed permanently; other revisions are untouched."
                confirmLabel="Delete revision"
                destructive
                pending={deleteRevisionMutation.isPending}
                onConfirm={() =>
                  revisionToDelete != null && deleteRevisionMutation.mutate(revisionToDelete)
                }
              />
            </div>
          )}

          {activeTab === 'lifecycle' && (
            <div className="space-y-4">
              <RecentAlertsPanel alerts={recentAlerts} />
              <PurgeJobPanel deviceId={deviceId} isAdmin={isAdmin} />
              <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
              <h2 className="text-sm font-semibold text-text">Device Lifecycle & Permanent Purge</h2>
              <p className="text-xs text-text-dim">
                Retiring a device stops polling while preserving historical telemetry. Permanently purging a retired device deletes all historical rows across every partition.
              </p>
              <div className="flex flex-wrap items-center gap-3">
                {device?.retired_at ? (
                  <>
                    <button
                      type="button"
                      onClick={() => retireMutation.mutate('restore')}
                      className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-on-accent"
                    >
                      <RotateCcw className="h-3.5 w-3.5" /> Restore Active Polling
                    </button>
                    <button
                      type="button"
                      onClick={() => setPurgeDialogOpen(true)}
                      className="flex items-center gap-1.5 rounded-md bg-sig-crit px-3 py-1.5 text-xs font-semibold text-white"
                    >
                      <Trash2 className="h-3.5 w-3.5" /> Permanently Purge Device Data
                    </button>
                  </>
                ) : (
                  <button
                    type="button"
                    onClick={() => retireMutation.mutate('retire')}
                    className="flex items-center gap-1.5 rounded-md border border-sig-warn/40 bg-sig-warn/10 px-3 py-1.5 text-xs font-semibold text-sig-warn"
                  >
                    <Archive className="h-3.5 w-3.5" /> Retire Device (Preserve History)
                  </button>
                )}
              </div>
              </div>
            </div>
          )}
        </>
      )}

      {/*
        The purge dialog. The previous one sent only the password and the TOTP
        code, so the server rejected EVERY purge with a 400 on `confirm_name`
        — the feature was present and unusable. This one collects all three
        the server asks for and shows the estimate before the operator commits.
      */}
      <AlertConfigDrawer
        open={alertConfigOpen}
        onOpenChange={setAlertConfigOpen}
        scope="device"
        id={deviceId}
        name={detail?.device?.name ?? `device ${deviceId}`}
        // The Event Profile is assigned through an ADMIN-ONLY endpoint.
        canAssignEventProfile={isAdmin}
      />

      <PurgeDeviceDialog
        open={purgeDialogOpen}
        onOpenChange={setPurgeDialogOpen}
        deviceId={deviceId}
        deviceName={detail?.device?.name ?? `device ${deviceId}`}
        totpEnabled={me?.totp_enabled}
        onPurged={() => navigate('/devices')}
      />
    </div>
  );
}
