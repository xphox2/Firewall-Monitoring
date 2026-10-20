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
} from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatBytes, formatRelativeTime } from '@/lib/utils';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { SlideOverDrawer, DrawerTab } from '@/components/ui/slide-over-drawer';
import { StepUpAuthDialog } from '@/components/ui/step-up-auth-dialog';
import { useToast } from '@/components/ui/toast';
import { ColumnDef } from '@tanstack/react-table';

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
  snmpv3_security_level?: string;
  snmpv3_auth_type?: string;
  snmpv3_priv_type?: string;
  ssh_poll_enabled?: boolean;
  ssh_port?: number;
  ssh_username?: string;
  api_port?: number;
  syslog_source_ips?: string;
  flow_source_ips?: string;
  trap_source_ips?: string;
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
    return <DeviceDetailView deviceId={deviceId} />;
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

  // Tabbed Device Editor Drawer State (replaces the 1,599px #device-modal)
  const [editorOpen, setEditorOpen] = useState(false);
  const [editorTab, setEditorTab] = useState<'general' | 'snmp' | 'credentials' | 'telemetry' | 'test'>('general');
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

  const saveDeviceMutation = useMutation({
    mutationFn: async () => {
      if (editingDevice.id) {
        return apiFetch(`/admin/api/devices/${editingDevice.id}`, {
          method: 'PUT',
          body: editingDevice,
        });
      }
      return apiFetch('/admin/api/devices', {
        method: 'POST',
        body: editingDevice,
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
    mutationFn: async () =>
      apiFetch<{ success: boolean; message: string }>('/admin/api/devices/test', {
        method: 'POST',
        body: editingDevice,
      }),
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
              <span
                className={cn(
                  'h-2 w-2 rounded-full shrink-0',
                  row.original.retired_at
                    ? 'bg-text-mute'
                    : row.original.status === 'online'
                      ? 'bg-sig-ok'
                      : 'bg-sig-crit'
                )}
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
        accessorKey: 'cpu_usage',
        header: 'CPU / Mem',
        cell: ({ row }) => {
          const cpu = Math.round(row.original.cpu_usage ?? 0);
          const mem = Math.round(row.original.memory_usage ?? 0);
          return (
            <div className="space-y-1 w-28 font-mono text-[11px]">
              <div className="flex items-center justify-between">
                <span className="text-text-faint">CPU</span>
                <span>{cpu}%</span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-bg-panel overflow-hidden">
                <div
                  className={cn('h-full', cpu > 85 ? 'bg-sig-crit' : cpu > 70 ? 'bg-sig-warn' : 'bg-accent')}
                  style={{ width: `${Math.min(100, cpu)}%` }}
                />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-text-faint">MEM</span>
                <span>{mem}%</span>
              </div>
            </div>
          );
        },
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
    { id: 'telemetry', label: 'Syslog / Flow IPs' },
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
          className="flex items-center gap-1.5 rounded-md bg-accent px-3.5 py-2 text-xs font-semibold text-white hover:opacity-90 self-start"
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
            className="w-full rounded-md border border-border bg-bg-card pl-8 pr-3 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
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
                  ? 'bg-bg-card text-text shadow-sm border border-border'
                  : 'text-text-dim hover:text-text'
              )}
            >
              {mode}
            </button>
          ))}
        </div>
      </div>

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
              <span>CPU: {Math.round(dev.cpu_usage ?? 0)}% • Mem: {Math.round(dev.memory_usage ?? 0)}%</span>
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
              <button
                type="button"
                onClick={() => setEditorOpen(false)}
                className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text-dim"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={!editingDevice.name || !editingDevice.ip_address || saveDeviceMutation.isPending}
                onClick={() => saveDeviceMutation.mutate()}
                className="rounded-md bg-accent px-4 py-1.5 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
              >
                {saveDeviceMutation.isPending ? 'Saving…' : 'Save Device'}
              </button>
            </div>
          </div>
        }
      >
        {editorTab === 'general' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-text-dim mb-1">Device Name / Hostname</label>
                <input
                  type="text"
                  value={editingDevice.name ?? ''}
                  onChange={(e) => setEditingDevice((p) => ({ ...p, name: e.target.value }))}
                  placeholder="fw-dc1-edge01"
                  className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-text-dim mb-1">Management IP Address</label>
                <input
                  type="text"
                  value={editingDevice.ip_address ?? ''}
                  onChange={(e) => setEditingDevice((p) => ({ ...prevIp(p, e.target.value) }))}
                  placeholder="10.0.1.1"
                  className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <label className="block text-xs font-medium text-text-dim mb-1">Vendor Profile</label>
                <select
                  value={editingDevice.vendor ?? 'generic'}
                  onChange={(e) => setEditingDevice((p) => ({ ...p, vendor: e.target.value }))}
                  className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
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
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-text-dim mb-1">Site Assignment</label>
                <select
                  value={editingDevice.site_id ?? ''}
                  onChange={(e) =>
                    setEditingDevice((p) => ({
                      ...p,
                      site_id: e.target.value ? Number(e.target.value) : null,
                    }))
                  }
                  className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
                >
                  <option value="">Unassigned (Global)</option>
                  {(sitesList ?? []).map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-text-dim mb-1">Collector Probe</label>
                <select
                  value={editingDevice.probe_id ?? ''}
                  onChange={(e) =>
                    setEditingDevice((p) => ({
                      ...p,
                      probe_id: e.target.value ? Number(e.target.value) : null,
                    }))
                  }
                  className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
                >
                  <option value="">Direct (Primary Server)</option>
                  {(probesList ?? []).map((pr) => (
                    <option key={pr.id} value={pr.id}>
                      {pr.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

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
                <label className="block text-xs font-medium text-text-dim mb-1">SNMP Version</label>
                <select
                  value={editingDevice.snmp_version ?? '2c'}
                  onChange={(e) => setEditingDevice((p) => ({ ...p, snmp_version: e.target.value }))}
                  className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
                >
                  <option value="2c">SNMP v2c</option>
                  <option value="3">SNMP v3 (AuthPriv)</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-text-dim mb-1">SNMP UDP Port</label>
                <input
                  type="number"
                  value={editingDevice.snmp_port ?? 161}
                  onChange={(e) => setEditingDevice((p) => ({ ...p, snmp_port: Number(e.target.value) }))}
                  className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
                />
              </div>
            </div>

            {editingDevice.snmp_version !== '3' && editingDevice.snmp_version !== 'v3' ? (
              <div>
                <label className="block text-xs font-medium text-text-dim mb-1">
                  SNMP v2c Community String
                </label>
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
                      className="flex items-center gap-1 rounded border border-border bg-bg-panel px-2.5 py-2 text-xs text-text-dim hover:text-text"
                    >
                      <Eye className="h-3.5 w-3.5" /> Reveal
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-text-dim mb-1">SNMPv3 Username</label>
                  <input
                    type="text"
                    value={editingDevice.snmpv3_username ?? ''}
                    onChange={(e) =>
                      setEditingDevice((p) => ({ ...p, snmpv3_username: e.target.value }))
                    }
                    className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
                  />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-text-dim mb-1">Auth Protocol</label>
                    <select
                      value={editingDevice.snmpv3_auth_type ?? 'SHA'}
                      onChange={(e) =>
                        setEditingDevice((p) => ({ ...p, snmpv3_auth_type: e.target.value }))
                      }
                      className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
                    >
                      <option value="SHA">SHA-1</option>
                      <option value="SHA256">SHA-256</option>
                      <option value="MD5">MD5</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-text-dim mb-1">Priv Protocol</label>
                    <select
                      value={editingDevice.snmpv3_priv_type ?? 'AES'}
                      onChange={(e) =>
                        setEditingDevice((p) => ({ ...p, snmpv3_priv_type: e.target.value }))
                      }
                      className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
                    >
                      <option value="AES">AES-128</option>
                      <option value="AES256">AES-256</option>
                      <option value="DES">DES</option>
                    </select>
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
                <label className="block text-xs font-medium text-text-dim mb-1">SSH Username</label>
                <input
                  type="text"
                  value={editingDevice.ssh_username ?? ''}
                  onChange={(e) => setEditingDevice((p) => ({ ...p, ssh_username: e.target.value }))}
                  className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-text-dim mb-1">SSH Port</label>
                <input
                  type="number"
                  value={editingDevice.ssh_port ?? 22}
                  onChange={(e) => setEditingDevice((p) => ({ ...p, ssh_port: Number(e.target.value) }))}
                  className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
                />
              </div>
            </div>
          </div>
        )}

        {editorTab === 'telemetry' && (
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">
                Additional Syslog Source IPs (comma-separated)
              </label>
              <input
                type="text"
                value={editingDevice.syslog_source_ips ?? ''}
                onChange={(e) =>
                  setEditingDevice((p) => ({ ...p, syslog_source_ips: e.target.value }))
                }
                placeholder="e.g. 10.255.0.1, 172.16.1.1"
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">
                Additional sFlow / NetFlow Source IPs
              </label>
              <input
                type="text"
                value={editingDevice.flow_source_ips ?? ''}
                onChange={(e) => setEditingDevice((p) => ({ ...p, flow_source_ips: e.target.value }))}
                placeholder="e.g. 10.255.0.1"
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
              />
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
              className="flex items-center gap-2 rounded-md bg-accent px-4 py-2 text-xs font-semibold text-white hover:opacity-90"
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
          const res = await apiFetch<{ value: string }>(
            `/admin/api/devices/${editingDevice.id}/reveal-secret`,
            {
              method: 'POST',
              body: { field: revealField, password, totp_code },
            }
          );
          if (res?.value) {
            setRevealedSecrets((prev) => ({ ...prev, [revealField]: res.value }));
          }
          setRevealField(null);
        }}
      />
    </div>
  );
}

function prevIp(p: Partial<DeviceRecord>, ip: string): Partial<DeviceRecord> {
  return { ...p, ip_address: ip };
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

  const { data: detail, isLoading } = useQuery({
    queryKey: ['device-detail', deviceId],
    queryFn: () => apiFetch<Record<string, any>>(`/admin/api/devices/${deviceId}/detail`),
    refetchInterval: 15_000,
  });

  // GetDeviceConfigHistory wraps the rows: {revisions, total_all, ...}. Typing
  // this as an array made `.map` throw and (before the ErrorBoundary) blanked
  // the whole console when the Config tab opened.
  const { data: configHistory } = useQuery({
    queryKey: ['device-config-history', deviceId],
    queryFn: () =>
      apiFetch<{
        revisions?: Array<{ id: number; timestamp: string; checksum: string }>;
        total_all?: number;
      }>(`/admin/api/devices/${deviceId}/config-history`),
    enabled: activeTab === 'config',
  });
  const configRevs = configHistory?.revisions ?? [];

  const { data: capabilities } = useQuery({
    queryKey: ['device-capabilities', deviceId],
    queryFn: () => apiFetch<Record<string, any>>(`/admin/api/devices/${deviceId}/capabilities`),
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
  });

  const device: DeviceRecord | undefined = detail?.device;
  const interfaces: any[] = detail?.interfaces ?? [];
  const vpns: any[] = detail?.vpn_status ?? detail?.vpn_statuses ?? detail?.vpns ?? [];
  const sensors: any[] = detail?.hardware_sensors ?? [];
  const cpuUsage = detail?.system_status?.cpu_usage ?? device?.cpu_usage ?? 0;
  const memoryUsage = detail?.system_status?.memory_usage ?? device?.memory_usage ?? 0;

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
                    ? 'bg-bg-card text-text shadow-sm border border-border'
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
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-semibold text-xs text-text">
                          {iface.name || `ifIndex ${iface.index}`}
                        </span>
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
                      </div>
                      <div className="flex items-center justify-between text-[11px] font-mono text-text-dim">
                        <span>RX: {formatBytes(iface.in_bytes ?? 0)}</span>
                        <span>TX: {formatBytes(iface.out_bytes ?? 0)}</span>
                      </div>
                    </div>
                  ))}
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
                      <span
                        className={cn(
                          'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
                          v.status === 'up' ? 'bg-sig-ok/15 text-sig-ok' : 'bg-sig-crit/15 text-sig-crit'
                        )}
                      >
                        {v.status || 'down'}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'resources' && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="rounded-xl border border-border bg-bg-card p-4">
                <div className="text-xs text-text-dim">CPU Utilization</div>
                <div className="text-2xl font-mono font-bold text-text mt-1">
                  {Math.round(cpuUsage)}%
                </div>
              </div>
              <div className="rounded-xl border border-border bg-bg-card p-4">
                <div className="text-xs text-text-dim">Memory Utilization</div>
                <div className="text-2xl font-mono font-bold text-text mt-1">
                  {Math.round(memoryUsage)}%
                </div>
              </div>
              <div className="rounded-xl border border-border bg-bg-card p-4">
                <div className="text-xs text-text-dim">Hardware Sensors</div>
                <div className="text-2xl font-mono font-bold text-text mt-1">{sensors.length}</div>
              </div>
            </div>
          )}

          {activeTab === 'security' && (
            <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
              <h2 className="text-sm font-semibold text-text">
                Vendor Telemetry Capability Matrix (24h Observed)
              </h2>
              <pre className="rounded-lg border border-border bg-bg-panel p-3 font-mono text-xs text-text overflow-x-auto">
                {JSON.stringify(capabilities ?? { status: 'Loaded' }, null, 2)}
              </pre>
            </div>
          )}

          {activeTab === 'diagnostics' && (
            <div className="rounded-xl border border-border bg-bg-card p-4 space-y-2">
              <h2 className="text-sm font-semibold text-text">Polling & Reachability Diagnostics</h2>
              <p className="text-xs text-text-dim">
                Last polled: {formatRelativeTime(device?.last_polled)}
              </p>
            </div>
          )}

          {activeTab === 'config' && (
            <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
              <h2 className="text-sm font-semibold text-text">
                Configuration Revisions ({configRevs.length})
              </h2>
              {configRevs.length === 0 ? (
                <p className="text-xs text-text-dim">No configuration backups archived yet.</p>
              ) : (
                <div className="space-y-2">
                  {configRevs.map((rev) => (
                    <div
                      key={rev.id}
                      className="flex items-center justify-between rounded-lg border border-border bg-bg-panel px-3 py-2 text-xs"
                    >
                      <span className="font-mono text-text">
                        Revision #{rev.id} • {formatRelativeTime(rev.timestamp)}
                      </span>
                      <span className="font-mono text-text-dim">
                        {rev.checksum?.slice(0, 12)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'lifecycle' && (
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
                      className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white"
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
          )}
        </>
      )}

      <StepUpAuthDialog
        open={purgeDialogOpen}
        onOpenChange={setPurgeDialogOpen}
        danger
        title="Permanently Purge Retired Device"
        description="This action irreversibly deletes this device and all historical telemetry. Enter your admin password to confirm."
        confirmLabel="Permanently Purge"
        onConfirm={async ({ password, totp_code }) => {
          await apiFetch(`/admin/api/devices/${deviceId}/purge`, {
            method: 'POST',
            body: { password, totp_code },
          });
          toast({ title: 'Device purge job started', variant: 'info' });
          navigate('/devices');
        }}
      />
    </div>
  );
}
