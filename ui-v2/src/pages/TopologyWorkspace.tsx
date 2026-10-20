import { useState, useMemo } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Network,
  Cable,
  Shield,
  Play,
  RotateCcw,
  Trash2,
  Eye,
  CheckCircle2,
  ArrowRight,
} from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { SlideOverDrawer, DrawerTab } from '@/components/ui/slide-over-drawer';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { ClassicFallback } from '@/components/ui/classic-fallback';
import { useToast } from '@/components/ui/toast';
import { ColumnDef } from '@tanstack/react-table';

type TopologyTab = 'map' | 'connections' | 'ipsec';

interface ConnectionRecord {
  id: number;
  name: string;
  source_device_id: number;
  source_device_name?: string;
  dest_device_id: number;
  dest_device_name?: string;
  connection_type: string;
  status: string;
  bandwidth_mbps?: number;
  latency_ms?: number;
}

interface IPSecTunnelIntent {
  id: number;
  name: string;
  endpoint_a_device_id: number;
  endpoint_a_name?: string;
  endpoint_b_device_id: number;
  endpoint_b_name?: string;
  ike_version?: number;
  deploy_state?: string;
  status?: string;
  updated_at?: string;
}

export function TopologyWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = (searchParams.get('tab') as TopologyTab) || 'map';

  const setTab = (tab: TopologyTab) => {
    setSearchParams({ tab }, { replace: true });
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <Network className="h-3.5 w-3.5" />
            Monitor / Network Topology & Tunnels
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            Topology Map, Inter-Device Connections & IPSec Provisioning
          </h1>
          <p className="text-xs text-text-dim mt-0.5">
            Unified view of L2/L3/VPN device interconnections, link evidence, and automated IPSec tunnel provisioning sagas.
          </p>
        </div>

        <div className="flex items-center gap-1 rounded-lg bg-bg-panel p-1 border border-border self-start">
          <button
            type="button"
            onClick={() => setTab('map')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'map'
                ? 'bg-bg-card text-text shadow-sm border border-border'
                : 'text-text-dim hover:text-text'
            )}
          >
            <Network className="h-3.5 w-3.5 text-accent" />
            Network Map
          </button>
          <button
            type="button"
            onClick={() => setTab('connections')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'connections'
                ? 'bg-bg-card text-text shadow-sm border border-border'
                : 'text-text-dim hover:text-text'
            )}
          >
            <Cable className="h-3.5 w-3.5 text-accent" />
            Connections
          </button>
          <button
            type="button"
            onClick={() => setTab('ipsec')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'ipsec'
                ? 'bg-bg-card text-text shadow-sm border border-border'
                : 'text-text-dim hover:text-text'
            )}
          >
            <Shield className="h-3.5 w-3.5 text-accent" />
            IPSec Tunnels
          </button>
        </div>
      </div>

      {activeTab === 'map' && <NetworkMapSubTab />}
      {activeTab === 'connections' && <ConnectionsSubTab />}
      {activeTab === 'ipsec' && <IpsecTunnelsSubTab />}
    </div>
  );
}

// ============================================================================
// SUB-TAB 1: NETWORK MAP
// ============================================================================
function NetworkMapSubTab() {
  const { data: mapData, isLoading } = useQuery({
    queryKey: ['vpn-map-data'],
    queryFn: () => apiFetch<any>('/admin/api/connections/vpn-map'),
    refetchInterval: 20_000,
  });
  const { data: deviceList } = useQuery({
    queryKey: ['devices-for-topology'],
    queryFn: () => apiFetch<Array<{ id: number; name: string; ip_address?: string }>>('/admin/api/devices'),
  });

  // GetVPNMapData returns a map keyed by device ID ("7" -> {total, up, down,
  // tunnels:[...]}), not {nodes, edges}. Reading nodes/edges rendered an empty
  // map on every install.
  const vpnMap: Record<
    string,
    {
      total?: number;
      up?: number;
      down?: number;
      tunnels?: Array<{
        tunnel_name: string;
        status: string;
        remote_ip?: string;
        matched_name?: string;
        bytes_in?: number;
        bytes_out?: number;
      }>;
    }
  > = mapData ?? {};
  const devicesById = new Map((deviceList ?? []).map((d) => [String(d.id), d]));

  const nodes = Object.entries(vpnMap).map(([id, vpn]) => {
    const device = devicesById.get(id);
    return {
      id,
      name: device?.name ?? `Device ${id}`,
      ip_address: device?.ip_address ?? '',
      status: (vpn.up ?? 0) > 0 ? 'up' : 'down',
    };
  });
  const edges = Object.entries(vpnMap).flatMap(([deviceId, vpn]) =>
    (vpn.tunnels ?? []).map((t) => ({ ...t, device_id: deviceId })),
  );

  return (
    <div className="space-y-4">
      <ClassicFallback
        title="The interactive topology map is not in the preview yet"
        description="The classic console draws the live graph: pan/zoom, compound sites, expandable tunnel bundles with VLAN sublanes, LLDP link evidence and alert overlays. The preview lists VPN-carrying devices instead."
        href="/admin/connections"
        label="Open the live map"
      />
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-xl border border-border bg-bg-card p-3.5">
          <div className="text-[11px] uppercase text-text-faint">Topology Nodes</div>
          <div className="text-xl font-mono font-bold text-text mt-0.5">{nodes.length}</div>
        </div>
        <div className="rounded-xl border border-border bg-bg-card p-3.5">
          <div className="text-[11px] uppercase text-text-faint">Active Links</div>
          <div className="text-xl font-mono font-bold text-sig-ok mt-0.5">
            {edges.filter((e) => e.status === 'up').length}
          </div>
        </div>
        <div className="rounded-xl border border-border bg-bg-card p-3.5">
          <div className="text-[11px] uppercase text-text-faint">Degraded / Down Links</div>
          <div className="text-xl font-mono font-bold text-sig-crit mt-0.5">
            {edges.filter((e) => e.status && e.status !== 'up').length}
          </div>
        </div>
        <div className="rounded-xl border border-border bg-bg-card p-3.5">
          <div className="text-[11px] uppercase text-text-faint">Total Tracked Circuits</div>
          <div className="text-xl font-mono font-bold text-accent mt-0.5">{edges.length}</div>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-bg-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-text">Live Topology Graph Matrix</h2>
          <span className="text-xs text-text-dim">Auto-refreshing every 20s</span>
        </div>

        {isLoading ? (
          <div className="h-64 flex items-center justify-center text-xs text-text-dim">
            Loading topology graph…
          </div>
        ) : nodes.length === 0 ? (
          <div className="h-64 flex flex-col items-center justify-center text-center">
            <Network className="h-8 w-8 text-text-mute mb-2" />
            <div className="text-sm font-semibold text-text">No topology nodes discovered yet</div>
            <p className="text-xs text-text-dim mt-1 max-w-md">
              Add devices and inter-device connections or enable LLDP/CDP/VPN discovery to populate the topology map.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {nodes.map((n: any, idx: number) => (
              <div
                key={n.id || idx}
                className="rounded-lg border border-border bg-bg-panel p-3.5 flex items-center justify-between"
              >
                <div>
                  <div className="font-semibold text-xs text-text">{n.name || n.label}</div>
                  <div className="font-mono text-[11px] text-text-dim">{n.ip_address || n.site_name || 'Node'}</div>
                </div>
                <span
                  className={cn(
                    'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
                    n.status === 'online' || n.status === 'up'
                      ? 'bg-sig-ok/15 text-sig-ok'
                      : 'bg-sig-crit/15 text-sig-crit'
                  )}
                >
                  {n.status || 'online'}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// SUB-TAB 2: CONNECTIONS + 5-TAB CONNECTION DETAIL DRAWER
// ============================================================================
function ConnectionsSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: connList, isLoading } = useQuery({
    queryKey: ['device-connections'],
    queryFn: () => apiFetch<ConnectionRecord[]>('/admin/api/connections'),
  });

  const connections = connList ?? [];

  const [selectedConn, setSelectedConn] = useState<ConnectionRecord | null>(null);
  const [detailTab, setDetailTab] = useState<'overview' | 'source' | 'dest' | 'evidence' | 'traffic'>('overview');

  const { data: connDetail } = useQuery({
    queryKey: ['connection-detail', selectedConn?.id],
    queryFn: () => apiFetch<any>(`/admin/api/connections/${selectedConn?.id}/detail`),
    enabled: Boolean(selectedConn?.id),
  });

  const [connToDelete, setConnToDelete] = useState<ConnectionRecord | null>(null);
  const deleteMutation = useMutation({
    mutationFn: async (id: number) => apiFetch(`/admin/api/connections/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      toast({ title: 'Connection deleted', variant: 'info' });
      setConnToDelete(null);
      // The drawer would otherwise keep re-fetching detail for a deleted row.
      setSelectedConn(null);
      queryClient.invalidateQueries({ queryKey: ['device-connections'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Delete failed', description: err.message, variant: 'error' });
    },
  });

  const columns = useMemo<ColumnDef<ConnectionRecord, unknown>[]>(
    () => [
      {
        accessorKey: 'name',
        header: 'Connection',
        cell: ({ row }) => (
          <div>
            <div className="font-semibold text-text">{row.original.name || `Link #${row.original.id}`}</div>
            <div className="text-[11px] text-text-dim flex items-center gap-1">
              <span>{row.original.source_device_name || `Dev #${row.original.source_device_id}`}</span>
              <ArrowRight className="h-3 w-3 text-accent" />
              <span>{row.original.dest_device_name || `Dev #${row.original.dest_device_id}`}</span>
            </div>
          </div>
        ),
      },
      {
        accessorKey: 'connection_type',
        header: 'Type',
        cell: ({ row }) => (
          <span className="rounded bg-bg-panel px-2 py-0.5 font-mono text-[10px] uppercase text-text-dim">
            {row.original.connection_type || 'ipsec'}
          </span>
        ),
      },
      {
        accessorKey: 'status',
        header: 'Status',
        cell: ({ row }) => (
          <span
            className={cn(
              'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
              row.original.status === 'up' || row.original.status === 'online'
                ? 'bg-sig-ok/15 text-sig-ok'
                : 'bg-sig-crit/15 text-sig-crit'
            )}
          >
            {row.original.status || 'unknown'}
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
              onClick={() => {
                setSelectedConn(row.original);
                setDetailTab('overview');
              }}
              className="rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text hover:bg-bg-hover"
            >
              Inspect
            </button>
            <button
              type="button"
              onClick={() => setConnToDelete(row.original)}
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

  const detailTabs: DrawerTab[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'source', label: 'Source Tunnels' },
    { id: 'dest', label: 'Dest Tunnels' },
    { id: 'evidence', label: 'Link Evidence' },
    { id: 'traffic', label: 'Traffic & Flows' },
  ];

  return (
    <div className="space-y-4">
      <ResponsiveDataView
        data={connections}
        columns={columns}
        isLoading={isLoading}
        onRowClick={(row) => {
          setSelectedConn(row);
          setDetailTab('overview');
        }}
        emptyTitle="No inter-device connections configured."
        renderMobileCard={(c) => (
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-sm text-text">{c.name || `Link #${c.id}`}</span>
              <span className="rounded bg-bg-panel px-2 py-0.5 text-[10px] uppercase text-text-dim">
                {c.status || 'unknown'}
              </span>
            </div>
            <div className="text-xs text-text-dim">
              {c.source_device_name || `#${c.source_device_id}`} → {c.dest_device_name || `#${c.dest_device_id}`}
            </div>
          </div>
        )}
      />

      <SlideOverDrawer
        open={Boolean(selectedConn)}
        onOpenChange={(open) => {
          if (!open) setSelectedConn(null);
        }}
        title={selectedConn?.name || `Connection #${selectedConn?.id}`}
        subtitle="5-tab connection health, tunnel correlation, and L2/L3 link evidence."
        size="xl"
        tabs={detailTabs}
        activeTab={detailTab}
        onTabChange={(id) => setDetailTab(id as typeof detailTab)}
      >
        <div className="space-y-3">
          <ClassicFallback
            title="Full connection detail lives in the classic console"
            description="Source/destination tunnel tables, per-tunnel traffic charts, LLDP/FDB/ARP evidence and the traffic-analysis charts are not rebuilt here yet."
            href={`/admin/connections/${selectedConn?.id ?? ''}`}
            label="Open connection detail"
          />
          <pre className="rounded-lg border border-border bg-bg-panel p-3 font-mono text-xs text-text overflow-x-auto">
            {JSON.stringify(connDetail ?? selectedConn ?? {}, null, 2)}
          </pre>
        </div>
      </SlideOverDrawer>

      <ConfirmDialog
        open={!!connToDelete}
        onOpenChange={(open) => {
          if (!open) setConnToDelete(null);
        }}
        title={`Delete connection ${connToDelete?.name || `#${connToDelete?.id ?? ''}`}?`}
        description="Discovery will re-add this link if the devices still report it. This cannot be undone."
        confirmLabel="Delete connection"
        destructive
        pending={deleteMutation.isPending}
        onConfirm={() => connToDelete && deleteMutation.mutate(connToDelete.id)}
      />
    </div>
  );
}

// ============================================================================
// SUB-TAB 3: IPSEC TUNNEL WIZARD & DEPLOY SAGA
// ============================================================================
function IpsecTunnelsSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: tunnelsList, isLoading } = useQuery({
    queryKey: ['ipsec-tunnels'],
    queryFn: () => apiFetch<IPSecTunnelIntent[]>('/admin/api/ipsec/tunnels'),
    refetchInterval: 15_000,
  });

  const tunnels = tunnelsList ?? [];

  const [selectedTunnel, setSelectedTunnel] = useState<IPSecTunnelIntent | null>(null);
  const [tunnelToDeploy, setTunnelToDeploy] = useState<IPSecTunnelIntent | null>(null);
  const [previewText, setPreviewText] = useState<any>(null);

  const actionMutation = useMutation({
    mutationFn: async ({ id, action }: { id: number; action: string }) =>
      apiFetch(`/admin/api/ipsec/tunnels/${id}/${action}`, { method: 'POST' }),
    onSuccess: (_, vars) => {
      toast({ title: `IPSec ${vars.action} triggered`, variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['ipsec-tunnels'] });
    },
    onError: (err: Error) => {
      toast({ title: 'IPSec action failed', description: err.message, variant: 'error' });
    },
  });

  const loadPreview = async (tunnel: IPSecTunnelIntent) => {
    setSelectedTunnel(tunnel);
    try {
      const res = await apiFetch<any>(`/admin/api/ipsec/tunnels/${tunnel.id}/preview`);
      setPreviewText(res);
    } catch (err) {
      setPreviewText({ error: err instanceof Error ? err.message : 'Preview failed' });
    }
  };

  const columns = useMemo<ColumnDef<IPSecTunnelIntent, unknown>[]>(
    () => [
      {
        accessorKey: 'name',
        header: 'Tunnel Intent',
        cell: ({ row }) => (
          <div>
            <div className="font-semibold text-text">{row.original.name}</div>
            <div className="text-[11px] font-mono text-text-dim">
              IKEv{row.original.ike_version || 2} • Updated {formatRelativeTime(row.original.updated_at)}
            </div>
          </div>
        ),
      },
      {
        accessorKey: 'deploy_state',
        header: 'Deploy Saga State',
        cell: ({ row }) => (
          <span className="rounded bg-bg-panel px-2 py-0.5 font-mono text-[10px] uppercase text-text-dim">
            {row.original.deploy_state || row.original.status || 'draft'}
          </span>
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex items-center justify-end gap-1.5">
            <button
              type="button"
              onClick={() => loadPreview(row.original)}
              className="flex items-center gap-1 rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text-dim hover:text-text"
            >
              <Eye className="h-3 w-3" /> Preview CLI
            </button>
            <button
              type="button"
              onClick={() => actionMutation.mutate({ id: row.original.id, action: 'preflight' })}
              className="flex items-center gap-1 rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text-dim hover:text-text"
            >
              <CheckCircle2 className="h-3 w-3 text-accent" /> Preflight
            </button>
            <button
              type="button"
              onClick={() => setTunnelToDeploy(row.original)}
              className="flex items-center gap-1 rounded border border-sig-ok/40 bg-sig-ok/10 px-2 py-1 text-[11px] font-semibold text-sig-ok"
            >
              <Play className="h-3 w-3" /> Deploy
            </button>
            <button
              type="button"
              onClick={() => actionMutation.mutate({ id: row.original.id, action: 'recheck' })}
              className="rounded border border-border bg-bg-panel p-1 text-text-dim hover:text-text"
              title="Re-verify SA liveness"
            >
              <RotateCcw className="h-3.5 w-3.5" />
            </button>
          </div>
        ),
      },
    ],
    [actionMutation]
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-text">IPSec Tunnel Intents & Deploy Saga ({tunnels.length})</h2>
          <p className="text-xs text-text-dim">
            Vendor-validated IPSec Phase 1/Phase 2 intents with read-only REST preflight, atomic deploy, and rollback snapshots.
          </p>
        </div>
      </div>

      <ResponsiveDataView
        data={tunnels}
        columns={columns}
        isLoading={isLoading}
        emptyTitle="No IPSec tunnel intents created yet."
        renderMobileCard={(t) => (
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-sm text-text">{t.name}</span>
              <span className="rounded bg-bg-panel px-2 py-0.5 text-[10px] uppercase text-text-dim">
                {t.deploy_state || 'draft'}
              </span>
            </div>
          </div>
        )}
      />

      <SlideOverDrawer
        open={Boolean(selectedTunnel)}
        onOpenChange={(open) => {
          if (!open) setSelectedTunnel(null);
        }}
        title={`IPSec Preview & Saga: ${selectedTunnel?.name ?? ''}`}
        size="xl"
      >
        <pre className="rounded-lg border border-border bg-bg-panel p-3 font-mono text-xs text-text overflow-x-auto whitespace-pre-wrap">
          {JSON.stringify(previewText ?? {}, null, 2)}
        </pre>
      </SlideOverDrawer>

      <ConfirmDialog
        open={!!tunnelToDeploy}
        onOpenChange={(open) => {
          if (!open) setTunnelToDeploy(null);
        }}
        title={`Deploy ${tunnelToDeploy?.name ?? 'this tunnel'} to the live firewall?`}
        description="Deploy pushes the validated Phase 1/Phase 2 configuration and can interrupt traffic on the tunnel."
        confirmLabel="Deploy tunnel"
        pending={actionMutation.isPending}
        onConfirm={() => {
          if (!tunnelToDeploy) return;
          actionMutation.mutate({ id: tunnelToDeploy.id, action: 'deploy' });
          setTunnelToDeploy(null);
        }}
      />
    </div>
  );
}
