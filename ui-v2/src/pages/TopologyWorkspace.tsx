import { lazy, Suspense, useCallback, useEffect, useState, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
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
  Undo2,
  Search,
} from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { SlideOverDrawer, DrawerTab } from '@/components/ui/slide-over-drawer';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import type { MapEdge, MapNode, MapSite } from '@/components/topology/topology-map';
import {
  IpsecPreviewPanel,
  type IpsecPreview,
} from '@/components/topology/ipsec-preview';
import {
  ConnectionEvidence,
  ConnectionOverview,
  ConnectionTraffic,
  ConnectionTunnels,
  type ConnectionDetail,
} from '@/components/topology/connection-detail-panels';
import { activeTopologyDevices, linkState } from '@/lib/topology';
import {
  ConnectionEditor,
  type ConnectionDevice,
} from '@/components/topology/connection-editor';
import { SkeletonValue } from '@/components/ui/skeleton';

// Cytoscape + fcose are ~400 KB; load them only when the map tab is opened.
const TopologyMap = lazy(() =>
  import('@/components/topology/topology-map').then((mod) => ({ default: mod.TopologyMap })),
);
import { useToast } from '@/components/ui/toast';
import { ColumnDef } from '@tanstack/react-table';

type TopologyTab = 'map' | 'connections' | 'ipsec';

interface TopologyDevice {
  id: number;
  name: string;
  ip_address?: string;
  site_id?: number | null;
  status?: string;
  // Retirement is a soft delete: the row survives, but the device is no longer
  // polled and must not be drawn on the map. /admin/api/devices is unscoped,
  // so the filter is applied by activeTopologyDevices().
  retired_at?: string | null;
}

interface TopologySite {
  id: number;
  name: string;
}

interface ConnectionStatusSummary {
  devices?: Array<{ id: number; alert_severity?: string }>;
}

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
  source_if_name?: string;
  dest_if_name?: string;
  // The notes the operator wrote on the link. Editable in the connection
  // editor, so the list has to carry it.
  notes?: string;
}

// The LIST response for an IPSec tunnel intent.
//
// The field names are the model's, not invented ones: the tunnel row promotes
// its endpoints as a_device_id / b_device_id (internal/models/models.go), and
// the server appends deletable / editable. The previous names here
// (endpoint_a_device_id, endpoint_b_device_id, deploy_state) matched NOTHING
// on the wire, which is why the "Deploy Saga State" column sorted to a no-op
// and the IKE version rendered as a hardcoded "IKEv2" for every tunnel.
//
// ike_version is the intent's REAL version ("ikev1" / "ikev2"), decoded from
// the stored intent by the server. It is a string, not a number.
interface IPSecTunnelIntent {
  id: number;
  name: string;
  enabled?: boolean;
  status?: string;
  last_error?: string;
  a_device_id?: number;
  b_device_id?: number;
  a_vendor?: string;
  b_vendor?: string;
  ike_version?: string;
  last_deployed_at?: string;
  created_at?: string;
  updated_at?: string;
  // deletable is the SERVER's rule (the tunnel carries no deployment), not a
  // status approximation — the deploy record is never serialized, so the
  // client cannot work it out for itself.
  deletable?: boolean;
  editable?: boolean;
}

export function TopologyWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = (searchParams.get('tab') as TopologyTab) || 'map';

  const setTab = (tab: TopologyTab) => {
    setSearchParams({ tab }, { replace: true });
  };

  // Stable identity: the map's Cytoscape init effect depends on this callback
  // and must not tear down the graph when the page re-renders.
  const openConnection = useCallback(
    (connectionId: number) =>
      setSearchParams({ tab: 'connections', conn: String(connectionId) }, { replace: true }),
    [setSearchParams],
  );

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
                ? 'bg-bg-card text-text shadow-xs border border-border'
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
                ? 'bg-bg-card text-text shadow-xs border border-border'
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
                ? 'bg-bg-card text-text shadow-xs border border-border'
                : 'text-text-dim hover:text-text'
            )}
          >
            <Shield className="h-3.5 w-3.5 text-accent" />
            IPSec Tunnels
          </button>
        </div>
      </div>

      {activeTab === 'map' && <NetworkMapSubTab onOpenConnection={openConnection} />}
      {activeTab === 'connections' && <ConnectionsSubTab />}
      {activeTab === 'ipsec' && <IpsecTunnelsSubTab />}
    </div>
  );
}

// ============================================================================
// SUB-TAB 1: NETWORK MAP
// ============================================================================
function NetworkMapSubTab({
  onOpenConnection,
}: {
  onOpenConnection?: (connectionId: number) => void;
}) {
  const navigate = useNavigate();
  const { data: mapData, isLoading } = useQuery({
    queryKey: ['vpn-map-data'],
    queryFn: () => apiFetch<any>('/admin/api/connections/vpn-map'),
    refetchInterval: 20_000,
  });
  const { data: deviceList, isLoading: devicesLoading } = useQuery({
    queryKey: ['devices-for-topology'],
    queryFn: () => apiFetch<TopologyDevice[]>('/admin/api/devices'),
    refetchInterval: 30_000,
  });
  const { data: siteList, isLoading: sitesLoading } = useQuery({
    queryKey: ['sites-for-topology'],
    queryFn: () => apiFetch<TopologySite[]>('/admin/api/sites'),
  });
  const { data: connList, isLoading: connsLoading } = useQuery({
    queryKey: ['device-connections'],
    queryFn: () => apiFetch<ConnectionRecord[]>('/admin/api/connections'),
    refetchInterval: 30_000,
  });
  // Alerts-only severity for the map's node rings. The summary endpoint
  // deliberately excludes offline/down-link state (already shown by the node
  // and edge colours), unlike the NOC composite worst_severity.
  const { data: statusSummary } = useQuery({
    queryKey: ['connection-status-summary'],
    queryFn: () =>
      apiFetch<ConnectionStatusSummary>('/admin/api/connections/status-summary'),
    refetchInterval: 30_000,
  });
  const { severityByDevice, severitySignature } = useMemo(() => {
    const map = new Map<number, string>();
    for (const device of statusSummary?.devices ?? []) {
      if (device.alert_severity) map.set(device.id, device.alert_severity);
    }
    const signature = Array.from(map.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([id, severity]) => `${id}:${severity}`)
      .join(',');
    return { severityByDevice: map, severitySignature: signature };
  }, [statusSummary]);

  const openDevice = useCallback(
    (deviceId: number) => navigate(`/devices/${deviceId}`),
    [navigate],
  );

  // Rebuild the graph only when the underlying data changes: a refetch that
  // returns structurally identical JSON keeps these references stable (React
  // Query structural sharing), so pan/zoom and selection survive the poll.
  const { nodes, edges, mapSites, deadPeers, retiredCount, activeDeviceCount } = useMemo(() => {
    // The fleet filter. /admin/api/devices is deliberately unscoped (a retired
    // device must still be nameable on its own page), so the map applies the
    // retirement filter itself — otherwise a decommissioned device is drawn as
    // a live node, painted with the status frozen at retire time, and its
    // tunnels are drawn from it.
    const allDevices = deviceList ?? [];
    const devices = activeTopologyDevices(allDevices);
    const retiredCount = allDevices.length - devices.length;
    const sites = siteList ?? [];
    const connections = connList ?? [];
    // GetVPNMapData is keyed by device ID ("7" -> {total, up, down, tunnels}).
    const vpnMap = (mapData ?? {}) as Record<
      string,
      {
        tunnels?: Array<{
          tunnel_name: string;
          status: string;
          remote_ip?: string;
          matched_name?: string;
          matched_device_id?: number;
          tunnel_group?: string;
          // peer_state: "active" | "retired" | "removed" (the far end's
          // lifecycle). peer_name: the far end's device name.
          peer_state?: string;
          peer_name?: string;
        }>;
      }
    >;

    const siteName = new Map(sites.map((site) => [site.id, site.name]));
    const deviceById = new Map(devices.map((device) => [String(device.id), device]));

    const siteNodes: MapSite[] = sites.map((site) => ({ id: site.id, name: site.name }));
    const deviceNodes: MapNode[] = devices.map((device) => ({
      id: String(device.id),
      deviceId: device.id,
      label: device.name,
      kind: 'device',
      siteId: device.site_id ?? null,
      siteName: device.site_id ? siteName.get(device.site_id) : undefined,
      status: device.status,
      ip: device.ip_address,
    }));

    const links: MapEdge[] = [];
    const external = new Map<string, MapNode>();
    // Tunnels whose far end is a decommissioned device. They are NOT drawn as a
    // phantom branch, but they are listed so the operator can see that a
    // cleanup is outstanding.
    const deadPeers: Array<{
      deviceName: string;
      tunnelName: string;
      peerName: string;
      peerState: string;
    }> = [];

    for (const connection of connections) {
      const source = String(connection.source_device_id);
      const target = String(connection.dest_device_id);
      if (!deviceById.has(source) || !deviceById.has(target)) continue;
      const ports = [connection.source_if_name, connection.dest_if_name]
        .filter(Boolean)
        .join(' ↔ ');
      links.push({
        id: `conn-${connection.id}`,
        source,
        target,
        kind: 'connection',
        label: ports ? `${connection.connection_type} · ${ports}` : connection.connection_type,
        status: connection.status,
        connectionId: connection.id,
      });
    }

    for (const [deviceId, vpn] of Object.entries(vpnMap)) {
      if (!deviceById.has(deviceId)) continue;
      for (const [idx, tunnel] of (vpn.tunnels ?? []).entries()) {
        // A retired or REMOVED peer is dead: the tunnel can never come up, and
        // the device it pointed at is decommissioned. Drawing it produced a
        // PHANTOM external node — the dead peer's IP, status down, edged from
        // the live firewall. Both the node and the edge are skipped: skipping
        // only one leaves either an orphan node or a dangling edge. The tunnel
        // is listed below the map instead, so the information is not lost — it
        // just stops being a branch on the graph.
        const peerState = tunnel.peer_state;
        if (peerState === 'retired' || peerState === 'removed') {
          deadPeers.push({
            deviceName: deviceById.get(deviceId)?.name ?? deviceId,
            tunnelName: tunnel.tunnel_name,
            peerName: tunnel.peer_name || '(device removed)',
            peerState,
          });
          continue;
        }
        // matched_device_id is the backend's authoritative peer resolution
        // (provisioned peer wins; a dialup remote_ip is a NAT gateway, not the
        // peer). Re-deriving it from remote_ip picks the wrong device.
        const remoteDevice = tunnel.matched_device_id
          ? deviceById.get(String(tunnel.matched_device_id))
          : undefined;
        const remote = tunnel.remote_ip ?? '';
        const matched = tunnel.matched_name ?? '';
        let targetId = remoteDevice ? String(remoteDevice.id) : '';
        if (!targetId) {
          const key = remote || matched || `unknown-${deviceId}-${idx}`;
          targetId = `ext-${key}`;
          if (!external.has(targetId)) {
            external.set(targetId, {
              id: targetId,
              label: remote || matched || 'remote peer',
              kind: 'external',
              status: tunnel.status,
            });
          }
        }
        links.push({
          id: `tunnel-${deviceId}-${idx}`,
          source: deviceId,
          target: targetId,
          kind: 'tunnel',
          label: tunnel.tunnel_name,
          status: tunnel.status,
        });
      }
    }

    return {
      nodes: [...deviceNodes, ...external.values()],
      edges: links,
      mapSites: siteNodes,
      deadPeers,
      retiredCount,
      activeDeviceCount: devices.length,
    };
  }, [deviceList, siteList, connList, mapData]);

  const upLinks = edges.filter((edge) => linkState(edge.status) === 'up').length;
  const downLinks = edges.filter((edge) => linkState(edge.status) === 'down').length;
  // The link counters are only meaningful once both link sources have
  // answered: before that they are a rendered ZERO, which reads as "no links
  // are down" rather than "not known yet".
  const linksLoading = connsLoading || sitesLoading;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-xl border border-border bg-bg-card p-3.5">
          <div className="text-[11px] uppercase text-text-faint">Devices</div>
          <div className="mt-0.5 text-xl font-mono font-bold text-text">
            <SkeletonValue loading={devicesLoading} width="w-10" />
            {devicesLoading ? null : activeDeviceCount}
          </div>
          {retiredCount > 0 && (
            <div className="mt-0.5 text-[10px] text-text-faint">
              {retiredCount} retired hidden
            </div>
          )}
        </div>
        <div className="rounded-xl border border-border bg-bg-card p-3.5">
          <div className="text-[11px] uppercase text-text-faint">Up Links</div>
          <div className="mt-0.5 text-xl font-mono font-bold text-sig-ok">
            <SkeletonValue loading={linksLoading} width="w-10" />
            {linksLoading ? null : upLinks}
          </div>
        </div>
        <div className="rounded-xl border border-border bg-bg-card p-3.5">
          <div className="text-[11px] uppercase text-text-faint">Down / Degraded</div>
          <div className="mt-0.5 text-xl font-mono font-bold text-sig-crit">
            <SkeletonValue loading={linksLoading} width="w-10" />
            {linksLoading ? null : downLinks}
          </div>
        </div>
        <div className="rounded-xl border border-border bg-bg-card p-3.5">
          <div className="text-[11px] uppercase text-text-faint">Links & Tunnels</div>
          <div className="mt-0.5 text-xl font-mono font-bold text-accent">
            <SkeletonValue loading={linksLoading} width="w-10" />
            {linksLoading ? null : edges.length}
          </div>
        </div>
      </div>

      {isLoading ? (
        <div className="rounded-xl border border-border bg-bg-card p-10 text-center text-xs text-text-dim">
          Loading topology…
        </div>
      ) : (
        <Suspense
          fallback={
            <div className="rounded-xl border border-border bg-bg-card p-10 text-center text-xs text-text-dim">
              Loading the interactive map…
            </div>
          }
        >
          <TopologyMap
            sites={mapSites}
            nodes={nodes}
            edges={edges}
            severityByDevice={severityByDevice}
            severitySignature={severitySignature}
            onSelectDevice={openDevice}
            onSelectConnection={onOpenConnection}
          />
        </Suspense>
      )}

      {deadPeers.length > 0 && (
        <div className="rounded-xl border border-sig-warn/40 bg-sig-warn/5 p-3.5">
          <div className="text-[11px] uppercase tracking-wide text-sig-warn">
            {deadPeers.length} tunnel{deadPeers.length === 1 ? '' : 's'} point at a decommissioned peer
          </div>
          <ul className="mt-1.5 space-y-0.5 text-[11px] text-text-dim">
            {deadPeers.map((d, i) => (
              <li key={`${d.deviceName}-${d.tunnelName}-${i}`}>
                <span className="font-mono text-text">{d.deviceName}</span> →{' '}
                <span className="font-mono">{d.tunnelName}</span> · peer{' '}
                <span className="font-mono">{d.peerName}</span>{' '}
                <span className="text-text-faint">({d.peerState})</span>
              </li>
            ))}
          </ul>
          <p className="mt-1.5 text-[11px] text-text-faint">
            These tunnels are not drawn: the peer can never come up. Roll the tunnel back from the
            IPSec Tunnels tab to remove its configuration from the live device.
          </p>
        </div>
      )}

      <p className="text-[11px] text-text-faint">
        Links come from declared inter-device connections and live IPSec tunnels. Drag nodes to
        arrange the map, then use Save layout to keep those positions in this browser (Reset restores
        the automatic layout). Parallel links and tunnels collapse into bundles — click one to expand
        its members; click a link to open its detail, where the Link Evidence tab lists the member
        ports and VLANs.
      </p>
    </div>
  );
}

// ============================================================================
// SUB-TAB 2: CONNECTIONS + 5-TAB CONNECTION DETAIL DRAWER
// ============================================================================
function ConnectionsSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();

  const { data: connList, isLoading } = useQuery({
    queryKey: ['device-connections'],
    queryFn: () => apiFetch<ConnectionRecord[]>('/admin/api/connections'),
  });

  // The device list, for the connection editor's endpoint pickers.
  const { data: deviceList } = useQuery({
    queryKey: ['devices-for-connections'],
    queryFn: () => apiFetch<ConnectionDevice[]>('/admin/api/devices'),
  });

  const connections = connList ?? [];

  const [selectedConn, setSelectedConn] = useState<ConnectionRecord | null>(null);
  // The connection being created or edited in the editor drawer.
  const [connToEdit, setConnToEdit] = useState<ConnectionRecord | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);

  // Arriving from the map's edge click: open that connection, then drop the
  // one-shot query param so closing the drawer doesn't reopen it.
  const requestedConn = Number(searchParams.get('conn') ?? '');
  useEffect(() => {
    if (!requestedConn || !connList) return;
    const match = connList.find((conn) => conn.id === requestedConn);
    if (match) setSelectedConn(match);
    setSearchParams({ tab: 'connections' }, { replace: true });
  }, [requestedConn, connList, setSearchParams]);
  const [detailTab, setDetailTab] = useState<'overview' | 'source' | 'dest' | 'evidence' | 'traffic'>('overview');

  const { data: connDetail, isError: connDetailError } = useQuery({
    queryKey: ['connection-detail', selectedConn?.id],
    queryFn: () => apiFetch<ConnectionDetail>(`/admin/api/connections/${selectedConn?.id}/detail`),
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
              onClick={() => {
                setConnToEdit(row.original);
                setEditorOpen(true);
              }}
              className="rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text hover:bg-bg-hover"
            >
              Edit
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
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-text-dim">
          Declared links between monitored devices. Auto-detected links appear here
          too, and can be inspected but not edited.
        </p>
        <button
          type="button"
          onClick={() => {
            setConnToEdit(null);
            setEditorOpen(true);
          }}
          className="rounded-md border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-semibold text-accent"
        >
          New connection
        </button>
      </div>

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

      <ConnectionEditor
        open={editorOpen}
        onOpenChange={setEditorOpen}
        connection={connToEdit}
        devices={deviceList ?? []}
        onSaved={() => {
          queryClient.invalidateQueries({ queryKey: ['device-connections'] });
          queryClient.invalidateQueries({ queryKey: ['vpn-map-data'] });
        }}
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
        {connDetailError && (
          <div className="mb-3 rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit">
            Could not load connection detail. It may have been deleted or the endpoint retired.
          </div>
        )}
        {detailTab === 'overview' && <ConnectionOverview detail={connDetail} />}
        {detailTab === 'source' && (
          <ConnectionTunnels tunnels={connDetail?.source_tunnels} side="source" />
        )}
        {detailTab === 'dest' && (
          <ConnectionTunnels tunnels={connDetail?.dest_tunnels} side="destination" />
        )}
        {detailTab === 'evidence' && <ConnectionEvidence detail={connDetail} />}
        {detailTab === 'traffic' && selectedConn && (
          <ConnectionTraffic
            key={selectedConn.id}
            connectionId={selectedConn.id}
            hasFlowData={connDetail?.has_flow_data}
          />
        )}
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

// IPSEC_ROLLBACKABLE mirrors the server's rollback fromStatuses (degraded, up,
// down, error, rollback_failed, deploying). The Rollback button is offered only
// for those, so the UI never shows an action the server would refuse.
const IPSEC_ROLLBACKABLE = new Set([
  'degraded',
  'up',
  'down',
  'error',
  'rollback_failed',
  'deploying',
]);

// IPSEC_ROLLBACK_TERMINAL: the two statuses a rollback can settle on.
const IPSEC_ROLLBACK_TERMINAL = new Set(['rolled_back', 'rollback_failed']);

// IPSEC_DELETABLE mirrors the legacy console's delete rule (admin-ipsec.js
// canDelete): the intent row can only be removed once the tunnel carries no
// deployment — a rollback clears the deploy record, and the server refuses the
// delete with "roll back before deleting" otherwise.
//
// The server states the rule directly on each row (`deletable`), so the button
// follows THAT rather than guessing from the status: a partially-deployed
// `error` tunnel still carries its record, and the server would refuse the
// delete even though the status says it is allowed.
const IPSEC_DELETABLE = new Set(['draft', 'rolled_back', 'error']);

// ipsecTunnelDeletable reports whether the tunnel intent may be deleted.
//
// The server states its own rule on each row (`deletable` = the tunnel carries
// no deployment). The status set is only the fallback for a server that
// predates the field — the same approximation the legacy console makes.
function ipsecTunnelDeletable(t: IPSecTunnelIntent): boolean {
  if (typeof t.deletable === 'boolean') return t.deletable;
  return IPSEC_DELETABLE.has(ipsecTunnelStatus(t));
}

// ipsecDeleteDisabledReason explains, per status, what a delete is waiting for.
function ipsecDeleteDisabledReason(t: IPSecTunnelIntent): string {
  const status = ipsecTunnelStatus(t);
  if (status === 'deploying' || status === 'rolling_back') {
    return 'A deploy or rollback is in flight — wait for it to settle';
  }
  return 'Roll back before deleting — the tunnel still has a deployment recorded';
}

// A discovered object: one of the tunnel's objects the DEVICE reported, with
// the uuid the removal will address it by.
interface IPSecDiscoveredObject {
  token: string;
  object_type: string;
  uuid: string;
  description: string;
  matched?: Record<string, string>;
  unverified?: string[];
  duplicate?: boolean;
}

// The discovery report: what the device holds for this tunnel. It is the
// operator's review BEFORE anything is removed.
interface IPSecDiscoveryReport {
  tunnel_id: number;
  end: number;
  status: 'none' | 'pending' | 'complete' | 'failed';
  found: IPSecDiscoveredObject[];
  unresolved: string[];
  unsearched?: string[];
  duplicates?: string[];
  captures: Record<string, string>;
  note?: string;
}

function ipsecTunnelStatus(t: IPSecTunnelIntent): string {
  // `status` is the field the server sends. There is no `deploy_state` on the
  // wire — the deploy record is never serialized — so a fallback to it would
  // have been a fallback to nothing.
  return (t.status || 'draft').toLowerCase();
}

// The IKE version the tunnel was actually built with. The server decodes it
// from the stored intent; an intent that cannot be decoded reports nothing,
// and nothing is shown rather than a guessed "IKEv2".
function ipsecTunnelIKE(t: IPSecTunnelIntent): string | null {
  const raw = (t.ike_version || '').trim().toLowerCase();
  if (raw === 'ikev1' || raw === '1') return 'IKEv1';
  if (raw === 'ikev2' || raw === '2') return 'IKEv2';
  return null;
}

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
  const [tunnelToRollback, setTunnelToRollback] = useState<IPSecTunnelIntent | null>(null);
  const [tunnelToDelete, setTunnelToDelete] = useState<IPSecTunnelIntent | null>(null);
  const [previewText, setPreviewText] = useState<IpsecPreview | null>(null);

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

  // Rollback reverses the deployed configuration on the devices. The POST only
  // STARTS the saga — the terminal status is poll-driven, so the UI polls the
  // deploy endpoint until the rollback settles (the legacy admin console does
  // the same). Without this the operator had no way to run a rollback from the
  // V2 console at all.
  const rollbackMutation = useMutation({
    mutationFn: async (tunnel: IPSecTunnelIntent) => {
      await apiFetch(`/admin/api/ipsec/tunnels/${tunnel.id}/rollback`, { method: 'POST' });
      for (let attempt = 0; attempt < 60; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        const res = await apiFetch<{ status?: string; note?: string }>(
          `/admin/api/ipsec/tunnels/${tunnel.id}/deploy`,
        );
        const status = (res?.status || '').toLowerCase();
        if (IPSEC_ROLLBACK_TERMINAL.has(status)) return res;
      }
      return null;
    },
    onSuccess: (res, tunnel) => {
      const status = (res?.status || '').toLowerCase();
      if (status === 'rolled_back') {
        toast({
          title: `IPSec rollback complete: ${tunnel.name}`,
          description: res?.note,
          variant: 'success',
        });
      } else if (status) {
        toast({
          title: `IPSec rollback ended as ${status}: ${tunnel.name}`,
          description: res?.note,
          variant: 'error',
        });
      } else {
        toast({
          title: `IPSec rollback still in progress: ${tunnel.name}`,
          description: 'The rollback has not reached a terminal state yet — refresh to check again.',
          variant: 'warning',
        });
      }
      queryClient.invalidateQueries({ queryKey: ['ipsec-tunnels'] });
    },
    onError: (err: Error) => {
      toast({ title: 'IPSec rollback failed', description: err.message, variant: 'error' });
    },
  });

  // Find the tunnel's objects ON THE DEVICE. The removal addresses them by
  // their device-assigned uuid, and those uuids come from the apply's
  // response — which may be long gone. This asks the device instead, and shows
  // what it holds BEFORE anything is removed.
  const [discovery, setDiscovery] = useState<IPSecDiscoveryReport | null>(null);
  const discoverMutation = useMutation({
    mutationFn: async (tunnel: IPSecTunnelIntent) => {
      await apiFetch(`/admin/api/ipsec/tunnels/${tunnel.id}/discover`, { method: 'POST' });
      for (let attempt = 0; attempt < 30; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        const rep = await apiFetch<IPSecDiscoveryReport>(
          `/admin/api/ipsec/tunnels/${tunnel.id}/discover`,
        );
        if (rep?.status && rep.status !== 'pending') return rep;
      }
      return null;
    },
    onSuccess: (rep, tunnel) => {
      if (!rep) {
        toast({
          title: `The device did not answer for ${tunnel.name}`,
          description: 'The probe is still running — try again in a moment.',
          variant: 'warning',
        });
        return;
      }
      setDiscovery(rep);
      if (rep.status === 'failed') {
        toast({
          title: `The device could not be searched for ${tunnel.name}`,
          description: rep.note,
          variant: 'error',
        });
        return;
      }
      toast({
        title:
          rep.found.length > 0
            ? `Found ${rep.found.length} object(s) for ${tunnel.name} on the device`
            : `The device reports no object for ${tunnel.name}`,
        description: rep.note,
        variant: rep.found.length > 0 ? 'success' : 'info',
      });
    },
    onError: (err: Error) => {
      toast({ title: 'The device search failed', description: err.message, variant: 'error' });
    },
  });

  // Delete removes the tunnel INTENT from Firewall-Mon. It never touches the
  // devices — the rollback does that — which is why the server refuses the
  // delete while a deployment is still recorded.
  const deleteTunnelMutation = useMutation({
    mutationFn: async (id: number) => apiFetch(`/admin/api/ipsec/tunnels/${id}`, { method: 'DELETE' }),
    onSuccess: (_res, id) => {
      const name = tunnels.find((t) => t.id === id)?.name;
      toast({ title: `Tunnel deleted${name ? `: ${name}` : ''}`, variant: 'info' });
      setTunnelToDelete(null);
      queryClient.invalidateQueries({ queryKey: ['ipsec-tunnels'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Delete failed', description: err.message, variant: 'error' });
    },
  });

  const loadPreview = async (tunnel: IPSecTunnelIntent) => {
    setSelectedTunnel(tunnel);
    // Clear the previous tunnel's render so the drawer cannot show it under the
    // new tunnel's title while the fetch is in flight.
    setPreviewText(null);
    try {
      const res = await apiFetch<IpsecPreview>(`/admin/api/ipsec/tunnels/${tunnel.id}/preview`);
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
        cell: ({ row }) => {
          const ike = ipsecTunnelIKE(row.original);
          return (
            <div>
              <div className="font-semibold text-text">{row.original.name}</div>
              <div className="text-[11px] font-mono text-text-dim">
                {ike ? `${ike} • ` : ''}
                Updated {formatRelativeTime(row.original.updated_at)}
              </div>
            </div>
          );
        },
      },
      {
        // `status` is the field the server sends. The old accessorKey was
        // `deploy_state`, which is not on the wire at all, so sorting this
        // column compared undefined against undefined and never reordered
        // anything.
        accessorKey: 'status',
        header: 'Deploy Saga State',
        cell: ({ row }) => (
          <span className="rounded bg-bg-panel px-2 py-0.5 font-mono text-[10px] uppercase text-text-dim">
            {ipsecTunnelStatus(row.original)}
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
            {IPSEC_ROLLBACKABLE.has(ipsecTunnelStatus(row.original)) && (
              <button
                type="button"
                onClick={() => discoverMutation.mutate(row.original)}
                className="flex items-center gap-1 rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text-dim hover:text-text"
                title="Ask the device where this tunnel's objects are (read-only)"
              >
                <Search className="h-3 w-3" /> Find on device
              </button>
            )}
            {IPSEC_ROLLBACKABLE.has(ipsecTunnelStatus(row.original)) && (
              <button
                type="button"
                onClick={() => setTunnelToRollback(row.original)}
                className="flex items-center gap-1 rounded border border-sig-warn/40 bg-sig-warn/10 px-2 py-1 text-[11px] font-semibold text-sig-warn"
                title="Remove the deployed configuration from the devices"
              >
                <Undo2 className="h-3 w-3" /> Rollback
              </button>
            )}
            <button
              type="button"
              onClick={() => setTunnelToDelete(row.original)}
              disabled={!ipsecTunnelDeletable(row.original)}
              className={cn(
                'flex items-center gap-1 rounded border border-border bg-bg-panel px-2 py-1 text-[11px]',
                ipsecTunnelDeletable(row.original)
                  ? 'text-sig-crit hover:bg-sig-crit/10'
                  : 'cursor-not-allowed text-text-faint opacity-60',
              )}
              title={
                ipsecTunnelDeletable(row.original)
                  ? 'Delete this tunnel intent'
                  : ipsecDeleteDisabledReason(row.original)
              }
            >
              <Trash2 className="h-3 w-3" /> Delete
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
                {ipsecTunnelStatus(t)}
              </span>
            </div>
          </div>
        )}
      />

      {discovery && discovery.found.length > 0 && (
        <div className="rounded-xl border border-border bg-bg-card p-3.5">
          <div className="text-[11px] uppercase tracking-wide text-text-dim">
            On the device — tunnel #{discovery.tunnel_id}, end {discovery.end === 0 ? 'A' : 'B'}
          </div>
          <p className="mt-1 text-[11px] text-text-dim">
            These objects carry this tunnel's name. Rolling back removes them by the uuid below.
          </p>
          <ul className="mt-2 space-y-1 text-[11px]">
            {discovery.found.map((o) => (
              <li key={`${o.token}-${o.uuid}`} className="flex flex-wrap items-baseline gap-2">
                <span className="rounded bg-bg-panel px-1.5 py-0.5 font-mono text-[10px] uppercase text-text-dim">
                  {o.object_type}
                </span>
                <span className="font-mono text-text">{o.uuid}</span>
                <span className="font-mono text-text-dim">{o.description}</span>
                {o.unverified && o.unverified.length > 0 && (
                  <span className="text-sig-warn">
                    not confirmed by: {o.unverified.join(', ')}
                  </span>
                )}
                {o.duplicate && (
                  <span className="text-sig-crit">
                    duplicate — the removal addresses only one of them
                  </span>
                )}
              </li>
            ))}
          </ul>
          {discovery.unresolved.length > 0 && (
            <p className="mt-2 text-[11px] text-sig-warn">
              Not located on the device: {discovery.unresolved.join(', ')} — those objects were not
              found, so they cannot be removed by uuid.
            </p>
          )}
          {discovery.unsearched && discovery.unsearched.length > 0 && (
            <p className="mt-1 text-[11px] text-sig-crit">
              Not searched: {discovery.unsearched.join(', ')} — the device did not answer for those,
              so their absence is not proven.
            </p>
          )}
          {discovery.duplicates && discovery.duplicates.length > 0 && (
            <p className="mt-1 text-[11px] text-sig-crit">
              Duplicated on the device: {discovery.duplicates.join(', ')} — the removal addresses one
              of each, so the other stays behind.
            </p>
          )}
          {discovery.note && <p className="mt-1 text-[11px] text-text-faint">{discovery.note}</p>}
        </div>
      )}

      <SlideOverDrawer
        open={Boolean(selectedTunnel)}
        onOpenChange={(open) => {
          if (!open) setSelectedTunnel(null);
        }}
        title={`IPSec Preview & Saga: ${selectedTunnel?.name ?? ''}`}
        size="xl"
      >
        <IpsecPreviewPanel preview={previewText} />
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

      <ConfirmDialog
        open={!!tunnelToRollback}
        onOpenChange={(open) => {
          if (!open) setTunnelToRollback(null);
        }}
        title={`Roll back ${tunnelToRollback?.name ?? 'this tunnel'}?`}
        description="Rollback removes this tunnel's Phase 1/Phase 2 configuration from every endpoint it was deployed to (connection, local/remote auth, child SAs, PSK and the floating firewall rules). Traffic on the tunnel stops. An endpoint that has been retired or removed is skipped — its objects, if any, must be cleaned by hand."
        confirmLabel="Roll back tunnel"
        pending={rollbackMutation.isPending}
        onConfirm={() => {
          if (!tunnelToRollback) return;
          rollbackMutation.mutate(tunnelToRollback);
          setTunnelToRollback(null);
        }}
      />

      <ConfirmDialog
        open={!!tunnelToDelete}
        onOpenChange={(open) => {
          if (!open) setTunnelToDelete(null);
        }}
        title={`Delete ${tunnelToDelete?.name ?? 'this tunnel'}?`}
        description="This removes the tunnel intent from Firewall-Mon. It does not touch the devices — roll the tunnel back first so its configuration is removed there too. This cannot be undone."
        confirmLabel="Delete tunnel"
        destructive
        pending={deleteTunnelMutation.isPending}
        onConfirm={() => tunnelToDelete && deleteTunnelMutation.mutate(tunnelToDelete.id)}
      />
    </div>
  );
}
