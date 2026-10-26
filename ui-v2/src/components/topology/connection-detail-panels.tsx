import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, Cable, ShieldCheck } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatBytes, formatCompactNumber } from '@/lib/utils';
import { formatBitsPerSecond } from '@/lib/chart';
import { bucketSeconds } from '@/lib/chart';
import { TimeSeriesChart } from '@/components/charts/time-series-chart';
import { DetailSection } from '@/components/ui/detail-section';
import { ConnectionBridge } from '@/components/topology/connection-bridge';

export interface TunnelRow {
  id?: number;
  tunnel_name: string;
  tunnel_type?: string;
  remote_ip?: string;
  status?: string;
  bytes_in?: number;
  bytes_out?: number;
  packets_in?: number;
  packets_out?: number;
  phase1_name?: string;
  local_subnet?: string;
  remote_subnet?: string;
  tunnel_uptime?: number;
  interface_name?: string;
  mode?: string;
}

export interface InterfaceRow {
  device_id?: number;
  device_name?: string;
  if_name?: string;
  if_index?: number;
  ip_address?: string;
  subnet?: string;
  kind?: string;
  vlan_id?: number;
  parent?: string;
  speed?: number;
  status?: string;
  in_bytes?: number;
  out_bytes?: number;
}

export interface OverlayRow {
  device_id?: number;
  device_name?: string;
  type?: string;
  name?: string;
  vni?: number;
  carrier_iface?: string;
  dest_port?: number;
  remote_vteps?: string[];
  status?: string;
  in_bytes?: number;
  out_bytes?: number;
}

export interface EvidenceRow {
  tier?: string;
  device_id?: number;
  device_name?: string;
  fresh?: boolean;
  local_if_name?: string;
  local_if_index?: number;
  remote_mac?: string;
  remote_ip?: string;
  remote_port?: string;
  remote_sysname?: string;
  vlan_id?: number;
  timestamp?: string;
  note?: string;
}

export interface Phase2Row {
  source_tunnel?: string;
  dest_tunnel?: string;
  source_phase1?: string;
  dest_phase1?: string;
  local_subnet?: string;
  remote_subnet?: string;
  source_status?: string;
  dest_status?: string;
  src_bytes_in?: number;
  src_bytes_out?: number;
  dst_bytes_in?: number;
  dst_bytes_out?: number;
  src_uptime?: number;
  dst_uptime?: number;
}

export interface ConnectionDetail {
  connection?: {
    id: number;
    name?: string;
    connection_type?: string;
    status?: string;
    latency?: number;
    source_device_id?: number;
    dest_device_id?: number;
    source_device?: { id?: number; name?: string; ip_address?: string };
    dest_device?: { id?: number; name?: string; ip_address?: string };
  };
  family?: string;
  source_tunnels?: TunnelRow[];
  dest_tunnels?: TunnelRow[];
  interfaces?: InterfaceRow[];
  overlays?: OverlayRow[];
  evidence?: EvidenceRow[];
  total_bytes_in?: number;
  total_bytes_out?: number;
  throughput_in?: number;
  throughput_out?: number;
  has_flow_data?: boolean;
  phase2_matches?: Phase2Row[];
  window_hours?: number;
  source_window?: { tunnel_name?: string; in_bytes?: number; out_bytes?: number };
  dest_window?: { tunnel_name?: string; in_bytes?: number; out_bytes?: number };
  source_provenance?: { shared_counter?: boolean; interleaved?: Record<string, boolean> };
  dest_provenance?: { shared_counter?: boolean; interleaved?: Record<string, boolean> };
}

interface TrafficPoint {
  bucket: string;
  bucket_ms: number;
  in_bytes: number;
  out_bytes: number;
  in_packets: number;
  out_packets: number;
}

const FAMILY_LABEL: Record<string, string> = {
  tunnel: 'VPN tunnel',
  overlay: 'Overlay (VXLAN / L3)',
  direct: 'Direct link',
  offnet: 'Off-net',
};

function duration(seconds?: number): string {
  if (!seconds || seconds <= 0) return '';
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function StatusChip({ status }: { status?: string }) {
  const value = String(status ?? 'unknown').toLowerCase();
  const up = /up|online|active|ok|established/.test(value);
  const down = /down|offline|failed|error/.test(value);
  return (
    <span
      className={cn(
        'rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
        up
          ? 'bg-sig-ok/15 text-sig-ok'
          : down
            ? 'bg-sig-crit/15 text-sig-crit'
            : 'bg-bg-panel text-text-faint',
      )}
    >
      {status || 'unknown'}
    </span>
  );
}

export function ConnectionOverview({ detail }: { detail: ConnectionDetail | undefined }) {
  if (!detail) return <p className="p-6 text-center text-xs text-text-dim">Loading connection…</p>;
  const connection = detail.connection;
  const source = connection?.source_device;
  const dest = connection?.dest_device;

  return (
    <div className="space-y-4">
      {/* The bridge: the source and destination joined by a live link. */}
      <ConnectionBridge
        sourceName={source?.name}
        destName={dest?.name}
        status={connection?.status}
        connectionType={connection?.connection_type}
      />

      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded bg-accent/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-accent">
          {FAMILY_LABEL[detail.family ?? ''] ?? detail.family ?? 'link'}
        </span>
        <StatusChip status={connection?.status} />
        <span className="font-mono text-[11px] text-text-dim">{connection?.connection_type}</span>
        {connection?.latency ? (
          <span className="font-mono text-[11px] text-text-faint">
            {connection.latency.toFixed(1)} ms
          </span>
        ) : null}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {[
          { label: 'Source', device: source, fallback: connection?.source_device_id },
          { label: 'Destination', device: dest, fallback: connection?.dest_device_id },
        ].map((endpoint) => (
          <div
            key={endpoint.label}
            className="rounded-lg border border-border bg-bg-panel px-3 py-2.5"
          >
            <div className="text-[10px] uppercase text-text-faint">{endpoint.label}</div>
            <div className="text-xs font-semibold text-text">
              {endpoint.device?.name || `Device #${endpoint.fallback ?? '?'}`}
            </div>
            <div className="font-mono text-[11px] text-text-dim">
              {endpoint.device?.ip_address || '—'}
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
        {/* Direct links return before the throughput loop; showing 0 bps beside
            GB of cumulative traffic would be actively misleading. */}
        {detail.family !== 'direct' && (
          <>
            <Kpi
              label="Throughput in"
              value={formatBitsPerSecond((detail.throughput_in ?? 0) * 8)}
              tone="text-accent"
            />
            <Kpi
              label="Throughput out"
              value={formatBitsPerSecond((detail.throughput_out ?? 0) * 8)}
              tone="text-accent"
            />
          </>
        )}
        <Kpi label="Cumulative in" value={formatBytes(detail.total_bytes_in ?? 0)} />
        <Kpi label="Cumulative out" value={formatBytes(detail.total_bytes_out ?? 0)} />
      </div>

      {detail.window_hours ? (
        <DetailSection
          title={`Window totals (${detail.window_hours}h, reset-safe)`}
          fields={[
            [
              'Source',
              detail.source_window
                ? `${formatBytes(detail.source_window.in_bytes ?? 0)} in · ${formatBytes(
                    detail.source_window.out_bytes ?? 0,
                  )} out`
                : '',
            ],
            [
              'Destination',
              detail.dest_window
                ? `${formatBytes(detail.dest_window.in_bytes ?? 0)} in · ${formatBytes(
                    detail.dest_window.out_bytes ?? 0,
                  )} out`
                : '',
            ],
          ]}
        />
      ) : null}

      <div className="flex flex-wrap items-center gap-3 text-[11px] text-text-dim">
        <span className={cn('flex items-center gap-1', detail.has_flow_data ? 'text-sig-ok' : '')}>
          <Activity className="h-3.5 w-3.5" />
          {detail.has_flow_data ? 'Flow telemetry available' : 'No flow telemetry in the window'}
        </span>
        <span className="flex items-center gap-1">
          <Cable className="h-3.5 w-3.5" />
          {(detail.source_tunnels ?? []).length} / {(detail.dest_tunnels ?? []).length} tunnels
        </span>
        <span className="flex items-center gap-1">
          <ShieldCheck className="h-3.5 w-3.5" />
          {(detail.phase2_matches ?? []).length} phase-2 match(es)
        </span>
      </div>
    </div>
  );
}

function Kpi({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-border bg-bg-panel p-2.5">
      <div className="text-[10px] uppercase text-text-faint">{label}</div>
      <div className={cn('mt-0.5 font-mono text-sm font-bold', tone ?? 'text-text')}>{value}</div>
    </div>
  );
}

export function ConnectionTunnels({
  tunnels,
  side,
}: {
  tunnels: TunnelRow[] | undefined;
  side: 'source' | 'destination';
}) {
  const rows = tunnels ?? [];
  if (rows.length === 0) {
    return (
      <p className="p-6 text-center text-xs text-text-faint">
        No tunnels reported on the {side} device.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-xs">
        <thead>
          <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-faint">
            <th scope="col" className="px-2 py-1.5">Tunnel</th>
            <th scope="col" className="px-2 py-1.5">Phase-1</th>
            <th scope="col" className="px-2 py-1.5">Status</th>
            <th scope="col" className="px-2 py-1.5">Remote</th>
            <th scope="col" className="px-2 py-1.5 text-right">In / Out</th>
            <th scope="col" className="px-2 py-1.5 text-right">Uptime</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border/60">
          {rows.map((tunnel, idx) => (
            <tr key={`${tunnel.tunnel_name}-${idx}`}>
              <td className="px-2 py-1.5 font-mono text-[11px] text-text">{tunnel.tunnel_name}</td>
              <td className="px-2 py-1.5 font-mono text-[10px] text-text-faint">
                {tunnel.phase1_name || '—'}
              </td>
              <td className="px-2 py-1.5">
                <StatusChip status={tunnel.status} />
              </td>
              <td className="px-2 py-1.5 font-mono text-[10px] text-text-dim">
                {tunnel.remote_ip || '—'}
              </td>
              <td className="px-2 py-1.5 text-right font-mono text-[10px] text-text-dim">
                {formatBytes(tunnel.bytes_in ?? 0)} / {formatBytes(tunnel.bytes_out ?? 0)}
              </td>
              <td className="px-2 py-1.5 text-right font-mono text-[10px] text-text-faint">
                {duration(tunnel.tunnel_uptime) || '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ConnectionEvidence({ detail }: { detail: ConnectionDetail | undefined }) {
  if (!detail) return <p className="p-6 text-center text-xs text-text-dim">Loading evidence…</p>;
  const interfaces = detail.interfaces ?? [];
  const overlays = detail.overlays ?? [];
  const matches = detail.phase2_matches ?? [];

  return (
    <div className="space-y-4">
      {interfaces.length > 0 && (
        <div>
          <h3 className="mb-1.5 text-xs font-semibold text-text">Member interfaces</h3>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-faint">
                  <th scope="col" className="px-2 py-1.5">Device</th>
                  <th scope="col" className="px-2 py-1.5">Interface</th>
                  <th scope="col" className="px-2 py-1.5">Kind</th>
                  <th scope="col" className="px-2 py-1.5">VLAN</th>
                  <th scope="col" className="px-2 py-1.5">IP / subnet</th>
                  <th scope="col" className="px-2 py-1.5">Speed</th>
                  <th scope="col" className="px-2 py-1.5">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {interfaces.map((iface, idx) => (
                  <tr key={`${iface.device_id}-${iface.if_name}-${idx}`}>
                    <td className="px-2 py-1.5 text-[11px] text-text">{iface.device_name || '—'}</td>
                    <td className="px-2 py-1.5 font-mono text-[11px] text-text">{iface.if_name}</td>
                    <td className="px-2 py-1.5 font-mono text-[10px] uppercase text-text-dim">
                      {iface.kind || '—'}
                    </td>
                    <td className="px-2 py-1.5 font-mono text-[10px] text-text-dim">
                      {iface.vlan_id ? iface.vlan_id : '—'}
                    </td>
                    <td className="px-2 py-1.5 font-mono text-[10px] text-text-dim">
                      {iface.ip_address || '—'}
                      {iface.subnet ? ` · ${iface.subnet}` : ''}
                    </td>
                    <td className="px-2 py-1.5 font-mono text-[10px] text-text-faint">
                      {iface.speed ? `${Math.round(iface.speed / 1_000_000)} Mbps` : '—'}
                    </td>
                    <td className="px-2 py-1.5">
                      <StatusChip status={iface.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {overlays.length > 0 && (
        <div>
          <h3 className="mb-1.5 text-xs font-semibold text-text">Overlays</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {overlays.map((overlay, idx) => (
              <div
                key={`${overlay.device_id}-${overlay.name}-${idx}`}
                className="rounded-lg border border-border bg-bg-panel px-2.5 py-2"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[11px] font-semibold text-text">
                    {overlay.name}
                  </span>
                  <StatusChip status={overlay.status} />
                </div>
                <div className="font-mono text-[10px] text-text-dim">
                  {overlay.type} · VNI {overlay.vni ?? '—'}
                  {overlay.carrier_iface ? ` · via ${overlay.carrier_iface}` : ''}
                </div>
                {overlay.remote_vteps && overlay.remote_vteps.length > 0 && (
                  <div className="truncate font-mono text-[10px] text-text-faint">
                    VTEPs: {overlay.remote_vteps.join(', ')}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <h3 className="mb-1.5 text-xs font-semibold text-text">L2 link evidence (LLDP / FDB / ARP)</h3>
        {(detail.evidence ?? []).length === 0 ? (
          <p className="text-[11px] text-text-faint">
            No link evidence for this connection — it has aged out, was configured manually, or
            the endpoints do not expose LLDP/FDB/ARP.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-faint">
                  <th scope="col" className="px-2 py-1.5">Tier</th>
                  <th scope="col" className="px-2 py-1.5">Device / port</th>
                  <th scope="col" className="px-2 py-1.5">Remote</th>
                  <th scope="col" className="px-2 py-1.5">VLAN</th>
                  <th scope="col" className="px-2 py-1.5">Fresh</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {(detail.evidence ?? []).map((row, idx) => (
                  <tr key={`${row.tier}-${row.device_id}-${idx}`}>
                    <td className="px-2 py-1.5 font-mono text-[10px] uppercase text-accent">
                      {row.tier || '—'}
                    </td>
                    <td className="px-2 py-1.5 font-mono text-[10px] text-text">
                      {row.device_name || `#${row.device_id ?? '?'}`} · {row.local_if_name || '—'}
                    </td>
                    <td className="px-2 py-1.5 font-mono text-[10px] text-text-dim">
                      {[row.remote_sysname, row.remote_port, row.remote_mac, row.remote_ip]
                        .filter(Boolean)
                        .join(' · ') || '—'}
                    </td>
                    <td className="px-2 py-1.5 font-mono text-[10px] text-text-dim">
                      {row.vlan_id ? row.vlan_id : '—'}
                    </td>
                    <td className="px-2 py-1.5 text-[10px]">
                      <span className={row.fresh ? 'text-sig-ok' : 'text-text-faint'}>
                        {row.fresh ? 'fresh' : 'stale'}
                      </span>
                      {row.note && (
                        <span className="ml-1 text-sig-warn" title={row.note}>
                          note
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div>
        <h3 className="mb-1.5 text-xs font-semibold text-text">Phase-2 correlation</h3>
        {matches.length === 0 ? (
          <p className="text-[11px] text-text-faint">
            No phase-2 selector pair matched between the two ends.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-faint">
                  <th scope="col" className="px-2 py-1.5">Source ↔ destination</th>
                  <th scope="col" className="px-2 py-1.5">Selectors</th>
                  <th scope="col" className="px-2 py-1.5">Status</th>
                  <th scope="col" className="px-2 py-1.5 text-right">Uptime</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {matches.map((match, idx) => (
                  <tr key={`${match.source_tunnel}-${match.dest_tunnel}-${idx}`}>
                    <td className="px-2 py-1.5 font-mono text-[10px] text-text">
                      {match.source_tunnel} ↔ {match.dest_tunnel}
                    </td>
                    <td className="px-2 py-1.5 font-mono text-[10px] text-text-dim">
                      {match.local_subnet || '—'} → {match.remote_subnet || '—'}
                    </td>
                    <td className="px-2 py-1.5">
                      <span className="flex flex-wrap gap-1">
                        <StatusChip status={match.source_status} />
                        <StatusChip status={match.dest_status} />
                      </span>
                    </td>
                    <td className="px-2 py-1.5 text-right font-mono text-[10px] text-text-faint">
                      {duration(match.src_uptime) || '—'} / {duration(match.dst_uptime) || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {(detail.source_provenance?.shared_counter || detail.dest_provenance?.shared_counter) && (
        <div className="rounded-lg border border-sig-warn/40 bg-sig-warn/10 px-3 py-2 text-[11px] text-sig-warn">
          One endpoint reports a single counter series across all of its phase-2 names, so
          per-selector byte totals cannot be attributed. Use the window totals above.
        </div>
      )}
    </div>
  );
}

// Only the presets the handler understands (1h/24h/7d/30d); "6h" would fall
// through to the 24h default.
const TRAFFIC_RANGES = [
  { value: '1h', label: '1h' },
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
  { value: '30d', label: '30d' },
] as const;

export function ConnectionTraffic({
  connectionId,
  hasFlowData,
}: {
  connectionId: number;
  hasFlowData?: boolean;
}) {
  const [range, setRange] = useState<'1h' | '24h' | '7d' | '30d'>('24h');

  const { data, isLoading, isError } = useQuery({
    queryKey: ['connection-traffic', connectionId, range],
    queryFn: () =>
      apiFetch<TrafficPoint[]>(`/admin/api/connections/${connectionId}/traffic?range=${range}`),
  });

  const points = Array.isArray(data) ? data : [];

  const chart = useMemo(() => {
    const timestamps = points.map((point) => point.bucket_ms);
    const seconds = bucketSeconds(timestamps) || 3600;
    return {
      timestamps,
      inbound: points.map((point) => ((Number(point.in_bytes) || 0) * 8) / seconds),
      outbound: points.map((point) => ((Number(point.out_bytes) || 0) * 8) / seconds),
      totalIn: points.reduce((sum, point) => sum + (Number(point.in_bytes) || 0), 0),
      totalOut: points.reduce((sum, point) => sum + (Number(point.out_bytes) || 0), 0),
    };
  }, [points]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-0.5 rounded-lg border border-border bg-bg-panel p-1">
          {TRAFFIC_RANGES.map((option) => (
            <button
              key={option.value}
              type="button"
              onClick={() => setRange(option.value)}
              className={cn(
                'rounded px-2 py-1 font-mono text-[11px] font-medium',
                range === option.value ? 'bg-accent text-white' : 'text-text-dim hover:text-text',
              )}
            >
              {option.label}
            </button>
          ))}
        </div>
        <div className="flex gap-3 font-mono text-[11px] text-text-dim">
          <span>
            <span className="text-accent">{formatBytes(chart.totalIn)}</span> in
          </span>
          <span>
            <span className="text-sig-warn">{formatBytes(chart.totalOut)}</span> out
          </span>
        </div>
      </div>

      {isError ? (
        <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit">
          Could not load connection traffic.
        </div>
      ) : (
        <div className="rounded-xl border border-border bg-bg-card p-3.5">
          <TimeSeriesChart
            title={`Connection throughput — ${range}`}
            timestamps={chart.timestamps}
            series={[
              { label: 'Inbound', color: '#7DD3FC', values: chart.inbound },
              { label: 'Outbound', color: '#FCD34D', values: chart.outbound },
            ]}
            kind="bps"
            isLoading={isLoading}
            emptyMessage="No traffic data for this range."
          />
        </div>
      )}

      {hasFlowData === false && (
        <p className="text-[11px] text-text-faint">
          Flow telemetry is not available for this connection; the chart uses tunnel/interface
          counters.
        </p>
      )}

      <div className="grid grid-cols-3 gap-2">
        <Kpi label="Samples" value={formatCompactNumber(points.length)} />
        <Kpi
          label="Peak in"
          value={formatBitsPerSecond(Math.max(0, ...chart.inbound))}
          tone="text-accent"
        />
        <Kpi
          label="Peak out"
          value={formatBitsPerSecond(Math.max(0, ...chart.outbound))}
          tone="text-sig-warn"
        />
      </div>
    </div>
  );
}
