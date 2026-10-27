import type { ReactNode } from 'react';
import { cn, formatBytes, formatRelativeTime } from '@/lib/utils';
import { licenceState, syncTone } from '@/lib/device-status';

function Card({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
}) {
  return (
    <div className="rounded-xl border border-border bg-bg-card p-4">
      <div className="mb-3">
        <h2 className="text-sm font-semibold text-text">{title}</h2>
        {subtitle && <p className="text-[11px] text-text-faint">{subtitle}</p>}
      </div>
      {children}
    </div>
  );
}

function usageTone(pct: number): string {
  if (pct >= 90) return 'bg-sig-crit';
  if (pct >= 75) return 'bg-sig-warn';
  return 'bg-accent';
}

export function CoreCpuPanel({ processors }: { processors: any[] }) {
  if (!processors?.length) return null;
  const cores = [...processors].sort((a, b) => (a.index ?? 0) - (b.index ?? 0));
  return (
    <Card title={`Per-core CPU (${cores.length})`}>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
        {cores.map((core, idx) => {
          const usage = Math.max(0, Math.min(100, Number(core.usage) || 0));
          return (
            <div key={core.index ?? idx} className="rounded-lg border border-border bg-bg-panel p-2">
              <div className="flex items-center justify-between font-mono text-[11px]">
                <span className="text-text-faint">core {core.index ?? idx}</span>
                <span className="text-text">{usage.toFixed(0)}%</span>
              </div>
              <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-bg-card">
                <div className={cn('h-full', usageTone(usage))} style={{ width: `${usage}%` }} />
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

export function DiskUsagePanel({ disks }: { disks: any[] }) {
  if (!disks?.length) return null;
  return (
    <Card title={`Filesystems (${disks.length})`}>
      <div className="space-y-2">
        {disks.map((disk, idx) => {
          const pct = Math.max(0, Math.min(100, Number(disk.used_percent) || 0));
          return (
            <div key={`${disk.mount}-${idx}`} className="space-y-1">
              <div className="flex items-center justify-between font-mono text-[11px]">
                <span className="text-text">{disk.mount || '—'}</span>
                <span className="text-text-dim">
                  {formatBytes(disk.used_bytes ?? 0)} / {formatBytes(disk.total_bytes ?? 0)} (
                  {pct.toFixed(0)}%)
                </span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-bg-panel">
                <div className={cn('h-full', usageTone(pct))} style={{ width: `${pct}%` }} />
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

export function LoadAveragePanel({ load }: { load: any }) {
  if (!load) return null;
  const values = [
    ['1 min', load.load1],
    ['5 min', load.load5],
    ['15 min', load.load15],
  ] as const;
  return (
    <Card title="Load Average" subtitle={`Sampled ${formatRelativeTime(load.timestamp)}`}>
      <div className="grid grid-cols-3 gap-2">
        {values.map(([label, value]) => (
          <div key={label} className="rounded-lg border border-border bg-bg-panel p-2 text-center">
            <div className="text-[10px] uppercase text-text-faint">{label}</div>
            <div className="font-mono text-lg text-text">{Number(value ?? 0).toFixed(2)}</div>
          </div>
        ))}
      </div>
    </Card>
  );
}

export function SecurityStatsPanel({ stats }: { stats: any }) {
  if (!stats) return null;
  const rows = [
    ['AV detected', stats.av_detected],
    ['AV blocked', stats.av_blocked],
    ['IPS detected', stats.ips_detected],
    ['IPS blocked', stats.ips_blocked],
    ['IPS critical', stats.ips_critical],
    ['IPS high', stats.ips_high],
    ['Web HTTP blocked', stats.wf_http_blocked],
    ['Web HTTPS blocked', stats.wf_https_blocked],
    ['URL blocked', stats.wf_url_blocked],
  ] as const;
  return (
    <Card
      title="Security Inspection Counters"
      subtitle={`Latest sample ${formatRelativeTime(stats.timestamp)}`}
    >
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
        {rows.map(([label, value]) => (
          <div key={label} className="rounded-lg border border-border bg-bg-panel p-2">
            <div className="text-[10px] uppercase text-text-faint">{label}</div>
            <div className="font-mono text-base text-text">{Number(value ?? 0)}</div>
          </div>
        ))}
      </div>
    </Card>
  );
}

export function LicencePanel({ licences }: { licences: any[] }) {
  if (!licences?.length) return null;
  return (
    <Card title={`Licences & Subscriptions (${licences.length})`}>
      <div className="space-y-2">
        {licences.map((lic, idx) => {
          const state = licenceState(lic);
          const { days, expired, expiring } = state;
          return (
            <div
              key={`${lic.description}-${idx}`}
              className="rounded-lg border border-border bg-bg-panel p-2.5"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-semibold text-text">
                  {lic.description || 'Licence'}
                </span>
                <span
                  className={cn(
                    'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
                    state.tone === 'crit' && 'bg-sig-crit/15 text-sig-crit',
                    state.tone === 'warn' && 'bg-sig-warn/15 text-sig-warn',
                    state.tone === 'ok' && 'bg-sig-ok/15 text-sig-ok',
                  )}
                >
                  {state.label}
                </span>
              </div>
              <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-[11px] text-text-dim">
                <span>expires {lic.expiry_date || '—'}</span>
                {days != null && (
                  <span className={expired ? 'text-sig-crit' : expiring ? 'text-sig-warn' : ''}>
                    {expired
                      ? days === 0
                        ? 'today'
                        : `${Math.abs(days)}d ago`
                      : days === 0
                        ? 'today'
                        : `in ${days}d`}
                  </span>
                )}
                {lic.details && <span className="text-text-faint">{lic.details}</span>}
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

export function HAPanel({ rows }: { rows: any[] }) {
  if (!rows?.length) return null;
  return (
    <Card title="High Availability Cluster" subtitle={`${rows.length} member row(s)`}>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left text-xs">
          <thead>
            <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-faint">
              <th scope="col" className="px-2 py-1.5">Mode</th>
              <th scope="col" className="px-2 py-1.5">Group</th>
              <th scope="col" className="px-2 py-1.5">Member</th>
              <th scope="col" className="px-2 py-1.5">Serial</th>
              <th scope="col" className="px-2 py-1.5">Sync</th>
              <th scope="col" className="px-2 py-1.5 text-right">CPU</th>
              <th scope="col" className="px-2 py-1.5 text-right">Mem</th>
              <th scope="col" className="px-2 py-1.5 text-right">Sessions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/60 font-mono text-[11px]">
            {rows.map((ha, idx) => (
              <tr key={`${ha.member_serial}-${idx}`}>
                <td className="px-2 py-1.5 text-text">{ha.system_mode || '—'}</td>
                <td className="px-2 py-1.5 text-text-dim">
                  {ha.group_name || (ha.group_id ? `#${ha.group_id}` : '—')}
                </td>
                <td className="px-2 py-1.5 text-text">{ha.member_hostname || '—'}</td>
                <td className="px-2 py-1.5 text-text-faint">{ha.member_serial || '—'}</td>
                <td className="px-2 py-1.5">
                  {(() => {
                    const tone = syncTone(ha.sync_status);
                    return (
                      <span
                        className={cn(
                          'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
                          tone === 'ok' && 'bg-sig-ok/15 text-sig-ok',
                          tone === 'crit' && 'bg-sig-crit/15 text-sig-crit',
                          tone === 'warn' && 'bg-sig-warn/15 text-sig-warn',
                        )}
                      >
                        {ha.sync_status || 'unknown'}
                      </span>
                    );
                  })()}
                </td>
                <td className="px-2 py-1.5 text-right">{Math.round(ha.cpu_usage ?? 0)}%</td>
                <td className="px-2 py-1.5 text-right">{Math.round(ha.memory_usage ?? 0)}%</td>
                <td className="px-2 py-1.5 text-right">{ha.session_count ?? 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function SdwanPanel({ rows }: { rows: any[] }) {
  if (!rows?.length) return null;
  return (
    <Card title="SD-WAN Health" subtitle={`${rows.length} member(s)`}>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left text-xs">
          <thead>
            <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-faint">
              <th scope="col" className="px-2 py-1.5">Name</th>
              <th scope="col" className="px-2 py-1.5">Interface</th>
              <th scope="col" className="px-2 py-1.5">State</th>
              <th scope="col" className="px-2 py-1.5 text-right">Latency</th>
              <th scope="col" className="px-2 py-1.5 text-right">Loss</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/60 font-mono text-[11px]">
            {rows.map((row, idx) => (
              <tr key={`${row.name}-${row.interface}-${idx}`}>
                <td className="px-2 py-1.5 text-text">{row.name || '—'}</td>
                <td className="px-2 py-1.5 text-text-dim">{row.interface || '—'}</td>
                <td className="px-2 py-1.5">
                  <span
                    className={cn(
                      'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
                      /up|ok|alive/i.test(row.state || '')
                        ? 'bg-sig-ok/15 text-sig-ok'
                        : 'bg-sig-crit/15 text-sig-crit',
                    )}
                  >
                    {row.state || 'unknown'}
                  </span>
                </td>
                <td className="px-2 py-1.5 text-right">{Number(row.latency ?? 0).toFixed(1)} ms</td>
                <td className="px-2 py-1.5 text-right">{Number(row.packet_loss ?? 0).toFixed(1)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function PingSlaPanel({ rows }: { rows: any[] }) {
  if (!rows?.length) return null;
  return (
    <Card title={`Ping SLA (${rows.length} target${rows.length === 1 ? '' : 's'})`}>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left text-xs">
          <thead>
            <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-faint">
              <th scope="col" className="px-2 py-1.5">Target</th>
              <th scope="col" className="px-2 py-1.5 text-right">Avg</th>
              <th scope="col" className="px-2 py-1.5 text-right">Min</th>
              <th scope="col" className="px-2 py-1.5 text-right">Max</th>
              <th scope="col" className="px-2 py-1.5 text-right">Loss</th>
              <th scope="col" className="px-2 py-1.5 text-right">Samples</th>
              <th scope="col" className="px-2 py-1.5 text-right">Updated</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/60 font-mono text-[11px]">
            {rows.map((row, idx) => (
              <tr key={`${row.target_ip}-${idx}`}>
                <td className="px-2 py-1.5 text-text">{row.target_ip || '—'}</td>
                <td className="px-2 py-1.5 text-right">{Number(row.avg_latency ?? 0).toFixed(1)} ms</td>
                <td className="px-2 py-1.5 text-right text-text-dim">
                  {Number(row.min_latency ?? 0).toFixed(1)}
                </td>
                <td className="px-2 py-1.5 text-right text-text-dim">
                  {Number(row.max_latency ?? 0).toFixed(1)}
                </td>
                <td
                  className={cn(
                    'px-2 py-1.5 text-right',
                    Number(row.packet_loss ?? 0) > 0 ? 'text-sig-warn' : '',
                  )}
                >
                  {Number(row.packet_loss ?? 0).toFixed(1)}%
                </td>
                <td className="px-2 py-1.5 text-right text-text-faint">{row.samples ?? 0}</td>
                <td className="px-2 py-1.5 text-right text-text-faint">
                  {formatRelativeTime(row.updated_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function RecentAlertsPanel({ alerts }: { alerts: any[] }) {
  const rows = (alerts ?? []).slice(0, 10);
  if (rows.length === 0) return null;
  return (
    <Card title="Recent Alerts" subtitle="The ten most recent alerts for this device">
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left text-xs">
          <thead>
            <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-faint">
              <th scope="col" className="px-2 py-1.5">When</th>
              <th scope="col" className="px-2 py-1.5">Severity</th>
              <th scope="col" className="px-2 py-1.5">Type</th>
              <th scope="col" className="px-2 py-1.5">Message</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/60">
            {rows.map((alert, idx) => (
              <tr key={alert.id ?? idx}>
                <td className="px-2 py-1.5 font-mono text-[11px] text-text-dim">
                  {formatRelativeTime(alert.timestamp)}
                </td>
                <td className="px-2 py-1.5">
                  <span
                    className={cn(
                      'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
                      alert.severity === 'critical'
                        ? 'bg-sig-crit/15 text-sig-crit'
                        : alert.severity === 'warning'
                          ? 'bg-sig-warn/15 text-sig-warn'
                          : 'bg-accent/15 text-accent-text',
                    )}
                  >
                    {alert.severity || 'info'}
                  </span>
                </td>
                <td className="px-2 py-1.5 font-mono text-[11px] text-text-dim">
                  {alert.alert_type || '—'}
                </td>
                <td className="px-2 py-1.5 text-[11px] text-text">{alert.message || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
