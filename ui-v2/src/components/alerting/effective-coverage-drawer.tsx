import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '@/lib/api';
import { cn, formatDateTime } from '@/lib/utils';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { Select } from '@/components/ui/input';

interface EffectiveLayer {
  layer: string;
  profile_id: number;
  profile_name: string;
}

interface EffectiveToggle {
  alert_type: string;
  family: string;
  enabled: boolean;
  decided_by: string;
}

interface EffectiveRule {
  layer: string;
  rule_id: number;
  name: string;
  priority: number;
  source: string;
  action: string;
  alert_type?: string;
  expires_at?: string;
}

interface EffectiveConfig {
  chain?: EffectiveLayer[];
  toggles?: EffectiveToggle[];
  rules?: EffectiveRule[];
}

const LAYER_STYLE: Record<string, string> = {
  device: 'bg-accent/15 text-accent',
  site: 'bg-sig-warn/15 text-sig-warn',
  default: 'bg-bg-panel text-text-dim',
};

function layerLabel(layer: string): string {
  return layer ? layer.charAt(0).toUpperCase() + layer.slice(1) : '—';
}

/**
 * The classic console's "Effective coverage" view: pick a device or site and
 * see the resolved profile chain, every alert type's On/Off state with the
 * layer that decided it, and the rules in evaluation order. Computed server-
 * side by the same locked resolver the firing path uses, so this cannot
 * disagree with what actually fires.
 */
export function EffectiveCoverageDrawer({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [deviceId, setDeviceId] = useState('');
  const [siteId, setSiteId] = useState('');

  const { data: devices = [] } = useQuery({
    queryKey: ['effective-devices'],
    queryFn: () =>
      apiFetch<Array<{ id: number; name: string; retired_at?: string | null }>>(
        '/admin/api/devices',
      ),
    enabled: open,
  });
  const { data: sites = [] } = useQuery({
    queryKey: ['effective-sites'],
    queryFn: () => apiFetch<Array<{ id: number; name: string }>>('/admin/api/sites'),
    enabled: open,
  });

  const scope = deviceId ? `device_id=${deviceId}` : siteId ? `site_id=${siteId}` : '';
  const { data, isLoading, isError } = useQuery({
    queryKey: ['effective-coverage', deviceId, siteId],
    queryFn: () => apiFetch<EffectiveConfig>(`/admin/api/event-config/effective?${scope}`),
    enabled: open && Boolean(scope),
  });

  const groups = useMemo(() => {
    const map = new Map<string, EffectiveToggle[]>();
    for (const toggle of data?.toggles ?? []) {
      const list = map.get(toggle.family) ?? [];
      list.push(toggle);
      map.set(toggle.family, list);
    }
    return Array.from(map.entries());
  }, [data]);

  const chain = data?.chain ?? [];
  const rules = data?.rules ?? [];

  return (
    <SlideOverDrawer
      open={open}
      onOpenChange={onOpenChange}
      title="Effective coverage"
      subtitle="Pick a device or site to see which alert types fire there and which layer decided each one."
      size="xl"
    >
      <div className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">Device</span>
            <Select
              value={deviceId}
              onChange={(e) => {
                setDeviceId(e.target.value);
                if (e.target.value) setSiteId('');
              }}
             
            >
              <option value="">— pick a device —</option>
              {devices
                .filter((device) => !device.retired_at)
                .map((device) => (
                  <option key={device.id} value={device.id}>
                    {device.name}
                  </option>
                ))}
            </Select>
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">…or site</span>
            <Select
              value={siteId}
              onChange={(e) => {
                setSiteId(e.target.value);
                if (e.target.value) setDeviceId('');
              }}
             
            >
              <option value="">— pick a site —</option>
              {sites.map((site) => (
                <option key={site.id} value={site.id}>
                  {site.name}
                </option>
              ))}
            </Select>
          </label>
        </div>

        {!scope ? (
          <p className="rounded-lg border border-border bg-bg-card p-4 text-center text-xs text-text-faint">
            Choose a device or site to resolve its coverage.
          </p>
        ) : isLoading ? (
          <p className="p-6 text-center text-xs text-text-dim">Resolving…</p>
        ) : isError ? (
          <p className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit">
            Could not resolve the effective configuration for this scope.
          </p>
        ) : (
          <>
            <section className="space-y-1.5">
              <h3 className="text-[10px] font-semibold uppercase tracking-wider text-text-faint">
                Profile chain
              </h3>
              {chain.length === 0 ? (
                <p className="text-[11px] text-text-faint">No profile layer resolved.</p>
              ) : (
                <div className="flex flex-wrap items-center gap-1.5">
                  {chain.map((layer, idx) => (
                    <span key={`${layer.layer}-${layer.profile_id}`} className="flex items-center gap-1.5">
                      {idx > 0 && <span className="text-text-faint">→</span>}
                      <span
                        className={cn(
                          'rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
                          LAYER_STYLE[layer.layer] ?? LAYER_STYLE['default'],
                        )}
                      >
                        {layerLabel(layer.layer)}
                      </span>
                      <span className="text-xs text-text">{layer.profile_name}</span>
                    </span>
                  ))}
                </div>
              )}
            </section>

            <section className="space-y-2">
              <h3 className="text-[10px] font-semibold uppercase tracking-wider text-text-faint">
                Alert types ({data?.toggles?.length ?? 0})
              </h3>
              {groups.length === 0 ? (
                <p className="text-[11px] text-text-faint">No alert types resolved.</p>
              ) : (
                groups.map(([family, toggles]) => (
                  <div key={family} className="rounded-lg border border-border bg-bg-card">
                    <div className="border-b border-border bg-bg-panel/40 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-text-faint">
                      {family}
                    </div>
                    <div className="divide-y divide-border/60">
                      {toggles.map((toggle) => (
                        <div
                          key={toggle.alert_type}
                          className="flex flex-wrap items-center justify-between gap-2 px-3 py-1.5"
                        >
                          <span className="font-mono text-[11px] text-text">{toggle.alert_type}</span>
                          <div className="flex items-center gap-2">
                            <span
                              className={cn(
                                'rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
                                toggle.enabled
                                  ? 'bg-sig-ok/15 text-sig-ok'
                                  : 'bg-sig-crit/15 text-sig-crit',
                              )}
                            >
                              {toggle.enabled ? 'On' : 'Off'}
                            </span>
                            <span className="text-[10px] text-text-faint">
                              {toggle.decided_by === 'implicit'
                                ? 'nothing overrides it'
                                : `decided by the ${toggle.decided_by} layer`}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </section>

            <section className="space-y-1.5">
              <h3 className="text-[10px] font-semibold uppercase tracking-wider text-text-faint">
                Rules in evaluation order ({rules.length})
              </h3>
              {rules.length === 0 ? (
                <p className="text-[11px] text-text-faint">No rules apply to this scope.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse text-left text-xs">
                    <thead>
                      <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-faint">
                        <th scope="col" className="px-2 py-1.5">Rule</th>
                        <th scope="col" className="px-2 py-1.5">Layer</th>
                        <th scope="col" className="px-2 py-1.5 text-right">Priority</th>
                        <th scope="col" className="px-2 py-1.5">Source</th>
                        <th scope="col" className="px-2 py-1.5">Action</th>
                        <th scope="col" className="px-2 py-1.5">Type</th>
                        <th scope="col" className="px-2 py-1.5">Expires</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/60">
                      {rules.map((rule) => (
                        <tr key={`${rule.layer}-${rule.rule_id}`}>
                          <td className="px-2 py-1.5 text-[11px] text-text">{rule.name}</td>
                          <td className="px-2 py-1.5">
                            <span
                              className={cn(
                                'rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
                                LAYER_STYLE[rule.layer] ?? LAYER_STYLE['default'],
                              )}
                            >
                              {layerLabel(rule.layer)}
                            </span>
                          </td>
                          <td className="px-2 py-1.5 text-right font-mono text-[10px] text-text-dim">
                            {rule.priority}
                          </td>
                          <td className="px-2 py-1.5 font-mono text-[10px] text-text-dim">
                            {rule.source}
                          </td>
                          <td className="px-2 py-1.5 font-mono text-[10px] uppercase text-text-dim">
                            {rule.action}
                          </td>
                          <td className="px-2 py-1.5 font-mono text-[10px] text-text-faint">
                            {rule.alert_type || '—'}
                          </td>
                          <td className="px-2 py-1.5 font-mono text-[10px] text-text-faint">
                            {rule.expires_at ? formatDateTime(rule.expires_at) : '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            <p className="text-[10px] text-text-faint">
              Computed by the same resolver the alert engine uses, so it cannot disagree with what
              actually fires.
            </p>
          </>
        )}
      </div>
    </SlideOverDrawer>
  );
}
