import { useEffect, useMemo } from 'react';
import { cn } from '@/lib/utils';
import { ID_TYPES, defaultIdentity, identityError, type EndForm, type IpsecHints } from '@/lib/ipsec';

export interface WizardDevice {
  id: number;
  name: string;
  vendor?: string;
  ip_address?: string;
  uuid?: string;
  retired_at?: string | null;
}

export interface IpsecEndFormProps {
  label: 'A' | 'B';
  value: EndForm;
  onChange: (next: EndForm) => void;
  devices: WizardDevice[];
  /** The hints for the selected device, once they have loaded. */
  hints?: IpsecHints | null;
  /** The identity types the vendor pair supports. */
  idTypes: string[];
  /** The other end's device, so the two cannot be the same device. */
  otherDeviceId: number | null;
}

/**
 * One end of a tunnel.
 *
 * The fields are V1's, and the mapping onto the intent is in
 * `lib/ipsec.ts` `buildIntent` — this component only collects them.
 */
export function IpsecEndForm({
  label,
  value,
  onChange,
  devices,
  hints,
  idTypes,
  otherDeviceId,
}: IpsecEndFormProps) {
  const set = <K extends keyof EndForm>(key: K, v: EndForm[K]) =>
    onChange({ ...value, [key]: v });

  const device = devices.find((d) => d.id === value.deviceId);
  const interfaces = hints?.interfaces ?? [];
  const lanIfaces = useMemo(
    () => interfaces.filter((i) => i.is_lan).map((i) => i.name),
    [interfaces],
  );
  const wanIfaces = useMemo(
    () => interfaces.filter((i) => !i.is_lan).map((i) => i.name),
    [interfaces],
  );

  // When the device changes, the facts that come FROM the device are
  // refilled: the egress interface, the LAN interfaces, the peer IP and the
  // local identity. A device that has never been polled returns nothing, so
  // every field stays editable.
  useEffect(() => {
    if (!device) return;
    const next: EndForm = { ...value, vendor: device.vendor ?? value.vendor };
    if (hints) {
      if (hints.suggested_egress && !next.egressIface) next.egressIface = hints.suggested_egress;
      if (hints.suggested_lan && next.lanIfaces.length === 0) next.lanIfaces = [hints.suggested_lan];
      if (hints.suggested_peer_ip && !next.peerIp) next.peerIp = hints.suggested_peer_ip;
      // The device's own LAN subnets are the obvious starting point for the
      // protected subnets. The legacy console prefilled them from here.
      if (hints.lan_subnets?.length && next.protectedSubnets.length === 0) {
        next.protectedSubnets = [...hints.lan_subnets];
      }
    }
    if (!next.localId?.value) {
      next.localId = defaultIdentity(next.localId?.type ?? 'fqdn', device.uuid, next.peerIp);
    }
    if (JSON.stringify(next) !== JSON.stringify(value)) onChange(next);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device?.id, hints]);

  const idError = identityError(value.localId);

  return (
    <div className="space-y-3 rounded-lg border border-border bg-bg-panel p-3">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-text">End {label}</span>
        {device ? (
          <span className="font-mono text-[10px] text-text-faint">
            {device.vendor ?? 'unknown vendor'}
          </span>
        ) : null}
      </div>

      <label className="block">
        <span className="mb-1 block text-[11px] font-medium text-text-dim">Device</span>
        <select
          value={value.deviceId || ''}
          onChange={(e) => set('deviceId', Number(e.target.value) || 0)}
          aria-label={`End ${label} device`}
          className="w-full rounded-md border border-border bg-bg-card px-2.5 py-1.5 text-xs text-text"
        >
          <option value="">Select a device…</option>
          {devices.map((d) => (
            <option key={d.id} value={d.id} disabled={d.id === otherDeviceId}>
              {d.name}
              {d.retired_at ? ' (retired)' : ''}
            </option>
          ))}
        </select>
        {otherDeviceId !== null && value.deviceId === otherDeviceId ? (
          <span className="mt-1 block text-[10px] text-sig-crit">
            The two ends cannot be the same device.
          </span>
        ) : null}
      </label>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <label className="block">
          <span className="mb-1 block text-[11px] font-medium text-text-dim">Peer IP</span>
          <input
            type="text"
            value={value.peerIp}
            disabled={value.dynamic}
            onChange={(e) => set('peerIp', e.target.value)}
            placeholder="203.0.113.9"
            className="w-full rounded-md border border-border bg-bg-card px-2.5 py-1.5 font-mono text-xs text-text disabled:opacity-60"
          />
        </label>
        <label className="block">
          <span className="mb-1 block text-[11px] font-medium text-text-dim">Egress interface</span>
          <input
            type="text"
            list={`ipsec-egress-${label}`}
            value={value.egressIface}
            onChange={(e) => set('egressIface', e.target.value)}
            placeholder="wan"
            className="w-full rounded-md border border-border bg-bg-card px-2.5 py-1.5 font-mono text-xs text-text"
          />
          {wanIfaces.length > 0 ? (
            <datalist id={`ipsec-egress-${label}`}>
              {wanIfaces.map((name) => (
                <option key={name} value={name} />
              ))}
            </datalist>
          ) : null}
        </label>
      </div>

      <label className="flex items-center gap-2 text-[11px] text-text-dim">
        <input
          type="checkbox"
          checked={value.dynamic}
          onChange={(e) => set('dynamic', e.target.checked)}
          className="h-3.5 w-3.5 rounded accent-accent"
        />
        Dynamic peer (the address is assigned by the provider)
      </label>

      <div>
        <span className="mb-1 block text-[11px] font-medium text-text-dim">
          LAN interface(s)
        </span>
        {lanIfaces.length > 0 ? (
          <div className="mb-1 flex flex-wrap gap-2">
            {lanIfaces.map((name) => (
              <label key={name} className="flex items-center gap-1 text-[11px] text-text-dim">
                <input
                  type="checkbox"
                  checked={value.lanIfaces.includes(name)}
                  onChange={(e) =>
                    set(
                      'lanIfaces',
                      e.target.checked
                        ? [...value.lanIfaces, name]
                        : value.lanIfaces.filter((n) => n !== name),
                    )
                  }
                  className="h-3.5 w-3.5 rounded accent-accent"
                />
                {name}
              </label>
            ))}
          </div>
        ) : null}
        <input
          type="text"
          value={value.lanIfaces.join(', ')}
          onChange={(e) =>
            set(
              'lanIfaces',
              e.target.value
                .split(',')
                .map((s) => s.trim())
                .filter(Boolean),
            )
          }
          placeholder="Comma-separated interface names"
          className="w-full rounded-md border border-border bg-bg-card px-2.5 py-1.5 font-mono text-xs text-text"
        />
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <label className="block">
          <span className="mb-1 block text-[11px] font-medium text-text-dim">
            Local identity type
          </span>
          <select
            value={value.localId?.type ?? 'fqdn'}
            onChange={(e) =>
              set('localId', {
                type: e.target.value,
                value: defaultIdentity(e.target.value, device?.uuid, value.peerIp).value,
              })
            }
            aria-label={`End ${label} identity type`}
            className="w-full rounded-md border border-border bg-bg-card px-2.5 py-1.5 text-xs text-text"
          >
            {(idTypes.length > 0 ? idTypes : [...ID_TYPES]).map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          <span className="mb-1 block text-[11px] font-medium text-text-dim">
            Local identity
          </span>
          <input
            type="text"
            value={value.localId?.value ?? ''}
            onChange={(e) =>
              set('localId', { type: value.localId?.type ?? 'fqdn', value: e.target.value })
            }
            className={cn(
              'w-full rounded-md border border-border bg-bg-card px-2.5 py-1.5 font-mono text-xs text-text',
              idError && 'border-sig-crit',
            )}
          />
          {idError ? (
            <span className="mt-1 block text-[10px] text-sig-crit">{idError}</span>
          ) : null}
        </label>
      </div>

      <label className="block">
        <span className="mb-1 block text-[11px] font-medium text-text-dim">
          Protected subnets
        </span>
        <textarea
          rows={2}
          value={value.protectedSubnets.join('\n')}
          onChange={(e) =>
            set(
              'protectedSubnets',
              e.target.value
                .split(/[\n,]/)
                .map((s) => s.trim())
                .filter(Boolean),
            )
          }
          placeholder={'192.168.113.0/24\n192.168.114.0/24'}
          className="w-full rounded-md border border-border bg-bg-card px-2.5 py-1.5 font-mono text-xs text-text"
        />
      </label>

      <label className="block">
        <span className="mb-1 block text-[11px] font-medium text-text-dim">
          Gateway (optional)
        </span>
        <input
          type="text"
          value={value.gateway}
          onChange={(e) => set('gateway', e.target.value)}
          placeholder="Only for a self-lockout workaround"
          className="w-full rounded-md border border-border bg-bg-card px-2.5 py-1.5 font-mono text-xs text-text"
        />
      </label>
    </div>
  );
}
