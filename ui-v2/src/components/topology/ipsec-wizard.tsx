import { useCallback, useEffect, useMemo, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { ArrowRight, Check, Loader2, TriangleAlert, X } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn } from '@/lib/utils';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { useToast } from '@/components/ui/toast';
import {
  PSK_MASK,
  buildIntent,
  changeCustomCrypto,
  findingScope,
  isAeadCipher,
  identityError,
  pathKey,
  pruneDisabledPaths,
  restoreCrypto,
  type CapabilitiesResponse,
  type CustomControl,
  type EndForm,
  type Finding,
  type IntentForm,
  type IpsecHints,
  type PreviewResponse,
  type ProfileName,
} from '@/lib/ipsec';
import { IpsecEndForm, type WizardDevice } from './ipsec-end-form';
import { Input, Select } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

export type { WizardDevice };

type Phase = 'design' | 'paths' | 'verify';

export interface IpsecWizardProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The tunnel being edited. Null means "create". */
  tunnelId?: number | null;
  /** The devices to pick the two ends from. */
  devices: WizardDevice[];
  onSaved?: () => void;
}

const EMPTY_END: EndForm = {
  deviceId: 0,
  vendor: '',
  peerIp: '',
  dynamic: false,
  egressIface: '',
  lanIfaces: [],
  localId: { type: 'fqdn', value: '' },
  protectedSubnets: [],
  gateway: '',
};

function emptyForm(): IntentForm {
  return {
    mode: 'route-based',
    profile: 'modern',
    custom: {
      ike_version: 'ikev2',
      ike: { enc: '', integ: '', prf: '', dh: '' },
      esp: { enc: '', integ: '', pfs: '' },
    },
    profiles: [],
    psk: '',
    ends: [{ ...EMPTY_END }, { ...EMPTY_END }],
    disabledPaths: {},
  };
}

export function IpsecWizard({
  open,
  onOpenChange,
  tunnelId,
  devices,
  onSaved,
}: IpsecWizardProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [phase, setPhase] = useState<Phase>('design');
  const [form, setForm] = useState<IntentForm>(emptyForm);
  const [caps, setCaps] = useState<CapabilitiesResponse | null>(null);
  const [hints, setHints] = useState<Record<number, IpsecHints>>({});
  const [preview, setPreview] = useState<PreviewResponse | null>(null);
  // The exact intent the preview was rendered for. Save is offered only while
  // the form still produces THIS intent: the tabs are free, and an edit made
  // after a clean preview was once saved on the strength of the old one.
  const [previewedIntent, setPreviewedIntent] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [previewing, setPreviewing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEdit = Boolean(tunnelId);

  // --- load an existing tunnel -------------------------------------------------
  useEffect(() => {
    if (!open) return;
    setError(null);
    setPreview(null);
    setPreviewedIntent(null);
    setPhase('design');
    // The whole form state is reset, not just the phase: the previous
    // session's profile, capabilities and hints would otherwise leak into
    // the next tunnel - and a stale profile is what silently rewrote a
    // Custom tunnel's crypto.
    setForm(emptyForm());
    setCaps(null);
    setHints({});
    if (!tunnelId) return;
    let cancelled = false;
    setLoading(true);
    apiFetch<{
      intent?: {
        enabled: boolean;
        ike_version: string;
        mode: string;
        ike: { enc: string; integ: string; prf: string; dh: string };
        esp: { enc: string; integ: string; pfs: string };
        ike_lifetime_secs: number;
        dpd: { delay_secs: number; timeout_secs: number };
        psk?: string;
        disabled_paths?: string[];
        ends: Array<{
          device_id: number;
          vendor: string;
          peer_ip: string;
          egress_iface: string;
          gateway: string;
          lan_ifaces?: string[];
          local_id: { type: string; value: string };
          dynamic: boolean;
          protected_subnets: string[];
          child_lifetime_secs: number;
          mss_clamp: number;
        }>;
      };
      status?: string;
      last_error?: string;
    }>(`/admin/api/ipsec/tunnels/${tunnelId}`)
      .then((res) => {
        if (cancelled) return;
        const intent = res.intent;
        if (!intent) {
          setError('The tunnel could not be read.');
          return;
        }
        setForm((prev) => {
          const next: IntentForm = {
            ...prev,
            mode: intent.mode,
            custom: {
              ike_version: intent.ike_version,
              ike: { ...intent.ike },
              esp: { ...intent.esp },
            },
            // The mask means "unchanged" on an edit, and the server folds the
            // stored key back in.
            psk: intent.psk === PSK_MASK ? PSK_MASK : (intent.psk ?? ''),
            disabledPaths: Object.fromEntries(
              (intent.disabled_paths ?? []).map((p) => [p, true]),
            ),
            ends: intent.ends.map((e) => ({
              deviceId: e.device_id,
              vendor: e.vendor,
              peerIp: e.peer_ip,
              dynamic: e.dynamic,
              egressIface: e.egress_iface,
              gateway: e.gateway,
              lanIfaces: e.lan_ifaces ?? [],
              localId: { type: e.local_id?.type ?? 'fqdn', value: e.local_id?.value ?? '' },
              protectedSubnets: e.protected_subnets ?? [],
            })) as [EndForm, EndForm],
          };
          return next;
        });
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'The tunnel could not be read.');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, tunnelId]);

  // --- the devices' hints ------------------------------------------------------
  const loadHints = useCallback(async (deviceId: number) => {
    if (!deviceId) return;
    try {
      const res = await apiFetch<IpsecHints>(`/admin/api/devices/${deviceId}/ipsec-hints`);
      setHints((prev) => ({ ...prev, [deviceId]: res }));
    } catch {
      // A device that has never been polled returns empty hints, and a
      // device the server does not know 404s. Either way the fields stay
      // editable.
    }
  }, []);

  useEffect(() => {
    if (!open) return;
    for (const end of form.ends) {
      if (end.deviceId && !hints[end.deviceId]) void loadHints(end.deviceId);
    }
  }, [open, form.ends, hints, loadHints]);

  // --- the vendors' capabilities ------------------------------------------------
  const vendorA = form.ends[0].vendor;
  const vendorB = form.ends[1].vendor;

  useEffect(() => {
    if (!open || !vendorA || !vendorB) {
      setCaps(null);
      return;
    }
    let cancelled = false;
    apiFetch<CapabilitiesResponse>(
      `/admin/api/ipsec/capabilities?a=${encodeURIComponent(vendorA)}&b=${encodeURIComponent(vendorB)}`,
    )
      .then((res) => {
        if (cancelled) return;
        setCaps(res);
        setForm((prev) => {
          const modes = res.allowed?.modes ?? [];
          const next = { ...prev, profiles: res.profiles ?? prev.profiles };
          if (modes.length > 0 && !modes.includes(next.mode)) {
            // The mode comes from the vendors' INTERSECTION. OPNsense is
            // policy-based only, so a hardcoded default would be wrong for
            // every OPNsense pair.
            next.mode = modes[0];
          }
          // Restore the profile the stored intent came from - INCLUDING the
          // Custom case. The intent stores the RESOLVED crypto, not the
          // profile's name, so the form has to infer it. Leaving the profile
          // alone would show "Modern" for a Custom tunnel and silently
          // rewrite its crypto on save.
          //
          // EDIT ONLY. On create there is no stored crypto to infer from -
          // the form's custom crypto is an empty placeholder, which matches
          // no preset, so running the inference there would flip the default
          // profile to "Custom" with empty selectors, and the operator never
          // touched the dropdown.
          if (isEdit && next.profiles.length > 0) {
            const restored = restoreCrypto(
              {
                ike: prev.custom.ike,
                esp: prev.custom.esp,
                ike_version: prev.custom.ike_version,
              },
              next.profiles,
            );
            next.profile = restored.profile;
          }
          return next;
        });
      })
      .catch((err) => {
        if (!cancelled) {
          setCaps(null);
          setError(
            err instanceof Error ? err.message : 'The vendor capabilities could not be read.',
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, [open, vendorA, vendorB]);

  const setEnd = (index: 0 | 1, next: EndForm) => {
    setForm((prev) => {
      const ends = [...prev.ends] as [EndForm, EndForm];
      ends[index] = next;
      const disabled = pruneDisabledPaths(prev.disabledPaths, ends);
      return { ...prev, ends, disabledPaths: disabled };
    });
  };

  // --- the paths phase ----------------------------------------------------------
  const paths = useMemo(() => {
    const out: Array<{ key: string; a: string; b: string; disabled: boolean }> = [];
    for (const aNet of form.ends[0].protectedSubnets) {
      for (const bNet of form.ends[1].protectedSubnets) {
        // CANONICAL, or not at all. The server compares the stored key
        // exactly against its own canonical form, so a raw key would leave
        // the path ENABLED even though the operator turned it off - a
        // silent fail-open the server only warns about.
        const key = pathKey(aNet, bNet);
        if (!key) continue;
        out.push({ key, a: aNet, b: bNet, disabled: Boolean(form.disabledPaths[key]) });
      }
    }
    return out;
  }, [form.ends, form.disabledPaths]);

  // The paths whose key cannot be canonicalised. A path the server cannot
  // match would stay enabled even if it were "disabled", so the toggle is not
  // offered for them - and the operator is told.
  const uncanonicalisable = useMemo(() => {
    let count = 0;
    for (const aNet of form.ends[0].protectedSubnets) {
      for (const bNet of form.ends[1].protectedSubnets) {
        if (!pathKey(aNet, bNet)) count += 1;
      }
    }
    return count;
  }, [form.ends]);

  const togglePath = (key: string) => {
    setForm((prev) => ({
      ...prev,
      disabledPaths: { ...prev.disabledPaths, [key]: !prev.disabledPaths[key] },
    }));
  };

  // --- the preview --------------------------------------------------------------
  const runPreview = async () => {
    setPreviewing(true);
    setError(null);
    try {
      const body = buildIntent(form);
      const res = await apiFetch<PreviewResponse>('/admin/api/ipsec/preview', {
        method: 'POST',
        body,
      });
      setPreview(res);
      setPreviewedIntent(JSON.stringify(body));
      setPhase('verify');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The preview failed.');
    } finally {
      setPreviewing(false);
    }
  };

  const blocking = (preview?.validation ?? []).filter((f) => f.severity === 'block');
  const currentIntent = useMemo(() => JSON.stringify(buildIntent(form)), [form]);
  const previewIsCurrent = preview !== null && previewedIntent === currentIntent;

  // --- the Custom crypto --------------------------------------------------------
  const changeCustom = (control: CustomControl, value: string | boolean) =>
    setForm((p) => ({ ...p, custom: changeCustomCrypto(p.custom, control, value) }));

  const customSelect = (
    label: string,
    control: Exclude<CustomControl, 'pfs'>,
    value: string,
    options: string[],
    placeholder: string | null,
  ) => (
    <label className="block">
      <span className="mb-1 block text-[11px] font-medium text-text-dim">{label}</span>
      <Select
        className="bg-bg-card px-2.5 py-1.5"
        value={value}
        onChange={(e) => changeCustom(control, e.target.value)}
      >
        {placeholder !== null ? <option value="">{placeholder}</option> : null}
        {options.map((v) => (
          <option key={v} value={v}>
            {v}
          </option>
        ))}
      </Select>
    </label>
  );

  // --- save ---------------------------------------------------------------------
  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const body = buildIntent(form);
      if (tunnelId) {
        await apiFetch(`/admin/api/ipsec/tunnels/${tunnelId}`, { method: 'PUT', body });
      } else {
        await apiFetch('/admin/api/ipsec/tunnels', { method: 'POST', body });
      }
      toast({
        title: tunnelId ? 'Tunnel updated' : 'Tunnel created',
        variant: 'success',
      });
      queryClient.invalidateQueries({ queryKey: ['ipsec-tunnels'] });
      queryClient.invalidateQueries({ queryKey: ['vpn-map-data'] });
      onOpenChange(false);
      onSaved?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The tunnel could not be saved.');
    } finally {
      setSaving(false);
    }
  };

  const identityErrors = form.ends.map((e) => identityError(e.localId));
  const canPreview =
    form.ends[0].deviceId > 0 &&
    form.ends[1].deviceId > 0 &&
    form.ends[0].deviceId !== form.ends[1].deviceId &&
    !identityErrors.some(Boolean);

  const findingTone = (f: Finding) =>
    f.severity === 'block'
      ? 'border-sig-crit/40 bg-sig-crit/10 text-sig-crit-text'
      : 'border-sig-warn/40 bg-sig-warn/10 text-sig-warn-text';

  const findingLabel = (f: Finding) => {
    const scope = findingScope(f);
    return scope === 'tunnel' ? 'Tunnel' : `End ${scope}`;
  };

  return (
    <SlideOverDrawer
      open={open}
      onOpenChange={onOpenChange}
      title={isEdit ? 'Edit tunnel' : 'New IPSec tunnel'}
      subtitle="The name, the VTI subnet and the inner IPs are assigned by the server."
      size="2xl"
      tabs={[
        { id: 'design', label: '1 · Design' },
        { id: 'paths', label: '2 · Paths' },
        { id: 'verify', label: '3 · Verify' },
      ]}
      activeTab={phase}
      onTabChange={(id) => setPhase(id as Phase)}
      footer={
        <>
          <Button  variant="secondary"
            type="button"
            onClick={() => onOpenChange(false)}
            
          >
            Cancel
          </Button>
          {phase === 'design' ? (
            <button
              type="button"
              onClick={() => setPhase('paths')}
              disabled={!canPreview}
              className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text-dim hover:text-text disabled:opacity-50"
            >
              Next: Paths
            </button>
          ) : null}
          {phase !== 'verify' || !previewIsCurrent ? (
            <button
              type="button"
              onClick={runPreview}
              disabled={!canPreview || previewing}
              className="rounded-md border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-semibold text-accent-text disabled:opacity-50"
            >
              {previewing ? 'Rendering…' : 'Preview the config'}
            </button>
          ) : null}
          {phase === 'verify' ? (
            <Button
              type="button"
              onClick={save}
              // A CURRENT preview is required: without one there are no
              // findings, so nothing would stand between an invalid intent
              // and the database - and a preview of an earlier design says
              // nothing about this one.
              disabled={saving || !previewIsCurrent || blocking.length > 0}
            >
              {saving ? 'Saving…' : isEdit ? 'Save changes' : 'Create tunnel'}
            </Button>
          ) : null}
        </>
      }
    >
      {loading ? (
        <div className="flex items-center gap-2 text-xs text-text-dim">
          <Loader2 className="h-3.5 w-3.5 animate-spin motion-reduce:animate-none" />
          Loading the tunnel…
        </div>
      ) : null}

      {error ? (
        <div
          role="alert"
          className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit-text"
        >
          {error}
        </div>
      ) : null}

      {phase === 'design' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <IpsecEndForm
              label="A"
              value={form.ends[0]}
              onChange={(next) => setEnd(0, next)}
              devices={devices}
              hints={hints[form.ends[0].deviceId]}
              idTypes={caps?.allowed?.id_types ?? []}
              otherDeviceId={form.ends[1].deviceId || null}
            />
            <IpsecEndForm
              label="B"
              value={form.ends[1]}
              onChange={(next) => setEnd(1, next)}
              devices={devices}
              hints={hints[form.ends[1].deviceId]}
              idTypes={caps?.allowed?.id_types ?? []}
              otherDeviceId={form.ends[0].deviceId || null}
            />
          </div>

          <div className="rounded-lg border border-border bg-bg-panel p-3 space-y-3">
            <h3 className="text-xs font-semibold text-text">Tunnel</h3>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="block">
                <span className="mb-1 block text-[11px] font-medium text-text-dim">Mode</span>
                <Select  className="bg-bg-card px-2.5 py-1.5"
                  value={form.mode}
                  onChange={(e) => setForm((p) => ({ ...p, mode: e.target.value }))}
                  aria-label="Tunnel mode"
                  
                >
                  {(caps?.allowed?.modes ?? [form.mode]).map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </Select>
                {caps && (caps.allowed?.modes?.length ?? 0) === 1 ? (
                  <span className="mt-1 block text-[10px] text-text-faint">
                    This vendor pair supports one mode only.
                  </span>
                ) : null}
              </label>

              <label className="block">
                <span className="mb-1 block text-[11px] font-medium text-text-dim">
                  Crypto profile
                </span>
                <Select  className="bg-bg-card px-2.5 py-1.5"
                  value={form.profile}
                  onChange={(e) =>
                    setForm((p) => ({ ...p, profile: e.target.value as ProfileName }))
                  }
                  aria-label="Crypto profile"
                  
                >
                  {form.profiles.map((p) => (
                    <option key={p.name} value={p.name}>
                      {p.label}
                    </option>
                  ))}
                  <option value="custom">Custom</option>
                </Select>
              </label>
            </div>

            {form.profile === 'custom' ? (
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                {customSelect('IKE version', 'ike_version', form.custom.ike_version, caps?.allowed?.ike_versions ?? ['ikev2'], null)}
                {customSelect('Encryption (IKE + ESP)', 'enc', form.custom.ike.enc, caps?.allowed?.encryption ?? [], 'Select…')}
                {customSelect(
                  'Integrity (IKE + ESP)',
                  'integ',
                  form.custom.ike.integ,
                  isAeadCipher(form.custom.ike.enc) ? [] : caps?.allowed?.integrity ?? [],
                  isAeadCipher(form.custom.ike.enc) ? 'None (AEAD cipher)' : 'Select…',
                )}
                {customSelect('PRF', 'prf', form.custom.ike.prf, caps?.allowed?.prf ?? [], 'Select…')}
                {customSelect('DH group', 'dh', form.custom.ike.dh, caps?.allowed?.dh_groups ?? [], 'Select…')}
                <label className="flex items-center gap-2 self-end pb-1.5 text-[11px] font-medium text-text-dim">
                  <input
                    type="checkbox"
                    checked={form.custom.esp.pfs !== ''}
                    // PFS reuses the DH group, so it needs one first - and a
                    // vendor pair that cannot do PFS does not offer it.
                    disabled={!form.custom.ike.dh || caps?.allowed?.pfs === false}
                    onChange={(e) => changeCustom('pfs', e.target.checked)}
                  />
                  Perfect forward secrecy (ESP uses the DH group)
                </label>
              </div>
            ) : null}

            <label className="block">
              <span className="mb-1 block text-[11px] font-medium text-text-dim">
                Pre-shared key
              </span>
              <Input  mono className="bg-bg-card px-2.5 py-1.5"
                type="password"
                value={form.psk}
                onChange={(e) => setForm((p) => ({ ...p, psk: e.target.value }))}
                placeholder={
                  isEdit
                    ? 'Leave as-is to keep the stored key'
                    : 'Leave blank and the server generates one'
                }
                autoComplete="new-password"
                
              />
              {form.psk && form.psk !== PSK_MASK && form.psk.length < 20 ? (
                <span className="mt-1 block text-[10px] text-sig-warn-text">
                  A pre-shared key must be at least 20 characters.
                </span>
              ) : null}
            </label>
          </div>
        </div>
      )}

      {phase === 'paths' && (
        <div className="space-y-3">
          <p className="text-xs text-text-dim">
            Every path between a protected subnet on one side and one on the other
            is enabled unless it is turned off here. A path the server does not
            recognise is silently left enabled, so the keys are canonicalised.
          </p>
          {paths.length === 0 ? (
            <p className="text-xs text-text-faint">
              Add protected subnets to both ends first.
            </p>
          ) : uncanonicalisable > 0 ? (
            <p className="text-xs text-sig-warn-text">
              {uncanonicalisable} path(s) cannot be toggled: their subnet is not
              IPv4, and a path key the server cannot match would silently stay
              enabled. Those paths stay enabled.
            </p>
          ) : (
            <div className="overflow-hidden rounded-lg border border-border">
              <table className="w-full border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-border bg-bg-panel text-[11px] uppercase tracking-wider text-text-faint">
                    <th className="px-3 py-2 font-semibold">End A subnet</th>
                    <th className="px-3 py-2 font-semibold">End B subnet</th>
                    <th className="px-3 py-2 font-semibold">Path</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/70">
                  {paths.map((p) => (
                    <tr key={p.key}>
                      <td className="px-3 py-2 font-mono text-text-dim">{p.a}</td>
                      <td className="px-3 py-2 font-mono text-text-dim">{p.b}</td>
                      <td className="px-3 py-2">
                        <button
                          type="button"
                          onClick={() => togglePath(p.key)}
                          aria-pressed={p.disabled}
                          className={cn(
                            'inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-semibold uppercase',
                            p.disabled
                              ? 'bg-sig-crit/15 text-sig-crit-text'
                              : 'bg-sig-ok/15 text-sig-ok-text',
                          )}
                        >
                          {p.disabled ? <X className="h-3 w-3" /> : <Check className="h-3 w-3" />}
                          {p.disabled ? 'Disabled' : 'Enabled'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {phase === 'verify' && (
        <div className="space-y-4">
          {preview && !previewIsCurrent ? (
            <p role="status" className="rounded-lg border border-sig-warn/40 bg-sig-warn/10 px-3 py-2 text-xs text-sig-warn-text">
              The design changed after this preview. Preview it again before saving — the
              findings below describe the earlier design.
            </p>
          ) : null}
          {!preview ? (
            <p className="rounded-lg border border-border bg-bg-panel px-3 py-2 text-xs text-text-dim">
              No preview yet — run one to see what each side will receive and what
              the server makes of it.
            </p>
          ) : preview.validation.length > 0 ? (
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-text">Findings</h3>
              <ul className="space-y-1.5">
                {preview.validation.map((f, i) => (
                  <li
                    key={`${f.code}-${i}`}
                    className={cn('rounded-lg border px-3 py-2 text-[11px]', findingTone(f))}
                  >
                    <div className="flex items-center gap-1.5 font-semibold">
                      <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
                      {findingLabel(f)} · {f.code}
                    </div>
                    <div className="mt-0.5">{f.message}</div>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="text-xs text-sig-ok-text">No findings — the configuration validates.</p>
          )}

          {preview?.psk_autogen ? (
            <p className="rounded-lg border border-border bg-bg-panel px-3 py-2 text-[11px] text-text-dim">
              No pre-shared key was entered, so the server generates one when the
              tunnel is saved.
            </p>
          ) : null}

          {preview?.provisional ? (
            <p className="rounded-lg border border-border bg-bg-panel px-3 py-2 text-[11px] text-text-dim">
              The name, the VTI subnet and the inner IPs are placeholders until the
              tunnel is saved.
            </p>
          ) : null}

          {preview && preview.ends.length === 0 ? (
            <p className="rounded-lg border border-sig-warn/40 bg-sig-warn/10 px-3 py-2 text-[11px] text-sig-warn-text">
              Nothing is rendered while a blocking finding stands — fix the
              findings above and preview again.
            </p>
          ) : null}

          {preview?.ends.map((end) => (
            <div key={end.end} className="rounded-lg border border-border bg-bg-panel p-3">
              <div className="mb-1.5 flex flex-wrap items-center gap-2">
                <span className="text-xs font-semibold text-text">
                  End {end.end === 0 ? 'A' : 'B'}
                </span>
                <span className="font-mono text-[10px] text-text-faint">{end.vendor}</span>
                <span className="text-[10px] text-text-faint">
                  {end.steps} apply step{end.steps === 1 ? '' : 's'}
                </span>
              </div>
              {end.auto_objects.length > 0 ? (
                <p className="mb-1.5 text-[10px] text-text-faint">
                  Auto-injected objects: {end.auto_objects.join(', ')}
                </p>
              ) : null}
              <pre className="max-h-64 overflow-auto rounded bg-bg-card p-2 font-mono text-[10px] text-text-dim">
                {end.preview}
              </pre>
            </div>
          ))}

          <button
            type="button"
            onClick={runPreview}
            disabled={previewing}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text-dim hover:text-text disabled:opacity-50"
          >
            {previewing ? 'Rendering…' : 'Preview again'}
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>
      )}
    </SlideOverDrawer>
  );
}
