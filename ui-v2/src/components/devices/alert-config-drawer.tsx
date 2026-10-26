import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { RotateCcw, Save } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn } from '@/lib/utils';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { useToast } from '@/components/ui/toast';
import {
  buildAlertConfigBody,
  buildEventProfileBody,
  isValidAlertConfig,
} from '@/lib/alert-config';

/** The device-level override. `null` means "inherit". */
export interface DeviceAlertConfig {
  device_id: number;
  policy_id?: number | null;
  event_profile_id?: number | null;
  cpu_threshold: number;
  memory_threshold: number;
  disk_threshold: number;
  session_threshold: number;
  cooldown_minutes: number;
  alerts_enabled: boolean;
}

/** The site-level override. `storm_sources` is tri-state: null = inherit. */
export interface SiteAlertConfig {
  site_id: number;
  policy_id?: number | null;
  event_profile_id?: number | null;
  cpu_threshold: number;
  memory_threshold: number;
  disk_threshold: number;
  session_threshold: number;
  cooldown_minutes: number;
  storm_sources?: number | null;
}

interface PolicyOption {
  id: number;
  name: string;
}

interface ProfileOption {
  id: number;
  name: string;
}

export interface AlertConfigDrawerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** "device" or "site" — the endpoints and the fields differ. */
  scope: 'device' | 'site';
  /** The device or site id. */
  id: number;
  /** The name, for the drawer title. */
  name: string;
  /**
   * Whether the operator may assign an Event Profile.
   *
   * The Event Profile is assigned through its own endpoint, which is
   * ADMIN-ONLY. Offering the picker to an operator means a save that commits
   * the alert-config and then answers 403 on the profile - a partial write
   * and a misleading "could not save".
   */
  canAssignEventProfile?: boolean;
}

interface FormState {
  policy_id: string;
  event_profile_id: string;
  cpu_threshold: string;
  memory_threshold: string;
  disk_threshold: string;
  session_threshold: string;
  cooldown_minutes: string;
  alerts_enabled: boolean;
  storm_sources: string;
}

const EMPTY: FormState = {
  policy_id: '',
  event_profile_id: '',
  cpu_threshold: '',
  memory_threshold: '',
  disk_threshold: '',
  session_threshold: '',
  cooldown_minutes: '',
  alerts_enabled: true,
  storm_sources: '',
};

/**
 * The per-device / per-site alert override.
 *
 * The console had only the GLOBAL settings and the notification policies, so
 * a noisy device or site could not be given its own thresholds — every device
 * in the fleet raised on the same numbers.
 *
 * The server's contract, which the form follows exactly:
 *
 * - The PUT BINDS ONTO the existing row, so an absent field PRESERVES the
 *   stored value rather than zeroing it. The form therefore sends only the
 *   fields the operator actually changed.
 * - `policy_id` and `event_profile_id` are pointers: null means "inherit".
 * - The Event Profile is NOT set here. V1 assigns it through the dedicated
 *   admin-only `/event-profile` endpoint, and the server caches the
 *   resolution — so it is sent separately, below.
 * - `storm_sources` is a site-only tri-state: blank inherits, 0 disables the
 *   digest for that site, and a positive number sets the threshold.
 */
export function AlertConfigDrawer({
  open,
  onOpenChange,
  scope,
  id,
  name,
  canAssignEventProfile = true,
}: AlertConfigDrawerProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<FormState>(EMPTY);

  const configKey = scope === 'device' ? 'device-alert-config' : 'site-alert-config';
  const path = scope === 'device' ? `/admin/api/devices/${id}` : `/admin/api/sites/${id}`;

  const { data: config, isLoading } = useQuery({
    queryKey: [configKey, id],
    queryFn: () =>
      apiFetch<DeviceAlertConfig | SiteAlertConfig>(`/admin/api${path}/alert-config`),
    enabled: open,
    retry: false,
  });

  const { data: policies } = useQuery({
    queryKey: ['alert-policies'],
    queryFn: () => apiFetch<PolicyOption[]>('/admin/api/alert-policies'),
    enabled: open,
  });

  const { data: profiles } = useQuery({
    queryKey: ['event-rule-profiles'],
    queryFn: () => apiFetch<ProfileOption[]>('/admin/api/event-rule-profiles'),
    enabled: open && canAssignEventProfile,
  });

  useEffect(() => {
    if (!open || !config) return;
    const device = scope === 'device' ? (config as DeviceAlertConfig) : null;
    const site = scope === 'site' ? (config as SiteAlertConfig) : null;
    setForm({
      policy_id: config.policy_id ? String(config.policy_id) : '',
      event_profile_id: config.event_profile_id ? String(config.event_profile_id) : '',
      cpu_threshold: String(config.cpu_threshold ?? ''),
      memory_threshold: String(config.memory_threshold ?? ''),
      disk_threshold: String(config.disk_threshold ?? ''),
      session_threshold: String(config.session_threshold ?? ''),
      cooldown_minutes: String(config.cooldown_minutes ?? ''),
      alerts_enabled: device ? device.alerts_enabled !== false : true,
      storm_sources:
        site && site.storm_sources != null ? String(site.storm_sources) : '',
    });
  }, [open, config, scope]);

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }));

  const valid = isValidAlertConfig(form);

  const save = async () => {
    if (!valid) return;
    const body = buildAlertConfigBody(form, scope);

    try {
      await apiFetch(`/admin/api${path}/alert-config`, { method: 'PUT', body });
      // The Event Profile has its own admin-only endpoint; the server
      // refreshes the resolution cache from it, so it is sent separately.
      const profileBody = canAssignEventProfile
        ? buildEventProfileBody(config?.event_profile_id, form.event_profile_id)
        : null;
      if (profileBody) {
        await apiFetch(`/admin/api${path}/event-profile`, {
          method: 'PUT',
          body: profileBody,
        });
      }
      toast({
        title: scope === 'device' ? 'Device alert override saved' : 'Site alert override saved',
        variant: 'success',
      });
      queryClient.invalidateQueries({ queryKey: [configKey, id] });
      queryClient.invalidateQueries({ queryKey: ['alert-config-overview'] });
      onOpenChange(false);
    } catch (err) {
      toast({
        title: 'Could not save the override',
        description: err instanceof Error ? err.message : 'request failed',
        variant: 'error',
      });
    }
  };

  const reset = async () => {
    try {
      await apiFetch(`/admin/api${path}/alert-config`, { method: 'DELETE' });
      toast({ title: 'Override reset to the global defaults', variant: 'info' });
      queryClient.invalidateQueries({ queryKey: [configKey, id] });
      onOpenChange(false);
    } catch (err) {
      toast({
        title: 'Could not reset the override',
        description: err instanceof Error ? err.message : 'request failed',
        variant: 'error',
      });
    }
  };

  const numberField = (
    label: string,
    key: 'cpu_threshold' | 'memory_threshold' | 'disk_threshold' | 'session_threshold' | 'cooldown_minutes',
    max?: number,
  ) => (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-text-dim">{label}</span>
      <input
        type="number"
        min={0}
        max={max}
        value={form[key]}
        onChange={(e) => set(key, e.target.value)}
        className={cn(
          'w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text',
          max != null && !isValidAlertConfig({ ...form, [key]: form[key] }) && 'border-sig-crit',
        )}
      />
      {max != null && !isValidAlertConfig({ ...form, [key]: form[key] }) ? (
        <span className="mt-1 block text-[10px] text-sig-crit">Must be between 0 and 100.</span>
      ) : null}
    </label>
  );

  return (
    <SlideOverDrawer
      open={open}
      onOpenChange={onOpenChange}
      title={`Alert overrides — ${name}`}
      subtitle="Per-object thresholds and routing. A blank field KEEPS the current override; 'Reset to defaults' removes the override so the global values apply."
      size="lg"
      footer={
        <>
          <button
            type="button"
            onClick={reset}
            className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text-dim hover:text-text"
          >
            <RotateCcw className="mr-1 inline h-3.5 w-3.5" />
            Reset to defaults
          </button>
          <button
            type="button"
            onClick={save}
            disabled={!valid || isLoading}
            className="rounded-md bg-accent px-3.5 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
          >
            <Save className="mr-1 inline h-3.5 w-3.5" />
            Save override
          </button>
        </>
      }
    >
      <div className="space-y-4">
        {scope === 'device' ? (
          <label className="flex items-center gap-2 text-xs text-text">
            <input
              type="checkbox"
              checked={form.alerts_enabled}
              onChange={(e) => set('alerts_enabled', e.target.checked)}
              className="h-4 w-4 rounded accent-accent"
            />
            Alerts enabled for this device
          </label>
        ) : null}

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">
              Notification profile
            </span>
            <select
              value={form.policy_id}
              onChange={(e) => set('policy_id', e.target.value)}
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            >
              <option value="">Inherit</option>
              {(policies ?? []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>

          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">
              Event profile
              {!canAssignEventProfile ? (
                <span className="ml-1 text-[10px] font-normal text-text-faint">Admin only</span>
              ) : null}
            </span>
            <select
              value={form.event_profile_id}
              disabled={!canAssignEventProfile}
              onChange={(e) => set('event_profile_id', e.target.value)}
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text disabled:opacity-60"
            >
              <option value="">Inherit</option>
              {(profiles ?? []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
          {numberField('CPU threshold (%)', 'cpu_threshold', 100)}
          {numberField('Memory threshold (%)', 'memory_threshold', 100)}
          {numberField('Disk threshold (%)', 'disk_threshold', 100)}
          {numberField('Session threshold', 'session_threshold')}
          {numberField('Cooldown (minutes)', 'cooldown_minutes')}
        </div>

        {scope === 'site' ? (
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">
              Storm digest threshold (distinct sources)
            </span>
            <input
              type="number"
              min={0}
              value={form.storm_sources}
              onChange={(e) => set('storm_sources', e.target.value)}
              placeholder="Unchanged"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
            />
            <span className="mt-1 block text-[10px] text-text-faint">
              Blank keeps the current override. 0 disables the digest for this
              site.
            </span>
          </label>
        ) : null}
      </div>
    </SlideOverDrawer>
  );
}
