/**
 * The per-device / per-site alert override.
 *
 * The console had only the GLOBAL settings and the notification policies, so a
 * noisy device or site could not be given its own thresholds — every device in
 * the fleet raised on the same numbers.
 *
 * The server's contract, which the form follows exactly:
 *
 * - The PUT BINDS ONTO the existing row, so an absent field PRESERVES the
 *   stored value rather than zeroing it. The body therefore carries only the
 *   fields the operator actually changed.
 * - `policy_id` and `event_profile_id` are pointers: null means "inherit".
 * - The Event Profile is NOT set here. V1 assigns it through the dedicated
 *   admin-only `/event-profile` endpoint, and the server caches the
 *   resolution — so it is sent separately.
 * - `storm_sources` is a site-only tri-state: blank inherits, 0 disables the
 *   digest for that site, and a positive number sets the threshold.
 */

export interface AlertConfigValues {
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

export type AlertConfigScope = 'device' | 'site';

/**
 * The body for PUT /admin/api/{devices,sites}/:id/alert-config.
 *
 * Only the fields the operator CHANGED are sent, because the server binds
 * onto the existing row: a field sent as 0 would overwrite the stored value
 * with a zero. A field left blank is omitted, which the server reads as
 * "keep what is stored".
 */
export function buildAlertConfigBody(
  values: AlertConfigValues,
  scope: AlertConfigScope,
): Record<string, unknown> {
  const body: Record<string, unknown> = {};

  // The policy is a POINTER on the model, so "inherit" is an explicit null.
  // Omitting it would leave the stored policy in place, which is not what
  // clearing the picker means.
  body.policy_id = values.policy_id === '' ? null : Number(values.policy_id);

  const num = (v: string) => (v === '' ? undefined : Number(v));
  const cpu = num(values.cpu_threshold);
  if (cpu !== undefined) body.cpu_threshold = cpu;
  const memory = num(values.memory_threshold);
  if (memory !== undefined) body.memory_threshold = memory;
  const disk = num(values.disk_threshold);
  if (disk !== undefined) body.disk_threshold = disk;
  const sessions = num(values.session_threshold);
  if (sessions !== undefined) body.session_threshold = sessions;
  const cooldown = num(values.cooldown_minutes);
  if (cooldown !== undefined) body.cooldown_minutes = cooldown;

  if (scope === 'device') {
    body.alerts_enabled = values.alerts_enabled;
  } else if (values.storm_sources !== '') {
    // Site only, and tri-state: blank inherits, so it is omitted.
    body.storm_sources = Number(values.storm_sources);
  }

  return body;
}

/**
 * The Event Profile is assigned through its own admin-only endpoint, not
 * through the alert-config body.
 *
 * Returns the body for PUT /admin/api/{devices,sites}/:id/event-profile, or
 * null when the profile did not change and no call is needed.
 */
export function buildEventProfileBody(
  currentProfileId: number | null | undefined,
  nextProfileId: string,
): { profile_id: number | null } | null {
  const next = nextProfileId === '' ? null : Number(nextProfileId);
  const current = currentProfileId ?? null;
  if (next === current) return null;
  return { profile_id: next };
}

/**
 * The server validates the percentages as 0-100 and the rest as
 * non-negative. Checking here keeps the operator from getting a 400 for a
 * typo.
 */
export function isValidAlertConfig(values: AlertConfigValues): boolean {
  const pct = (v: string) => {
    if (v === '') return true;
    const n = Number(v);
    return Number.isFinite(n) && n >= 0 && n <= 100;
  };
  const nonNeg = (v: string) => {
    if (v === '') return true;
    const n = Number(v);
    return Number.isFinite(n) && n >= 0;
  };
  return (
    pct(values.cpu_threshold) &&
    pct(values.memory_threshold) &&
    pct(values.disk_threshold) &&
    nonNeg(values.session_threshold) &&
    nonNeg(values.cooldown_minutes) &&
    nonNeg(values.storm_sources)
  );
}
