/**
 * The per-device / per-site alert override.
 *
 * The console had only the GLOBAL settings and the notification policies, so a
 * noisy device or site could not be given its own thresholds — every device in
 * the fleet raised on the same numbers.
 *
 * The server's contract, which the form follows exactly:
 *
 * - The PUT BINDS ONTO the existing row. The form is seeded from that row, so
 *   it sends the WHOLE override back — the same as V1 — and a field the
 *   operator blanked really is cleared.
 * - A threshold or cooldown of 0 means "inherit": the alert engine only
 *   applies an override that is > 0 (internal/alerts/policy.go,
 *   overrideThreshold). So a stored 0 is shown blank, and a blank is sent as 0.
 * - `policy_id` and `event_profile_id` are pointers: null means "inherit".
 * - The Event Profile rides in the SAME body as the config, so the server
 *   writes both in one transaction. It is only sent when it changed, because
 *   assigning one is admin-only (see buildEventProfileBody).
 * - `storm_sources` is a site-only tri-state: blank inherits (null), 0 disables
 *   the digest for that site, and a positive number sets the threshold.
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
 * The alert-config route for a device or a site.
 *
 * One place, because the drawer once built `/admin/api` into a path and then
 * prefixed it again — `/admin/api/admin/api/...` — and every load, save and
 * reset 404ed while every gate stayed green.
 */
export function alertConfigUrl(scope: AlertConfigScope, id: number | string): string {
  return scope === 'device'
    ? `/admin/api/devices/${id}/alert-config`
    : `/admin/api/sites/${id}/alert-config`;
}

/**
 * A stored threshold as the form shows it: 0 is "inherit", so it is blank.
 */
export function thresholdField(stored: number | null | undefined): string {
  return stored ? String(stored) : '';
}

/**
 * The body for PUT /admin/api/{devices,sites}/:id/alert-config.
 *
 * Every field is sent. The form was seeded from the stored row, so an
 * untouched field round-trips its own value, and a field the operator blanked
 * is sent as its "inherit" value — 0 for a threshold, null for a pointer.
 * Omitting a blank instead would leave the stored override in place: the
 * operator could never hand a threshold back to the policy.
 */
export function buildAlertConfigBody(
  values: AlertConfigValues,
  scope: AlertConfigScope,
): Record<string, unknown> {
  const num = (v: string) => (v === '' ? 0 : Number(v));
  const body: Record<string, unknown> = {
    policy_id: values.policy_id === '' ? null : Number(values.policy_id),
    cpu_threshold: num(values.cpu_threshold),
    memory_threshold: num(values.memory_threshold),
    disk_threshold: num(values.disk_threshold),
    session_threshold: num(values.session_threshold),
    cooldown_minutes: num(values.cooldown_minutes),
  };

  if (scope === 'device') {
    body.alerts_enabled = values.alerts_enabled;
  } else {
    // Tri-state: blank inherits, and inherit is an explicit null — the
    // column is a pointer, so an omitted key would keep the stored override.
    body.storm_sources = values.storm_sources === '' ? null : Number(values.storm_sources);
  }

  return body;
}

/**
 * The `event_profile_id` to put in the alert-config body, or null when the
 * profile did not change and the key must be left OUT.
 *
 * Leaving it out matters: the server reads an absent key as "leave the
 * assignment alone", and assigning or clearing a profile is admin-only, so a
 * key sent on every save would make a non-admin's save fail.
 */
export function buildEventProfileBody(
  currentProfileId: number | null | undefined,
  nextProfileId: string,
): { event_profile_id: number | null } | null {
  const next = nextProfileId === '' ? null : Number(nextProfileId);
  const current = currentProfileId ?? null;
  if (next === current) return null;
  return { event_profile_id: next };
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
