export type Tone = 'ok' | 'warn' | 'crit';

/**
 * HA sync status vocabulary. Healthy members report "synchronized" (ASA probe),
 * "active"/"standby" or "up"; failed ones "unsynchronized", "not in sync",
 * "out of sync", "down", "error", "failed". An /in.?sync/ test alone both misses
 * "synchronized" and greens "not in sync".
 */
export function syncTone(status: string | null | undefined): Tone {
  // The Cisco ASA probe appends a free-form detail suffix, e.g.
  // "active (Active unit)" / "standby (Standby unit)". Match on the leading
  // status token, not the whole string.
  const value = String(status ?? '')
    .trim()
    .toLowerCase()
    .replace(/\s*\([^)]*\)\s*$/, '');
  if (/unsynchronized|out.?of.?sync|not.?in.?sync|^(down|error|failed)$/.test(value)) return 'crit';
  if (/synchronized|^in.?sync$|^(up|active|standby)$/.test(value)) return 'ok';
  return 'warn';
}

export interface LicenceState {
  hasDate: boolean;
  expired: boolean;
  expiring: boolean;
  days: number | null;
  label: string;
  tone: Tone;
}

/**
 * Licence tone/label. The date is the source of truth; the probe's status is
 * only used when there is no parseable expiry (e.g. "perpetual"), so the badge
 * colour and the word on it can never disagree.
 */
export function licenceState(
  licence: { expiry_date?: string | null; status?: string | null } | null | undefined,
  now: number = Date.now(),
): LicenceState {
  const raw = licence?.expiry_date ? new Date(licence.expiry_date) : null;
  const hasDate = !!raw && !Number.isNaN(raw.getTime());
  if (hasDate) {
    const expired = raw!.getTime() < now;
    const days = Math.ceil((raw!.getTime() - now) / 86_400_000);
    const expiring = !expired && days <= 30;
    return {
      hasDate: true,
      expired,
      expiring,
      days,
      label: expired ? 'expired' : expiring ? 'expiring' : 'ok',
      tone: expired ? 'crit' : expiring ? 'warn' : 'ok',
    };
  }
  const status = String(licence?.status ?? '')
    .trim()
    .toLowerCase();
  const tone: Tone = /expired|invalid|fail/.test(status)
    ? 'crit'
    : /active|ok|valid|perpetual/.test(status)
      ? 'ok'
      : 'warn';
  return {
    hasDate: false,
    expired: false,
    expiring: false,
    days: null,
    label: licence?.status || 'unknown',
    tone,
  };
}
