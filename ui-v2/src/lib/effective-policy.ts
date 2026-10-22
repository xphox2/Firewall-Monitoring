export interface EffectiveAlertValues {
  threshold?: number;
  clear_threshold?: number;
  mode?: string;
  zscore_k?: number;
  cooldown_minutes?: number;
  severity?: string;
  alert_enabled?: boolean;
  storm_sources?: number;
  in_maintenance?: boolean;
  policy_id?: number | null;
  rule_matched?: boolean;
  rule_severity?: string;
  notify_email?: boolean;
  notify_slack?: boolean;
  notify_discord?: boolean;
  notify_webhook?: boolean;
  notify_pagerduty?: boolean;
  notify_opsgenie?: boolean;
  notify_teams?: boolean;
  escalation_enabled?: boolean;
  escalation_minutes?: number;
  escalation_repeat?: number;
}

export interface EffectiveAlertProvenance {
  threshold?: string;
  cooldown?: string;
  suppressed_by_rule?: boolean;
  alerts_disabled?: boolean;
  toggle_layer?: string;
  rule_id?: number;
  rule_name?: string;
}

export interface EffectiveAlertConfig {
  alert_type?: string;
  effective?: EffectiveAlertValues;
  provenance?: EffectiveAlertProvenance;
}

/** Percent thresholds are ratios on the wire; sessions are a raw count. */
export function formatAlertThreshold(
  alertType: string | undefined,
  value: number | null | undefined,
): string {
  if (value == null || !Number.isFinite(Number(value))) return '—';
  if (alertType === 'SESSIONS_HIGH') return Math.round(Number(value)).toLocaleString();
  return `${Math.round(Number(value) * 100) / 100}%`;
}

export function provenanceLabel(layer: string | undefined): string {
  switch (String(layer ?? '').toLowerCase()) {
    case '':
    case 'default':
      return 'the default chain';
    case 'global':
      return 'Global';
    case 'policy':
      return 'Policy';
    case 'site':
      return 'Site';
    case 'device':
      return 'Device';
    case 'rule':
      return 'the matching event rule';
    default:
      return layer ?? 'the default chain';
  }
}

const CHANNELS: Array<[keyof EffectiveAlertValues, string]> = [
  ['notify_email', 'Email'],
  ['notify_slack', 'Slack'],
  ['notify_discord', 'Discord'],
  ['notify_webhook', 'Webhook'],
  ['notify_pagerduty', 'PagerDuty'],
  ['notify_opsgenie', 'Opsgenie'],
  ['notify_teams', 'Teams'],
];

export function enabledChannels(effective: EffectiveAlertValues | undefined): string[] {
  return CHANNELS.filter(([key]) => Boolean(effective?.[key])).map(([, label]) => label);
}

export type EffectiveTone = 'ok' | 'warn' | 'crit';

export interface EffectiveState {
  tone: EffectiveTone;
  label: string;
  detail: string;
}

/**
 * The one status line for a simulated scope, in the same precedence the firing
 * path applies: a disabled scope cannot fire even with a valid threshold, and a
 * maintenance window or a suppressing event rule mutes it next.
 */
export function describeEffectiveState(
  effective: EffectiveAlertValues | undefined,
  provenance: EffectiveAlertProvenance | undefined,
): EffectiveState {
  if (provenance?.alerts_disabled || effective?.alert_enabled === false) {
    const layer = provenance?.toggle_layer;
    return {
      tone: 'crit',
      label: 'Alerts are off',
      detail: layer
        ? `Turned off at the ${provenanceLabel(layer)} layer — nothing fires for this type.`
        : 'The master switch is off for this scope — nothing fires for this type.',
    };
  }
  if (effective?.in_maintenance) {
    return {
      tone: 'warn',
      label: 'In a maintenance window',
      detail: 'Firing is suppressed right now; the resolved values below apply again when the window ends.',
    };
  }
  if (provenance?.suppressed_by_rule) {
    return {
      tone: 'warn',
      label: 'Suppressed by an event rule',
      detail: `${provenance.rule_name || `Rule #${provenance.rule_id ?? '?'}`} matches this scope, so the alert is muted.`,
    };
  }
  return {
    tone: 'ok',
    label: 'Active',
    detail: 'An alert fires with the values below when this threshold is crossed.',
  };
}
