export interface AlertPolicy {
  id: number;
  name: string;
  description?: string;
  is_default?: boolean;
  // Wire fields match models.AlertPolicy exactly. The previous *_enabled names
  // were never bound by the handler, and because UpdateAlertPolicy binds a
  // fresh struct and Save()s every column, sending them silently disabled all
  // channels and erased the webhook URLs on the next edit.
  notify_email?: boolean;
  notify_slack?: boolean;
  notify_discord?: boolean;
  notify_teams?: boolean;
  notify_webhook?: boolean;
  notify_pagerduty?: boolean;
  notify_opsgenie?: boolean;
  email_recipients?: string;
  slack_webhook_url?: string;
  discord_webhook_url?: string;
  webhook_url?: string;
  cooldown_minutes?: number;
  escalation_enabled?: boolean;
  escalation_minutes?: number;
  escalation_repeat?: number;
  escalation_steps?: string;
  rules?: Array<{
    alert_type: string;
    enabled: boolean;
    severity?: string;
  }>;
}

export interface AlertPolicyDraft {
  name: string;
  description: string;
  cooldown: string;
  email: boolean;
  slack: boolean;
  discord: boolean;
  teams: boolean;
  webhook: boolean;
  pagerduty: boolean;
  recipients: string;
}

/**
 * Build the PUT/POST body for a notification profile.
 *
 * UpdateAlertPolicy binds a fresh models.AlertPolicy and calls db.Save (a
 * full-column write), so every persisted column must be present or it is
 * written back as its zero value. The read path masks webhook URLs as
 * "********"; sending that mask back is what triggers the handler's
 * preserve-on-write restore. `rules` is deliberately omitted: it is an
 * association edited through /alert-policies/:id/rules, and echoing a stale
 * array back into Save would upsert it.
 */
export function buildAlertPolicyBody(
  existing: Partial<AlertPolicy> | null,
  draft: AlertPolicyDraft,
): Record<string, unknown> {
  // `|| 15` turned a deliberate 0 (no cooldown) into 15; only fall back when
  // the field is genuinely empty or non-numeric.
  const cooldownRaw = Number(draft.cooldown);
  const cooldown =
    draft.cooldown.trim() !== '' && Number.isFinite(cooldownRaw) && cooldownRaw >= 0
      ? cooldownRaw
      : 15;

  return {
    name: draft.name.trim(),
    description: draft.description.trim(),
    cooldown_minutes: cooldown,
    notify_email: draft.email,
    notify_slack: draft.slack,
    notify_discord: draft.discord,
    notify_teams: draft.teams,
    notify_webhook: draft.webhook,
    notify_pagerduty: draft.pagerduty,
    notify_opsgenie: existing?.notify_opsgenie ?? false,
    email_recipients: draft.recipients.trim(),
    slack_webhook_url: existing?.slack_webhook_url ?? '',
    discord_webhook_url: existing?.discord_webhook_url ?? '',
    webhook_url: existing?.webhook_url ?? '',
    escalation_enabled: existing?.escalation_enabled ?? false,
    escalation_minutes: existing?.escalation_minutes ?? 30,
    escalation_repeat: existing?.escalation_repeat ?? 3,
    escalation_steps: existing?.escalation_steps ?? '',
    is_default: existing?.is_default ?? false,
  };
}
