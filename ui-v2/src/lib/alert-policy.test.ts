import { describe, expect, it } from 'vitest';
import { buildAlertPolicyBody, type AlertPolicy, type AlertPolicyDraft } from './alert-policy';

function draft(overrides: Partial<AlertPolicyDraft> = {}): AlertPolicyDraft {
  return {
    name: '  Tier 1  ',
    description: ' primary routing ',
    cooldown: '15',
    email: true,
    slack: false,
    discord: false,
    teams: false,
    webhook: false,
    pagerduty: false,
    recipients: 'ops@example.com ',
    ...overrides,
  };
}

const existing: AlertPolicy = {
  id: 7,
  name: 'Tier 1',
  is_default: true,
  notify_email: true,
  notify_slack: true,
  notify_opsgenie: true,
  email_recipients: 'ops@example.com',
  slack_webhook_url: '********',
  discord_webhook_url: '',
  webhook_url: '********',
  escalation_enabled: true,
  escalation_minutes: 45,
  escalation_repeat: 5,
  escalation_steps: '[{"after_minutes":5,"channels":["slack"]}]',
  rules: [{ alert_type: 'CPU_HIGH', enabled: true }],
};

describe('buildAlertPolicyBody', () => {
  it('uses the handler field names, not *_enabled', () => {
    const body = buildAlertPolicyBody(existing, draft());
    expect(body).toMatchObject({
      notify_email: true,
      notify_slack: false,
      notify_discord: false,
      notify_teams: false,
      notify_webhook: false,
      notify_pagerduty: false,
    });
    expect(body).not.toHaveProperty('email_enabled');
    expect(body).not.toHaveProperty('slack_enabled');
  });

  it('round-trips every column a full Save would otherwise zero', () => {
    const body = buildAlertPolicyBody(existing, draft());
    expect(body).toMatchObject({
      slack_webhook_url: '********',
      webhook_url: '********',
      notify_opsgenie: true,
      escalation_enabled: true,
      escalation_minutes: 45,
      escalation_repeat: 5,
      escalation_steps: '[{"after_minutes":5,"channels":["slack"]}]',
      is_default: true,
    });
  });

  it('does not echo the rules association back into Save', () => {
    expect(buildAlertPolicyBody(existing, draft())).not.toHaveProperty('rules');
  });

  it('trims text fields and preserves an explicit zero cooldown', () => {
    const body = buildAlertPolicyBody(null, draft({ cooldown: '0' }));
    expect(body.name).toBe('Tier 1');
    expect(body.description).toBe('primary routing');
    expect(body.email_recipients).toBe('ops@example.com');
    expect(body.cooldown_minutes).toBe(0);
  });

  it('defaults a blank cooldown to 15 and an unknown policy to safe zeros', () => {
    const body = buildAlertPolicyBody(null, draft({ cooldown: '' }));
    expect(body.cooldown_minutes).toBe(15);
    expect(body).toMatchObject({
      notify_opsgenie: false,
      slack_webhook_url: '',
      escalation_enabled: false,
      is_default: false,
    });
  });
});
