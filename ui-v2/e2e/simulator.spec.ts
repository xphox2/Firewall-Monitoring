import { expect, test } from '@playwright/test';
import { installApiMocks } from './mocks';

test('renders the resolved effective alert policy including maintenance', async ({ page }) => {
  await installApiMocks(page, [
    {
      match: (url) => url.pathname === '/admin/api/alert-config/overview',
      body: { global: {}, overrides: [] },
    },
    { match: (url) => url.pathname === '/admin/api/settings', body: [] },
    { match: (url) => url.pathname === '/admin/api/alert-policies', body: [] },
    { match: (url) => url.pathname === '/admin/api/event-rule-profiles', body: [] },
    {
      match: (url) => url.pathname === '/admin/api/devices',
      body: [{ id: 1, name: 'FW-1' }],
    },
    { match: (url) => url.pathname === '/admin/api/alert-types', body: [] },
    {
      match: (url) => url.pathname === '/admin/api/alert-config/effective',
      body: {
        alert_type: 'CPU_HIGH',
        effective: {
          threshold: 80,
          clear_threshold: 75,
          mode: 'static',
          zscore_k: 0,
          cooldown_minutes: 15,
          severity: 'critical',
          alert_enabled: true,
          storm_sources: 5,
          in_maintenance: true,
          policy_id: 3,
          rule_matched: false,
          notify_email: true,
          notify_slack: true,
          notify_teams: true,
          notify_discord: false,
          notify_webhook: false,
          notify_pagerduty: false,
          notify_opsgenie: false,
          escalation_enabled: true,
          escalation_minutes: 30,
          escalation_repeat: 10,
        },
        provenance: { threshold: 'global', cooldown: 'policy' },
      },
    },
  ]);

  await page.goto('/admin/v2/configuration/alerting?tab=effective');
  await expect(page.getByText('Effective Alert Policy Simulator')).toBeVisible();

  await page.getByLabel('Select device to simulate effective policy').selectOption('1');
  await expect(page.getByText('Firing threshold')).toBeVisible();
  await expect(page.getByText('80%')).toBeVisible();
  await expect(page.getByText('75%', { exact: true })).toBeVisible();
  await expect(page.getByText('15 min')).toBeVisible();
  await expect(page.getByText('Notification channels', { exact: true })).toBeVisible();
  for (const channel of ['Email', 'Slack', 'Teams']) {
    await expect(page.getByText(channel, { exact: true })).toBeVisible();
  }
  await expect(page.getByText('from Global')).toBeVisible();
  await expect(page.getByText('In a maintenance window.')).toBeVisible();
  await expect(page.getByText('No channels enabled')).toHaveCount(0);
});
