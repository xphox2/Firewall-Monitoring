import { describe, expect, it } from 'vitest';
import {
  describeEffectiveState,
  enabledChannels,
  formatAlertThreshold,
  provenanceLabel,
} from './effective-policy';

describe('formatAlertThreshold', () => {
  it('renders percentages for resource alerts and a count for sessions', () => {
    expect(formatAlertThreshold('CPU_HIGH', 80)).toBe('80%');
    expect(formatAlertThreshold('DISK_HIGH', 91.256)).toBe('91.26%');
    expect(formatAlertThreshold('SESSIONS_HIGH', 12000)).toBe('12,000');
  });

  it('renders a dash for a missing or non-finite value', () => {
    expect(formatAlertThreshold('CPU_HIGH', undefined)).toBe('—');
    expect(formatAlertThreshold('CPU_HIGH', Number.NaN)).toBe('—');
  });
});

describe('provenanceLabel', () => {
  it('maps resolver layers to operator-facing names', () => {
    expect(provenanceLabel('global')).toBe('Global');
    expect(provenanceLabel('policy')).toBe('Policy');
    expect(provenanceLabel('site')).toBe('Site');
    expect(provenanceLabel('device')).toBe('Device');
    expect(provenanceLabel('rule')).toBe('the matching event rule');
    expect(provenanceLabel('')).toBe('the default chain');
    expect(provenanceLabel(undefined)).toBe('the default chain');
  });
});

describe('enabledChannels', () => {
  it('lists only enabled channels in a stable order', () => {
    expect(
      enabledChannels({ notify_email: true, notify_slack: false, notify_teams: true }),
    ).toEqual(['Email', 'Teams']);
    expect(enabledChannels(undefined)).toEqual([]);
  });
});

describe('describeEffectiveState', () => {
  it('prioritises a disabled scope over everything else', () => {
    expect(
      describeEffectiveState(
        { alert_enabled: false, in_maintenance: true },
        { alerts_disabled: true, toggle_layer: 'device' },
      ),
    ).toEqual({
      tone: 'crit',
      label: 'Alerts are off',
      detail: 'Turned off at the Device layer — nothing fires for this type.',
    });
  });

  it('reports maintenance before a suppressing rule', () => {
    const state = describeEffectiveState(
      { in_maintenance: true },
      { suppressed_by_rule: true, rule_name: 'quiet hours' },
    );
    expect(state.tone).toBe('warn');
    expect(state.label).toBe('In a maintenance window');
  });

  it('names the suppressing rule', () => {
    const state = describeEffectiveState(
      {},
      { suppressed_by_rule: true, rule_name: 'mute disk' },
    );
    expect(state.detail).toContain('mute disk');
  });

  it('is active otherwise', () => {
    expect(describeEffectiveState({ alert_enabled: true }, {}).tone).toBe('ok');
  });
});
