import { describe, expect, it } from 'vitest';
import {
  capabilityFeatureRows,
  capabilityFieldRows,
  capabilitySummary,
  capabilityTone,
  stateLabel,
} from './device-capabilities';

describe('capabilityFeatureRows', () => {
  it('orders available features first and sorts alphabetically within a state', () => {
    const rows = capabilityFeatureRows({
      zeta: { state: 'unsupported', fields: ['src_mac'] },
      beta: { state: 'supported', fields: ['action'] },
      alpha: { state: 'supported', fields: ['src_ip'] },
      gamma: { state: 'degraded', fields: ['user'] },
    });
    expect(rows.map((r) => r.name)).toEqual(['alpha', 'beta', 'gamma', 'zeta']);
    expect(rows[0].fields).toEqual(['src_ip']);
  });

  it('tolerates missing fields and unknown states', () => {
    const rows = capabilityFeatureRows({ weird: { state: 'mystery' } });
    expect(rows).toEqual([{ name: 'weird', state: 'mystery', fields: [] }]);
  });
});

describe('capabilityFieldRows', () => {
  it('sorts fields alphabetically', () => {
    const rows = capabilityFieldRows({
      src_ip: { state: 'native', source: 'syslog', count: 4 },
      action: { state: 'native', source: 'syslog', count: 9 },
    });
    expect(rows.map((r) => r.name)).toEqual(['action', 'src_ip']);
  });
});

describe('capabilitySummary', () => {
  it('counts known verdicts and ignores anything else', () => {
    expect(
      capabilitySummary({
        a: { state: 'supported' },
        b: { state: 'supported' },
        c: { state: 'degraded' },
        d: { state: 'inactive' },
        e: { state: 'unsupported' },
        f: { state: '???' },
      }),
    ).toEqual({ supported: 2, degraded: 1, inactive: 1, unsupported: 1 });
  });
});

describe('capabilityTone', () => {
  it('maps field and feature states to one visual language', () => {
    expect(capabilityTone('supported')).toBe('ok');
    expect(capabilityTone('native')).toBe('ok');
    expect(capabilityTone('degraded')).toBe('warn');
    expect(capabilityTone('config_dependent')).toBe('accent');
    expect(capabilityTone('unsupported')).toBe('crit');
    expect(capabilityTone('inactive')).toBe('muted');
  });
});

describe('stateLabel', () => {
  it('humanises snake_case states', () => {
    expect(stateLabel('config_dependent')).toBe('Config Dependent');
    expect(stateLabel(undefined)).toBe('Unknown');
  });
});
