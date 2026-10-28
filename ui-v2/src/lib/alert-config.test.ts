import { describe, expect, it } from 'vitest';
import {
  alertConfigUrl,
  buildAlertConfigBody,
  buildEventProfileBody,
  isValidAlertConfig,
  thresholdField,
  type AlertConfigValues,
} from './alert-config';

const BASE: AlertConfigValues = {
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

describe('alertConfigUrl', () => {
  it('is the real route, with /admin/api exactly once', () => {
    // The drawer once prefixed /admin/api onto a path that already had it,
    // and every load, save and reset 404ed.
    expect(alertConfigUrl('device', 7)).toBe('/admin/api/devices/7/alert-config');
    expect(alertConfigUrl('site', '3')).toBe('/admin/api/sites/3/alert-config');
    expect(alertConfigUrl('device', 7).match(/\/admin\/api/g)).toHaveLength(1);
  });
});

describe('thresholdField', () => {
  it('shows a stored 0 (inherit) as blank, and a value as itself', () => {
    expect(thresholdField(0)).toBe('');
    expect(thresholdField(null)).toBe('');
    expect(thresholdField(undefined)).toBe('');
    expect(thresholdField(85)).toBe('85');
  });
});

describe('buildAlertConfigBody', () => {
  it('sends a blanked threshold as 0, which the engine reads as "inherit"', () => {
    // The PUT binds onto the stored row, so OMITTING a blank would keep the
    // old override: the operator could never hand a threshold back.
    const body = buildAlertConfigBody(BASE, 'device');
    expect(body.cpu_threshold).toBe(0);
    expect(body.memory_threshold).toBe(0);
    expect(body.disk_threshold).toBe(0);
    expect(body.session_threshold).toBe(0);
    expect(body.cooldown_minutes).toBe(0);
  });

  it('sends the thresholds the operator set', () => {
    const body = buildAlertConfigBody(
      { ...BASE, cpu_threshold: '90', memory_threshold: '80', disk_threshold: '95', session_threshold: '500', cooldown_minutes: '15' },
      'device',
    );
    expect(body.cpu_threshold).toBe(90);
    expect(body.memory_threshold).toBe(80);
    expect(body.disk_threshold).toBe(95);
    expect(body.session_threshold).toBe(500);
    expect(body.cooldown_minutes).toBe(15);
  });

  it('round-trips a seeded row unchanged', () => {
    // The form is seeded with thresholdField(stored), so an untouched save
    // writes back exactly what was stored.
    const stored = { cpu_threshold: 0, memory_threshold: 70, disk_threshold: 0, session_threshold: 900, cooldown_minutes: 5 };
    const values: AlertConfigValues = {
      ...BASE,
      cpu_threshold: thresholdField(stored.cpu_threshold),
      memory_threshold: thresholdField(stored.memory_threshold),
      disk_threshold: thresholdField(stored.disk_threshold),
      session_threshold: thresholdField(stored.session_threshold),
      cooldown_minutes: thresholdField(stored.cooldown_minutes),
    };
    expect(buildAlertConfigBody(values, 'device')).toMatchObject(stored);
  });

  it('sends an explicit null for an inherited policy', () => {
    const body = buildAlertConfigBody(BASE, 'device');
    expect(body.policy_id).toBeNull();
    expect(buildAlertConfigBody({ ...BASE, policy_id: '4' }, 'device').policy_id).toBe(4);
  });

  it('sends alerts_enabled for a device and not for a site', () => {
    expect(buildAlertConfigBody({ ...BASE, alerts_enabled: false }, 'device').alerts_enabled).toBe(false);
    expect('alerts_enabled' in buildAlertConfigBody({ ...BASE, alerts_enabled: false }, 'site')).toBe(false);
  });

  it('sends storm_sources for a site only, and null when blank (inherit)', () => {
    // Tri-state: blank inherits, 0 disables the digest, N sets it. The column
    // is a pointer, so inherit must be an explicit null - as V1 sends it.
    expect(buildAlertConfigBody({ ...BASE, storm_sources: '0' }, 'site').storm_sources).toBe(0);
    expect(buildAlertConfigBody({ ...BASE, storm_sources: '25' }, 'site').storm_sources).toBe(25);
    expect(buildAlertConfigBody(BASE, 'site').storm_sources).toBeNull();
    expect('storm_sources' in buildAlertConfigBody({ ...BASE, storm_sources: '5' }, 'device')).toBe(false);
  });

  it('never puts the event profile in the config body itself', () => {
    // The drawer adds it only when it changed (buildEventProfileBody).
    const body = buildAlertConfigBody({ ...BASE, event_profile_id: '7' }, 'device');
    expect('event_profile_id' in body).toBe(false);
  });
});

describe('buildEventProfileBody', () => {
  it('returns null when the profile did not change, so the key is left out', () => {
    expect(buildEventProfileBody(3, '3')).toBeNull();
    expect(buildEventProfileBody(null, '')).toBeNull();
    expect(buildEventProfileBody(undefined, '')).toBeNull();
  });

  it('carries the new profile under the key the server reads', () => {
    expect(buildEventProfileBody(3, '5')).toEqual({ event_profile_id: 5 });
  });

  it('sends an explicit null to go back to inheriting', () => {
    expect(buildEventProfileBody(3, '')).toEqual({ event_profile_id: null });
  });
});

describe('isValidAlertConfig', () => {
  it('accepts blank fields (they inherit)', () => {
    expect(isValidAlertConfig(BASE)).toBe(true);
  });

  it('rejects a percentage outside 0-100', () => {
    expect(isValidAlertConfig({ ...BASE, cpu_threshold: '101' })).toBe(false);
    expect(isValidAlertConfig({ ...BASE, memory_threshold: '-1' })).toBe(false);
    expect(isValidAlertConfig({ ...BASE, disk_threshold: '100' })).toBe(true);
  });

  it('rejects a negative count or cooldown', () => {
    expect(isValidAlertConfig({ ...BASE, session_threshold: '-5' })).toBe(false);
    expect(isValidAlertConfig({ ...BASE, cooldown_minutes: '-5' })).toBe(false);
  });

  it('rejects a negative storm threshold', () => {
    expect(isValidAlertConfig({ ...BASE, storm_sources: '-1' })).toBe(false);
  });
});
