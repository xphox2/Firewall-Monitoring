import { describe, expect, it } from 'vitest';
import {
  buildAlertConfigBody,
  buildEventProfileBody,
  isValidAlertConfig,
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

describe('buildAlertConfigBody', () => {
  it('OMITS a field the operator left blank', () => {
    // The server BINDS onto the existing row, so an absent field PRESERVES
    // the stored value. A field sent as 0 would overwrite it with a zero.
    const body = buildAlertConfigBody(BASE, 'device');
    expect('cpu_threshold' in body).toBe(false);
    expect('memory_threshold' in body).toBe(false);
    expect('disk_threshold' in body).toBe(false);
    expect('session_threshold' in body).toBe(false);
    expect('cooldown_minutes' in body).toBe(false);
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

  it('sends an explicit null for an inherited policy', () => {
    // policy_id is a POINTER on the model: null means "inherit", and
    // omitting it would leave the stored policy in place - which is not what
    // clearing the picker means.
    const body = buildAlertConfigBody(BASE, 'device');
    expect(body.policy_id).toBeNull();
    expect(buildAlertConfigBody({ ...BASE, policy_id: '4' }, 'device').policy_id).toBe(4);
  });

  it('sends alerts_enabled for a device and not for a site', () => {
    expect(buildAlertConfigBody({ ...BASE, alerts_enabled: false }, 'device').alerts_enabled).toBe(false);
    expect('alerts_enabled' in buildAlertConfigBody({ ...BASE, alerts_enabled: false }, 'site')).toBe(false);
  });

  it('sends storm_sources for a site only, and omits it when blank', () => {
    // The site threshold is tri-state: blank inherits, 0 disables the digest.
    expect(buildAlertConfigBody({ ...BASE, storm_sources: '0' }, 'site').storm_sources).toBe(0);
    expect(buildAlertConfigBody({ ...BASE, storm_sources: '25' }, 'site').storm_sources).toBe(25);
    expect('storm_sources' in buildAlertConfigBody(BASE, 'site')).toBe(false);
    expect('storm_sources' in buildAlertConfigBody({ ...BASE, storm_sources: '5' }, 'device')).toBe(false);
  });

  it('never sends the event profile — it has its own endpoint', () => {
    const body = buildAlertConfigBody({ ...BASE, event_profile_id: '7' }, 'device');
    expect('event_profile_id' in body).toBe(false);
  });
});

describe('buildEventProfileBody', () => {
  it('returns null when the profile did not change', () => {
    expect(buildEventProfileBody(3, '3')).toBeNull();
    expect(buildEventProfileBody(null, '')).toBeNull();
    expect(buildEventProfileBody(undefined, '')).toBeNull();
  });

  it('sends the new profile', () => {
    expect(buildEventProfileBody(3, '5')).toEqual({ profile_id: 5 });
  });

  it('sends an explicit null to go back to inheriting', () => {
    expect(buildEventProfileBody(3, '')).toEqual({ profile_id: null });
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
