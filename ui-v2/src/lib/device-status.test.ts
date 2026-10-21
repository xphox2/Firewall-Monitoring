import { describe, expect, it } from 'vitest';
import { licenceState, syncTone } from './device-status';

const NOW = Date.parse('2026-10-20T12:00:00Z');
const inDays = (days: number) => new Date(NOW + days * 86_400_000).toISOString();

describe('syncTone', () => {
  it('greens the real healthy vocabulary', () => {
    for (const value of ['synchronized', 'in sync', 'in-sync', 'up', 'active', 'standby']) {
      expect(syncTone(value)).toBe('ok');
    }
  });

  it('handles the Cisco ASA detail suffix', () => {
    // Pinned by TestCiscoASA_ParseHAStatus_FailoverPair.
    expect(syncTone('active (Active unit)')).toBe('ok');
    expect(syncTone('standby (Standby unit)')).toBe('ok');
    expect(syncTone('error (Failed unit)')).toBe('crit');
    expect(syncTone('down (Peer unreachable)')).toBe('crit');
  });

  it('reds the real failure vocabulary', () => {
    for (const value of ['unsynchronized', 'not in sync', 'out of sync', 'down', 'error', 'failed']) {
      expect(syncTone(value)).toBe('crit');
    }
  });

  it('does not green "not in sync" and warns on unknown values', () => {
    expect(syncTone('not in sync')).not.toBe('ok');
    expect(syncTone('')).toBe('warn');
    expect(syncTone(undefined)).toBe('warn');
  });
});

describe('licenceState', () => {
  it('marks a licence that expired earlier today as expired, not "expiring"', () => {
    const state = licenceState(
      { expiry_date: new Date(NOW - 0.5 * 86_400_000).toISOString(), status: 'active' },
      NOW,
    );
    expect(state.expired).toBe(true);
    expect(state.tone).toBe('crit');
    expect(state.label).toBe('expired');
  });

  it('warns within 30 days and is ok beyond', () => {
    expect(licenceState({ expiry_date: inDays(10) }, NOW)).toMatchObject({
      expiring: true,
      tone: 'warn',
      days: 10,
    });
    expect(licenceState({ expiry_date: inDays(60) }, NOW)).toMatchObject({
      expiring: false,
      tone: 'ok',
      days: 60,
    });
  });

  it('falls back to status only when there is no parseable date', () => {
    expect(licenceState({ expiry_date: '', status: 'perpetual' }, NOW)).toMatchObject({
      label: 'perpetual',
      tone: 'ok',
      days: null,
    });
    expect(licenceState({ expiry_date: 'n/a', status: 'expired' }, NOW)).toMatchObject({
      label: 'expired',
      tone: 'crit',
    });
  });
});
