import { describe, expect, it } from 'vitest';
import { resolveV1PathForV2Location } from './navigation';

describe('resolveV1PathForV2Location', () => {
  it('keeps the device id instead of collapsing to the list page', () => {
    expect(resolveV1PathForV2Location('/devices/42')).toBe('/admin/devices/42');
    expect(resolveV1PathForV2Location('/devices/42', '?tab=config')).toBe(
      '/admin/devices/42?tab=config',
    );
  });

  it('maps workspace paths and keeps the sub-tab query', () => {
    expect(resolveV1PathForV2Location('/overview')).toBe('/admin/dashboard');
    expect(resolveV1PathForV2Location('/events', '?tab=analytics')).toBe(
      '/admin/events?tab=analytics',
    );
    expect(resolveV1PathForV2Location('/topology', '?tab=ipsec')).toBe(
      '/admin/connections?tab=ipsec',
    );
  });

  it('places the query string before a settings anchor', () => {
    expect(resolveV1PathForV2Location('/configuration/system', '?tab=audit')).toBe(
      '/admin/settings?tab=audit#users',
    );
  });

  it('falls back to the classic dashboard for unknown paths', () => {
    expect(resolveV1PathForV2Location('/nope')).toBe('/admin/dashboard');
  });
});
