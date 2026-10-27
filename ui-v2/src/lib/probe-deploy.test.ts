import { describe, expect, it } from 'vitest';
import {
  KEY_UNAVAILABLE_NOTICE,
  SECRET_MASK,
  buildProbeEnv,
  isRealRegistrationKey,
} from './probe-deploy';

describe('isRealRegistrationKey', () => {
  it('rejects the redaction mask', () => {
    // The mask is truthy, so without this check the deploy modal would
    // render '********' as if it were a copyable key.
    expect(isRealRegistrationKey(SECRET_MASK)).toBe(false);
  });

  it('rejects an empty key', () => {
    expect(isRealRegistrationKey('')).toBe(false);
    expect(isRealRegistrationKey(undefined)).toBe(false);
    expect(isRealRegistrationKey(null)).toBe(false);
  });

  it('accepts a real key', () => {
    expect(isRealRegistrationKey('abc-123')).toBe(true);
  });
});

describe('buildProbeEnv', () => {
  it('composes the four variables in the legacy order', () => {
    const env = buildProbeEnv(
      { name: 'us-east-collector-01', site_id: 4, registration_key: 'secret-key' },
      'https://fwmon.example.com',
    );
    expect(env).toBe(
      [
        'PROBE_NAME=us-east-collector-01',
        'PROBE_SITE_ID=4',
        'PROBE_REGISTRATION_KEY=secret-key',
        'PROBE_SERVER_URL=https://fwmon.example.com',
      ].join('\n'),
    );
  });

  it('writes MISSING when the key is the redaction mask', () => {
    const env = buildProbeEnv({ name: 'p', site_id: 1, registration_key: SECRET_MASK }, 'https://x');
    expect(env).toContain('PROBE_REGISTRATION_KEY=MISSING');
  });

  it('writes MISSING when there is no key at all', () => {
    const env = buildProbeEnv({ name: 'p', site_id: 1 }, 'https://x');
    expect(env).toContain('PROBE_REGISTRATION_KEY=MISSING');
  });

  it('writes 0 for a probe with no site', () => {
    const env = buildProbeEnv({ name: 'p', site_id: null }, 'https://x');
    expect(env).toContain('PROBE_SITE_ID=0');
  });
});

describe('the key notice', () => {
  it('tells the operator the key is shown once', () => {
    expect(KEY_UNAVAILABLE_NOTICE).toContain('shown once');
    expect(KEY_UNAVAILABLE_NOTICE).toContain('Regenerate Key');
  });
});
