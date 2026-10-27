import { describe, expect, it } from 'vitest';
import { SECRET_MASK, hasStoredCredential, isMaskedSecret } from './device-secrets';

describe('hasStoredCredential', () => {
  it('says YES for a masked credential', () => {
    // The mask is what the server returns for a credential it HOLDS, so
    // reading the mask as "empty" is what made the Clear control
    // unreachable for the case it exists for.
    expect(hasStoredCredential(SECRET_MASK)).toBe(true);
  });

  it('says NO for an empty credential', () => {
    // An empty string is what the server returns for a field it does NOT
    // hold.
    expect(hasStoredCredential('')).toBe(false);
  });

  it('says NO for a missing value', () => {
    expect(hasStoredCredential(undefined)).toBe(false);
    expect(hasStoredCredential(null)).toBe(false);
    expect(hasStoredCredential(42)).toBe(false);
  });

  it('says YES for a real value', () => {
    expect(hasStoredCredential('the-secret')).toBe(true);
  });
});

describe('isMaskedSecret', () => {
  it('is true for a masked value that has not been revealed', () => {
    expect(isMaskedSecret(SECRET_MASK, false)).toBe(true);
  });

  it('is false once the value has been revealed', () => {
    expect(isMaskedSecret(SECRET_MASK, true)).toBe(false);
  });

  it('is false for an empty value', () => {
    expect(isMaskedSecret('', false)).toBe(false);
  });
});
