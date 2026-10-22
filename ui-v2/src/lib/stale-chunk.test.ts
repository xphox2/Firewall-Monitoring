import { describe, expect, it } from 'vitest';
import { isStaleChunkError } from './stale-chunk';

describe('isStaleChunkError', () => {
  it('recognises entry/chunk version skew in both directions', () => {
    for (const message of [
      "The requested module '../v2.js' does not provide an export named 'a'",
      'Failed to fetch dynamically imported module: /static/v2/chunks/topology-map.abc.js',
      'error loading dynamically imported module',
      'Importing a module script failed.',
      'ChunkLoadError: Loading chunk 12 failed.',
    ]) {
      expect(isStaleChunkError(new Error(message))).toBe(true);
    }
  });

  it('ignores ordinary runtime and network errors', () => {
    for (const message of ['Cannot read properties of undefined', 'NetworkError when attempting to fetch resource', '']) {
      expect(isStaleChunkError(new Error(message))).toBe(false);
    }
    expect(isStaleChunkError(null)).toBe(false);
    expect(isStaleChunkError(undefined)).toBe(false);
  });
});
