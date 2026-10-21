import { describe, expect, it } from 'vitest';
import { linkColour, linkState } from './topology';

describe('linkState', () => {
  it('classifies healthy link states', () => {
    for (const value of ['up', 'UP', 'online', 'active', 'ok', 'healthy', 'established']) {
      expect(linkState(value)).toBe('up');
    }
  });

  it('classifies failure states', () => {
    for (const value of ['down', 'offline', 'failed', 'error', 'critical']) {
      expect(linkState(value)).toBe('down');
    }
  });

  it('treats unknown/stale/empty as neither up nor down', () => {
    for (const value of ['', null, undefined, 'unknown', 'stale', 'pending', 'backup']) {
      expect(linkState(value)).toBe('unknown');
    }
  });

  it('maps states to legend colours', () => {
    expect(linkColour('up')).toBe('#4ade80');
    expect(linkColour('down')).toBe('#f87171');
    expect(linkColour('stale')).toBe('#94a3b8');
  });
});
