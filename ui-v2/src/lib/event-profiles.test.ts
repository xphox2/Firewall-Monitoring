import { describe, expect, it } from 'vitest';
import {
  buildTogglePayload,
  dirtyToggleCount,
  familyCounts,
  groupTypes,
  matrixFromToggles,
  setFamilyMode,
  type AlertTypeInfo,
} from './event-profiles';

const TYPES: AlertTypeInfo[] = [
  { type: 'CPU_HIGH', family: 'Metrics', description: 'CPU high' },
  { type: 'MEMORY_HIGH', family: 'Metrics', description: 'Memory high' },
  { type: 'LINK_DOWN', family: 'Availability', description: 'Link down' },
];

describe('matrixFromToggles', () => {
  it('maps true→on, false→off and absence→inherit', () => {
    const matrix = matrixFromToggles(TYPES, [
      { alert_type: 'CPU_HIGH', enabled: true },
      { alert_type: 'MEMORY_HIGH', enabled: false },
    ]);
    expect(matrix.get('CPU_HIGH')).toBe('on');
    expect(matrix.get('MEMORY_HIGH')).toBe('off');
    expect(matrix.get('LINK_DOWN')).toBe('inherit');
  });
});

describe('buildTogglePayload', () => {
  it('sends only on/off rows and omits inherit', () => {
    const matrix = matrixFromToggles(TYPES, [
      { alert_type: 'CPU_HIGH', enabled: true },
      { alert_type: 'MEMORY_HIGH', enabled: false },
    ]);
    expect(buildTogglePayload(TYPES, matrix)).toEqual({
      toggles: [
        { alert_type: 'CPU_HIGH', enabled: true },
        { alert_type: 'MEMORY_HIGH', enabled: false },
      ],
    });
  });

  it('round-trips an all-inherit matrix to an empty set', () => {
    const matrix = matrixFromToggles(TYPES, []);
    expect(buildTogglePayload(TYPES, matrix)).toEqual({ toggles: [] });
  });
});

describe('grouping and counts', () => {
  it('groups by family in registry order', () => {
    expect(groupTypes(TYPES).map((g) => g.family)).toEqual(['Metrics', 'Availability']);
    expect(groupTypes(TYPES)[0]?.types).toHaveLength(2);
  });

  it('counts each state per family', () => {
    const matrix = matrixFromToggles(TYPES, [{ alert_type: 'CPU_HIGH', enabled: false }]);
    const metrics = groupTypes(TYPES)[0]!;
    expect(familyCounts(metrics.types, matrix)).toEqual({ on: 0, off: 1, inherit: 1 });
  });
});

describe('bulk family actions and dirty tracking', () => {
  it('sets every type in a family', () => {
    const base = matrixFromToggles(TYPES, []);
    const next = setFamilyMode(base, groupTypes(TYPES)[0]!.types, 'off');
    expect(next.get('CPU_HIGH')).toBe('off');
    expect(next.get('MEMORY_HIGH')).toBe('off');
    expect(next.get('LINK_DOWN')).toBe('inherit');
    // Immutable: the original matrix is untouched.
    expect(base.get('CPU_HIGH')).toBe('inherit');
  });

  it('counts changed cells against the baseline', () => {
    const baseline = matrixFromToggles(TYPES, []);
    const edited = new Map(baseline);
    edited.set('CPU_HIGH', 'on');
    edited.set('LINK_DOWN', 'off');
    expect(dirtyToggleCount(TYPES, edited, baseline)).toBe(2);
    expect(dirtyToggleCount(TYPES, baseline, baseline)).toBe(0);
  });
});
