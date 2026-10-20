import { describe, expect, it } from 'vitest';
import {
  attributionLabel,
  changeCount,
  diffVerdict,
  filterLineRows,
  filterObjectChanges,
  severityRank,
  type ConfigDiffData,
  type ObjectChange,
} from './config-diff';

const change = (overrides: Partial<ObjectChange> = {}): ObjectChange => ({
  path: 'firewall/policy/10',
  kind: 'policy',
  name: 'Allow web',
  op: 'modified',
  attrs: [{ key: 'dstaddr', old: 'any', new: 'web-servers' }],
  risk: { severity: 'high', category: 'policy', summary: 'Destination narrowed' },
  ...overrides,
});

const diff = (overrides: Partial<ConfigDiffData> = {}): ConfigDiffData => ({
  from: { id: 1, timestamp: '2026-10-01T00:00:00Z' },
  to: { id: 2, timestamp: '2026-10-02T00:00:00Z' },
  vendor: 'fortigate',
  summary: { added: 0, removed: 0, modified: 1, max_severity: 'high', impact: 'Destination narrowed' },
  object_changes: [change()],
  line_diff: { rows: [{ op: 'delete', text: 'set dstaddr any', a: 10, b: 0 }], added: 0, removed: 1 },
  ...overrides,
});

describe('diffVerdict', () => {
  it('reports a critical object change as critical', () => {
    const v = diffVerdict(
      diff({
        summary: { added: 0, removed: 0, modified: 1, max_severity: 'critical' },
        object_changes: [change({ risk: { severity: 'critical' } })],
      }),
    );
    expect(v.tone).toBe('crit');
    expect(v.label).toMatch(/1 object changed/);
  });

  it('never reports "No changes" when the server withheld the diff', () => {
    const v = diffVerdict(
      diff({
        summary: { added: 0, removed: 0, modified: 0, max_severity: '' },
        object_changes: [],
        line_diff: {
          rows: [],
          added: 0,
          removed: 0,
          truncated: true,
          note: 'Secret masking could not be verified',
        },
      }),
    );
    expect(v.tone).toBe('warn');
    expect(v.label).toBe('Diff incomplete');
    expect(v.detail).toMatch(/masking/);
  });

  it('distinguishes "no object changes but raw lines differ" from "no changes"', () => {
    const volatileOnly = diffVerdict(
      diff({
        summary: { added: 0, removed: 0, modified: 0, max_severity: '' },
        object_changes: [],
        line_diff: { rows: [], added: 2, removed: 2 },
      }),
    );
    expect(volatileOnly.tone).toBe('info');
    expect(volatileOnly.label).toBe('No object-level changes');

    const identical = diffVerdict(
      diff({
        summary: { added: 0, removed: 0, modified: 0, max_severity: '' },
        object_changes: [],
        line_diff: { rows: [], added: 0, removed: 0 },
      }),
    );
    expect(identical.tone).toBe('ok');
    expect(identical.label).toBe('No changes');
  });
});

describe('filters', () => {
  const changes = [
    change(),
    change({
      name: 'Block telnet',
      kind: 'policy',
      path: 'firewall/policy/20',
      risk: { severity: 'critical', summary: 'Telnet allowed' },
      attrs: [{ key: 'service', old: 'HTTPS', new: 'TELNET' }],
    }),
    change({
      name: 'admin user',
      kind: 'user',
      path: 'system/admin',
      op: 'added',
      risk: { severity: 'info' },
      attrs: [],
    }),
  ];

  it('filters by severity and search text across attrs', () => {
    expect(filterObjectChanges(changes, '', new Set(['critical']))).toHaveLength(1);
    expect(filterObjectChanges(changes, 'telnet', null)).toHaveLength(1);
    expect(filterObjectChanges(changes, 'HTTPS', null)).toHaveLength(1);
    expect(filterObjectChanges(changes, '', null)).toHaveLength(3);
  });

  it('hides unchanged rows and filters the line diff', () => {
    const rows = [
      { op: 'equal' as const, text: 'config system', a: 1, b: 1 },
      { op: 'insert' as const, text: 'set dstaddr web', a: 0, b: 2 },
      { op: 'delete' as const, text: 'set dstaddr any', a: 2, b: 0 },
      { op: 'volatile' as const, text: 'set enc ENC xyz', a: 3, b: 3, vname: 'enc' },
    ];
    expect(filterLineRows(rows, '', false)).toHaveLength(4);
    expect(filterLineRows(rows, '', true)).toHaveLength(3);
    expect(filterLineRows(rows, 'dstaddr', true)).toHaveLength(2);
  });
});

describe('helpers', () => {
  it('counts and ranks severities', () => {
    expect(changeCount(diff())).toBe(1);
    expect(severityRank('critical')).toBeLessThan(severityRank('info'));
    expect(severityRank('nonsense')).toBe(4);
  });

  it('labels attribution honestly', () => {
    expect(attributionLabel({ id: 1, timestamp: '', changed_by: 'alice', change_method: 'ssh' })).toBe(
      'alice via ssh',
    );
    expect(attributionLabel({ id: 1, timestamp: '', attribution_checked: true })).toMatch(
      /out-of-band/,
    );
    expect(attributionLabel({ id: 1, timestamp: '' })).toBe('unattributed');
  });
});
