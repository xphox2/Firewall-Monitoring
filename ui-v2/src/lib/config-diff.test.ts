import { describe, expect, it } from 'vitest';
import {
  attributionLabel,
  changeCount,
  diffVerdict,
  filterLineRows,
  filterObjectChanges,
  filterSplitPairs,
  pairSplitRows,
  type LineRow,
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

const line = (op: LineRow['op'], text: string, a = 0, b = 0, vname?: string): LineRow => ({
  op,
  text,
  a,
  b,
  vname,
});

describe('pairSplitRows', () => {
  it('puts an equal row on both sides', () => {
    const [pair] = pairSplitRows([line('equal', 'hostname fw', 3, 3)]);
    expect(pair?.left).toMatchObject({ line: 3, text: 'hostname fw', op: 'equal' });
    expect(pair?.right).toMatchObject({ line: 3, text: 'hostname fw', op: 'equal' });
  });

  it('pairs a delete followed by an insert into one row', () => {
    const pairs = pairSplitRows([
      line('delete', 'set allowed 10.0.0.1', 10, 0),
      line('insert', 'set allowed 10.0.0.2', 0, 10),
    ]);
    expect(pairs).toHaveLength(1);
    expect(pairs[0]?.left?.text).toBe('set allowed 10.0.0.1');
    expect(pairs[0]?.right?.text).toBe('set allowed 10.0.0.2');
  });

  it('zips unequal runs and leaves the extra side empty', () => {
    const pairs = pairSplitRows([
      line('delete', 'a', 1, 0),
      line('delete', 'b', 2, 0),
      line('insert', 'c', 0, 1),
    ]);
    expect(pairs).toHaveLength(2);
    expect(pairs[0]).toMatchObject({ left: { text: 'a' }, right: { text: 'c' } });
    expect(pairs[1]?.left?.text).toBe('b');
    expect(pairs[1]?.right).toBeNull();
  });

  it('shows an insert-only run on the right', () => {
    const pairs = pairSplitRows([line('insert', 'new line', 0, 4)]);
    expect(pairs).toHaveLength(1);
    expect(pairs[0]?.left).toBeNull();
    expect(pairs[0]?.right?.text).toBe('new line');
  });

  it('shows a volatile row only on the to-side with its name', () => {
    const [pair] = pairSplitRows([line('volatile', 'set serial 123', 0, 7, 'serial')]);
    expect(pair?.left).toBeNull();
    expect(pair?.right?.op).toBe('volatile');
    expect(pair?.vname).toBe('serial');
  });

  it('does not pair a delete and insert separated by an equal row', () => {
    const pairs = pairSplitRows([
      line('delete', 'old', 1, 0),
      line('equal', 'same', 2, 2),
      line('insert', 'new', 0, 3),
    ]);
    expect(pairs).toHaveLength(3);
    expect(pairs[0]?.right).toBeNull();
    expect(pairs[2]?.left).toBeNull();
  });
});

describe('filterSplitPairs', () => {
  const pairs = pairSplitRows([
    line('equal', 'same', 1, 1),
    line('delete', 'old value', 2, 0),
    line('insert', 'new value', 0, 2),
    line('volatile', 'serial 999', 0, 3, 'serial'),
  ]);

  it('hides equal pairs only', () => {
    expect(filterSplitPairs(pairs, '', true)).toHaveLength(2);
  });

  it('matches either side of a pair', () => {
    expect(filterSplitPairs(pairs, 'old value', true)).toHaveLength(1);
    expect(filterSplitPairs(pairs, 'new value', true)).toHaveLength(1);
    expect(filterSplitPairs(pairs, 'serial', true)).toHaveLength(1);
  });
});
