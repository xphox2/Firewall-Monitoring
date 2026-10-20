import { describe, expect, it } from 'vitest';
import {
  EMPTY_DRAFT,
  buildDampen,
  buildMatch,
  buildRulePayload,
  draftError,
  draftFromRule,
  parseMatch,
  type Draft,
  type EventRuleRecord,
} from './event-rule';

function draft(overrides: Partial<Draft> = {}): Draft {
  return { ...EMPTY_DRAFT, name: 'Test rule', ...overrides };
}

describe('parseMatch', () => {
  it('treats an empty expression as one blank row', () => {
    const parsed = parseMatch('');
    expect(parsed.advanced).toBe(false);
    expect(parsed.rows).toHaveLength(1);
    expect(parsed.rows[0]?.field).toBe('');
  });

  it('reads a single condition', () => {
    const parsed = parseMatch('{"op":"eq","field":"src_ip","value":"198.51.100.9"}');
    expect(parsed.advanced).toBe(false);
    expect(parsed.rows).toEqual([{ field: 'src_ip', op: 'eq', value: '198.51.100.9' }]);
  });

  it('reads an AND tree and an in-list', () => {
    const parsed = parseMatch(
      '{"op":"and","conditions":[{"op":"in","field":"action","values":["deny","drop"]},{"op":"exists","field":"user"}]}',
    );
    expect(parsed.joiner).toBe('and');
    expect(parsed.rows).toEqual([
      { field: 'action', op: 'in', value: 'deny, drop', values: ['deny', 'drop'] },
      { field: 'user', op: 'exists', value: '' },
    ]);
  });

  it('keeps an empty top-level group verbatim (empty OR matches nothing)', () => {
    const emptyOr = '{"op":"or","conditions":[]}';
    expect(parseMatch(emptyOr)).toMatchObject({ advanced: true, raw: emptyOr });
  });

  it('preserves in-list values containing commas', () => {
    const parsed = parseMatch('{"op":"in","field":"device","values":["lab,rack-1"]}');
    expect(parsed.rows[0]?.values).toEqual(['lab,rack-1']);
    expect(buildMatch(draft({ rows: parsed.rows }))).toContain('"lab,rack-1"');
  });

  it('keeps nested trees and invalid JSON in advanced mode verbatim', () => {
    const nested = '{"op":"and","conditions":[{"op":"or","conditions":[]}]}';
    expect(parseMatch(nested)).toMatchObject({ advanced: true, raw: nested });
    expect(parseMatch('{oops')).toMatchObject({ advanced: true, raw: '{oops' });
  });
});

describe('buildMatch', () => {
  it('returns an empty string when no field is set', () => {
    expect(buildMatch(draft())).toBe('');
  });

  it('serializes one row as a bare condition', () => {
    const json = buildMatch(
      draft({ rows: [{ field: 'src_ip', op: 'contains', value: '198.51.100.' }] }),
    );
    expect(JSON.parse(json)).toEqual({
      op: 'contains',
      field: 'src_ip',
      value: '198.51.100.',
    });
  });

  it('omits the value for exists and splits in-lists', () => {
    const json = JSON.parse(
      buildMatch(
        draft({
          joiner: 'or',
          rows: [
            { field: 'user', op: 'exists', value: 'ignored' },
            { field: 'action', op: 'in', value: 'deny, drop' },
          ],
        }),
      ),
    );
    expect(json).toEqual({
      op: 'or',
      conditions: [
        { op: 'exists', field: 'user' },
        { op: 'in', field: 'action', values: ['deny', 'drop'] },
      ],
    });
  });

  it('passes advanced JSON through unchanged', () => {
    const raw = '{"op":"or","conditions":[{"op":"eq","field":"a","value":"b"}]}';
    expect(buildMatch(draft({ advanced: true, rawMatch: raw }))).toBe(raw);
  });
});

describe('buildDampen', () => {
  it('converts state minutes to seconds and keeps an explicit zero', () => {
    expect(JSON.parse(buildDampen(draft({ source: 'state', minUpMinutes: '60', dailyCap: '2' })))).toEqual({
      refire_mode: 'episode',
      min_up_seconds: 3600,
      daily_cap: 2,
    });
    expect(JSON.parse(buildDampen(draft({ source: 'state', minUpMinutes: '0' })))).toMatchObject({
      min_up_seconds: 0,
    });
  });

  it('omits unset metric fields instead of sending zero', () => {
    expect(JSON.parse(buildDampen(draft({ source: 'metric', metricMode: 'zscore', zscoreK: '3' })))).toEqual({
      mode: 'zscore',
      zscore_k: 3,
    });
  });

  it('keeps an explicit spike floor of 0', () => {
    expect(JSON.parse(buildDampen(draft({ source: 'spike', minThroughput: '0' })))).toEqual({
      min_throughput_mbps: 0,
    });
  });

  it('emits no dampening for sources that do not use it', () => {
    expect(buildDampen(draft({ source: 'syslog' }))).toBe('');
  });
});

describe('draftError', () => {
  it('rejects an empty in-list rather than saving a dead condition', () => {
    expect(
      draftError(draft({ rows: [{ field: 'action', op: 'in', value: '' }] })),
    ).toMatch(/at least one value/);
  });

  it('accepts a valid rule and rejects negative numbers', () => {
    expect(draftError(draft())).toBeNull();
    expect(draftError(draft({ priority: '-1' }))).toMatch(/Priority/);
    expect(draftError(draft({ cooldown: '-5' }))).toMatch(/Cooldown/);
    expect(draftError(draft({ expiresHours: '0' }))).toMatch(/hours/);
  });

  it('requires valid JSON in advanced mode', () => {
    expect(draftError(draft({ advanced: true, rawMatch: '{oops' }))).toMatch(/valid JSON/);
    expect(draftError(draft({ advanced: true, rawMatch: '' }))).toMatch(/match expression/);
  });
});

describe('buildRulePayload', () => {
  it('preserves priority 0 and defaults only a blank priority', () => {
    expect(buildRulePayload(draft({ priority: '0' })).priority).toBe(0);
    expect(buildRulePayload(draft({ priority: '' })).priority).toBe(100);
  });

  it('always sends profile_id and null-scopes an unset device/site/policy', () => {
    const payload = buildRulePayload(draft({ profileId: '7' }));
    expect(payload.profile_id).toBe(7);
    expect(payload.device_id).toBeNull();
    expect(payload.site_id).toBeNull();
    expect(payload.policy_id).toBeNull();
  });

  it('turns expiry hours into an absolute timestamp, and blank into null', () => {
    expect(buildRulePayload(draft()).expires_at).toBeNull();
    const iso = buildRulePayload(draft({ expiresHours: '24' })).expires_at as string;
    const hours = (new Date(iso).getTime() - Date.now()) / 3600_000;
    expect(hours).toBeGreaterThan(23.9);
    expect(hours).toBeLessThan(24.1);
  });
});

describe('draftFromRule', () => {
  const rule: EventRuleRecord = {
    id: 3,
    name: 'Suppress scanner',
    enabled: true,
    priority: 10,
    source: 'syslog',
    action: 'suppress',
    profile_id: 2,
    match_json: '{"op":"eq","field":"src_ip","value":"203.0.113.9"}',
    dampen_json: '',
  };

  it('round-trips the match expression and layering', () => {
    const d = draftFromRule(rule, '1');
    expect(d.profileId).toBe('2');
    expect(d.priority).toBe('10');
    expect(d.action).toBe('suppress');
    expect(buildRulePayload(d).match_json).toBe(rule.match_json);
  });

  it('keeps a sub-hour expiry from being extended on an untouched save', () => {
    const soon = new Date(Date.now() + 0.5 * 3600_000).toISOString();
    const d = draftFromRule({ ...rule, expires_at: soon }, '1');
    expect(Number(d.expiresHours)).toBeCloseTo(0.5, 1);
  });

  it('falls back to the default profile for an unset profile_id', () => {
    expect(draftFromRule({ ...rule, profile_id: 0 }, '5').profileId).toBe('5');
  });
});
