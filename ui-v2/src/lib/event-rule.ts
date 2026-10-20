/**
 * Pure helpers for the V2 event-rule editor. Kept out of the component so the
 * two things that historically broke here — the match-tree conversion and the
 * source-specific dampening blobs — are covered by tests.
 */

export interface EventRuleRecord {
  id: number;
  name: string;
  description?: string;
  enabled: boolean;
  priority: number;
  source: string;
  vendor_scope?: string;
  device_id?: number | null;
  site_id?: number | null;
  match_json?: string;
  action: string;
  alert_type?: string;
  severity?: string;
  group_by?: string;
  cooldown_minutes?: number | null;
  policy_id?: number | null;
  profile_id?: number;
  dampen_json?: string;
  expires_at?: string | null;
  seed_version?: number;
  hit_count?: number;
  last_hit_at?: string | null;
}

export interface ConditionRow {
  field: string;
  op: string;
  value: string;
  /** Parsed `in` list. Present until the operator edits the text, so a value
   * containing a comma is not silently split on an untouched save. */
  values?: string[];
}

export interface Draft {
  name: string;
  description: string;
  enabled: boolean;
  priority: string;
  source: string;
  vendor: string;
  deviceId: string;
  siteId: string;
  policyId: string;
  profileId: string;
  action: 'alert' | 'suppress';
  alertType: string;
  severity: string;
  groupBy: string;
  cooldown: string;
  expiresHours: string;
  advanced: boolean;
  rawMatch: string;
  joiner: 'and' | 'or';
  rows: ConditionRow[];
  minUpMinutes: string;
  dailyCap: string;
  metricMode: string;
  threshold: string;
  clearThreshold: string;
  zscoreK: string;
  stddevK: string;
  minDuration: string;
  minThroughput: string;
}

export const EMPTY_DRAFT: Draft = {
  name: '',
  description: '',
  enabled: true,
  priority: '100',
  source: 'syslog',
  vendor: '',
  deviceId: '',
  siteId: '',
  policyId: '',
  profileId: '',
  action: 'alert',
  alertType: '',
  severity: '',
  groupBy: '',
  cooldown: '',
  expiresHours: '',
  advanced: false,
  rawMatch: '',
  joiner: 'and',
  rows: [{ field: '', op: 'contains', value: '' }],
  minUpMinutes: '',
  dailyCap: '',
  metricMode: 'static',
  threshold: '',
  clearThreshold: '',
  zscoreK: '',
  stddevK: '',
  minDuration: '',
  minThroughput: '',
};

export function safeParse(json?: string | null): any {
  if (!json || !json.trim()) return null;
  try {
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/**
 * Converts a stored match_json tree into flat rows. Anything that cannot be
 * represented flat (nested AND/OR inside AND/OR) falls back to advanced mode so
 * saving an untouched rule never rewrites its expression.
 */
export function parseMatch(json?: string): {
  advanced: boolean;
  raw: string;
  joiner: 'and' | 'or';
  rows: ConditionRow[];
} {
  if (!json || !json.trim()) {
    return { advanced: false, raw: '', joiner: 'and', rows: [{ field: '', op: 'contains', value: '' }] };
  }
  const parsed = safeParse(json);
  if (!parsed) {
    return { advanced: true, raw: json, joiner: 'and', rows: [] };
  }
  const toRow = (c: any): ConditionRow | null => {
    if (!c || typeof c !== 'object' || c.op === 'and' || c.op === 'or') return null;
    if (c.op === 'in' && Array.isArray(c.values)) {
      const values = c.values.map((v: unknown) => String(v));
      return {
        field: String(c.field ?? ''),
        op: 'in',
        value: values.join(', '),
        values,
      };
    }
    return { field: String(c.field ?? ''), op: String(c.op ?? 'eq'), value: String(c.value ?? '') };
  };
  if (parsed.op === 'and' || parsed.op === 'or') {
    const kids = Array.isArray(parsed.conditions) ? parsed.conditions : [];
    if (kids.length === 0) {
      // A degenerate group is legal on the wire and NOT equivalent to an empty
      // expression: empty OR never matches, while "" matches everything.
      return { advanced: true, raw: json, joiner: 'and', rows: [] };
    }
    const rows = kids.map(toRow);
    if (rows.some((r: ConditionRow | null) => r === null)) {
      return { advanced: true, raw: json, joiner: 'and', rows: [] };
    }
    return {
      advanced: false,
      raw: '',
      joiner: parsed.op,
      rows: rows.length ? (rows as ConditionRow[]) : [{ field: '', op: 'contains', value: '' }],
    };
  }
  const row = toRow(parsed);
  if (!row) return { advanced: true, raw: json, joiner: 'and', rows: [] };
  return { advanced: false, raw: '', joiner: 'and', rows: [row] };
}

/** Serializes the editor state back into the server's match_json grammar. */
export function buildMatch(draft: Draft): string {
  if (draft.advanced) return draft.rawMatch.trim();
  const rows = draft.rows.filter((r) => r.field.trim() !== '');
  if (rows.length === 0) return '';
  const conditions = rows.map((r) => {
    if (r.op === 'exists') return { op: 'exists', field: r.field.trim() };
    if (r.op === 'in') {
      const values =
        r.values ?? r.value.split(',').map((v) => v.trim()).filter(Boolean);
      return { op: 'in', field: r.field.trim(), values };
    }
    return { op: r.op, field: r.field.trim(), value: r.value };
  });
  if (conditions.length === 1) return JSON.stringify(conditions[0]);
  return JSON.stringify({ op: draft.joiner, conditions });
}

/**
 * Source-specific dampen_json. `min_up_seconds` and `min_throughput_mbps` are
 * pointer-typed server-side, so an explicit 0 is meaningful (disable), while an
 * empty field must be OMITTED (inherit) rather than sent as 0.
 */
export function buildDampen(draft: Draft): string {
  const num = (v: string): number | undefined => {
    if (v.trim() === '') return undefined;
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  };
  if (draft.source === 'state') {
    const out: Record<string, unknown> = { refire_mode: 'episode' };
    const minutes = num(draft.minUpMinutes);
    if (minutes !== undefined) out.min_up_seconds = Math.round(minutes * 60);
    const cap = num(draft.dailyCap);
    if (cap !== undefined) out.daily_cap = Math.round(cap);
    return JSON.stringify(out);
  }
  if (draft.source === 'metric') {
    const out: Record<string, unknown> = { mode: draft.metricMode || 'static' };
    const t = num(draft.threshold);
    if (t !== undefined) out.threshold = t;
    const c = num(draft.clearThreshold);
    if (c !== undefined) out.clear_threshold = c;
    const k = num(draft.zscoreK);
    if (k !== undefined) out.zscore_k = k;
    return JSON.stringify(out);
  }
  if (draft.source === 'spike') {
    const out: Record<string, unknown> = {};
    const k = num(draft.stddevK);
    if (k !== undefined) out.stddev_k = k;
    const d = num(draft.minDuration);
    if (d !== undefined) out.min_duration_minutes = Math.round(d);
    const f = num(draft.minThroughput);
    if (f !== undefined) out.min_throughput_mbps = f;
    return Object.keys(out).length ? JSON.stringify(out) : '';
  }
  return '';
}

export function draftFromRule(rule: EventRuleRecord | null, defaultProfileId: string): Draft {
  if (!rule) return { ...EMPTY_DRAFT, profileId: defaultProfileId };
  const match = parseMatch(rule.match_json);
  const dampen = safeParse(rule.dampen_json) ?? {};
  const expiresHours = (() => {
    if (!rule.expires_at) return '';
    const ms = new Date(rule.expires_at).getTime() - Date.now();
    if (!Number.isFinite(ms) || ms <= 0) return '';
    // One decimal so re-saving an untouched temp rule does not extend it.
    return String(Math.max(0.1, Math.round((ms / 3600_000) * 10) / 10));
  })();
  return {
    name: rule.name ?? '',
    description: rule.description ?? '',
    enabled: rule.enabled ?? true,
    priority: String(rule.priority ?? 100),
    source: rule.source ?? 'syslog',
    vendor: rule.vendor_scope ?? '',
    deviceId: rule.device_id ? String(rule.device_id) : '',
    siteId: rule.site_id ? String(rule.site_id) : '',
    policyId: rule.policy_id ? String(rule.policy_id) : '',
    profileId: rule.profile_id ? String(rule.profile_id) : defaultProfileId,
    action: rule.action === 'suppress' ? 'suppress' : 'alert',
    alertType: rule.alert_type ?? '',
    severity: rule.severity ?? '',
    groupBy: rule.group_by ?? '',
    cooldown: rule.cooldown_minutes != null ? String(rule.cooldown_minutes) : '',
    expiresHours,
    advanced: match.advanced,
    rawMatch: match.raw,
    joiner: match.joiner,
    rows: match.rows,
    minUpMinutes:
      dampen.min_up_seconds != null ? String(Math.round(Number(dampen.min_up_seconds) / 60)) : '',
    dailyCap: dampen.daily_cap != null ? String(dampen.daily_cap) : '',
    metricMode: dampen.mode ?? 'static',
    threshold: dampen.threshold != null ? String(dampen.threshold) : '',
    clearThreshold: dampen.clear_threshold != null ? String(dampen.clear_threshold) : '',
    zscoreK: dampen.zscore_k != null ? String(dampen.zscore_k) : '',
    stddevK: dampen.stddev_k != null ? String(dampen.stddev_k) : '',
    minDuration: dampen.min_duration_minutes != null ? String(dampen.min_duration_minutes) : '',
    minThroughput: dampen.min_throughput_mbps != null ? String(dampen.min_throughput_mbps) : '',
  };
}

/** Returns a human-readable problem, or null when the draft can be saved. */
export function draftError(draft: Draft): string | null {
  if (!draft.name.trim()) return 'Rule name is required';
  if (draft.advanced) {
    if (!draft.rawMatch.trim()) return 'Advanced mode needs a match expression';
    try {
      JSON.parse(draft.rawMatch);
    } catch {
      return 'Match expression is not valid JSON';
    }
  } else {
    for (const row of draft.rows) {
      if (!row.field.trim()) continue;
      if (row.op === 'in') {
        const values = row.values ?? row.value.split(',').map((v) => v.trim()).filter(Boolean);
        if (values.length === 0) return `Condition "${row.field}" needs at least one value`;
      }
    }
  }
  const priority = Number(draft.priority);
  if (draft.priority.trim() !== '' && (!Number.isFinite(priority) || priority < 0)) {
    return 'Priority must be zero or greater';
  }
  const cooldown = Number(draft.cooldown);
  if (draft.cooldown.trim() !== '' && (!Number.isFinite(cooldown) || cooldown < 0)) {
    return 'Cooldown must be zero or greater';
  }
  const hours = Number(draft.expiresHours);
  if (draft.expiresHours.trim() !== '' && (!Number.isFinite(hours) || hours <= 0)) {
    return 'Temporary-rule hours must be greater than zero (leave blank for permanent)';
  }
  return null;
}

/** Builds the POST/PUT body. Priority 0 is preserved; profile_id is explicit. */
export function buildRulePayload(draft: Draft): Record<string, unknown> {
  const priorityNum = Number(draft.priority);
  const hoursNum = Number(draft.expiresHours);
  return {
    name: draft.name.trim(),
    description: draft.description.trim(),
    enabled: draft.enabled,
    priority: draft.priority.trim() !== '' && Number.isFinite(priorityNum) ? priorityNum : 100,
    source: draft.source,
    vendor_scope: draft.vendor,
    device_id: draft.deviceId ? Number(draft.deviceId) : null,
    site_id: draft.siteId ? Number(draft.siteId) : null,
    policy_id: draft.policyId ? Number(draft.policyId) : null,
    // Always explicit: omitting profile_id on update is tolerated but a wrong
    // value silently re-homes the rule to the Default layer.
    profile_id: Number(draft.profileId) || 0,
    match_json: buildMatch(draft),
    action: draft.action,
    alert_type: draft.alertType,
    severity: draft.severity,
    group_by: draft.groupBy.trim(),
    cooldown_minutes: draft.cooldown.trim() === '' ? null : Number(draft.cooldown),
    dampen_json: buildDampen(draft),
    expires_at:
      draft.expiresHours.trim() !== '' && Number.isFinite(hoursNum) && hoursNum > 0
        ? new Date(Date.now() + hoursNum * 3600_000).toISOString()
        : null,
  };
}
