export type DiffSeverity = 'info' | 'medium' | 'high' | 'critical';

export interface RevisionMeta {
  id: number;
  timestamp: string;
  checksum?: string;
  normalized_checksum?: string;
  trigger_source?: string;
  backup_quality?: string;
  changed_by?: string;
  change_method?: string;
  attributed?: boolean;
  attribution_checked?: boolean;
}

export interface AttrDelta {
  key: string;
  old: string;
  new: string;
}

export interface ObjectChange {
  path: string;
  kind: string;
  name: string;
  op: 'added' | 'removed' | 'modified' | string;
  attrs?: AttrDelta[];
  risk: {
    severity: DiffSeverity | string;
    category?: string;
    summary?: string;
    compliance_tags?: string[];
  };
}

export type LineOp = 'equal' | 'delete' | 'insert' | 'volatile';

export interface LineRow {
  op: LineOp;
  text: string;
  a: number;
  b: number;
  vname?: string;
}

export interface ConfigDiffData {
  from: RevisionMeta;
  to: RevisionMeta;
  vendor: string;
  volatile_patterns?: string[];
  object_changes?: ObjectChange[];
  summary: {
    added: number;
    removed: number;
    modified: number;
    max_severity: DiffSeverity | string;
    impact?: string;
  };
  line_diff: {
    rows: LineRow[];
    added: number;
    removed: number;
    truncated?: boolean;
    note?: string;
  };
}

export const DIFF_SEVERITIES: DiffSeverity[] = ['critical', 'high', 'medium', 'info'];

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  info: 3,
};

export function severityRank(severity: string | undefined): number {
  return SEVERITY_ORDER[severity ?? ''] ?? 4;
}

export function changeCount(diff: ConfigDiffData): number {
  return diff.summary.added + diff.summary.removed + diff.summary.modified;
}

export interface DiffVerdict {
  tone: 'ok' | 'info' | 'warn' | 'crit';
  label: string;
  detail: string;
}

/** Human verdict for the diff header. Never claims "no changes" from counts alone. */
export function diffVerdict(diff: ConfigDiffData): DiffVerdict {
  const objects = changeCount(diff);
  const lines = diff.line_diff.added + diff.line_diff.removed;
  // The server fails CLOSED when it cannot verify secret masking: it withholds
  // the rows but reports zero counts. Never render that as "No changes".
  if (diff.line_diff.truncated && lines === 0) {
    return {
      tone: 'warn',
      label: 'Diff incomplete',
      detail:
        diff.line_diff.note ||
        'The server withheld the diff (truncated or masking could not be verified).',
    };
  }
  if (objects === 0) {
    if (lines === 0) {
      return {
        tone: 'ok',
        label: 'No changes',
        detail: 'The two revisions are equivalent after normalization.',
      };
    }
    return {
      tone: 'info',
      label: 'No object-level changes',
      detail: `${lines} line${lines === 1 ? '' : 's'} differ at the raw level (volatile values or vendor formatting).`,
    };
  }
  const ranked = (diff.object_changes ?? [])
    .map((c) => c.risk?.severity ?? 'info')
    .sort((a, b) => severityRank(a) - severityRank(b));
  const worst = (diff.summary.max_severity || ranked[0] || 'info') as string;
  const tone: DiffVerdict['tone'] =
    worst === 'critical' ? 'crit' : worst === 'high' ? 'warn' : 'info';
  const parts = [
    diff.summary.added ? `${diff.summary.added} added` : '',
    diff.summary.removed ? `${diff.summary.removed} removed` : '',
    diff.summary.modified ? `${diff.summary.modified} modified` : '',
  ].filter(Boolean);
  return {
    tone,
    label: `${objects} object${objects === 1 ? '' : 's'} changed`,
    detail: `${parts.join(' · ')} · max severity ${worst}${diff.summary.impact ? ` — ${diff.summary.impact}` : ''}`,
  };
}

export function filterObjectChanges(
  changes: ObjectChange[],
  query: string,
  severities: Set<DiffSeverity> | null,
): ObjectChange[] {
  const needle = query.trim().toLowerCase();
  return changes.filter((change) => {
    if (severities && !severities.has((change.risk?.severity ?? 'info') as DiffSeverity)) {
      return false;
    }
    if (!needle) return true;
    const haystack = [
      change.name,
      change.kind,
      change.path,
      change.op,
      change.risk?.summary,
      change.risk?.category,
      ...(change.attrs ?? []).flatMap((a) => [a.key, a.old, a.new]),
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    return haystack.includes(needle);
  });
}

export function filterLineRows(rows: LineRow[], query: string, hideEqual: boolean): LineRow[] {
  const needle = query.trim().toLowerCase();
  return rows.filter((row) => {
    if (hideEqual && row.op === 'equal') return false;
    if (!needle) return true;
    return row.text.toLowerCase().includes(needle);
  });
}

/** Attribution label for a revision, e.g. "changed by alice via ssh". */
export function attributionLabel(meta: RevisionMeta | null | undefined): string {
  if (!meta) return '';
  if (meta.changed_by) {
    return `${meta.changed_by}${meta.change_method ? ` via ${meta.change_method}` : ''}`;
  }
  if (meta.attribution_checked) {
    return 'no authenticated session matched (possible out-of-band change)';
  }
  return 'unattributed';
}
