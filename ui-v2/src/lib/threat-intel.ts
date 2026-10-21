export interface ThreatLookup {
  query: string;
  kind?: 'ip' | 'asn';
  geo_enabled?: boolean;
  country?: string;
  asn?: number;
  asn_org?: string;
  asn_prefix?: string;
  known_bad?: boolean;
  threats?: Array<{ scope: string; category?: string; severity?: string }>;
  threat?: { scope: string; category?: string; severity?: string };
}

export interface LookupVerdict {
  tone: 'crit' | 'ok' | 'warn';
  label: string;
  detail: string;
}

/** Verdict for a reputation lookup; unknown/unavailable geo is a warning, not clean. */
export function lookupVerdict(result: ThreatLookup | null | undefined): LookupVerdict {
  if (!result) return { tone: 'warn', label: 'No result', detail: 'Run a lookup first.' };
  const scopes = result.threats ?? (result.threat ? [result.threat] : []);
  if (result.known_bad || scopes.length > 0) {
    const categories = scopes
      .map((s) => `${s.scope}:${s.category || 'known-bad'}`)
      .filter(Boolean)
      .join(', ');
    return {
      tone: 'crit',
      label: 'KNOWN-BAD',
      detail: categories || 'Listed by a threat-intel source.',
    };
  }
  if (result.kind === 'ip' && !result.country && !result.asn) {
    return {
      tone: 'warn',
      label: 'Not listed — no geo data',
      detail: 'No threat-intel match; GeoIP/ASN enrichment is unavailable for this address.',
    };
  }
  return {
    tone: 'ok',
    label: 'Not listed',
    detail: 'Not present in any enabled threat-intel source.',
  };
}

export interface FeedStatusRow {
  source: string;
  url?: string;
  category?: string;
  severity?: string;
  kind?: string;
  entry_count?: number;
  last_error?: string;
  last_sync_at?: string;
  last_duration_ms?: number;
  enabled?: boolean;
}

export interface FeedState {
  label: string;
  tone: 'ok' | 'warn' | 'crit' | 'muted';
  detail?: string;
}

export function feedState(feed: FeedStatusRow | null | undefined): FeedState {
  if (!feed) return { label: 'unknown', tone: 'muted' };
  if (feed.enabled === false) return { label: 'disabled', tone: 'muted', detail: 'Indicators purged' };
  if (feed.last_error) return { label: 'error', tone: 'crit', detail: feed.last_error };
  const synced = feed.last_sync_at ? new Date(feed.last_sync_at).getTime() : 0;
  if (!synced || synced <= 0) {
    return { label: 'never synced', tone: 'warn', detail: 'Waiting for the first poller run' };
  }
  return { label: 'ok', tone: 'ok' };
}

export interface IndicatorFilters {
  q: string;
  source: string;
  category: string;
  severity: string;
  activeOnly: boolean;
}

export const EMPTY_INDICATOR_FILTERS: IndicatorFilters = {
  q: '',
  source: '',
  category: '',
  severity: '',
  activeOnly: false,
};

export function buildIndicatorQuery(
  filters: IndicatorFilters,
  offset: number,
  limit = 50,
): string {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(Math.max(0, offset)),
  });
  if (filters.q.trim()) params.set('q', filters.q.trim());
  if (filters.source) params.set('source', filters.source);
  if (filters.category.trim()) params.set('category', filters.category.trim());
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.activeOnly) params.set('active', 'true');
  return params.toString();
}
