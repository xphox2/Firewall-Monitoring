export type NocFeedKind = 'all' | 'alerts' | 'detections' | 'silenced';

export interface NocFeedEntry {
  kind?: string;
  id: number;
  at?: string;
  last_seen?: string;
  repeat?: number;
  severity?: string;
  type?: string;
  message?: string;
  dedup_key?: string;
}

export interface NocFeedPayload {
  alerts?: NocFeedEntry[];
  detections?: NocFeedEntry[];
  silenced?: NocFeedEntry[];
}

export interface FeedRow {
  item: NocFeedEntry;
  list: 'alerts' | 'detections' | 'silenced';
}

function itemTime(item: NocFeedEntry): number {
  const value = item.last_seen || item.at;
  const ms = value ? new Date(value).getTime() : 0;
  return Number.isFinite(ms) ? ms : 0;
}

/** Merge the three feed lists, filter by kind, newest first, capped. */
export function mergeFeed(
  feed: NocFeedPayload | null | undefined,
  kind: NocFeedKind,
  count: number,
): FeedRow[] {
  const rows: FeedRow[] = [
    ...(feed?.alerts ?? []).map((item) => ({ item, list: 'alerts' as const })),
    ...(feed?.detections ?? []).map((item) => ({ item, list: 'detections' as const })),
    ...(feed?.silenced ?? []).map((item) => ({ item, list: 'silenced' as const })),
  ];
  return rows
    .filter((row) => kind === 'all' || row.list === kind)
    .sort((a, b) => itemTime(b.item) - itemTime(a.item))
    .slice(0, Math.max(0, count));
}
