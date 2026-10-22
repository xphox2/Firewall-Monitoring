export type LinkState = 'up' | 'down' | 'unknown';

/**
 * One classification for both edge colour and the KPI counters. Connection
 * statuses default to "unknown" and the poller emits "stale"; neither is a
 * failure, so they must not inflate the "down" count.
 */
export function linkState(status: string | null | undefined): LinkState {
  const value = String(status ?? '')
    .trim()
    .toLowerCase();
  if (!value) return 'unknown';
  if (/\b(up|online|active|ok|healthy|established)\b/.test(value)) return 'up';
  if (/\b(down|offline|failed|error|critical)\b/.test(value)) return 'down';
  return 'unknown';
}

export function linkColour(status: string | null | undefined): string {
  switch (linkState(status)) {
    case 'up':
      return '#4ade80';
    case 'down':
      return '#f87171';
    default:
      return '#94a3b8';
  }
}

export interface BundleableEdge {
  id: string;
  source: string;
  target: string;
  kind: 'connection' | 'tunnel';
  status?: string;
  label?: string;
  connectionId?: number;
}

export interface BundledEdge extends BundleableEdge {
  /** Collapsed carrier; its members are hidden until expanded. */
  bundle?: boolean;
  /** Hidden member of a bundle, revealed when the bundle expands. */
  sublane?: boolean;
  /** Element ids (`edge-<id>`) of a bundle's members. */
  members?: string[];
}

/**
 * Collapse parallel edges of the SAME kind between the same device pair into
 * one bundle. A pair with a single edge is returned directly: there is nothing
 * to expand, and its label already carries the ports.
 *
 * Bundles are down if any member is down, up if any member is up, else the
 * first member's original status — the same down-over-up precedence used for
 * the KPI counters.
 */
export function bundleEdges<T extends BundleableEdge>(
  edges: T[],
  enabled: boolean,
): Array<T & BundledEdge> {
  if (!enabled) return edges.map((edge) => ({ ...edge }));

  const groups = new Map<string, T[]>();
  for (const edge of edges) {
    // Kind is part of the key: a link bundle and a tunnel bundle between the
    // same pair are separate carriers, never merged into one count.
    const key = `${edge.kind}|${[edge.source, edge.target].sort().join('|')}`;
    const group = groups.get(key);
    if (group) group.push(edge);
    else groups.set(key, [edge]);
  }

  const drawn: Array<T & BundledEdge> = [];
  for (const [key, members] of groups) {
    if (members.length === 1) {
      drawn.push({ ...members[0] });
      continue;
    }
    const first = members[0];
    const states = members.map((member) => linkState(member.status));
    const status = states.includes('down')
      ? 'down'
      : states.includes('up')
        ? 'up'
        : first.status;
    drawn.push({
      id: `bundle-${key}`,
      source: first.source,
      target: first.target,
      kind: first.kind,
      status,
      label: `${members.length} ${first.kind === 'tunnel' ? 'tunnels' : 'links'}`,
      bundle: true,
      members: members.map((member) => `edge-${member.id}`),
    } as T & BundledEdge);
    for (const member of members) drawn.push({ ...member, sublane: true });
  }
  return drawn;
}

export interface MapPosition {
  x: number;
  y: number;
}

/**
 * Validate a positions payload read from localStorage. Storage is untrusted
 * and can contain stale/partial entries from an older build; a bad point must
 * never be used to position a node, or it would land at NaN and vanish.
 */
export function normalizePositions(value: unknown): Record<string, MapPosition> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out: Record<string, MapPosition> = {};
  for (const [id, raw] of Object.entries(value as Record<string, unknown>)) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const point = raw as { x?: unknown; y?: unknown };
    if (
      typeof point.x === 'number' &&
      Number.isFinite(point.x) &&
      typeof point.y === 'number' &&
      Number.isFinite(point.y)
    ) {
      out[id] = { x: point.x, y: point.y };
    }
  }
  return out;
}
