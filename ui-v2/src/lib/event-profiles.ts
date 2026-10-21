export type ToggleMode = 'on' | 'off' | 'inherit';

export interface AlertTypeInfo {
  type: string;
  family: string;
  description: string;
}

export interface ProfileToggle {
  alert_type: string;
  enabled: boolean;
}

export interface TogglePayloadRow {
  alert_type: string;
  enabled: boolean;
}

/**
 * The server stores a SPARSE toggle set: a row means On/Off, absence means
 * Inherit. Build the full matrix from the registry so the editor can render
 * every type in its three states.
 */
export function matrixFromToggles(
  types: AlertTypeInfo[],
  toggles: ProfileToggle[] | undefined,
): Map<string, ToggleMode> {
  const stored = new Map((toggles ?? []).map((t) => [t.alert_type, t.enabled]));
  const matrix = new Map<string, ToggleMode>();
  for (const info of types) {
    const value = stored.get(info.type);
    matrix.set(info.type, value === undefined ? 'inherit' : value ? 'on' : 'off');
  }
  return matrix;
}

/** Only On/Off rows are persisted; Inherit is expressed by omission. */
export function buildTogglePayload(
  types: AlertTypeInfo[],
  matrix: Map<string, ToggleMode>,
): { toggles: TogglePayloadRow[] } {
  const toggles: TogglePayloadRow[] = [];
  for (const info of types) {
    const mode = matrix.get(info.type) ?? 'inherit';
    if (mode === 'inherit') continue;
    toggles.push({ alert_type: info.type, enabled: mode === 'on' });
  }
  return { toggles };
}

export function groupTypes(
  types: AlertTypeInfo[],
): Array<{ family: string; types: AlertTypeInfo[] }> {
  const map = new Map<string, AlertTypeInfo[]>();
  for (const info of types) {
    const list = map.get(info.family) ?? [];
    list.push(info);
    map.set(info.family, list);
  }
  return Array.from(map.entries()).map(([family, list]) => ({ family, types: list }));
}

export function familyCounts(
  types: AlertTypeInfo[],
  matrix: Map<string, ToggleMode>,
): { on: number; off: number; inherit: number } {
  let on = 0;
  let off = 0;
  let inherit = 0;
  for (const info of types) {
    const mode = matrix.get(info.type) ?? 'inherit';
    if (mode === 'on') on += 1;
    else if (mode === 'off') off += 1;
    else inherit += 1;
  }
  return { on, off, inherit };
}

/** Set every type in a family (used by the bulk row actions). */
export function setFamilyMode(
  matrix: Map<string, ToggleMode>,
  types: AlertTypeInfo[],
  mode: ToggleMode,
): Map<string, ToggleMode> {
  const next = new Map(matrix);
  for (const info of types) next.set(info.type, mode);
  return next;
}

export function dirtyToggleCount(
  types: AlertTypeInfo[],
  matrix: Map<string, ToggleMode>,
  baseline: Map<string, ToggleMode>,
): number {
  let dirty = 0;
  for (const info of types) {
    if ((matrix.get(info.type) ?? 'inherit') !== (baseline.get(info.type) ?? 'inherit')) {
      dirty += 1;
    }
  }
  return dirty;
}
