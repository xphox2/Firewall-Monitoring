export interface CapabilityFieldCell {
  state: string;
  source: string;
  completeness?: string;
  note?: string;
  count: number;
  last_seen?: string;
}

export interface CapabilityFeatureCell {
  state: string;
  fields?: string[];
}

export interface DeviceCapabilities {
  device_id: number;
  vendor: string;
  hardware?: string;
  window_hours: number;
  fields: Record<string, CapabilityFieldCell>;
  features: Record<string, CapabilityFeatureCell>;
}

export type CapabilityTone = 'ok' | 'warn' | 'crit' | 'accent' | 'muted';

const FEATURE_RANK: Record<string, number> = {
  supported: 0,
  degraded: 1,
  inactive: 2,
  unsupported: 3,
};

export function stateLabel(state: string | undefined): string {
  const value = String(state ?? '').trim();
  if (!value) return 'Unknown';
  return value.replace(/_/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

export function capabilityTone(state: string | undefined): CapabilityTone {
  switch (String(state ?? '').toLowerCase()) {
    case 'supported':
    case 'native':
      return 'ok';
    case 'degraded':
    case 'partial':
      return 'warn';
    case 'config_dependent':
      return 'accent';
    case 'unsupported':
    case 'none':
      return 'crit';
    default:
      return 'muted';
  }
}

/** Available features first, then degraded/inactive/unsupported; alpha within a state. */
export function capabilityFeatureRows(
  features: Record<string, CapabilityFeatureCell> | undefined,
): Array<{ name: string; state: string; fields: string[] }> {
  return Object.entries(features ?? {})
    .map(([name, cell]) => ({
      name,
      state: String(cell?.state ?? ''),
      fields: Array.isArray(cell?.fields) ? cell.fields : [],
    }))
    .sort(
      (a, b) =>
        (FEATURE_RANK[a.state] ?? 9) - (FEATURE_RANK[b.state] ?? 9) ||
        a.name.localeCompare(b.name),
    );
}

export function capabilityFieldRows(
  fields: Record<string, CapabilityFieldCell> | undefined,
): Array<{ name: string } & CapabilityFieldCell> {
  return Object.entries(fields ?? {})
    .map(([name, cell]) => ({ name, ...cell }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export interface CapabilitySummary {
  supported: number;
  degraded: number;
  inactive: number;
  unsupported: number;
}

export function capabilitySummary(
  features: Record<string, CapabilityFeatureCell> | undefined,
): CapabilitySummary {
  const out: CapabilitySummary = { supported: 0, degraded: 0, inactive: 0, unsupported: 0 };
  for (const cell of Object.values(features ?? {})) {
    const state = String(cell?.state ?? '').toLowerCase();
    if (state in out) out[state as keyof CapabilitySummary] += 1;
  }
  return out;
}
