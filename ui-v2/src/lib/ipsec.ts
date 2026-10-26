/**
 * The IPSec tunnel intent: the canonical shape the server stores, renders and
 * validates.
 *
 * `internal/ipsec/intent.go` is the ONE canonical description of a tunnel. It
 * renders to both ends, so the field names here are the server's, not
 * invented ones.
 *
 * DERIVED FIELDS. The server assigns these and the console must NOT send
 * them: `id` (forced to 0 on create), `name` (`fwm-t<ID>`), `vti_subnet`
 * and `inner_ip` (allocated from the VTI subnet), and `reqid` (the tunnel id).
 * Sending them is at best ignored and at worst a validation failure.
 */

export interface IkeProposal {
  enc: string;
  integ: string;
  prf: string;
  dh: string;
}

export interface EspProposal {
  enc: string;
  integ: string;
  pfs: string;
}

export interface LocalId {
  type: string;
  value: string;
}

export interface EndpointSpec {
  device_id: number;
  vendor: string;
  peer_ip: string;
  egress_iface: string;
  gateway: string;
  /** The legacy single-interface field. The server normalises `lan_ifaces` into it. */
  lan_iface?: string;
  lan_ifaces: string[];
  local_id: LocalId;
  dynamic: boolean;
  protected_subnets: string[];
  child_lifetime_secs: number;
  mss_clamp: number;
}

export interface TunnelIntent {
  id?: number;
  enabled: boolean;
  ike_version: string;
  mode: string;
  ike: IkeProposal;
  esp: EspProposal;
  ike_lifetime_secs: number;
  dpd: { delay_secs: number; timeout_secs: number };
  psk?: string;
  disabled_paths: string[];
  ends: [EndpointSpec, EndpointSpec];
}

/** The mask the server uses for a stored PSK. */
export const PSK_MASK = '********';

/** V1's hardcoded values. Omitting them raises spurious warnings. */
export const DPD_DEFAULT = { delay_secs: 30, timeout_secs: 0 };
export const MSS_CLAMP_DEFAULT = 1350;

/** The identity types the server accepts. */
export const ID_TYPES = ['ip', 'fqdn', 'keyid'] as const;

/** The crypto presets the server ships. `custom` is a client-side concept. */
export type ProfileName = 'modern' | 'compatible' | 'custom';

export interface Profile {
  name: string;
  label: string;
  ike_version: string;
  ike: IkeProposal;
  esp: EspProposal;
  ike_lifetime_secs: number;
  child_lifetime_secs: number;
}

export interface CapabilityDescriptor {
  vendor: string;
  ike_versions: string[];
  modes: string[];
  encryption: string[];
  integrity: string[];
  prf: string[];
  dh_groups: string[];
  pfs: boolean;
  mss_clamp: boolean;
  id_types: string[];
  uses_lan_iface: boolean;
  auto_objects: string[];
}

export interface CapabilitiesResponse {
  a: CapabilityDescriptor;
  b: CapabilityDescriptor;
  /** The INTERSECTION of the two vendors' capabilities. */
  allowed: CapabilityDescriptor;
  profiles: Profile[];
}

export interface Finding {
  severity: string;
  code: string;
  message: string;
  /** Which end. ABSENT means the finding is about the tunnel as a whole. */
  end?: number | null;
  subject?: string;
}

export interface EndPreview {
  end: number;
  vendor: string;
  /** The rendered native configuration, redacted. */
  preview: string;
  auto_objects: string[];
  /** A COUNT of the apply steps, not the steps themselves. */
  steps: number;
}

export interface PreviewResponse {
  ends: EndPreview[];
  validation: Finding[];
  psk_autogen: boolean;
  provisional: boolean;
}

export interface DeviceIface {
  name: string;
  type_name?: string;
  status?: string;
  is_lan?: boolean;
  addresses: Array<{ ip: string; cidr?: string; public?: boolean }>;
}

export interface IpsecHints {
  wan_ip?: string;
  interfaces: DeviceIface[];
  suggested_egress?: string;
  suggested_lan?: string;
  suggested_peer_ip?: string;
  lan_subnets: string[];
}

/**
 * Canonicalise a CIDR the way the server does.
 *
 * The server canonicalises with `net.ParseCIDR` -> `net.IPNet.String()` and
 * compares the stored keys EXACTLY against that. A key it does not recognise
 * is a **silent fail-open**: the path stays enabled even though the operator
 * turned it off, and the server raises only a `disabled_path_unknown` WARNING.
 *
 * So the client's form has to be byte-identical to the server's for every
 * input the UI accepts. Two consequences:
 *
 * - IPv4 only. Go's canonical form for IPv6 is a different algorithm, and a
 *   half-right IPv6 compressor would be worse than none: a path that cannot
 *   be canonicalised is left ENABLED, visibly, rather than "disabled" in a
 *   way that does nothing. `pathKey` returns '' for it and the caller skips
 *   the toggle.
 * - Leading zeros are REJECTED, not normalised. Go's IPv4 parser rejects
 *   `192.168.001.001` outright, so accepting it here would produce a key the
 *   server can never match.
 */
export function canonNet(cidr: string): string {
  const m = /^\s*(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})\s*$/.exec(String(cidr ?? ''));
  if (!m) return '';
  const parts = m[1].split('.');
  // A leading zero (other than "0" itself) is not a valid IPv4 octet.
  if (parts.some((p) => p.length > 1 && p.startsWith('0'))) return '';
  const octets = parts.map((part) => Number(part));
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return '';
  const bits = Number(m[2]);
  if (bits < 0 || bits > 32) return '';
  const base =
    ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const net = (base & mask) >>> 0;
  return `${(net >>> 24) & 255}.${(net >>> 16) & 255}.${(net >>> 8) & 255}.${net & 255}/${bits}`;
}

/**
 * The key for one path between the two ends.
 *
 * A is the first end, B the second. The order is FIXED (the server does not
 * sort them), so the key is not symmetric.
 *
 * Returns '' when either side cannot be canonicalised. The caller must SKIP
 * that path rather than emit a raw key: a raw key is a silent fail-open.
 */
export function pathKey(aNet: string, bNet: string): string {
  const ca = canonNet(aNet);
  const cb = canonNet(bNet);
  return ca && cb ? `${ca}|${cb}` : '';
}

/**
 * The disabled-path keys, from a map of key -> disabled.
 *
 * The keys are canonicalised here as well as at the point they are built, so
 * a key that reached this function by any other route still cannot be a
 * non-canonical one.
 */
export function disabledPathsFrom(disabled: Record<string, boolean>): string[] {
  const out = new Set<string>();
  for (const [key, off] of Object.entries(disabled)) {
    if (!off) continue;
    const parts = key.split('|');
    if (parts.length !== 2) continue;
    const canonical = pathKey(parts[0], parts[1]);
    if (canonical) out.add(canonical);
  }
  return Array.from(out).sort();
}

/**
 * Drop the disabled-path keys that name a subnet no longer listed.
 *
 * An operator who edits a subnet has not asked to keep a rule about a
 * network they removed, and a stale key would be invisible — nothing on
 * screen would explain it.
 */
export function pruneDisabledPaths(
  disabled: Record<string, boolean>,
  ends: Array<{ protectedSubnets: string[] }>,
): Record<string, boolean> {
  const live = new Set<string>();
  const [a, b] = ends;
  for (const aNet of a?.protectedSubnets ?? []) {
    for (const bNet of b?.protectedSubnets ?? []) {
      const key = pathKey(aNet, bNet);
      if (key) live.add(key);
    }
  }
  const out: Record<string, boolean> = {};
  for (const [key, off] of Object.entries(disabled)) {
    if (off && live.has(key)) out[key] = true;
  }
  return out;
}

/**
 * The crypto a preset carries.
 *
 * The IKE version comes WITH the preset — it is not a separate choice, and
 * the two presets differ. The Custom profile is the only place the operator
 * picks an IKE version, and only the presets the vendor pair supports are
 * offered.
 */
export function profileCrypto(profile: Profile): {
  ike_version: string;
  ike: IkeProposal;
  esp: EspProposal;
  ike_lifetime_secs: number;
  child_lifetime_secs: number;
} {
  return {
    ike_version: profile.ike_version,
    ike: { ...profile.ike },
    esp: { ...profile.esp },
    ike_lifetime_secs: profile.ike_lifetime_secs,
    child_lifetime_secs: profile.child_lifetime_secs,
  };
}

/**
 * Work out whether a stored intent came from a preset or from Custom.
 *
 * The intent stores the RESOLVED crypto, not the profile's name, so the edit
 * path has to infer it by matching. When nothing matches, the operator was
 * on Custom and the form has to present it as such — showing a preset that
 * does not match what is stored would silently rewrite the crypto on save.
 */
export function restoreCrypto(
  intent: Pick<TunnelIntent, 'ike' | 'esp' | 'ike_version'>,
  profiles: Profile[],
): { profile: ProfileName; custom: boolean } {
  for (const profile of profiles) {
    if (
      profile.ike_version === intent.ike_version &&
      profile.ike.enc === intent.ike.enc &&
      profile.ike.integ === intent.ike.integ &&
      profile.ike.prf === intent.ike.prf &&
      profile.ike.dh === intent.ike.dh &&
      profile.esp.enc === intent.esp.enc &&
      profile.esp.integ === intent.esp.integ &&
      profile.esp.pfs === intent.esp.pfs
    ) {
      return { profile: profile.name as ProfileName, custom: false };
    }
  }
  return { profile: 'custom', custom: true };
}

/**
 * The default local identity.
 *
 * The server has NO default: an empty identity is a BLOCKING finding
 * (`id_missing`), so the console has to supply one. V1 used `fwm-<uuid>`
 * for an fqdn and the peer IP for an ip.
 */
export function defaultIdentity(
  type: string,
  deviceUuid: string | undefined,
  peerIp: string,
): LocalId {
  if (type === 'ip') return { type, value: peerIp };
  if (type === 'keyid') return { type, value: deviceUuid ? `fwm-${deviceUuid}` : '' };
  return { type: 'fqdn', value: deviceUuid ? `fwm-${deviceUuid}` : '' };
}

/**
 * The client's own check of an identity, mirroring the server's.
 *
 * The server blocks an empty identity and normalises the type, so catching it
 * here saves a round trip.
 */
export function identityError(identity: LocalId): string | null {
  const value = String(identity?.value ?? '').trim();
  if (!value) return 'The local identity is required.';
  if (identity.type === 'ip' && !/^\d+\.\d+\.\d+\.\d+$/.test(value)) {
    return 'An ip identity must be a dotted-quad address.';
  }
  if ((identity.type === 'fqdn' || identity.type === 'keyid') && /\s/.test(value)) {
    return 'A name identity cannot contain spaces.';
  }
  return null;
}

/**
 * Which end a finding is about.
 *
 * `end` is a POINTER on the server: it is ABSENT for a tunnel-wide finding
 * and 0 for the FIRST end. A plain `if (finding.end)` would drop end A
 * entirely, because 0 is falsy in JavaScript.
 */
export function findingScope(finding: Finding): 'A' | 'B' | 'tunnel' {
  if (finding.end === null || finding.end === undefined) return 'tunnel';
  return finding.end === 0 ? 'A' : 'B';
}

/**
 * The child lifetime for one end.
 *
 * The NON-INITIATOR end gets a longer child lifetime, so the two do not
 * rekey at the same moment. The server warns when they are equal or when the
 * child lifetime is not shorter than the IKE lifetime.
 */
export function childLifetimeFor(
  base: number,
  isInitiator: boolean,
): number {
  return isInitiator ? base : base * 2;
}

/** What the operator has filled in for one end. */
export interface EndForm {
  deviceId: number;
  vendor: string;
  peerIp: string;
  dynamic: boolean;
  egressIface: string;
  lanIfaces: string[];
  localId: LocalId;
  protectedSubnets: string[];
  gateway: string;
}

/** What the operator has filled in for the tunnel. */
export interface IntentForm {
  mode: string;
  profile: ProfileName;
  /** The Custom crypto. Only used when `profile` is 'custom'. */
  custom: {
    ike_version: string;
    ike: IkeProposal;
    esp: EspProposal;
  };
  /** The presets the server offers, for the preset path. */
  profiles: Profile[];
  /** The pre-shared key. Blank means "the server generates one" on create. */
  psk: string;
  ends: [EndForm, EndForm];
  /** The disabled-path map, keyed by the canonical "aCIDR|bCIDR". */
  disabledPaths: Record<string, boolean>;
}

/**
 * Assemble the intent the server stores.
 *
 * Two things are easy to get wrong and both are load-bearing:
 *
 * - `enabled`, `dpd` and `mss_clamp` are always sent. V1 hardcoded them, and
 *   omitting any of them raises a spurious warning (`dpd_off`, `mss_unset`)
 *   — and `enabled` omitted is FALSE, which would save the tunnel DISABLED.
 * - `mode` comes from the vendors' intersection, never a hardcoded default.
 *   OPNsense supports policy-based only, so a hardcoded "route-based" would
 *   be wrong for every OPNsense pair.
 */
export function buildIntent(form: IntentForm): TunnelIntent {
  const profile =
    form.profile === 'custom'
      ? null
      : form.profiles.find((p) => p.name === form.profile) ?? null;

  const crypto = profile
    ? profileCrypto(profile)
    : {
        ike_version: form.custom.ike_version,
        ike: { ...form.custom.ike },
        esp: { ...form.custom.esp },
        ike_lifetime_secs: 86400,
        child_lifetime_secs: 3600,
      };

  const baseChild = crypto.child_lifetime_secs;
  const ends: [EndpointSpec, EndpointSpec] = [
    {
      device_id: form.ends[0].deviceId,
      vendor: form.ends[0].vendor,
      peer_ip: form.ends[0].peerIp,
      egress_iface: form.ends[0].egressIface,
      gateway: form.ends[0].gateway,
      lan_ifaces: form.ends[0].lanIfaces,
      local_id: { ...form.ends[0].localId },
      dynamic: form.ends[0].dynamic,
      protected_subnets: form.ends[0].protectedSubnets,
      child_lifetime_secs: childLifetimeFor(baseChild, true),
      mss_clamp: MSS_CLAMP_DEFAULT,
    },
    {
      device_id: form.ends[1].deviceId,
      vendor: form.ends[1].vendor,
      peer_ip: form.ends[1].peerIp,
      egress_iface: form.ends[1].egressIface,
      gateway: form.ends[1].gateway,
      lan_ifaces: form.ends[1].lanIfaces,
      local_id: { ...form.ends[1].localId },
      dynamic: form.ends[1].dynamic,
      protected_subnets: form.ends[1].protectedSubnets,
      child_lifetime_secs: childLifetimeFor(baseChild, false),
      mss_clamp: MSS_CLAMP_DEFAULT,
    },
  ];

  return {
    enabled: true,
    ike_version: crypto.ike_version,
    mode: form.mode,
    ike: crypto.ike,
    esp: crypto.esp,
    ike_lifetime_secs: crypto.ike_lifetime_secs,
    dpd: { ...DPD_DEFAULT },
    // A blank PSK on create means "generate one"; on edit the mask means
    // "unchanged". The server decides which, from the same token.
    ...(form.psk ? { psk: form.psk } : {}),
    disabled_paths: disabledPathsFrom(form.disabledPaths),
    ends,
  };
}

