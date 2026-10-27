/**
 * The event filters.
 *
 * The console offered two of the server's eight net-event filters and two
 * of the eleven security-event filters, so an operator could not narrow
 * either stream by device, probe, site or rule.
 *
 * Two rules the server enforces and the query builders have to respect:
 *
 * 1. **The numeric filters are validated.** `device_id`, `probe_id`,
 *    `site_id`, `activity`, `action`, `class` and `severity` are rejected
 *    with a 400 when they are not numeric (AUDIT-251: a non-numeric value
 *    cast to a uint column is a 22P02 on Postgres and a silent no-match on
 *    SQLite). So a numeric filter is only ever sent when it parses.
 * 2. **`src_ip` and `dst_ip` must be a bare IP or a CIDR.** A malformed one
 *    is a 400, not a no-match, because it is cast to `inet`.
 */

/** The filters both event streams accept. */
export interface EventFilters {
  deviceId?: string;
  probeId?: string;
  siteId?: string;
  activity?: string;
  action?: string;
  /** The security-event class. */
  class?: string;
  severity?: string;
  /** A substring match, on the security events only. */
  adminUser?: string;
  sigName?: string;
  tunnelName?: string;
  wanName?: string;
  /** An exact match, on the net events only. */
  ruleKey?: string;
  srcIp?: string;
  dstIp?: string;
}

/**
 * A dotted-quad or a CIDR — what the server's `validIPOrCIDR` accepts.
 *
 * The server validates with `netip.ParsePrefix` / `netip.ParseAddr` and
 * answers a malformed value with a **400**, not a no-match. So this has to
 * agree with `netip`:
 *
 *  - an IPv4 octet may not have a LEADING ZERO (`netip` rejects
 *    `192.168.001.001` outright, since Go 1.17);
 *  - an IPv6 address is hex groups with at most ONE `::`, and a group is
 *    1–4 hex digits;
 *  - `10.0.0.1:443` is NEITHER an address nor a prefix — an operator who
 *    types an address with a port gets a 400, so it must not be sent;
 *  - a CIDR's prefix length is bounded by its family (32 for IPv4, 128 for
 *    IPv6).
 *
 * A loose "contains a colon" test would let `foo:bar` and
 * `10.0.0.1:443` through, and a single malformed destination takes the
 * whole stream down with a 400.
 */
export function isIpOrCidr(value: string): boolean {
  const trimmed = String(value ?? '').trim();
  if (!trimmed) return false;

  let addr = trimmed;
  let bits: number | null = null;
  if (trimmed.includes('/')) {
    const slash = trimmed.indexOf('/');
    addr = trimmed.slice(0, slash);
    const raw = trimmed.slice(slash + 1);
    if (!/^\d{1,3}$/.test(raw)) return false;
    bits = Number(raw);
  }

  const v4 = isIpv4(addr);
  if (v4) {
    if (bits !== null && bits > 32) return false;
    return true;
  }
  if (!isIpv6(addr)) return false;
  if (bits !== null && bits > 128) return false;
  return true;
}

/** A dotted quad with no leading zeros — what `netip.ParseAddr` accepts. */
function isIpv4(addr: string): boolean {
  const parts = addr.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

/**
 * An IPv6 address.
 *
 * `netip.ParseAddr` accepts an embedded IPv4 in the last group
 * (`::ffff:192.0.2.1`), so this does too.
 */
function isIpv6(addr: string): boolean {
  if (!addr.includes(':')) return false;
  // A zone ("fe80::1%eth0") is a scope, not part of the address.
  const zone = addr.indexOf('%');
  if (zone >= 0) {
    if (zone === 0 || zone === addr.length - 1) return false;
    addr = addr.slice(0, zone);
  }
  // At most ONE "::" — two of them is not an address.
  if (addr.split('::').length > 2) return false;
  const halves = addr.split('::');
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length > 1 ? (halves[1] ? halves[1].split(':') : []) : [];

  const groups = [...head, ...tail];
  if (groups.length > 8) return false;
  // Without "::" there must be exactly eight groups; with it, fewer.
  if (halves.length === 1 && groups.length !== 8) return false;
  if (halves.length > 1 && groups.length === 0) return false;

  for (const group of groups) {
    if (group === '') return false;
    // The last group may be an embedded IPv4.
    if (group.includes('.')) {
      if (group !== groups[groups.length - 1]) return false;
      if (!isIpv4(group)) return false;
      continue;
    }
    if (!/^[0-9A-Fa-f]{1,4}$/.test(group)) return false;
  }
  return true;
}

/** A non-negative integer — what the server's numeric validator accepts. */
function isNumeric(value: string | undefined): boolean {
  if (value === undefined || value === '') return false;
  return /^\d+$/.test(String(value).trim());
}

/**
 * Set a numeric filter, but only when it parses.
 *
 * Sending a non-numeric value is a 400, not a no-match, so an empty or
 * half-typed filter has to be OMITTED rather than sent.
 */
function setNumeric(params: URLSearchParams, name: string, value: string | undefined) {
  if (isNumeric(value)) params.set(name, String(value).trim());
}

/** Set a free-text filter, trimmed. */
function setText(params: URLSearchParams, name: string, value: string | undefined) {
  const trimmed = String(value ?? '').trim();
  if (trimmed) params.set(name, trimmed);
}

/**
 * The query for `GET /admin/api/events`.
 *
 * The server's parameters: `hours`, `device_id`, `probe_id`, `site_id`,
 * `activity`, `action`, `src_ip`, `dst_ip`, `rule_key`, `limit`, `offset`.
 */
export function buildNetEventQuery(
  filters: EventFilters,
  hours: number,
  limit: number,
  offset: number,
): URLSearchParams {
  const params = new URLSearchParams({
    hours: String(hours),
    limit: String(limit),
    offset: String(offset),
  });
  setNumeric(params, 'device_id', filters.deviceId);
  setNumeric(params, 'probe_id', filters.probeId);
  setNumeric(params, 'site_id', filters.siteId);
  setNumeric(params, 'activity', filters.activity);
  setNumeric(params, 'action', filters.action);
  setText(params, 'rule_key', filters.ruleKey);
  // An address that is not an address is a 400, so it is not sent.
  if (isIpOrCidr(String(filters.srcIp ?? ''))) params.set('src_ip', String(filters.srcIp).trim());
  if (isIpOrCidr(String(filters.dstIp ?? ''))) params.set('dst_ip', String(filters.dstIp).trim());
  return params;
}

/**
 * The query for `GET /admin/api/security-events`.
 *
 * The server's parameters: `hours`, `device_id`, `probe_id`, `class`,
 * `activity`, `action`, `severity`, `admin_user`, `sig_name`, `tunnel_name`,
 * `wan_name`, `limit`, `offset`.
 *
 * There is **no `site_id`** on this endpoint — the security events are
 * filtered by device or probe, not by site.
 */
export function buildSecEventQuery(
  filters: EventFilters,
  hours: number,
  limit: number,
  offset: number,
): URLSearchParams {
  const params = new URLSearchParams({
    hours: String(hours),
    limit: String(limit),
    offset: String(offset),
  });
  setNumeric(params, 'device_id', filters.deviceId);
  setNumeric(params, 'probe_id', filters.probeId);
  setNumeric(params, 'class', filters.class);
  setNumeric(params, 'activity', filters.activity);
  setNumeric(params, 'action', filters.action);
  setNumeric(params, 'severity', filters.severity);
  setText(params, 'admin_user', filters.adminUser);
  setText(params, 'sig_name', filters.sigName);
  setText(params, 'tunnel_name', filters.tunnelName);
  setText(params, 'wan_name', filters.wanName);
  return params;
}

/**
 * The page size.
 *
 * The server's pagination helper caps `limit` at 500 and defaults it to
 * 100 (`httputil.ParsePagination`). A larger request is clamped, so asking
 * for more is not an error — but it is not what the operator gets either.
 */
export const EVENT_PAGE_SIZE = 100;

/**
 * The server's page-size ceiling.
 *
 * `httputil.ParsePagination` clamps `limit` to 500. The client cannot ask
 * for more than that, and it is worth knowing what the ceiling is so the
 * pager does not offer a page that will come back short.
 */
export const EVENT_MAX_PAGE_SIZE = 500;
