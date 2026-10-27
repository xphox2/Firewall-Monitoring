/**
 * The syslog and trap filters.
 *
 * Both endpoints take a device and a probe, and the syslog one also takes
 * a severity CEILING (`severity <= N`, not equality — a dropdown that
 * mapped to equality would be quietly wrong).
 */

/** The syslog filters. */
export interface SyslogFilters {
  deviceId?: string;
  probeId?: string;
  /** The severity CEILING: the server returns everything at or below it. */
  severity?: string;
  /** A substring match over the message, the hostname and the app name. */
  search?: string;
}

/** The trap filters. */
export interface TrapFilters {
  deviceId?: string;
  severity?: string;
  trapType?: string;
}

/** A non-negative integer — what the server's numeric validator accepts. */
function isNumeric(value: string | undefined): boolean {
  if (value === undefined || value === '') return false;
  return /^\d+$/.test(String(value).trim());
}

function setNumeric(params: URLSearchParams, name: string, value: string | undefined) {
  if (isNumeric(value)) params.set(name, String(value).trim());
}

function setText(params: URLSearchParams, name: string, value: string | undefined) {
  const trimmed = String(value ?? '').trim();
  if (trimmed) params.set(name, trimmed);
}

/**
 * The query for `GET /admin/api/syslog`.
 *
 * The server's parameters: `hours`, `probe_id`, `device_id`, `severity`,
 * `search`, `limit`, `offset`.
 */
export function buildSyslogQuery(
  filters: SyslogFilters,
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
  setNumeric(params, 'severity', filters.severity);
  setText(params, 'search', filters.search);
  return params;
}

/**
 * The query for `GET /admin/api/traps`.
 *
 * The server's parameters: `device_id`, `severity` (an EXACT match here,
 * unlike syslog's ceiling), `trap_type`, `hours`, `limit`, `offset`.
 */
export function buildTrapQuery(
  filters: TrapFilters,
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
  setText(params, 'severity', filters.severity);
  setText(params, 'trap_type', filters.trapType);
  return params;
}

/**
 * The page size for the syslog and trap lists.
 *
 * The server clamps `limit` to 500 (`httputil.ParsePagination`), so a
 * bigger request is capped rather than refused.
 */
export const LIST_PAGE_SIZE = 100;

/** The server's page-size ceiling. */
export const LIST_MAX_PAGE_SIZE = 500;
