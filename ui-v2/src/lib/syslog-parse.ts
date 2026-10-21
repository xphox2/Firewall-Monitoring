export interface ParsedSyslog {
  type: string;
  subtype: string;
  severity: string;
  fields: Record<string, string>;
}

/**
 * FortiGate-style `key=value` (or `key="quoted value"`) extraction, matching the
 * classic console's parseFortiGateLog. Repeated keys keep the last value, as
 * the vendors' log lines do when a field is restated.
 */
export function parseSyslogKeyValues(raw: string | null | undefined): ParsedSyslog {
  const parsed: ParsedSyslog = { type: '', subtype: '', severity: '', fields: {} };
  if (!raw) return parsed;
  const pairs = raw.match(/(\w+(?:_[a-zA-Z0-9])*)=(?:"[^"]*"|[^\s"]+)/g) ?? [];
  for (const pair of pairs) {
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    const key = pair.slice(0, eq);
    const value = pair.slice(eq + 1).replace(/^"|"$/g, '');
    parsed.fields[key] = value;
    if (key === 'type') parsed.type = value;
    else if (key === 'subtype') parsed.subtype = value;
    else if (key === 'severity') parsed.severity = value;
  }
  return parsed;
}

/** The fields worth showing first, in the classic console's order. */
export const SYSLOG_KEY_FIELDS = [
  'srcip',
  'srcport',
  'dstip',
  'dstport',
  'proto',
  'action',
  'sentbyte',
  'rcvdbyte',
  'duration',
  'iface',
  'policyid',
  'vd',
  'sessionid',
  'srcintf',
  'dstintf',
  'hostname',
  'logid',
  'app',
  'appid',
  'apprisk',
  'virus',
  'file',
  'sig_name',
  'service',
  'ha_role',
];

export const SYSLOG_FIELD_LABELS: Record<string, string> = {
  srcip: 'Src IP',
  srcport: 'Src Port',
  dstip: 'Dst IP',
  dstport: 'Dst Port',
  proto: 'Protocol',
  action: 'Action',
  sentbyte: 'Sent Bytes',
  rcvdbyte: 'Rcvd Bytes',
  duration: 'Duration (s)',
  iface: 'Interface',
  policyid: 'Policy ID',
  vd: 'VDOM',
  sessionid: 'Session ID',
  srcintf: 'Src Intf',
  dstintf: 'Dst Intf',
  hostname: 'Hostname',
  logid: 'Log ID',
  app: 'Application',
  appid: 'App ID',
  apprisk: 'App Risk',
  virus: 'Virus',
  file: 'File',
  sig_name: 'Signature',
  service: 'Service',
  ha_role: 'HA Role',
};

export type SyslogSeverityTone = 'crit' | 'warn' | 'notice' | 'info';

/** Alert types whose message is a raw syslog line. */
export const SYSLOG_ALERT_TYPES = [
  'SYSLOG_EMERGENCY',
  'SYSLOG_CRITICAL',
  'SYSLOG_ALERT',
  'LOG_RULE_MATCH',
] as const;

export function isSyslogAlertType(alertType: string | null | undefined): boolean {
  return (SYSLOG_ALERT_TYPES as readonly string[]).includes(String(alertType ?? ''));
}

/** Fallback tone from the FortiGate `type=` category when no severity is logged. */
export function syslogTypeTone(type: string | null | undefined): SyslogSeverityTone {
  const value = String(type ?? '').toLowerCase();
  if (['ips', 'av', 'virus'].includes(value)) return 'crit';
  if (value === 'traffic') return 'info';
  return 'warn';
}

/** CEF-ish severity word → the badge tone the classic console uses. */
export function syslogSeverityTone(severity: string | null | undefined): SyslogSeverityTone {
  const value = String(severity ?? '').toLowerCase();
  if (['critical', 'high', 'alert', 'emergency'].includes(value)) return 'crit';
  if (['error', 'major'].includes(value)) return 'crit';
  if (['warning', 'medium'].includes(value)) return 'warn';
  if (value === 'notice') return 'notice';
  return 'info';
}
