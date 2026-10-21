import { describe, expect, it } from 'vitest';
import {
  SYSLOG_FIELD_LABELS,
  SYSLOG_KEY_FIELDS,
  isSyslogAlertType,
  parseSyslogKeyValues,
  syslogSeverityTone,
  syslogTypeTone,
} from './syslog-parse';

describe('parseSyslogKeyValues', () => {
  it('extracts type/subtype/severity and arbitrary fields', () => {
    const parsed = parseSyslogKeyValues(
      'date=2026-10-21 time=10:00:00 devname="fw-1" logid=0000000013 type=traffic subtype=forward srcip=10.0.0.5 dstip=198.51.100.9 action="deny" sentbyte=1200',
    );
    expect(parsed.type).toBe('traffic');
    expect(parsed.subtype).toBe('forward');
    expect(parsed.fields.devname).toBe('fw-1');
    expect(parsed.fields.srcip).toBe('10.0.0.5');
    expect(parsed.fields.action).toBe('deny');
    expect(parsed.fields.sentbyte).toBe('1200');
  });

  it('keeps quoted values containing spaces', () => {
    const parsed = parseSyslogKeyValues('type=event msg="user logged in from vpn" user=alice');
    expect(parsed.fields.msg).toBe('user logged in from vpn');
    expect(parsed.fields.user).toBe('alice');
  });

  it('keeps the last value for a repeated key', () => {
    expect(parseSyslogKeyValues('action=deny action=accept').fields.action).toBe('accept');
  });

  it('returns an empty result for missing or pair-free input', () => {
    expect(parseSyslogKeyValues('')).toEqual({ type: '', subtype: '', severity: '', fields: {} });
    expect(parseSyslogKeyValues(null).type).toBe('');
    expect(parseSyslogKeyValues('plain text without pairs').fields).toEqual({});
  });

  it('parses the rule/hostname prefix the alert engine prepends', () => {
    const parsed = parseSyslogKeyValues(
      '[Syslog Critical (severity 2)] fw-01: date=2026-10-21 type=traffic subtype=forward action=deny',
    );
    expect(parsed.type).toBe('traffic');
    expect(parsed.fields.action).toBe('deny');
  });

  it('ignores malformed pairs', () => {
    const parsed = parseSyslogKeyValues('=oops type=utm not-a-pair severity=warning');
    expect(parsed.type).toBe('utm');
    expect(parsed.severity).toBe('warning');
  });
});

describe('alert gating and type tones', () => {
  it('recognises the syslog-sourced alert types', () => {
    for (const type of ['SYSLOG_EMERGENCY', 'SYSLOG_CRITICAL', 'SYSLOG_ALERT', 'LOG_RULE_MATCH']) {
      expect(isSyslogAlertType(type)).toBe(true);
    }
    expect(isSyslogAlertType('CPU_HIGH')).toBe(false);
    expect(isSyslogAlertType(undefined)).toBe(false);
  });

  it('tones the FortiGate type categories', () => {
    expect(syslogTypeTone('traffic')).toBe('info');
    expect(syslogTypeTone('ips')).toBe('crit');
    expect(syslogTypeTone('av')).toBe('crit');
    expect(syslogTypeTone('utm')).toBe('warn');
  });
});

describe('syslog field presentation', () => {
  it('labels every key field', () => {
    for (const key of SYSLOG_KEY_FIELDS) {
      expect(SYSLOG_FIELD_LABELS[key], key).toBeTruthy();
    }
  });

  it('maps severity words to tones', () => {
    expect(syslogSeverityTone('critical')).toBe('crit');
    expect(syslogSeverityTone('major')).toBe('crit');
    expect(syslogSeverityTone('warning')).toBe('warn');
    expect(syslogSeverityTone('error')).toBe('crit');
    expect(syslogSeverityTone('notice')).toBe('notice');
    expect(syslogSeverityTone('information')).toBe('info');
    expect(syslogSeverityTone('')).toBe('info');
  });
});
