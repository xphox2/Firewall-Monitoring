import { useMemo } from 'react';
import { cn } from '@/lib/utils';
import {
  SYSLOG_FIELD_LABELS,
  SYSLOG_KEY_FIELDS,
  parseSyslogKeyValues,
  syslogSeverityTone,
  syslogTypeTone,
} from '@/lib/syslog-parse';

const SEVERITY_TONE: Record<string, string> = {
  crit: 'bg-sig-crit/15 text-sig-crit-text',
  warn: 'bg-sig-warn/15 text-sig-warn-text',
  notice: 'bg-accent/15 text-accent-text',
  info: 'bg-bg-panel text-text-dim',
};

function actionTone(action: string): string {
  const value = action.toLowerCase();
  if (['accept', 'pass', 'detected'].includes(value)) return 'bg-sig-ok/15 text-sig-ok-text';
  if (['deny', 'drop', 'blocked'].includes(value)) return 'bg-sig-crit/15 text-sig-crit-text';
  return 'bg-sig-warn/15 text-sig-warn-text';
}

function appRiskTone(risk: string): string {
  const value = risk.toLowerCase();
  if (['very-high', 'high'].includes(value)) return 'bg-sig-crit/15 text-sig-crit-text';
  if (value === 'medium') return 'bg-sig-warn/15 text-sig-warn-text';
  return 'bg-sig-ok/15 text-sig-ok-text';
}

/**
 * The classic console's "Parsed Syslog Fields" panel: key/value extraction for
 * syslog-sourced alerts (metric_name === 'syslog'). Renders nothing when the
 * message has no recognisable fields, so non-syslog alerts are untouched.
 */
export function ParsedSyslogFields({ raw }: { raw?: string | null }) {
  const parsed = useMemo(() => parseSyslogKeyValues(raw), [raw]);
  if (!parsed.type) return null;

  const rows = SYSLOG_KEY_FIELDS.filter(
    (key) => parsed.fields[key] !== undefined && parsed.fields[key] !== '',
  );
  // FortiGate logs `level=`, not `severity=`; fall back to it, then to the
  // type category, so the badge always means something.
  const level = parsed.fields.severity || parsed.fields.level || '';
  const tone = level ? syslogSeverityTone(level) : syslogTypeTone(parsed.type);
  const badge = level || parsed.type;

  return (
    <div className="rounded-lg border border-border bg-bg-card p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <h3 className="text-[10px] font-semibold uppercase tracking-wider text-text-faint">
          Parsed syslog fields
        </h3>
        <span
          className={cn(
            'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
            SEVERITY_TONE[tone],
          )}
        >
          {badge}
        </span>
        <span className="font-mono text-xs font-semibold text-accent">{parsed.type}</span>
        {parsed.subtype && (
          <span className="font-mono text-[11px] text-text-faint">/ {parsed.subtype}</span>
        )}
      </div>

      {rows.length === 0 ? (
        <p className="text-[11px] text-text-faint">
          The message has a type but no key fields worth showing.
        </p>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
          {rows.map((key) => (
            <div key={key} className="rounded bg-bg-panel px-2 py-1.5">
              <div className="text-[9px] uppercase text-text-faint">{SYSLOG_FIELD_LABELS[key]}</div>
              <div className="break-all font-mono text-[11px] text-text">
                {key === 'action' ? (
                  <span className={cn('rounded px-1', actionTone(parsed.fields[key]))}>
                    {parsed.fields[key]}
                  </span>
                ) : key === 'apprisk' ? (
                  <span className={cn('rounded px-1', appRiskTone(parsed.fields[key]))}>
                    {parsed.fields[key]}
                  </span>
                ) : (
                  parsed.fields[key]
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
