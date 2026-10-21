import { countryCodeToFlag, formatBytes, formatCompactNumber } from '@/lib/utils';

export interface BarRow {
  key: string;
  value: number;
}

/**
 * Ranked distribution list with an in-row bar. `count` values are formatted as
 * compact numbers; pass `bytes` when the value is a byte count.
 */
export function BarList({
  title,
  rows,
  bytes = false,
  flag = false,
  empty,
}: {
  title: string;
  rows: BarRow[] | undefined;
  bytes?: boolean;
  flag?: boolean;
  empty: string;
}) {
  const items = (rows ?? []).slice(0, 8);
  const max = Math.max(1, ...items.map((r) => r.value));
  return (
    <div className="rounded-xl border border-border bg-bg-card p-3.5">
      <h3 className="mb-2 text-xs font-semibold text-text">{title}</h3>
      {items.length === 0 ? (
        <p className="py-1 text-[11px] text-text-faint">{empty}</p>
      ) : (
        <div className="space-y-1.5">
          {items.map((row, idx) => (
            <div key={`${row.key}-${idx}`} className="space-y-0.5">
              <div className="flex items-center justify-between gap-2 font-mono text-[11px]">
                <span className="min-w-0 truncate text-text">
                  {flag && row.key.length === 2 ? (
                    <span className="mr-1.5">{countryCodeToFlag(row.key)}</span>
                  ) : null}
                  {row.key || 'Unknown'}
                </span>
                <span className="shrink-0 text-text-dim">
                  {bytes ? formatBytes(row.value) : formatCompactNumber(row.value)}
                </span>
              </div>
              <div className="h-1 overflow-hidden rounded-full bg-bg-panel">
                <div
                  className="h-full rounded-full bg-accent/70"
                  style={{ width: `${Math.max(2, (row.value / max) * 100)}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
