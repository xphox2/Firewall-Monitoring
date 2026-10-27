import { cn } from '@/lib/utils';

export interface RuleTestResult {
  scanned?: number;
  matched?: number;
  rate?: number;
  samples?: string[];
  vendor?: string;
  note?: string;
}

function Kpi({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-border bg-bg-panel p-2.5">
      <div className="text-[10px] uppercase text-text-faint">{label}</div>
      <div className={cn('mt-0.5 font-mono text-sm font-bold', tone ?? 'text-text')}>{value}</div>
    </div>
  );
}

export function RuleTestResultPanel({ result }: { result: RuleTestResult | null | undefined }) {
  if (!result) {
    return (
      <p className="text-[11px] text-text-faint">
        Run the test to scan recent syslog against this match expression.
      </p>
    );
  }
  const scanned = result.scanned ?? 0;
  const matched = result.matched ?? 0;
  const rate = result.rate != null ? result.rate * 100 : scanned > 0 ? (matched / scanned) * 100 : 0;

  return (
    <div className="space-y-2">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        <Kpi
          label="Matched"
          value={String(matched)}
          tone={matched > 0 ? 'text-sig-ok-text' : 'text-text'}
        />
        <Kpi label="Match rate" value={`${rate.toFixed(1)}%`} />
        <Kpi label="Scanned" value={String(scanned)} />
        <Kpi label="Vendor scope" value={result.vendor || 'per-device'} />
      </div>

      {(result.samples ?? []).length > 0 ? (
        <div>
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-text-faint">
            Matching samples ({(result.samples ?? []).length})
          </div>
          <div className="max-h-52 space-y-1 overflow-auto rounded-lg border border-border bg-bg-panel p-2">
            {(result.samples ?? []).map((sample, idx) => (
              <div
                key={idx}
                className="whitespace-pre-wrap break-all font-mono text-[10px] text-text-dim"
              >
                {sample}
              </div>
            ))}
          </div>
        </div>
      ) : (
        <p className="text-[11px] text-text-faint">
          No recent message matched this expression.
        </p>
      )}

      {result.note && <p className="text-[10px] text-text-faint">{result.note}</p>}

      <details className="rounded-lg border border-border bg-bg-card p-2.5">
        <summary className="cursor-pointer text-[11px] font-semibold text-text">Raw result</summary>
        <pre className="mt-1.5 max-h-48 overflow-auto rounded border border-border bg-bg-panel p-2 font-mono text-[10px] text-text-dim">
          {JSON.stringify(result, null, 2)}
        </pre>
      </details>
    </div>
  );
}
