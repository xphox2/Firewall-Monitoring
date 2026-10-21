import { Copy, ShieldAlert, ShieldCheck } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/components/ui/toast';

export interface IpsecPreviewEnd {
  end?: number;
  vendor?: string;
  preview?: string;
  auto_objects?: string[];
  steps?: number;
}

export interface IpsecFinding {
  severity?: string;
  code?: string;
  message?: string;
  end?: number;
  subject?: string;
}

export interface IpsecPreview {
  ends?: IpsecPreviewEnd[];
  validation?: IpsecFinding[];
  error?: string;
}

function findingTone(severity?: string): string {
  const value = String(severity ?? '').toLowerCase();
  if (/block|error|critical|deny/.test(value)) return 'bg-sig-crit/15 text-sig-crit';
  if (/warn/.test(value)) return 'bg-sig-warn/15 text-sig-warn';
  return 'bg-accent/15 text-accent';
}

export function IpsecPreviewPanel({ preview }: { preview: IpsecPreview | null | undefined }) {
  const { toast } = useToast();
  if (!preview) {
    return <p className="p-6 text-center text-xs text-text-dim">Loading preview…</p>;
  }
  if (preview.error) {
    return (
      <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit">
        {preview.error}
      </div>
    );
  }

  const findings = preview.validation ?? [];
  const ends = preview.ends ?? [];

  const copy = (text: string) => {
    if (!navigator.clipboard) {
      toast({ title: 'Copy unavailable', description: 'Needs a secure context.', variant: 'error' });
      return;
    }
    void navigator.clipboard
      .writeText(text)
      .then(() => toast({ title: 'Config copied', variant: 'success' }))
      .catch(() => toast({ title: 'Copy failed', variant: 'error' }));
  };

  return (
    <div className="space-y-4">
      <section className="space-y-1.5">
        <h3 className="flex items-center gap-1.5 text-xs font-semibold text-text">
          {findings.length === 0 ? (
            <ShieldCheck className="h-3.5 w-3.5 text-sig-ok" />
          ) : (
            <ShieldAlert className="h-3.5 w-3.5 text-sig-warn" />
          )}
          Validation ({findings.length})
        </h3>
        {findings.length === 0 ? (
          <p className="text-[11px] text-sig-ok">No validation findings — the preview is deployable.</p>
        ) : (
          <div className="space-y-1">
            {findings.map((finding, idx) => (
              <div
                key={`${finding.code}-${idx}`}
                className="rounded-lg border border-border bg-bg-panel px-2.5 py-2"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={cn(
                      'rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
                      findingTone(finding.severity),
                    )}
                  >
                    {finding.severity || 'note'}
                  </span>
                  {finding.code && (
                    <span className="font-mono text-[10px] text-text-faint">{finding.code}</span>
                  )}
                  {finding.end != null && (
                    <span className="font-mono text-[10px] text-text-dim">end {finding.end}</span>
                  )}
                  {finding.subject && (
                    <span className="font-mono text-[10px] text-text-faint">{finding.subject}</span>
                  )}
                </div>
                <p className="mt-0.5 text-[11px] text-text-dim">{finding.message}</p>
              </div>
            ))}
          </div>
        )}
      </section>

      {ends.length === 0 ? (
        <p className="text-[11px] text-text-faint">
          No rendered configuration — resolve the blocking findings above.
        </p>
      ) : (
        ends.map((end, idx) => (
          <section
            key={`${end.end}-${end.vendor}-${idx}`}
            className="rounded-lg border border-border bg-bg-panel"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2">
              <div className="flex flex-wrap items-center gap-2 text-[11px]">
                <span className="font-semibold text-text">End {end.end ?? idx + 1}</span>
                <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-accent">
                  {end.vendor || 'vendor'}
                </span>
                {end.steps != null && (
                  <span className="font-mono text-[10px] text-text-faint">{end.steps} step(s)</span>
                )}
              </div>
              <button
                type="button"
                onClick={() => copy(end.preview ?? '')}
                className="inline-flex items-center gap-1 rounded border border-border bg-bg-card px-2 py-1 text-[10px] font-medium text-text-dim hover:text-text"
              >
                <Copy className="h-3 w-3" />
                Copy
              </button>
            </div>
            {(end.auto_objects ?? []).length > 0 && (
              <div className="flex flex-wrap gap-1 px-3 pt-2">
                {(end.auto_objects ?? []).map((object) => (
                  <span
                    key={object}
                    className="rounded bg-bg-card px-1.5 py-0.5 font-mono text-[9px] text-text-faint"
                  >
                    {object}
                  </span>
                ))}
              </div>
            )}
            <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all p-3 font-mono text-[10px] text-text">
              {end.preview || '(empty preview)'}
            </pre>
          </section>
        ))
      )}

      <details className="rounded-lg border border-border bg-bg-card p-3">
        <summary className="cursor-pointer text-xs font-semibold text-text">Raw preview JSON</summary>
        <pre className="mt-2 max-h-64 overflow-auto rounded border border-border bg-bg-panel p-2 font-mono text-[10px] text-text-dim">
          {JSON.stringify(preview, null, 2)}
        </pre>
      </details>
    </div>
  );
}
