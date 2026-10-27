import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  Info,
  Search,
  ShieldAlert,
} from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatDateTime } from '@/lib/utils';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import {
  DIFF_SEVERITIES,
  attributionLabel,
  diffVerdict,
  filterLineRows,
  filterObjectChanges,
  filterSplitPairs,
  pairSplitRows,
  type ConfigDiffData,
  type DiffSeverity,
  type RevisionMeta,
} from '@/lib/config-diff';

const ROW_PAGE = 1500;

const OP_STYLE: Record<string, string> = {
  added: 'bg-sig-ok/15 text-sig-ok',
  removed: 'bg-sig-crit/15 text-sig-crit',
  modified: 'bg-sig-warn/15 text-sig-warn',
};

const SEV_STYLE: Record<string, string> = {
  critical: 'bg-sig-crit/15 text-sig-crit border-sig-crit/40',
  high: 'bg-sig-warn/15 text-sig-warn border-sig-warn/40',
  medium: 'bg-accent/15 text-accent-text border-accent/40',
  info: 'bg-bg-panel text-text-dim border-border',
};

const LINE_STYLE: Record<string, string> = {
  insert: 'bg-sig-ok/10 text-sig-ok',
  delete: 'bg-sig-crit/10 text-sig-crit',
  volatile: 'bg-accent/5 text-text-faint italic',
  equal: 'text-text-dim',
};

const LINE_PREFIX: Record<string, string> = {
  insert: '+',
  delete: '-',
  volatile: '~',
  equal: ' ',
};

export interface ConfigDiffDrawerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  deviceId: number;
  from: RevisionMeta | null;
  to: RevisionMeta | null;
}

export function ConfigDiffDrawer({
  open,
  onOpenChange,
  deviceId,
  from,
  to,
}: ConfigDiffDrawerProps) {
  const [tab, setTab] = useState<'objects' | 'lines'>('objects');
  const [query, setQuery] = useState('');
  const [severities, setSeverities] = useState<Set<DiffSeverity> | null>(null);
  const [hideEqual, setHideEqual] = useState(true);
  const [lineView, setLineView] = useState<'unified' | 'split'>('unified');
  const [visibleRows, setVisibleRows] = useState(ROW_PAGE);

  const enabled = open && !!from && !!to && from.id !== to.id;

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['config-diff', deviceId, from?.id, to?.id],
    queryFn: () =>
      apiFetch<ConfigDiffData>(
        `/admin/api/devices/${deviceId}/config-history/diff?from=${from?.id}&to=${to?.id}`,
      ),
    enabled,
    retry: false,
  });

  const changes = data?.object_changes ?? [];
  const rows = data?.line_diff.rows ?? [];
  const filteredChanges = useMemo(
    () => filterObjectChanges(changes, query, severities),
    [changes, query, severities],
  );
  const filteredRows = useMemo(
    () => filterLineRows(rows, query, hideEqual),
    [rows, query, hideEqual],
  );
  const pairedRows = useMemo(() => pairSplitRows(rows), [rows]);
  const splitPairs = useMemo(
    () => filterSplitPairs(pairedRows, query, hideEqual),
    [pairedRows, query, hideEqual],
  );
  const lineCount = lineView === 'split' ? splitPairs.length : filteredRows.length;
  const verdict = data ? diffVerdict(data) : null;

  const toggleSeverity = (severity: DiffSeverity) => {
    setSeverities((current) => {
      const next = new Set(current ?? DIFF_SEVERITIES);
      if (next.has(severity)) next.delete(severity);
      else next.add(severity);
      // Empty selection means "all" (the buttons are filters, not a whitelist),
      // so the operator can never land in an unrecoverable empty state.
      return next.size === DIFF_SEVERITIES.length || next.size === 0 ? null : next;
    });
  };

  const sameRevision = !!from && !!to && from.id === to.id;

  return (
    <SlideOverDrawer
      open={open}
      onOpenChange={onOpenChange}
      title={
        from && to ? `Config diff: revision #${from.id} → #${to.id}` : 'Config diff'
      }
      subtitle={
        from && to
          ? `${formatDateTime(from.timestamp)} → ${formatDateTime(to.timestamp)}`
          : 'Pick two revisions to compare.'
      }
      size="2xl"
      tabs={[
        { id: 'objects', label: 'Objects', badge: changes.length || undefined },
        {
          id: 'lines',
          label: 'Line diff',
          badge: data ? data.line_diff.added + data.line_diff.removed : undefined,
        },
      ]}
      activeTab={tab}
      onTabChange={(id) => setTab(id as 'objects' | 'lines')}
      footer={
        <div className="flex w-full items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            {from && (
              <a
                href={`/admin/api/devices/${deviceId}/config-history/${from.id}`}
                className="inline-flex items-center gap-1 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text-dim hover:text-text"
              >
                <Download className="h-3.5 w-3.5" />
                From #{from.id}
              </a>
            )}
            {to && (
              <a
                href={`/admin/api/devices/${deviceId}/config-history/${to.id}`}
                className="inline-flex items-center gap-1 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text-dim hover:text-text"
              >
                <Download className="h-3.5 w-3.5" />
                To #{to.id}
              </a>
            )}
          </div>
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            className="rounded-md bg-accent px-4 py-1.5 text-xs font-semibold text-on-accent hover:opacity-90"
          >
            Close
          </button>
        </div>
      }
    >
      {sameRevision ? (
        <div className="rounded-lg border border-border bg-bg-panel p-4 text-xs text-text-dim">
          From and To are the same revision — pick two different revisions to compare.
        </div>
      ) : (from?.normalized_checksum && to?.normalized_checksum &&
          from.normalized_checksum === to.normalized_checksum) ? (
        <div className="mb-4 rounded-lg border border-sig-ok/40 bg-sig-ok/10 px-3.5 py-2.5 text-xs text-sig-ok">
          Both revisions share the same normalized hash: no real configuration change between them.
        </div>
      ) : null}

      {isLoading && (
        <div className="p-6 text-center text-xs text-text-dim">Computing diff…</div>
      )}

      {!isLoading && error && (
        <div className="space-y-3 p-4">
          <div className="flex items-start gap-2 rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3.5 py-2.5 text-xs text-sig-crit">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error instanceof Error ? error.message : 'Could not compute the diff.'}</span>
          </div>
          <button
            type="button"
            onClick={() => refetch()}
            className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text"
          >
            Retry
          </button>
        </div>
      )}

      {!isLoading && !error && data && (
        <div className="space-y-4">
          {/* Verdict + attribution */}
          {verdict && (
            <div
              className={cn(
                'rounded-lg border px-3.5 py-3',
                verdict.tone === 'ok' && 'border-sig-ok/40 bg-sig-ok/10',
                verdict.tone === 'info' && 'border-border bg-bg-panel/40',
                verdict.tone === 'warn' && 'border-sig-warn/40 bg-sig-warn/10',
                verdict.tone === 'crit' && 'border-sig-crit/40 bg-sig-crit/10',
              )}
            >
              <div className="flex items-center gap-2">
                {verdict.tone === 'ok' ? (
                  <CheckCircle2 className="h-4 w-4 text-sig-ok" />
                ) : verdict.tone === 'crit' ? (
                  <ShieldAlert className="h-4 w-4 text-sig-crit" />
                ) : verdict.tone === 'warn' ? (
                  <AlertTriangle className="h-4 w-4 text-sig-warn" />
                ) : (
                  <Info className="h-4 w-4 text-text-dim" />
                )}
                <span className="text-sm font-semibold text-text">{verdict.label}</span>
              </div>
              <p className="mt-1 text-xs text-text-dim">{verdict.detail}</p>
              <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-text-faint">
                <span>Vendor: {data.vendor || 'unknown'}</span>
                <span>From: {attributionLabel(data.from)}</span>
                <span>To: {attributionLabel(data.to)}</span>
                {data.from.trigger_source && <span>Trigger: {data.from.trigger_source}</span>}
                {data.from.backup_quality && <span>Quality: {data.from.backup_quality}</span>}
              </div>
            </div>
          )}

          {/* Toolbar */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative min-w-[220px] flex-1">
              <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-faint" />
              <input
                type="search"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setVisibleRows(ROW_PAGE);
                }}
                placeholder={
                  tab === 'objects' ? 'Filter objects or attributes…' : 'Filter diff lines…'
                }
                className="w-full rounded border border-border bg-bg-panel py-1.5 pl-8 pr-3 font-mono text-xs text-text focus:border-accent focus:outline-hidden"
              />
            </div>
            {tab === 'objects' ? (
              <div className="flex items-center gap-1">
                {DIFF_SEVERITIES.map((severity) => {
                  const active = !severities || severities.has(severity);
                  return (
                    <button
                      key={severity}
                      type="button"
                      onClick={() => toggleSeverity(severity)}
                      className={cn(
                        'rounded border px-2 py-1 text-[10px] font-semibold uppercase',
                        active ? SEV_STYLE[severity] : 'border-border bg-bg-panel text-text-faint',
                      )}
                    >
                      {severity}
                    </button>
                  );
                })}
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-0.5 rounded border border-border bg-bg-panel p-0.5">
                  {(['unified', 'split'] as const).map((mode) => (
                    <button
                      key={mode}
                      type="button"
                      aria-pressed={lineView === mode}
                      onClick={() => setLineView(mode)}
                      className={cn(
                        'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
                        lineView === mode ? 'bg-bg-card text-text shadow-xs' : 'text-text-dim',
                      )}
                    >
                      {mode}
                    </button>
                  ))}
                </div>
                <label className="inline-flex items-center gap-1.5 text-[11px] text-text-dim">
                  <input
                    type="checkbox"
                    checked={hideEqual}
                    onChange={(e) => setHideEqual(e.target.checked)}
                  />
                  Hide unchanged
                </label>
              </div>
            )}
          </div>

          {data.line_diff.note && (
            <div className="rounded-lg border border-sig-warn/40 bg-sig-warn/10 px-3 py-2 text-[11px] text-sig-warn">
              {data.line_diff.note}
            </div>
          )}

          {tab === 'objects' && (
            <div className="space-y-2">
              {filteredChanges.length === 0 ? (
                <p className="p-4 text-center text-xs text-text-faint">
                  {changes.length === 0
                    ? 'No object-level changes. Use the line diff for raw differences.'
                    : 'No objects match the current filter.'}
                </p>
              ) : (
                filteredChanges.map((change, idx) => (
                  <details
                    key={`${change.path}-${change.op}-${idx}`}
                    className="rounded-lg border border-border bg-bg-panel/40"
                  >
                    <summary className="flex cursor-pointer flex-wrap items-center gap-2 px-3 py-2 text-xs">
                      <span
                        className={cn(
                          'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
                          OP_STYLE[change.op] ?? 'bg-bg-panel text-text-dim',
                        )}
                      >
                        {change.op}
                      </span>
                      <span
                        className={cn(
                          'rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase',
                          SEV_STYLE[(change.risk?.severity as string) ?? 'info'] ?? SEV_STYLE['info'],
                        )}
                      >
                        {change.risk?.severity ?? 'info'}
                      </span>
                      <span className="font-mono text-text">{change.name || change.path}</span>
                      <span className="text-[11px] text-text-faint">{change.kind}</span>
                      {change.risk?.summary && (
                        <span className="w-full text-[11px] text-text-dim sm:w-auto sm:flex-1 sm:text-right">
                          {change.risk.summary}
                        </span>
                      )}
                    </summary>
                    <div className="border-t border-border px-3 py-2">
                      <div className="font-mono text-[11px] text-text-faint">{change.path}</div>
                      {(change.attrs ?? []).length === 0 ? (
                        <p className="mt-1 text-[11px] text-text-dim">
                          {change.op === 'added' ? 'Object added.' : 'Object removed.'}
                        </p>
                      ) : (
                        <table className="mt-2 w-full text-left text-[11px]">
                          <thead className="text-text-faint">
                            <tr>
                              <th className="py-1 pr-3 font-medium">Attribute</th>
                              <th className="py-1 pr-3 font-medium">Old</th>
                              <th className="py-1 font-medium">New</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border/60">
                            {(change.attrs ?? []).map((attr) => (
                              <tr key={attr.key}>
                                <td className="py-1 pr-3 font-mono text-text">{attr.key}</td>
                                <td className="py-1 pr-3 font-mono text-sig-crit">
                                  {attr.old || '—'}
                                </td>
                                <td className="py-1 font-mono text-sig-ok">{attr.new || '—'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </div>
                  </details>
                ))
              )}
            </div>
          )}

          {tab === 'lines' && (
            <div className="overflow-hidden rounded-lg border border-border bg-bg-panel">
              {lineCount === 0 ? (
                <p className="p-4 text-center text-xs text-text-faint">
                  {rows.length === 0 ? 'No line-level differences.' : 'No lines match the filter.'}
                </p>
              ) : (
                <>
                  {lineView === 'unified' ? (
                    <div className="max-h-[60vh] overflow-auto">
                      {filteredRows.slice(0, visibleRows).map((row, idx) => (
                        <div
                          key={idx}
                          className={cn(
                            'flex items-start gap-2 whitespace-pre-wrap break-all px-2 py-0.5 font-mono text-[11px]',
                            LINE_STYLE[row.op] ?? LINE_STYLE['equal'],
                          )}
                        >
                          <span className="w-10 shrink-0 select-none text-right text-text-faint">
                            {row.a || ''}
                          </span>
                          <span className="w-10 shrink-0 select-none text-right text-text-faint">
                            {row.b || ''}
                          </span>
                          <span className="w-3 shrink-0 select-none">
                            {LINE_PREFIX[row.op] ?? ' '}
                          </span>
                          <span className="min-w-0 flex-1">{row.text}</span>
                          {row.vname && (
                            <span className="shrink-0 rounded bg-accent/10 px-1 text-[9px] uppercase text-accent-text">
                              {row.vname}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="max-h-[60vh] overflow-auto font-mono text-[11px]">
                      {splitPairs.slice(0, visibleRows).map((pair, idx) => {
                        const volatile = pair.right?.op === 'volatile';
                        return (
                          <div key={idx} className="grid grid-cols-2 border-b border-border/40">
                            <div
                              className={cn(
                                'flex items-start gap-2 whitespace-pre-wrap break-all px-2 py-0.5',
                                pair.left?.op === 'delete'
                                  ? LINE_STYLE['delete']
                                  : volatile
                                    ? LINE_STYLE['volatile']
                                    : 'text-text-dim',
                              )}
                            >
                              <span className="w-8 shrink-0 select-none text-right text-text-faint">
                                {pair.left?.line || ''}
                              </span>
                              <span className="min-w-0 flex-1">{pair.left?.text ?? ''}</span>
                            </div>
                            <div
                              className={cn(
                                'flex items-start gap-2 whitespace-pre-wrap break-all border-l border-border/40 px-2 py-0.5',
                                pair.right?.op === 'insert'
                                  ? LINE_STYLE['insert']
                                  : volatile
                                    ? LINE_STYLE['volatile']
                                    : 'text-text-dim',
                              )}
                            >
                              <span className="w-8 shrink-0 select-none text-right text-text-faint">
                                {pair.right?.line || ''}
                              </span>
                              <span className="min-w-0 flex-1">{pair.right?.text ?? ''}</span>
                              {pair.vname && (
                                <span className="shrink-0 rounded bg-accent/10 px-1 text-[9px] uppercase text-accent-text">
                                  {pair.vname}
                                </span>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                  {lineCount > visibleRows && (
                    <button
                      type="button"
                      onClick={() => setVisibleRows((n) => n + ROW_PAGE)}
                      className="w-full border-t border-border bg-bg-card px-3 py-2 text-xs font-medium text-accent hover:bg-bg-hover"
                    >
                      Show {Math.min(ROW_PAGE, lineCount - visibleRows)} more rows (
                      {lineCount - visibleRows} hidden)
                    </button>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      )}
    </SlideOverDrawer>
  );
}
