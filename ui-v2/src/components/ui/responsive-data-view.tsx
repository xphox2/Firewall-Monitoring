import React, { useEffect, useRef, useState } from 'react';
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
  type ColumnDef,
  type SortingState,
} from '@tanstack/react-table';
import { ArrowUpDown, ArrowUp, ArrowDown, ChevronRight, ChevronDown, Inbox, TriangleAlert, RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';
import { SkeletonRows } from './skeleton';

export interface ResponsiveDataViewProps<TData> {
  data: TData[];
  columns: ColumnDef<TData, any>[];
  renderMobileCard: (row: TData, index: number) => React.ReactNode;
  renderExpandedRow?: (row: TData) => React.ReactNode;
  onRowClick?: (row: TData) => void;
  /**
   * The accessible name of the mobile card's action.
   *
   * The card's content is caller-provided and may hold its own buttons
   * ("Edit"), so the action cannot be named by the whole card text. The
   * default takes the name from the row's identity - the first field that
   * names the row - and this prop overrides it.
   */
  rowLabel?: (row: TData) => string;
  getRowId?: (row: TData, index: number) => string;
  emptyTitle?: string;
  emptyDescription?: string;
  isLoading?: boolean;
  /**
   * True when the query FAILED. Without this the view cannot tell a failed
   * query from an empty result set, so a backend error rendered the empty
   * state ("No matching records") - which reads as "there is no data" when
   * the truth is "the server could not be reached".
   */
  isError?: boolean;
  /** The failure, for the error message. */
  error?: unknown;
  /** Retry the failed query. Without it the error state has no action. */
  onRetry?: () => void;
  className?: string;
}

/**
 * The name of a row, for the mobile card's action.
 *
 * The card's content is caller-provided and may hold its own buttons, so
 * the action's name is taken from the row's identity instead: the first
 * field that names the row.
 *
 * The field list is the console's own vocabulary - a flow names itself by
 * its addresses, a trap by its type, a syslog row by its host. A row that
 * none of them name returns null, and the caller falls back to the card's
 * own text: "Open row 3" is worse than the description the card already
 * shows.
 */
function defaultRowLabel(row: unknown): string | null {
  const fields = [
    'name',
    'device_name',
    'hostname',
    'host',
    'username',
    'title',
    'label',
    'key',
    'alert_type',
    'trap_type',
    'type',
    'category',
    'severity',
    'site_name',
    'collector_name',
    'address',
    'src_ip',
    'dst_ip',
    'source_ip',
    'src_addr',
    'dst_addr',
    'ip_address',
  ];
  const record = row as Record<string, unknown> | null;
  if (record) {
    for (const field of fields) {
      const value = record[field];
      if (typeof value === 'string' && value.trim()) return value.trim();
      if (typeof value === 'number') return String(value);
    }
  }
  return null;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  if (typeof error === 'string' && error) return error;
  return 'The request could not be completed.';
}

export function ResponsiveDataView<TData>({
  data,
  columns,
  renderMobileCard,
  renderExpandedRow,
  onRowClick,
  rowLabel,
  getRowId,
  emptyTitle = 'No matching records',
  emptyDescription = 'Adjust your filters or time window to see results.',
  isLoading = false,
  isError = false,
  error,
  onRetry,
  className,
}: ResponsiveDataViewProps<TData>) {
  const [sorting, setSorting] = useState<SortingState>([]);
  // The card's own text, for the rows whose fields do not name them.
  //
  // Before the action became a real button, the card's CONTENT was its
  // accessible name, and for the tables with no name-like field (a flow, a
  // trap, a syslog row) that description was the whole point. It is read
  // back here so the name does not regress to "Open row 3".
  const contentRefs = useRef(new Map<string, HTMLDivElement>());
  const [contentLabels, setContentLabels] = useState<Record<string, string>>({});
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});

  // Re-read the cards' text whenever the rows change.
  useEffect(() => {
    const next: Record<string, string> = {};
    contentRefs.current.forEach((el, id) => {
      // textContent, not innerText: the card stack is hidden at the
      // desktop width, and innerText is empty for a hidden element.
      const text = (el.textContent || '').replace(/\s+/g, ' ').trim();
      if (text) next[id] = text;
    });
    setContentLabels((prev) => {
      const keys = Object.keys(next);
      const same =
        keys.length === Object.keys(prev).length && keys.every((k) => prev[k] === next[k]);
      return same ? prev : next;
    });
  }, [data]);

  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getRowId,
  });

  if (isLoading) {
    return (
      <div className="rounded-lg border border-border bg-bg-card p-6">
        <SkeletonRows rows={5} />
      </div>
    );
  }

  // The error state comes BEFORE the empty state: a failed query must never
  // render "no data".
  if (isError) {
    return (
      <div
        className="rounded-lg border border-sig-crit/40 bg-sig-crit/5 p-10 text-center"
        role="alert"
      >
        <TriangleAlert className="mx-auto mb-2.5 h-8 w-8 text-sig-crit-text" />
        <div className="text-sm font-semibold text-text">Could not load this data</div>
        <div className="mx-auto mt-1 max-w-md text-xs text-text-dim">
          {errorMessage(error)}
        </div>
        {onRetry ? (
          <button
            type="button"
            onClick={onRetry}
            className="mt-3 inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text transition-colors hover:text-text"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Retry
          </button>
        ) : null}
      </div>
    );
  }

  if (!data || data.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-bg-card p-10 text-center">
        <Inbox className="mx-auto h-8 w-8 text-text-mute mb-2.5" />
        <div className="text-sm font-semibold text-text">{emptyTitle}</div>
        <div className="text-xs text-text-faint mt-1 max-w-md mx-auto">{emptyDescription}</div>
      </div>
    );
  }

  const rows = table.getRowModel().rows;

  return (
    <div className={cn('w-full min-w-0', className)}>
      {/* Mobile (<768px): Touch-Friendly NOC Card Stack — Zero Horizontal Overflow */}
      <div className="md:hidden space-y-2.5" data-testid="responsive-mobile-cards">
        {rows.map((row, idx) => {
          /*
           * The row's actions.
           *
           * The card and the table had SEPARATE markup, and thirteen tables
           * forgot the actions in the card — so on a phone an operator
           * could not approve a collector, disable a user, reset a
           * password, delete a flow or open a connection. The three-viewport
           * matrix found it: the interaction specs passed at the desktop
           * width and could not find the button at the phone width.
           *
           * The actions column and the selection column are rendered HERE,
           * from the columns themselves, so a table cannot forget them. A
           * table with neither gets neither.
           */
          const carriedCells = row
            .getVisibleCells()
            .filter(
              (cell) => cell.column.id === 'actions' || cell.column.id === 'select',
            );
          return (
          <div
            key={row.id}
            className={cn(
              'relative rounded-lg border border-border bg-bg-card p-3.5 transition-colors',
              onRowClick &&
                'cursor-pointer hover:border-border-strong active:bg-bg-hover',
            )}
          >
            {onRowClick ? (
              // The card's action is a REAL button, stretched over the card
              // and placed UNDER the content.
              //
              // The card used to carry role="button" itself, which made it a
              // control that CONTAINED the row's own buttons - a control
              // inside a control. A screen reader announces the card as a
              // button and the buttons inside it are inside another button;
              // axe's nested-interactive rule catches it, and it is a real
              // defect rather than a rule artefact.
              //
              // A sibling button cannot nest inside anything, so the
              // stretched button is a SIBLING of the content. The content
              // is pointer-events-none so a press lands on the button, and
              // the content's own controls are re-enabled so they still
              // work.
              <button
                type="button"
                onClick={() => onRowClick(row.original)}
                aria-label={
                  rowLabel
                    ? rowLabel(row.original)
                    : `Open ${
                        defaultRowLabel(row.original) ??
                        contentLabels[String(row.id)] ??
                        `row ${row.id}`
                      }`
                }
                className="absolute inset-0 z-0 h-full w-full cursor-pointer rounded-lg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
              />
            ) : null}
            <div
              ref={(el) => {
                if (el) contentRefs.current.set(String(row.id), el);
                else contentRefs.current.delete(String(row.id));
              }}
              className={cn(
                'relative z-10',
                // The press belongs to the stretched button, not to the
                // card's own text. The content's controls are put back.
                onRowClick &&
                  'pointer-events-none [&_a]:pointer-events-auto [&_button]:pointer-events-auto [&_input]:pointer-events-auto [&_select]:pointer-events-auto [&_textarea]:pointer-events-auto',
              )}
            >
              {renderMobileCard(row.original, idx)}
            </div>
            {carriedCells.length > 0 ? (
              <div className="relative z-20 mt-2 flex items-center justify-end gap-2">
                {carriedCells.map((cell) =>
                  flexRender(cell.column.columnDef.cell, cell.getContext()),
                )}
              </div>
            ) : null}
          </div>
          );
        })}
      </div>

      {/* Tablet & Desktop (>=768px): High-Density Tabular-Nums Data Grid */}
      <div
        className="hidden md:block rounded-lg border border-border bg-bg-card overflow-hidden"
        data-testid="responsive-desktop-table"
      >
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              {table.getHeaderGroups().map((headerGroup) => (
                <tr
                  key={headerGroup.id}
                  className="border-b border-border bg-bg-panel text-[11px] font-semibold uppercase tracking-wider text-text-faint"
                >
                  {renderExpandedRow && <th className="w-8 px-2 py-2.5" aria-label="Expand row" />}
                  {headerGroup.headers.map((header) => {
                    const canSort = header.column.getCanSort();
                    const sorted = header.column.getIsSorted();
                    const hideOnTablet = (header.column.columnDef.meta as { hideOnTablet?: boolean } | undefined)
                      ?.hideOnTablet;
                    // A column can also say where it STARTS: a column the
                    // legacy table hid below `lg` must not vanish below
                    // `xl` just because the shared view only had one
                    // breakpoint.
                    const hideUntil = (
                      header.column.columnDef.meta as
                        | { hideUntil?: 'sm' | 'md' | 'lg' | 'xl' }
                        | undefined
                    )?.hideUntil;
                    return (
                      <th
                        key={header.id}
                        scope="col"
                        // The sort state belongs on the header cell, so a
                        // screen reader announces it.
                        //
                        // A SORTABLE column that is not the sorted one
                        // carries "none", not nothing: the ARIA spec asks
                        // for aria-sort on every sortable header, so an
                        // operator can hear that the column can be sorted
                        // at all.
                        aria-sort={
                          !canSort
                            ? undefined
                            : sorted === 'asc'
                              ? 'ascending'
                              : sorted === 'desc'
                                ? 'descending'
                                : 'none'
                        }
                        className={cn(
                          'px-3.5 py-2.5 select-none whitespace-nowrap',
                          canSort && 'hover:text-text',
                          (hideOnTablet || hideUntil) &&
                            `hidden ${hideUntil ?? 'xl'}:table-cell`,
                        )}
                      >
                        <div className="inline-flex items-center gap-1">
                          {canSort ? (
                            // The sort is a real BUTTON: the <th> used to
                            // carry the click handler, which made it
                            // mouse-only and gave it no accessible name.
                            <button
                              type="button"
                              onClick={header.column.getToggleSortingHandler()}
                              className="inline-flex items-center gap-1 rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
                            >
                              {header.isPlaceholder
                                ? null
                                : flexRender(header.column.columnDef.header, header.getContext())}
                              <span className="text-text-mute">
                                {sorted === 'asc' ? (
                                  <ArrowUp className="h-3 w-3 text-accent" />
                                ) : sorted === 'desc' ? (
                                  <ArrowDown className="h-3 w-3 text-accent" />
                                ) : (
                                  <ArrowUpDown className="h-3 w-3 opacity-50" />
                                )}
                              </span>
                            </button>
                          ) : (
                            <>
                              {header.isPlaceholder
                                ? null
                                : flexRender(header.column.columnDef.header, header.getContext())}
                            </>
                          )}
                        </div>
                      </th>
                    );
                  })}
                </tr>
              ))}
            </thead>
            <tbody className="divide-y divide-border/70">
              {rows.map((row) => {
                const isExpanded = !!expandedRows[row.id];
                return (
                  <React.Fragment key={row.id}>
                    <tr
                      onClick={onRowClick ? () => onRowClick(row.original) : undefined}
                      // The row is operable from the keyboard when it is
                      // clickable. It keeps its ROW semantics - a `tr` with
                      // role="button" has no computed accessible name,
                      // because its content is spread across the cells.
                      tabIndex={onRowClick ? 0 : undefined}
                      onKeyDown={
                        onRowClick
                          ? (event) => {
                              if (event.key === 'Enter' || event.key === ' ') {
                                event.preventDefault();
                                onRowClick(row.original);
                              }
                            }
                          : undefined
                      }
                      className={cn(
                        'transition-colors hover:bg-bg-hover',
                        onRowClick &&
                          'cursor-pointer focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent',
                      )}
                    >
                      {renderExpandedRow && (
                        <td
                          className="w-8 px-2 py-2.5 text-center"
                          onClick={(e) => {
                            e.stopPropagation();
                            setExpandedRows((prev) => ({ ...prev, [row.id]: !prev[row.id] }));
                          }}
                        >
                          <button
                            type="button"
                            aria-label={isExpanded ? 'Collapse row details' : 'Expand row details'}
                            aria-expanded={isExpanded}
                            className="p-1 rounded hover:bg-bg-panel text-text-faint hover:text-text"
                          >
                            {isExpanded ? (
                              <ChevronDown className="h-3.5 w-3.5" />
                            ) : (
                              <ChevronRight className="h-3.5 w-3.5" />
                            )}
                          </button>
                        </td>
                      )}
                      {row.getVisibleCells().map((cell) => {
                        const hideOnTablet = (
                          cell.column.columnDef.meta as { hideOnTablet?: boolean } | undefined
                        )?.hideOnTablet;
                        return (
                          <td
                            key={cell.id}
                            className={cn(
                              'px-3.5 py-2.5 align-middle text-text tabular-nums',
                              hideOnTablet && 'hidden xl:table-cell',
                            )}
                          >
                            {flexRender(cell.column.columnDef.cell, cell.getContext())}
                          </td>
                        );
                      })}
                    </tr>
                    {renderExpandedRow && isExpanded && (
                      <tr className="bg-bg-panel/40">
                        <td colSpan={row.getVisibleCells().length + 1} className="px-4 py-3">
                          {renderExpandedRow(row.original)}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
