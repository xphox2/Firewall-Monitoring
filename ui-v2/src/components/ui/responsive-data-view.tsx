import React, { useState } from 'react';
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
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});

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
        <TriangleAlert className="mx-auto mb-2.5 h-8 w-8 text-sig-crit" />
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
            onClick={onRowClick ? () => onRowClick(row.original) : undefined}
            // A clickable card is a control, so it has to be one: role,
            // focusability and the Enter/Space keys. Without them the card
            // was mouse-only.
            role={onRowClick ? 'button' : undefined}
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
              'rounded-lg border border-border bg-bg-card p-3.5 transition-colors',
              onRowClick &&
                'cursor-pointer hover:border-border-strong active:bg-bg-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent',
            )}
          >
            {renderMobileCard(row.original, idx)}
            {carriedCells.length > 0 ? (
              <div
                className="mt-2 flex items-center justify-end gap-2"
                // The card is a button, so a press on an action must not
                // also trigger the card.
                onClick={(event) => event.stopPropagation()}
              >
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
                          hideOnTablet && 'hidden xl:table-cell',
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
