import { ChevronLeft, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface EventPagerProps {
  page: number;
  /** The server's total. Undefined when the endpoint does not report one. */
  total?: number;
  pageSize: number;
  onChange: (page: number) => void;
  /**
   * True when the server says the total was CAPPED.
   *
   * The count is only computed up to a limit, so a capped total is a LOWER
   * BOUND: the real number of matching rows may be larger. Saying "of 100"
   * when it is "of at least 100" would be a lie.
   */
  capped?: boolean;
}

/**
 * The pager for the event streams.
 *
 * The net and security event endpoints report a `total` inside their
 * payload, so the page count is exact — unless the count was capped, in
 * which case it is a lower bound and the pager says so.
 */
export function EventPager({
  page,
  total,
  pageSize,
  onChange,
  capped = false,
}: EventPagerProps) {
  const hasTotal = typeof total === 'number' && total > 0;
  const pageCount = hasTotal ? Math.max(1, Math.ceil((total as number) / pageSize)) : 0;
  const lastPage = pageCount > 0 ? pageCount - 1 : 0;
  const canPrev = page > 0;
  const canNext = hasTotal ? page < lastPage : true;

  if (!hasTotal && page === 0) return null;

  return (
    <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-text-dim">
      <span>
        {hasTotal ? (
          <>
            {page * pageSize + 1}
            {'–'}
            {Math.min((page + 1) * pageSize, total as number)}
            {' of '}
            {capped ? 'at least ' : ''}
            {(total as number).toLocaleString()}
          </>
        ) : (
          <>Showing page {page + 1}</>
        )}
      </span>
      <div className="flex items-center gap-1.5">
        <button
          type="button"
          onClick={() => onChange(Math.max(0, page - 1))}
          disabled={!canPrev}
          aria-label="Previous page"
          className="inline-flex items-center gap-1 rounded-md border border-border bg-bg-panel px-2 py-1 text-[11px] text-text-dim hover:text-text disabled:cursor-not-allowed disabled:opacity-40"
        >
          <ChevronLeft className="h-3 w-3" />
          Previous
        </button>
        <span className="font-mono">
          {pageCount > 0 ? `${page + 1} / ${pageCount}` : page + 1}
        </span>
        <button
          type="button"
          onClick={() => onChange(page + 1)}
          disabled={!canNext}
          aria-label="Next page"
          className={cn(
            'inline-flex items-center gap-1 rounded-md border border-border bg-bg-panel px-2 py-1 text-[11px] text-text-dim hover:text-text',
            'disabled:cursor-not-allowed disabled:opacity-40',
          )}
        >
          Next
          <ChevronRight className="h-3 w-3" />
        </button>
      </div>
    </div>
  );
}
