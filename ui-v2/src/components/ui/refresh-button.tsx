import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface RefreshButtonProps {
  /**
   * The query keys to invalidate.
   *
   * Each entry is a key PREFIX, so `['net-events']` invalidates the net
   * event queries whatever else is in the key. A page's polls have several
   * keys (the list, the stats, the analytics), and an operator pressing
   * "refresh" expects all of them to be re-fetched — not just the list.
   */
  queryKeys: string[][];
  label?: string;
  className?: string;
}

/**
 * The manual refresh.
 *
 * The console polls the live pages every ten to thirty seconds, but there
 * was no way to ask for a fresh reading: an operator watching an incident
 * had to wait for the next poll, and a page whose poll had failed looked
 * frozen.
 */
export function RefreshButton({
  queryKeys,
  label = 'Refresh',
  className,
}: RefreshButtonProps) {
  const queryClient = useQueryClient();
  const [pending, setPending] = useState(false);

  const refresh = async () => {
    if (pending) return;
    setPending(true);
    try {
      await Promise.all(
        queryKeys.map((queryKey) => queryClient.invalidateQueries({ queryKey })),
      );
    } finally {
      setPending(false);
    }
  };

  return (
    <button
      type="button"
      onClick={() => void refresh()}
      disabled={pending}
      title={`Re-fetch the ${label.toLowerCase()} now`}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-2.5 py-1.5',
        'text-[11px] font-medium text-text-dim hover:text-text disabled:cursor-not-allowed disabled:opacity-50',
        className,
      )}
    >
      <RefreshCw className={cn('h-3 w-3', pending && 'animate-spin motion-reduce:animate-none')} />
      {pending ? 'Refreshing…' : label}
    </button>
  );
}
