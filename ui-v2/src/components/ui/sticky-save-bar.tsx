import { useEffect } from 'react';
import { RotateCcw, Save, Loader2, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface StickySaveBarProps {
  isDirty: boolean;
  dirtyCount?: number;
  isSaving?: boolean;
  onSave: () => void;
  onDiscard: () => void;
  saveLabel?: string;
  summaryText?: string;
  className?: string;
}

export function StickySaveBar({
  isDirty,
  dirtyCount,
  isSaving = false,
  onSave,
  onDiscard,
  saveLabel = 'Save Changes',
  summaryText,
  className,
}: StickySaveBarProps) {
  useEffect(() => {
    if (!isDirty) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
        e.preventDefault();
        if (!isSaving) {
          onSave();
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isDirty, isSaving, onSave]);

  if (!isDirty) return null;

  const label =
    summaryText ||
    (dirtyCount && dirtyCount > 0
      ? `Unsaved changes (${dirtyCount} ${dirtyCount === 1 ? 'field' : 'fields'} modified)`
      : 'Unsaved configuration changes');

  return (
    <div
      role="region"
      aria-label="Unsaved changes action bar"
      data-testid="sticky-save-bar"
      className={cn(
        'fixed bottom-16 lg:bottom-4 left-3 right-3 lg:left-72 lg:right-6 z-40 mx-auto max-w-5xl',
        'rounded-lg border border-accent/40 bg-bg-card/95 backdrop-blur-md px-4 py-3 shadow-2xl',
        'flex flex-wrap items-center justify-between gap-3 transition-all',
        className,
      )}
    >
      <div className="flex items-center gap-2.5 min-w-0">
        <span className="flex h-2.5 w-2.5 relative shrink-0">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sig-warn opacity-75" />
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-sig-warn" />
        </span>
        <AlertCircle className="h-4 w-4 text-sig-warn shrink-0 hidden sm:block" />
        <span className="text-xs sm:text-sm font-medium text-text truncate">{label}</span>
      </div>

      <div className="flex items-center gap-2 shrink-0 ml-auto">
        <button
          type="button"
          onClick={onDiscard}
          disabled={isSaving}
          data-testid="sticky-discard-btn"
          className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text-dim hover:bg-bg-hover hover:text-text disabled:opacity-50 transition-colors"
        >
          <RotateCcw className="h-3.5 w-3.5" />
          Discard
        </button>
        <button
          type="button"
          onClick={onSave}
          disabled={isSaving}
          data-testid="sticky-save-btn"
          className="inline-flex items-center gap-1.5 rounded-md bg-accent px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-accent-hover disabled:opacity-60 transition-colors shadow-xs"
        >
          {isSaving ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Save className="h-3.5 w-3.5" />
          )}
          <span>{saveLabel}</span>
          <kbd className="hidden sm:inline-block ml-1 rounded bg-black/25 px-1.5 py-0.5 font-mono text-[10px] text-white/90">
            ⌘S
          </kbd>
        </button>
      </div>
    </div>
  );
}
