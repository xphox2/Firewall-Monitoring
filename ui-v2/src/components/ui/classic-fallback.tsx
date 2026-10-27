import { Info } from 'lucide-react';

export interface ClassicFallbackProps {
  title: string;
  description: string;
  href: string;
  label?: string;
}

/**
 * Inline notice for a V1 capability that the V2 preview does not implement yet.
 * The rewrite is route-complete but not feature-complete, so instead of letting
 * an operator hit a raw-JSON drawer (or discover the gap by accident), each
 * thin surface points at the equivalent classic page.
 */
export function ClassicFallback({
  title,
  description,
  href,
  label = 'Open in classic console',
}: ClassicFallbackProps) {
  return (
    <div className="rounded-lg border border-sig-warn/30 bg-sig-warn/[0.06] px-3.5 py-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-3">
        <Info className="h-4 w-4 shrink-0 text-sig-warn-text" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <div className="text-xs font-semibold text-text">{title}</div>
          <div className="text-[11px] leading-relaxed text-text-dim">{description}</div>
        </div>
        <a
          href={href}
          className="shrink-0 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:bg-bg-hover"
        >
          {label} →
        </a>
      </div>
    </div>
  );
}
