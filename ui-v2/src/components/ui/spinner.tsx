import { cn } from '@/lib/utils';

export interface SpinnerProps {
  /** Ring size. V1's `.fwmon-spinner` was 14px. */
  size?: 'xs' | 'sm' | 'md';
  className?: string;
  /**
   * Accessible label. Supply it when the spinner is the ONLY indication that
   * something is happening; omit it when there is adjacent text (a toast, a
   * button label) and the spinner is purely decorative.
   */
  label?: string;
}

const SIZES: Record<NonNullable<SpinnerProps['size']>, string> = {
  xs: 'h-3 w-3 border',
  sm: 'h-3.5 w-3.5 border-2',
  md: 'h-5 w-5 border-2',
};

/**
 * The rotating ring.
 *
 * Ports V1's `.fwmon-spinner` (web/admin/admin.html:38-39): a bordered ring
 * whose top edge is the accent colour, spinning once every 0.8s. V1 had nine
 * hand-rolled copies of this; they are all `fwmon-spinner` spans in the V1
 * markup.
 */
export function Spinner({ size = 'sm', className, label }: SpinnerProps) {
  return (
    <span
      className={cn('fwmon-spinner shrink-0 align-middle', SIZES[size], className)}
      role={label ? 'status' : undefined}
      aria-hidden={label ? undefined : true}
    >
      {label ? <span className="sr-only">{label}</span> : null}
    </span>
  );
}
