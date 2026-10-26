import { cn } from '@/lib/utils';

export type StatusDotState = 'online' | 'offline' | 'pending' | 'muted';

export interface StatusDotProps {
  state: StatusDotState;
  className?: string;
  /**
   * Text for assistive technology. The dot is decorative on its own - a
   * coloured circle tells a screen-reader user nothing - so a label is
   * required unless adjacent text already says the same thing.
   */
  label?: string;
}

/**
 * The status dot.
 *
 * Ports V1's `.pulse-dot` (cmd/api/static/css/admin-shared.css:966-991): an
 * 8px circle that pulses while the state is live or pending.
 *
 * V1's `@keyframes pulse` hard-coded a GREEN glow, so the amber `.pending`
 * dot glowed green. The glow colour is per-state here.
 *
 * `muted` is for a state that is not live at all — a retired device. It is
 * grey and does not pulse.
 */
export function StatusDot({ state, className, label }: StatusDotProps) {
  return (
    <span
      className={cn('pulse-dot', state, className)}
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    />
  );
}
