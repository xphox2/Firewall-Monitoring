import React from 'react';
import { cn } from '@/lib/utils';

export type ButtonVariant = 'default' | 'secondary' | 'ghost' | 'destructive' | 'outline';
export type ButtonSize = 'sm' | 'md' | 'lg' | 'icon';

const VARIANTS: Record<ButtonVariant, string> = {
  default: 'bg-accent text-white hover:bg-accent-hover',
  secondary: 'border border-border bg-bg-panel text-text-dim hover:text-text',
  ghost: 'text-text-dim hover:bg-bg-hover hover:text-text',
  destructive: 'bg-sig-crit text-white hover:opacity-90',
  outline: 'border border-border bg-bg-card text-text hover:border-border-strong hover:text-text',
};

const SIZES: Record<ButtonSize, string> = {
  sm: 'px-2 py-1 text-[11px]',
  md: 'px-3 py-1.5 text-xs',
  lg: 'px-4 py-2 text-sm',
  icon: 'p-1',
};

/**
 * The focus indicator.
 *
 * Every interactive control needs a VISIBLE focus indicator. The browser's
 * default ring is not enough: Safari does not draw a focus ring on a
 * `<button>` at all unless the author provides one, so a keyboard user in
 * Safari had no way to see where the focus was. `focus-visible` (rather than
 * `focus`) keeps the ring off mouse clicks, which is where the old
 * `focus:outline-hidden` habit came from.
 */
const FOCUS =
  'focus:outline-hidden focus-visible:outline-2 focus-visible:outline-solid focus-visible:outline-offset-2 focus-visible:outline-accent';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

/**
 * The button.
 *
 * The console had 274 raw `<button>` elements with hand-inlined Tailwind and
 * fourteen different class strings for the same visual weight, so a change to
 * the button's look meant finding every one of them. This is the shared
 * shape; the class strings that differ are the ones that differ on purpose.
 */
export function Button({
  className,
  variant = 'default',
  size = 'md',
  type = 'button',
  ...props
}: ButtonProps) {
  return (
    <button
      type={type}
      className={cn(
        'inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-colors',
        'disabled:cursor-not-allowed disabled:opacity-50',
        FOCUS,
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
      {...props}
    />
  );
}
