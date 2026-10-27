import React from 'react';
import { cn } from '@/lib/utils';

export type ButtonVariant =
  | 'default'
  | 'secondary'
  | 'icon'
  | 'danger-icon'
  | 'ghost'
  | 'destructive';
export type ButtonSize = 'sm' | 'md' | 'lg' | 'icon';

/*
 * The variants carry the console's OWN class strings, exactly.
 *
 * The console had 316 buttons with dozens of distinct strings for the same
 * visual weight. A primitive whose variants were approximations would
 * change how every button looks when it is adopted, so each variant here IS
 * one of the strings the console already used - the migration is then a
 * no-op visually, and what disappears is the duplication.
 */
const VARIANTS: Record<ButtonVariant, string> = {
  // The primary button. The hover DIMMS the button, which is what the
  // console's own primary buttons did.
  default: 'rounded-md bg-accent px-3.5 py-1.5 text-xs font-semibold text-on-accent hover:opacity-90',
  // The secondary button.
  secondary:
    'rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text-dim hover:text-text',
  // The small square icon button.
  icon: 'rounded border border-border bg-bg-panel p-1 text-text-dim hover:text-text',
  // The destructive icon button.
  'danger-icon': 'rounded border border-sig-crit/30 bg-sig-crit/10 p-1 text-sig-crit',
  // The ghost button.
  ghost: 'rounded-md text-text-dim hover:bg-bg-hover hover:text-text',
  // The destructive button.
  destructive:
    'rounded-md bg-sig-crit px-3.5 py-1.5 text-xs font-semibold text-white hover:opacity-90',
};

/*
 * The size carries only what the variant does not: the TYPE SCALE. The
 * padding is in the variant, because the console's strings differ in
 * padding and a primitive that normalized it would change how every button
 * looks.
 */
const SIZES: Record<ButtonSize, string> = {
  // The TYPE SCALE only. The weight lives in the variant: if it lived
  // here, `cn()` would let the size override the variant's `font-semibold`
  // and the first small primary button would silently lose its weight.
  sm: 'text-[11px]',
  md: 'text-xs',
  lg: 'text-sm',
  icon: 'text-xs',
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
        'inline-flex items-center justify-center gap-1.5 transition-colors',
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
