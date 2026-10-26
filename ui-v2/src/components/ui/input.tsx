import React from 'react';
import { cn } from '@/lib/utils';

/**
 * The shared focus indicator.
 *
 * Safari does not draw a focus ring on a `<button>` or an `<input>` unless
 * the author provides one, so a keyboard user in Safari had no way to see
 * where the focus was. `focus-visible` keeps the ring off mouse clicks,
 * and `focus:outline-hidden` stops the browser's own ring from appearing
 * alongside it.
 */
const FOCUS =
  'focus:outline-hidden focus-visible:outline-2 focus-visible:outline-solid focus-visible:outline-offset-2 focus-visible:outline-accent';

/**
 * The input's shape.
 *
 * The console had 183 raw `<input>` elements and fourteen different class
 * strings for the same visual weight, so a change to the input's look meant
 * finding every one of them.
 */
const INPUT_CLASSES =
  'w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text ' +
  'focus:border-accent disabled:cursor-not-allowed disabled:opacity-60';

export interface InputProps extends React.ComponentPropsWithRef<'input'> {
  /** The monospaced face, for identifiers, addresses and secrets. */
  mono?: boolean;
}

export function Input({ className, mono = false, ...props }: InputProps) {
  return <input className={cn(INPUT_CLASSES, mono && 'font-mono', FOCUS, className)} {...props} />;
}

export interface SelectProps extends React.ComponentPropsWithRef<'select'> {}

export function Select({ className, ...props }: SelectProps) {
  return (
    <select
      className={cn(
        'w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text',
        'focus:border-accent disabled:cursor-not-allowed disabled:opacity-60',
        FOCUS,
        className,
      )}
      {...props}
    />
  );
}

export interface TextareaProps extends React.ComponentPropsWithRef<'textarea'> {}

export function Textarea({ className, ...props }: TextareaProps) {
  return (
    <textarea
      className={cn(
        'w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text',
        'focus:border-accent disabled:cursor-not-allowed disabled:opacity-60',
        FOCUS,
        className,
      )}
      {...props}
    />
  );
}
