import React, { useId } from 'react';
import { cn } from '@/lib/utils';

export interface FieldProps {
  /** The visible label text. */
  label: React.ReactNode;
  /**
   * The control.
   *
   * It is WRAPPED by the label, so the association is IMPLICIT and no `id`
   * is needed. That matters: a hand-written `id`/`htmlFor` pair collides
   * the moment the same form is rendered twice on a page — which happens
   * here, because several drawers can be open at once — and a generated id
   * cannot be produced inside a `.map()` without extracting a component.
   */
  children: React.ReactNode;
  /** Optional help text, under the control. */
  hint?: React.ReactNode;
  /** Optional error text, under the control. */
  error?: React.ReactNode;
  /** Applied to the wrapper. */
  className?: string;
  /** Applied to the label TEXT, not to the wrapper. */
  labelClassName?: string;
  /**
   * A control BESIDE the labelled one — a "Reveal" or "Clear" button.
   *
   * It is deliberately OUTSIDE the <label>. A <label> that contains a
   * button is a control inside a control: the label's activation behaviour
   * (click the text, focus the field) also fires for the button, so the two
   * controls fight over the click.
   */
  action?: React.ReactNode;
}

/**
 * A labelled control.
 *
 * The console had 135 copies of the same label class string and 71 of them
 * were ORPHANED: a `<label>` with no `htmlFor` that did not wrap its
 * control, so a screen reader announced the text with no idea what it
 * labelled. Another 103 used a `<span>` as a pseudo-label, which is not a
 * label at all.
 *
 * Wrapping the control fixes all of that by construction: the label's
 * implicit association needs no id, so there is nothing to collide.
 */
export function Field({
  label,
  children,
  hint,
  error,
  className,
  labelClassName,
  action,
}: FieldProps) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy =
    [hintId, errorId].filter(Boolean).join(' ') || undefined;

  /*
   * The hint and the error are DESCRIBED BY the control, not part of its
   * name. Inside the <label> they would be folded into the accessible
   * name, so a field would be announced as "Auth Password Required for
   * SNMPv3 with an auth protocol" — a description smuggled into the name.
   *
   * They are also outside the label, so the label still wraps exactly one
   * labelable control and the implicit association is unambiguous.
   */
  const control = React.isValidElement(children)
    ? React.cloneElement(children as React.ReactElement<Record<string, unknown>>, {
        'aria-describedby':
          describedBy ??
          ((children.props as Record<string, unknown>)['aria-describedby'] as string | undefined),
        ...(error ? { 'aria-invalid': true } : {}),
      })
    : children;

  // Without an action the label wraps the control and nothing else, exactly
  // as before. WITH one, the label wraps only the control and the action
  // sits beside it — a <label> that contains a button is a control inside
  // a control.
  if (!action) {
    // The label wraps ONLY the label text and the control. The hint and the
    // error sit OUTSIDE it: inside a <label> they are folded into the
    // accessible name, so the field is announced as "Auth Password
    // Required for SNMPv3 with an auth protocol" - a description smuggled
    // into the name.
    return (
      <div className={cn('block', className)}>
        <label className="block">
          <span className={cn('mb-1 block text-xs font-medium text-text-dim', labelClassName)}>
            {label}
          </span>
          {control}
        </label>
        {hint ? (
          <span id={hintId} className="mt-1 block text-[10px] text-text-faint">
            {hint}
          </span>
        ) : null}
        {error ? (
          <span id={errorId} role="alert" className="mt-1 block text-[10px] text-sig-crit">
            {error}
          </span>
        ) : null}
      </div>
    );
  }

  return (
    <div className={cn('block', className)}>
      <div className="flex items-end gap-2">
        <label className="min-w-0 flex-1">
          <span className={cn('mb-1 block text-xs font-medium text-text-dim', labelClassName)}>
            {label}
          </span>
          {control}
        </label>
        {action}
      </div>
      {hint ? (
        <span id={hintId} className="mt-1 block text-[10px] text-text-faint">
          {hint}
        </span>
      ) : null}
      {error ? (
        <span id={errorId} role="alert" className="mt-1 block text-[10px] text-sig-crit">
          {error}
        </span>
      ) : null}
    </div>
  );
}
