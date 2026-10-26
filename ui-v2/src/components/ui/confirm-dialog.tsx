import { useRef } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { AlertTriangle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel?: string;
  cancelLabel?: string;
  destructive?: boolean;
  pending?: boolean;
  onConfirm: () => void;
}

/**
 * Small confirmation gate for destructive one-click actions (delete user,
 * drop connection, remove IRC server…). These used to fire straight from a
 * table trash icon with no second step and no way back.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  destructive = false,
  pending = false,
  onConfirm,
}: ConfirmDialogProps) {
  const contentRef = useRef<HTMLDivElement>(null);
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-[60] bg-black/65 backdrop-blur-[1px]" />
        <Dialog.Content
          ref={contentRef}
          // `tabIndex={-1}` makes the panel itself focusable, which is what
          // the autofocus handler below needs.
          tabIndex={-1}
          className="fixed left-1/2 top-1/2 z-[60] w-[calc(100vw-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 rounded-xl border border-border bg-bg-card p-5 shadow-2xl focus:outline-hidden"
          onOpenAutoFocus={(event) => {
            // Default focus lands on the destructive button; send it to the
            // dialog itself so Enter cannot delete anything by reflex.
            //
            // The focus has to be moved EXPLICITLY. Radix skips its own
            // autofocus when this handler prevents the default, and the
            // panel is not focusable without `tabIndex={-1}`, so before this
            // the focus stayed on the trigger — which Radix had just marked
            // `aria-hidden`. A keyboard user was left on a hidden element,
            // with the screen reader's cursor nowhere.
            event.preventDefault();
            contentRef.current?.focus();
          }}
        >
          <div className="flex items-start gap-3">
            <div
              className={cn(
                'rounded-full p-2',
                destructive ? 'bg-sig-crit/15 text-sig-crit' : 'bg-sig-warn/15 text-sig-warn',
              )}
            >
              <AlertTriangle className="h-4 w-4" />
            </div>
            <div className="min-w-0 flex-1">
              <Dialog.Title className="font-display text-sm font-bold text-text">{title}</Dialog.Title>
              <Dialog.Description className="mt-1 text-xs leading-relaxed text-text-dim">
                {description}
              </Dialog.Description>
            </div>
          </div>

          <div className="mt-5 flex justify-end gap-2">
            <Dialog.Close asChild>
              <Button variant="secondary">{cancelLabel}</Button>
            </Dialog.Close>
            <Button
              disabled={pending}
              onClick={onConfirm}
              variant={destructive ? 'destructive' : 'default'}
            >
              {pending ? 'Working…' : confirmLabel}
            </Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
