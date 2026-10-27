import React, { createContext, useCallback, useContext, useState } from 'react';
import { CheckCircle2, AlertTriangle, XCircle, Info, X } from 'lucide-react';
import { cn } from '@/lib/utils';

export type ToastVariant = 'success' | 'error' | 'warning' | 'info';

export interface ToastItem {
  id: string;
  title: string;
  description?: string;
  variant: ToastVariant;
}

interface ToastContextValue {
  toast: (opts: { title: string; description?: string; variant?: ToastVariant }) => void;
  success: (title: string, description?: string) => void;
  error: (title: string, description?: string) => void;
  warning: (title: string, description?: string) => void;
}

const ToastContext = createContext<ToastContextValue>({
  toast: () => {},
  success: () => {},
  error: () => {},
  warning: () => {},
});

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);

  const dismiss = useCallback((id: string) => {
    setItems((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const toast = useCallback(
    ({
      title,
      description,
      variant = 'info',
    }: {
      title: string;
      description?: string;
      variant?: ToastVariant;
    }) => {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      setItems((prev) => [...prev.slice(-4), { id, title, description, variant }]);
      setTimeout(() => dismiss(id), 5000);
    },
    [dismiss],
  );

  const success = useCallback(
    (title: string, description?: string) => toast({ title, description, variant: 'success' }),
    [toast],
  );
  const error = useCallback(
    (title: string, description?: string) => toast({ title, description, variant: 'error' }),
    [toast],
  );
  const warning = useCallback(
    (title: string, description?: string) => toast({ title, description, variant: 'warning' }),
    [toast],
  );

  return (
    <ToastContext.Provider value={{ toast, success, error, warning }}>
      {children}
      {/*
        The toast list is NOT a live region.

        Each toast carries `role="status"`, which is itself a polite live
        region. A live region INSIDE a live region announces the message
        TWICE: once for the container seeing new content, and once for the
        toast's own region. So the container is a positioning wrapper and
        the toast is the only live region.
      */}
      <div className="fixed top-14 right-4 z-[90] flex flex-col gap-2 w-[calc(100vw-2rem)] sm:w-96 pointer-events-none">
        {items.map((item) => (
          <div
            key={item.id}
            // The ONE live region: a status message. Announced once, when
            // it is inserted.
            role="status"
            className={cn(
              'pointer-events-auto flex items-start gap-3 rounded-lg border p-3.5 shadow-lg transition-all bg-bg-card border-border text-text',
              item.variant === 'success' && 'border-l-4 border-l-sig-ok',
              item.variant === 'error' && 'border-l-4 border-l-sig-crit',
              item.variant === 'warning' && 'border-l-4 border-l-sig-warn',
              item.variant === 'info' && 'border-l-4 border-l-accent',
            )}
          >
            {item.variant === 'success' && <CheckCircle2 className="h-4 w-4 text-sig-ok-text shrink-0 mt-0.5" />}
            {item.variant === 'error' && <XCircle className="h-4 w-4 text-sig-crit-text shrink-0 mt-0.5" />}
            {item.variant === 'warning' && <AlertTriangle className="h-4 w-4 text-sig-warn-text shrink-0 mt-0.5" />}
            {item.variant === 'info' && <Info className="h-4 w-4 text-accent shrink-0 mt-0.5" />}
            <div className="flex-1 min-w-0">
              <div className="text-xs font-semibold text-text">{item.title}</div>
              {item.description && (
                <div className="text-xs text-text-faint mt-0.5 break-words">{item.description}</div>
              )}
            </div>
            <button
              type="button"
              onClick={() => dismiss(item.id)}
              aria-label="Dismiss notification"
              className="text-text-faint hover:text-text p-1 rounded"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}
