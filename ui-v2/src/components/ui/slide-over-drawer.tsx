import React from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface DrawerTab {
  id: string;
  label: string;
  badge?: string | number;
}

export interface SlideOverDrawerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  subtitle?: string;
  badge?: React.ReactNode;
  size?: 'md' | 'lg' | 'xl' | '2xl';
  tabs?: DrawerTab[];
  activeTab?: string;
  onTabChange?: (tabId: string) => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
}

const SIZE_CLASSES: Record<NonNullable<SlideOverDrawerProps['size']>, string> = {
  md: 'w-full sm:max-w-md',
  lg: 'w-full sm:max-w-xl',
  xl: 'w-full sm:max-w-2xl',
  '2xl': 'w-full sm:max-w-4xl',
};

export function SlideOverDrawer({
  open,
  onOpenChange,
  title,
  subtitle,
  badge,
  size = 'xl',
  tabs,
  activeTab,
  onTabChange,
  children,
  footer,
}: SlideOverDrawerProps) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/65 backdrop-blur-[1px] transition-opacity" />
        <Dialog.Content
          data-testid="slide-over-drawer"
          className={cn(
            'fixed inset-y-0 right-0 z-50 flex flex-col bg-bg-card border-l border-border shadow-2xl focus:outline-hidden',
            SIZE_CLASSES[size],
          )}
        >
          {/* Pinned Header */}
          <div className="shrink-0 border-b border-border bg-bg-card px-5 py-4">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <Dialog.Title className="font-display text-base font-bold text-text truncate">
                    {title}
                  </Dialog.Title>
                  {badge}
                </div>
                {subtitle ? (
                  <Dialog.Description className="mt-1 text-xs text-text-faint">
                    {subtitle}
                  </Dialog.Description>
                ) : (
                  <Dialog.Description className="sr-only">{title}</Dialog.Description>
                )}
              </div>
              <Dialog.Close
                aria-label="Close drawer"
                className="rounded-md p-1.5 text-text-faint hover:bg-bg-panel hover:text-text transition-colors"
              >
                <X className="h-4 w-4" />
              </Dialog.Close>
            </div>

            {/* Optional Segmented Sub-Tabs inside Pinned Header */}
            {tabs && tabs.length > 0 && (
              <div
                role="tablist"
                aria-label={`${title} sections`}
                className="mt-3.5 flex items-center gap-1 overflow-x-auto border-b border-border -mb-4 pb-0"
              >
                {tabs.map((tab) => {
                  const isActive = activeTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      type="button"
                      role="tab"
                      aria-selected={isActive}
                      onClick={() => onTabChange?.(tab.id)}
                      className={cn(
                        'inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-xs font-medium whitespace-nowrap transition-colors',
                        isActive
                          ? 'border-accent text-accent font-semibold'
                          : 'border-transparent text-text-faint hover:text-text hover:border-border-strong',
                      )}
                    >
                      <span>{tab.label}</span>
                      {tab.badge !== undefined && (
                        <span
                          className={cn(
                            'rounded-full px-1.5 py-0.2 font-mono text-[10px]',
                            isActive
                              ? 'bg-accent/15 text-accent'
                              : 'bg-bg-panel text-text-faint',
                          )}
                        >
                          {tab.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Scrollable Body */}
          <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">{children}</div>

          {/* Permanently Pinned Sticky Footer */}
          {footer && (
            <div
              data-testid="drawer-sticky-footer"
              className="shrink-0 border-t border-border bg-bg-panel/90 px-5 py-3.5 flex items-center justify-end gap-2.5"
            >
              {footer}
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
