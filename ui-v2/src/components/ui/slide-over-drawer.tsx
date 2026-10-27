import React, { useId } from 'react';
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
  /**
   * Which edge the drawer is docked to.
   *
   * The mobile navigation is a LEFT drawer (a menu opens from the left edge);
   * the inspection drawers are right-hand sheets. Hard-coding "right" would
   * have turned the navigation into a right-hand drawer.
   */
  side?: 'left' | 'right';
  /** The footer content is right-aligned; a nav drawer needs it left. */
  footerAlign?: 'start' | 'end';
  /**
   * Replaces the default title block.
   *
   * The navigation drawer wants a brand header, not a title. The replacement
   * MUST include a `Dialog.Title` (Radix needs one for the dialog to be
   * named), so the caller imports it.
   */
  header?: React.ReactNode;
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
  side = 'right',
  footerAlign = 'end',
  header,
}: SlideOverDrawerProps) {
  // A stable id prefix for the tab strip's ARIA wiring.
  const tabGroupId = useId();
  const isLeft = side === 'left';
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/65 backdrop-blur-[1px] transition-opacity" />
        <Dialog.Content
          data-testid="slide-over-drawer"
          className={cn(
            'fixed inset-y-0 z-50 flex flex-col bg-bg-card border-border shadow-2xl focus:outline-hidden',
            isLeft ? 'left-0 border-r' : 'right-0 border-l',
            SIZE_CLASSES[size],
          )}
        >
          {/* Pinned Header */}
          <div className="shrink-0 border-b border-border bg-bg-card px-5 py-4">
            <div className="flex items-start justify-between gap-4">
              {header ?? (
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
              )}
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
                onKeyDown={(event) => {
                  // The ARIA tabs pattern: Arrow keys move between tabs, Home
                  // and End jump to the ends. The strip used to be reachable
                  // only with the mouse.
                  if (!tabs.length) return;
                  const index = tabs.findIndex((tab) => tab.id === activeTab);
                  if (index < 0) return;
                  let next = index;
                  if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
                  else if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
                  else if (event.key === 'Home') next = 0;
                  else if (event.key === 'End') next = tabs.length - 1;
                  else return;
                  event.preventDefault();
                  onTabChange?.(tabs[next].id);
                  // The focus moves with the selection, as the pattern requires.
                  const strip = event.currentTarget as HTMLElement;
                  const buttons = strip.querySelectorAll<HTMLButtonElement>('[role="tab"]');
                  buttons[next]?.focus();
                }}
              >
                {tabs.map((tab) => {
                  const isActive = activeTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      type="button"
                      role="tab"
                      id={`${tabGroupId}-tab-${tab.id}`}
                      aria-selected={isActive}
                      // The SINGLE-PANEL variant of the tabs pattern: every
                    // tab points at the one panel, and the panel is named by
                    // the selected tab. Pointing each tab at a panel of its
                    // own would leave the inactive tabs pointing at
                    // elements that are not in the DOM.
                    aria-controls={`${tabGroupId}-panel`}
                      // Roving tabindex: only the selected tab is in the tab order, so
                      // Tab moves past the strip instead of through every tab.
                      tabIndex={isActive ? 0 : -1}
                      onClick={() => onTabChange?.(tab.id)}
                      className={cn(
                        'inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-xs font-medium whitespace-nowrap transition-colors',
                        'focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent',
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
                              ? 'bg-accent/15 text-accent-text'
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
          <div
            className="flex-1 overflow-y-auto px-5 py-4 space-y-5"
            role={tabs && tabs.length > 0 && activeTab ? 'tabpanel' : undefined}
            id={
              tabs && tabs.length > 0 && activeTab
                ? `${tabGroupId}-panel`
                : undefined
            }
            aria-labelledby={
              tabs && tabs.length > 0 && activeTab
                ? `${tabGroupId}-tab-${activeTab}`
                : undefined
            }
          >
            {children}
          </div>

          {/* Permanently Pinned Sticky Footer */}
          {footer && (
            <div
              data-testid="drawer-sticky-footer"
              className={cn(
                'shrink-0 border-t border-border bg-bg-panel/90 px-5 py-3.5 flex items-center gap-2.5',
                footerAlign === 'start' ? 'justify-start' : 'justify-end',
              )}
            >
              {footer}
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
