import { useEffect, useRef, useState } from 'react';
import { cn } from '@/lib/utils';
import { OVERLAY_DELAY_MS, elapsedSeconds, overlayShouldShow } from '@/lib/motion';
import { Spinner } from './spinner';

export { OVERLAY_DELAY_MS };

export interface LoadingOverlayProps {
  /** True while the load is in flight. */
  active: boolean;
  /** The text beside the spinner. */
  label?: string;
  /** Called when the operator cancels. Without it, no Cancel button is shown. */
  onCancel?: () => void;
  /** Dim the content behind the overlay. */
  dim?: boolean;
  /**
   * The element that carries `aria-busy`. Usually the panel the content is
   * being loaded into.
   */
  hostRef?: React.RefObject<HTMLElement | null>;
  /**
   * Elements that OWN Escape. A text field that started the load keeps its
   * own Escape behaviour, so Esc only cancels when focus is somewhere that
   * does not already use it.
   */
  escScope?: React.RefObject<HTMLElement | null>[];
  className?: string;
}

/**
 * The loading overlay.
 *
 * Ports V1's `.fwmon-chart-overlay` (cmd/api/static/css/admin-design-system.css:
 * 443-486) together with the machinery behind `AdminCommon.chartLoad()`
 * (cmd/api/static/js/admin-common.js:2194-2287).
 *
 * What V1 did, and what is reproduced here:
 *
 * - `role="status"` on the overlay, so it is announced as a status region.
 * - `aria-busy="true"` on the host for the WHOLE load, set immediately - the
 *   overlay itself only appears after 250ms, but assistive technology is told
 *   about the load at once.
 * - The elapsed counter is `aria-live="off"`. It ticks every second, and a
 *   polite live region would announce "1s", "2s", "3s" to a screen reader
 *   for the whole load.
 * - The Cancel button suppresses `mousedown`. Without it, pressing Cancel
 *   blurs whatever had focus, a pending text edit commits, that starts a new
 *   load, and the button is removed from under the click.
 * - Escape cancels only when nothing else owns it: an Esc something else
 *   already handled is not ours, a dialog always owns its own Escape, a form
 *   field owns it unless it is one of the load's own controls, and a load
 *   whose results are not on screen is not the one being looked at.
 */
export function LoadingOverlay({
  active,
  label = 'Loading higher-resolution data…',
  onCancel,
  dim = true,
  hostRef,
  escScope = [],
  className,
}: LoadingOverlayProps) {
  const [visible, setVisible] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const startedAt = useRef<number | null>(null);
  const overlayRef = useRef<HTMLDivElement>(null);

  // The 250ms delay, and the clock starts when the LOAD starts - not when the
  // overlay appears - so the elapsed count is honest.
  useEffect(() => {
    if (!active) {
      setVisible(false);
      setElapsed(0);
      startedAt.current = null;
      return;
    }
    startedAt.current = Date.now();
    // A new load starts the clock at zero. Without this the overlay would
    // show the PREVIOUS load's elapsed count for up to a second.
    setElapsed(0);
    const timer = setTimeout(() => {
      // The rule lives in lib/motion so it can be tested; the timeout only
      // decides WHEN to ask.
      if (overlayShouldShow(true, startedAt.current, Date.now())) setVisible(true);
    }, OVERLAY_DELAY_MS);
    return () => clearTimeout(timer);
  }, [active]);

  // The elapsed ticker. aria-live is off (see the doc comment).
  useEffect(() => {
    if (!visible) return;
    const id = setInterval(() => {
      setElapsed(elapsedSeconds(startedAt.current, Date.now()));
    }, 1000);
    return () => clearInterval(id);
  }, [visible]);

  // aria-busy on the host, for the WHOLE load. It is set at once, because
  // assistive technology should be told about the load immediately - even
  // though the overlay itself does not appear for another 250ms.
  useEffect(() => {
    const host = hostRef?.current;
    if (!host) return;
    if (active) host.setAttribute('aria-busy', 'true');
    else host.removeAttribute('aria-busy');
    return () => host.removeAttribute('aria-busy');
  }, [active, hostRef]);

  // The `fwmon-loading` class goes on only while the overlay is actually
  // showing. It carries the host's min-height, so a fast load must not
  // reserve space for an overlay that never appeared. (V1 kept these two
  // apart for the same reason: admin-common.js:2248 sets aria-busy at once,
  // :2256 adds the class inside the 250ms show timer.)
  useEffect(() => {
    const host = hostRef?.current;
    if (!host) return;
    if (visible) host.classList.add('fwmon-loading');
    else host.classList.remove('fwmon-loading');
    return () => host.classList.remove('fwmon-loading');
  }, [visible, hostRef]);

  // Escape ownership. Ported from V1's `chartLoad` key handler.
  useEffect(() => {
    if (!visible || !onCancel) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      // An Esc something else already handled is not ours.
      if (event.defaultPrevented) return;
      // A dialog always owns its own Escape. V1 also excluded its own
      // confirm overlay, which is not a [role=dialog] element.
      if (document.querySelector('[role="dialog"], .fwmon-confirm-overlay')) return;
      // A load whose results are not rendered is not the one being looked at.
      if (!overlayRef.current || overlayRef.current.getClientRects().length === 0) return;
      const target = event.target as HTMLElement | null;
      if (target?.closest?.('[role="dialog"], .fwmon-confirm-overlay')) return;
      const field = target?.closest?.('input, textarea, select');
      const owned = escScope.some((ref) => ref.current?.contains(target));
      if (!field || owned) onCancel();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [visible, onCancel, escScope]);

  if (!visible) return null;

  return (
    <div
      ref={overlayRef}
      className={cn('fwmon-chart-overlay', dim ? null : 'fwmon-chart-overlay--plain', className)}
      role="status"
      data-testid="loading-overlay"
    >
      <div className="fwmon-chart-overlay-box">
        <Spinner />
        <span className="fwmon-chart-overlay-text">{label}</span>
        <span className="fwmon-chart-overlay-elapsed" aria-live="off">
          {elapsed}s
        </span>
        {onCancel ? (
          <button
            type="button"
            // No focus change on press: a blur would commit a pending text
            // edit, start a new load and remove this button before the click
            // lands. (V1's chartLoad did the same.)
            onMouseDown={(event) => event.preventDefault()}
            onClick={onCancel}
            className="rounded-md border border-border bg-bg-card px-2.5 py-1 text-xs font-medium text-text-dim transition-colors hover:text-text"
          >
            Cancel
          </button>
        ) : null}
      </div>
    </div>
  );
}
