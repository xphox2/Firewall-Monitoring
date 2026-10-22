const RELOAD_MARKER = 'fwmon.v2.stale-chunk-reload';

/**
 * Errors a browser raises when the HTML/entry from one build tries to load a
 * lazy chunk from another. The chunk may have been replaced by a deploy, or it
 * may be the new chunk importing minified names the old entry does not export.
 */
export function isStaleChunkError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error ?? '');
  return /failed to fetch dynamically imported module|error loading dynamically imported module|importing a module script failed|does not provide an export named|chunkloaderror/i.test(
    message,
  );
}

/**
 * Reload once (per short window) when a stale chunk or entry/chunk mismatch is
 * detected. The guard prevents a reload loop when a genuinely broken bundle
 * fails the same way every time; the ErrorBoundary and the reload button remain
 * available for that case.
 *
 * Returns true when a reload was triggered.
 */
export function reloadForStaleChunk(error: unknown): boolean {
  if (!isStaleChunkError(error)) return false;
  if (typeof window === 'undefined') return false;
  try {
    const last = Number(window.sessionStorage.getItem(RELOAD_MARKER) ?? 0);
    if (Number.isFinite(last) && Date.now() - last < 30_000) return false;
    window.sessionStorage.setItem(RELOAD_MARKER, String(Date.now()));
  } catch {
    // Private mode / blocked storage: reload is still the only recovery, but a
    // loop guard is impossible. One reload is better than a dead lazy route.
  }
  window.location.reload();
  return true;
}
