import { useEffect, useState } from 'react';

/**
 * Whether the operator has asked for reduced motion, tracked live.
 *
 * The OS setting can change while the console is open, so this listens for
 * the change rather than reading it once. Two things need it:
 *
 * - the topology particle canvas, whose loop cannot be stopped by CSS at
 *   all (it is a `requestAnimationFrame` loop, not a CSS animation);
 * - the connection bridge's SMIL particles, which SMIL runs outside CSS's
 *   reach.
 *
 * It lives here rather than in `lib/motion.ts` because that module is pure
 * logic with no React dependency, and it is imported by node-environment unit
 * tests.
 */
export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => {
    try {
      return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    } catch {
      return false;
    }
  });

  useEffect(() => {
    let media: MediaQueryList;
    try {
      media = window.matchMedia('(prefers-reduced-motion: reduce)');
    } catch {
      return;
    }
    const onChange = () => setReduced(media.matches);
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, []);

  return reduced;
}
