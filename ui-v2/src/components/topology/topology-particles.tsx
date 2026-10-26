import { useEffect, useRef } from 'react';
import type { Core, EdgeSingular } from 'cytoscape';
import { particleColourForKind } from '@/lib/motion';
import { useTheme } from '@/lib/theme';
import { usePrefersReducedMotion } from '@/lib/use-reduced-motion';

/**
 * The traffic particles.
 *
 * Ports V1's particle system (cmd/api/static/js/diagram-cytoscape.js:1041-1239,
 * `startParticles` / `addParticlePair` / `stopParticles`): dots travelling along
 * the live edges of the map, so a link that carries traffic is visibly
 * different from a link that is merely up.
 *
 * This is a REIMPLEMENTATION, not a transcription. V1's version branched on
 * edge data keys that V2 does not have - `edgeType` ('tunnel-bundle',
 * 'sublane', 'offnet', 'pipe-bg'), `connType`, `tunnelHalf`, `tunnelPeerId`,
 * `childConns`. V2's edge model is `kind: 'connection' | 'tunnel'` plus the
 * bundle flags, so the V1 branches have no equivalent to copy.
 *
 * What is kept from V1:
 * - a canvas layer over the graph, sized to the device pixel ratio, with
 *   `pointer-events: none` so it never steals a click;
 * - particles only on edges that are UP (`status === 'up'`) and not hidden;
 * - a bidirectional pair per edge - a bright forward dot and a dimmer,
 *   smaller return dot;
 * - a hard cap on the particle count (V1: 80);
 * - the particle follows the edge's actual curve, not a straight chord;
 * - the loop is torn down on unmount (V1's `stopParticles`).
 */

/** V1's cap. */
const MAX_PARTICLES = 80;

interface Particle {
  edge: EdgeSingular;
  /** 0-1 along the edge. */
  progress: number;
  speed: number;
  /** 1 = forwards, -1 = backwards. */
  direction: 1 | -1;
  colour: string;
  radius: number;
  alpha: number;
}

/**
 * Resolve the CSS variable to a concrete colour the canvas can use.
 *
 * A canvas cannot paint `var(--fwmon-accent)`, so the token is resolved once
 * per particle.
 */
function resolveColour(value: string, fallback: string): string {
  if (!value.startsWith('var(')) return value;
  const match = /var\(\s*(--[\w-]+)/.exec(value);
  if (!match) return fallback;
  try {
    const resolved = getComputedStyle(document.documentElement)
      .getPropertyValue(match[1])
      .trim();
    return resolved || fallback;
  } catch {
    return fallback;
  }
}

export interface TopologyParticlesProps {
  /** The graph to draw over. Null until the graph exists. */
  cy: Core | null;
  /** The element the canvas is layered on top of. */
  hostRef: React.RefObject<HTMLElement | null>;
  max?: number;
}

export function TopologyParticles({ cy, hostRef, max = MAX_PARTICLES }: TopologyParticlesProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  // The particle colour comes from a CSS token, and a Day/Night flip changes
  // it. The theme is watched so the particles are repainted in the new
  // palette instead of staying in the old one.
  const { theme } = useTheme();
  const reduced = usePrefersReducedMotion();

  useEffect(() => {
    const host = hostRef.current;
    if (!cy || !host) return;

    // Reduced motion: no particles at all. A canvas loop cannot be stopped by
    // CSS, so this has to be decided in JavaScript.
    if (reduced) return;

    const canvas = document.createElement('canvas');
    canvas.style.cssText =
      'position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:5;';
    host.parentElement?.appendChild(canvas);
    canvasRef.current = canvas;

    const ctx = canvas.getContext('2d');
    if (!ctx) {
      canvas.remove();
      canvasRef.current = null;
      return;
    }

    const particles: Particle[] = [];
    let frame = 0;
    let last = 0;
    let dpr = window.devicePixelRatio || 1;

    const resize = () => {
      const rect = host.getBoundingClientRect();
      dpr = window.devicePixelRatio || 1;
      canvas.width = Math.max(1, Math.round(rect.width * dpr));
      canvas.height = Math.max(1, Math.round(rect.height * dpr));
      canvas.style.width = `${rect.width}px`;
      canvas.style.height = `${rect.height}px`;
    };
    resize();

    // V1's addParticlePair: a bright forward dot and a dimmer, smaller
    // return dot.
    const addPair = (edge: EdgeSingular, colour: string) => {
      if (particles.length >= max) return;
      particles.push({
        edge,
        progress: Math.random(),
        speed: 0.0003 + Math.random() * 0.00015,
        direction: 1,
        colour,
        radius: 3,
        alpha: 0.85,
      });
      if (particles.length < max) {
        particles.push({
          edge,
          progress: Math.random(),
          speed: 0.00022 + Math.random() * 0.0001,
          direction: -1,
          colour,
          radius: 2,
          alpha: 0.4,
        });
      }
    };

    // Rebuild the particle set from the graph's live edges. The graph is
    // reconciled in place, so the edges change without the component
    // re-rendering - this runs on every frame instead, which keeps the
    // particles in step with a link that has just gone down.
    const syncParticles = () => {
      const live = cy.edges().filter((edge) => {
        if (edge.style('display') === 'none') return false;
        return String(edge.data('status') ?? '').toLowerCase() === 'up';
      });
      const liveIds = new Set(live.map((edge) => edge.id()));

      // Drop particles whose edge is gone or no longer up.
      for (let i = particles.length - 1; i >= 0; i -= 1) {
        if (!liveIds.has(particles[i].edge.id())) particles.splice(i, 1);
      }

      // Add a pair for any up edge that does not have one yet. The colour is
      // resolved here, so a theme flip repaints the particles that are added
      // afterwards; the ones already on screen are repainted by the theme
      // effect below.
      const covered = new Set(particles.map((p) => p.edge.id()));
      for (const edge of live) {
        if (covered.has(edge.id())) continue;
        if (particles.length >= max) break;
        addPair(edge, resolveColour(particleColourForKind(String(edge.data('kind') ?? '')), '#4c8dff'));
      }
    };

    const animate = (timestamp: number) => {
      if (!last) last = timestamp;
      const dt = timestamp - last;
      last = timestamp;

      // A graphics problem must never take the map down with it: the
      // particles are decoration, so a failure costs the motion and nothing
      // else. The whole frame is guarded, not just the per-particle body.
      try {
        const rect = host.getBoundingClientRect();
        if (
          canvas.width !== Math.round(rect.width * dpr) ||
          canvas.height !== Math.round(rect.height * dpr)
        ) {
          resize();
        }

        syncParticles();

        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.save();
        ctx.scale(dpr, dpr);
        const pan = cy.pan();
        const zoom = cy.zoom();

        // Iterate over a COPY: a particle that throws is spliced out of the
        // live array, and splicing the array being iterated would skip the
        // next one for a frame.
        for (const p of particles.slice()) {
          try {
            if (p.edge.removed()) continue;
            if (p.edge.style('display') === 'none') continue;

            p.progress += p.speed * dt * p.direction;
            if (p.progress > 1) p.progress -= 1;
            if (p.progress < 0) p.progress += 1;

            const src = p.edge.sourceEndpoint();
            const tgt = p.edge.targetEndpoint();
            if (!src || !tgt) continue;

            // Follow the edge's actual curve. Cytoscape's 'bezier' curve style
            // exposes its two control points, so the particle travels the same
            // path the line is drawn on. A straight chord would visibly leave
            // the edge.
            const cps = p.edge.controlPoints();
            let mx: number;
            let my: number;
            if (cps.length >= 2) {
              const t = p.progress;
              const mt = 1 - t;
              const [c1, c2] = cps;
              mx =
                mt * mt * mt * src.x +
                3 * mt * mt * t * c1.x +
                3 * mt * t * t * c2.x +
                t * t * t * tgt.x;
              my =
                mt * mt * mt * src.y +
                3 * mt * mt * t * c1.y +
                3 * mt * t * t * c2.y +
                t * t * t * tgt.y;
            } else {
              mx = src.x + (tgt.x - src.x) * p.progress;
              my = src.y + (tgt.y - src.y) * p.progress;
            }

            const rx = mx * zoom + pan.x;
            const ry = my * zoom + pan.y;

            ctx.beginPath();
            ctx.arc(rx, ry, Math.max(0.5, p.radius * zoom), 0, Math.PI * 2);
            ctx.fillStyle = p.colour;
            ctx.globalAlpha = p.alpha;
            ctx.fill();
          } catch {
            // Drop the offending particle rather than retrying it every frame.
            const index = particles.indexOf(p);
            if (index >= 0) particles.splice(index, 1);
          }
        }

        ctx.restore();
      } catch {
        // The frame itself failed. Stop the loop rather than spinning on a
        // broken graph: the map is a separate canvas and does not depend on
        // the particles.
        return;
      }

      frame = requestAnimationFrame(animate);
    };

    frame = requestAnimationFrame(animate);

    return () => {
      if (frame) cancelAnimationFrame(frame);
      frame = 0;
      particles.length = 0;
      if (canvas.parentNode) canvas.parentNode.removeChild(canvas);
      canvasRef.current = null;
    };
    // `theme` is a dependency because a Day/Night flip changes the CSS token
    // the particle colour comes from, and a canvas cannot read `var(...)`.
    // The effect re-runs, so the particles are rebuilt in the new palette.
  }, [cy, hostRef, max, reduced, theme]);

  return null;
}
