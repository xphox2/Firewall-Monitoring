import { useId } from 'react';
import { usePrefersReducedMotion } from '@/lib/use-reduced-motion';

/**
 * The connection bridge.
 *
 * Ports V1's `renderBridge` (cmd/api/static/js/admin-connection-detail.js:
 * 132-174): the source and destination boxes joined by a curved path, with
 * dots travelling along it when the link is up, a glow on a healthy link, and
 * a slow opacity pulse on a down one.
 *
 * The V2 console had no bridge graphic at all - `ui-v2/src` contained no SVG
 * whatsoever - so this is the graphic as well as the motion.
 *
 * The particles are SMIL `<animateMotion>`. That is deliberate (it matches
 * V1 exactly and needs no animation loop), but it has one consequence:
 * **SMIL ignores CSS**, so a `prefers-reduced-motion` media query cannot stop
 * it. The particles are therefore omitted in JavaScript, by not rendering
 * them at all.
 */

export interface ConnectionBridgeProps {
  sourceName?: string;
  destName?: string;
  status?: string;
  /** The connection type, shown nowhere but kept for the caller's future use. */
  connectionType?: string;
}

function statusColour(status?: string): string {
  const value = String(status ?? '').toLowerCase();
  if (/up|online|active|ok|established/.test(value)) return 'var(--fwmon-sig-ok)';
  if (/down|offline|failed|error/.test(value)) return 'var(--fwmon-sig-crit)';
  return 'var(--fwmon-text-mute)';
}

function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, Math.max(0, max - 1))}…`;
}

export function ConnectionBridge({ sourceName, destName, status }: ConnectionBridgeProps) {
  const reduced = usePrefersReducedMotion();
  // The path id has to be unique: two bridges on one page would both answer
  // to "#bridge-path" and the particles would travel the wrong one.
  const rawId = useId().replace(/[^a-zA-Z0-9_-]/g, '');
  const pathId = `bridge-path-${rawId}`;
  const glowId = `bridge-glow-${rawId}`;

  const value = String(status ?? '').toLowerCase();
  const up = /up|online|active|ok|established/.test(value);
  const down = /down|offline|failed|error/.test(value);
  const edge = statusColour(status);

  return (
    <svg
      className="block w-full"
      height={100}
      viewBox="0 0 700 100"
      role="img"
      aria-label={`${sourceName ?? 'source'} to ${destName ?? 'destination'}, link ${status ?? 'unknown'}`}
    >
      <defs>
        <filter id={glowId} x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation={3} result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      <rect
        x={20}
        y={25}
        width={140}
        height={50}
        rx={8}
        style={{ fill: 'var(--fwmon-card-bg)', stroke: edge }}
        strokeWidth={2}
      />
      <text
        x={90}
        y={48}
        textAnchor="middle"
        style={{ fill: 'var(--fwmon-text)' }}
        fontSize={12}
        fontWeight={600}
      >
        {truncate(sourceName ?? 'source', 16)}
      </text>
      <text x={90} y={64} textAnchor="middle" style={{ fill: 'var(--fwmon-text-faint)' }} fontSize={10}>
        Source
      </text>

      <rect
        x={540}
        y={25}
        width={140}
        height={50}
        rx={8}
        style={{ fill: 'var(--fwmon-card-bg)', stroke: edge }}
        strokeWidth={2}
      />
      <text
        x={610}
        y={48}
        textAnchor="middle"
        style={{ fill: 'var(--fwmon-text)' }}
        fontSize={12}
        fontWeight={600}
      >
        {truncate(destName ?? 'destination', 16)}
      </text>
      <text x={610} y={64} textAnchor="middle" style={{ fill: 'var(--fwmon-text-faint)' }} fontSize={10}>
        Destination
      </text>

      <path
        id={pathId}
        d="M160,50 Q350,10 540,50"
        fill="none"
        stroke="var(--fwmon-accent)"
        strokeWidth={2}
        filter={up ? `url(#${glowId})` : undefined}
      >
        {down ? (
          <animate attributeName="opacity" values="1;0.3;1" dur="2s" repeatCount="indefinite" />
        ) : null}
      </path>

      {up && !reduced ? (
        <>
          <circle r={4} fill="var(--fwmon-accent)" opacity={0.85}>
            <animateMotion dur="3s" begin="0s" repeatCount="indefinite" fill="freeze">
              <mpath href={`#${pathId}`} />
            </animateMotion>
          </circle>
          <circle r={4} fill="var(--fwmon-accent)" opacity={0.85}>
            <animateMotion dur="3s" begin="1.5s" repeatCount="indefinite" fill="freeze">
              <mpath href={`#${pathId}`} />
            </animateMotion>
          </circle>
          <circle r={3} fill="var(--fwmon-accent)" opacity={0.7}>
            <animateMotion
              dur="3.5s"
              begin="0.5s"
              repeatCount="indefinite"
              fill="freeze"
              keyPoints="1;0"
              keyTimes="0;1"
              calcMode="linear"
            >
              <mpath href={`#${pathId}`} />
            </animateMotion>
          </circle>
          <circle r={3} fill="var(--fwmon-accent)" opacity={0.7}>
            <animateMotion
              dur="3.5s"
              begin="2s"
              repeatCount="indefinite"
              fill="freeze"
              keyPoints="1;0"
              keyTimes="0;1"
              calcMode="linear"
            >
              <mpath href={`#${pathId}`} />
            </animateMotion>
          </circle>
        </>
      ) : null}
    </svg>
  );
}
