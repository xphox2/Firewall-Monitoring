import { cn } from '@/lib/utils';
import { gaugePercent, gaugeStrokeColour } from '@/lib/motion';

export interface GaugeProps {
  /** Current value. */
  value: number;
  /** The value that reads as 100%. */
  max: number;
  /** Pixel size of the dial. V1 used an 80px viewBox. */
  size?: number;
  /** Text inside the dial. Defaults to the rounded percentage. */
  label?: string;
  className?: string;
}

const RADIUS = 32;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

/**
 * The donut gauge.
 *
 * Ports V1's `.gauge-fill` (cmd/api/static/css/admin-shared.css:1311-1346)
 * together with the geometry V1 kept in JavaScript
 * (cmd/api/static/js/admin-connection-detail.js:104-128) - the arc sweep and
 * the threshold colours.
 *
 * The stroke colour is a `var()` so a Day/Night flip re-resolves instantly:
 * SVG presentation attributes cannot take `var()`, but an inline style can.
 */
export function Gauge({ value, max, size = 80, label, className }: GaugeProps) {
  const pct = gaugePercent(value, max);
  const offset = CIRCUMFERENCE - (pct / 100) * CIRCUMFERENCE;
  const colour = gaugeStrokeColour(pct);

  return (
    <div className={cn('gauge', className)} style={{ width: size, height: size }}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 80 80"
        // The visible text below carries the value, so the SVG is decorative:
        // announcing it too would read the percentage twice.
        aria-hidden="true"
        focusable="false"
      >
        <circle className="gauge-bg" cx="40" cy="40" r={RADIUS} />
        <circle
          className="gauge-fill"
          cx="40"
          cy="40"
          r={RADIUS}
          style={{ stroke: colour }}
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="gauge-text">{label ?? `${Math.round(pct)}%`}</div>
    </div>
  );
}
