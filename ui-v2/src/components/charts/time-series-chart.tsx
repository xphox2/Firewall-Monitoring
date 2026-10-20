import { useEffect, useRef } from 'react';
import uPlot from 'uplot';
import 'uplot/dist/uPlot.min.css';
import { useTheme } from '@/lib/theme';
import { formatAxisValue, formatValue, type ChartKind, type ChartSeries } from '@/lib/chart';

export interface TimeSeriesChartProps {
  /** Epoch milliseconds, one per point. */
  timestamps: number[];
  series: ChartSeries[];
  kind: ChartKind;
  title?: string;
  height?: number;
  isLoading?: boolean;
  emptyMessage?: string;
}

function cssVar(name: string, fallback: string): string {
  try {
    const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return value || fallback;
  } catch {
    return fallback;
  }
}

/**
 * uPlot wrapper used by every V2 time-series chart. The classic console uses
 * uPlot too, so the axis/grid palette and interaction model stay identical
 * without adding a second charting engine to the bundle.
 */
export function TimeSeriesChart({
  timestamps,
  series,
  kind,
  title,
  height = 220,
  isLoading = false,
  emptyMessage = 'No data in this range.',
}: TimeSeriesChartProps) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const chartRef = useRef<uPlot | null>(null);
  const { theme } = useTheme();

  const hasData = timestamps.length > 0 && series.some((s) => s.values.some((v) => v != null));

  useEffect(() => {
    const host = hostRef.current;
    if (!host || !hasData) {
      chartRef.current?.destroy();
      chartRef.current = null;
      return;
    }

    const draw = () => {
      const width = host.clientWidth;
      if (width < 40) return; // hidden tab: wait for a resize
      chartRef.current?.destroy();
      const axis = cssVar('--fwmon-axis-stroke', '#828d99');
      const grid = cssVar('--fwmon-grid-stroke', '#1c222b');
      const tick = cssVar('--fwmon-tick-stroke', '#2a313b');
      const font = '11px "JetBrains Mono", ui-monospace, monospace';

      const data: uPlot.AlignedData = [
        timestamps.map((t) => Math.floor(t / 1000)),
        ...series.map((s) => s.values),
      ];

      chartRef.current = new uPlot(
        {
          width,
          height,
          padding: [8, 8, 0, 0],
          legend: { show: false },
          cursor: {
            // No drag-zoom yet: a local zoom with no refetch would look like a
            // date-range change and silently stop following the pills.
            drag: { x: false, y: false },
            points: { show: false },
          },
          scales: { x: { time: true }, y: { auto: true } },
          axes: [
            {
              stroke: axis,
              font,
              size: 28,
              grid: { stroke: grid, width: 1 },
              ticks: { stroke: tick, width: 1, size: 4 },
              space: 60,
            },
            {
              stroke: axis,
              font,
              size: 56,
              grid: { stroke: grid, width: 1 },
              ticks: { stroke: tick, width: 1, size: 4 },
              values: (_u, values) => values.map((v) => formatAxisValue(v, kind)),
            },
          ],
          series: [
            {},
            ...series.map((s) => ({
              label: s.label,
              stroke: s.color,
              width: 1.5,
              points: { show: false },
              spanGaps: true,
            })),
          ],
        },
        data,
        host,
      );
    };

    // Defer the first paint by a frame: ThemeProvider applies data-theme in its
    // own effect (parent effects run after child effects), so reading the CSS
    // variables synchronously here would pick up the previous theme's colors.
    let frame = requestAnimationFrame(() => draw());
    const observer = new ResizeObserver(() => {
      const width = host.clientWidth;
      if (width < 40) return; // hidden tab
      if (chartRef.current) {
        chartRef.current.setSize({ width, height });
        return;
      }
      // First visible layout: schedule (never draw inline) so the parent
      // ThemeProvider effect has applied data-theme before colors are read.
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => draw());
    });
    observer.observe(host);

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      chartRef.current?.destroy();
      chartRef.current = null;
    };
  }, [timestamps, series, kind, height, hasData, theme]);

  return (
    <div className="space-y-2">
      {(title || series.length > 0) && (
        <div className="flex flex-wrap items-center justify-between gap-2">
          {title && <div className="text-xs font-semibold text-text">{title}</div>}
          <div className="flex flex-wrap items-center gap-3">
            {series.map((s) => {
              const last = s.values.length ? s.values[s.values.length - 1] : null;
              return (
                <span key={s.label} className="inline-flex items-center gap-1.5 text-[11px] text-text-dim">
                  <span
                    className="h-2 w-2 rounded-full"
                    style={{ backgroundColor: s.color }}
                    aria-hidden="true"
                  />
                  {s.label}
                  <span className="font-mono text-text-faint">{formatValue(last, kind)}</span>
                </span>
              );
            })}
          </div>
        </div>
      )}

      {isLoading && !hasData ? (
        <div
          className="flex items-center justify-center rounded-lg border border-border bg-bg-panel text-xs text-text-faint"
          style={{ height }}
        >
          Loading chart…
        </div>
      ) : !hasData ? (
        <div
          className="flex items-center justify-center rounded-lg border border-border bg-bg-panel text-xs text-text-faint"
          style={{ height }}
        >
          {emptyMessage}
        </div>
      ) : (
        <div
          ref={hostRef}
          className="w-full overflow-hidden rounded-lg border border-border bg-bg-panel"
          style={{ height }}
        />
      )}
    </div>
  );
}
