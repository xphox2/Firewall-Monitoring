import { cn, formatRelativeTime } from '@/lib/utils';
import {
  capabilityFeatureRows,
  capabilityFieldRows,
  capabilitySummary,
  capabilityTone,
  stateLabel,
  type CapabilityTone,
  type DeviceCapabilities,
} from '@/lib/device-capabilities';

const TONE_CLASS: Record<CapabilityTone, string> = {
  ok: 'bg-sig-ok/15 text-sig-ok',
  warn: 'bg-sig-warn/15 text-sig-warn',
  crit: 'bg-sig-crit/15 text-sig-crit',
  accent: 'bg-accent/15 text-accent',
  muted: 'bg-bg-panel text-text-faint',
};

function StateBadge({ state }: { state: string }) {
  return (
    <span
      className={cn(
        'inline-flex rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
        TONE_CLASS[capabilityTone(state)],
      )}
    >
      {stateLabel(state)}
    </span>
  );
}

/**
 * The static vendor profile joined with what the device was observed sending
 * in the window. This used to be a raw JSON dump; the tables answer the two
 * operational questions directly: which features can this box feed, and which
 * fields is it actually sending?
 */
export function DeviceCapabilitiesPanel({
  capabilities,
  isLoading,
}: {
  capabilities?: DeviceCapabilities;
  isLoading?: boolean;
}) {
  if (isLoading) {
    return <p className="p-4 text-center text-xs text-text-dim">Loading capability matrix…</p>;
  }
  if (!capabilities) {
    return (
      <p className="rounded-xl border border-border bg-bg-card p-4 text-xs text-text-dim">
        No capability data for this device.
      </p>
    );
  }

  const features = capabilityFeatureRows(capabilities.features);
  const fields = capabilityFieldRows(capabilities.fields);
  const summary = capabilitySummary(capabilities.features);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11px] text-text-dim">
          Vendor <span className="font-mono text-text">{capabilities.vendor || 'unknown'}</span>
        </span>
        <span className="text-text-faint">·</span>
        <span className="text-[11px] text-text-dim">
          Observed over the last {capabilities.window_hours}h
        </span>
        {capabilities.hardware && (
          <span className="rounded bg-sig-warn/15 px-1.5 py-0.5 text-[10px] font-medium text-sig-warn">
            {capabilities.hardware}
          </span>
        )}
      </div>

      <div className="flex flex-wrap gap-1.5">
        <span className="rounded bg-sig-ok/15 px-2 py-0.5 text-[10px] font-semibold text-sig-ok">
          {summary.supported} supported
        </span>
        <span className="rounded bg-sig-warn/15 px-2 py-0.5 text-[10px] font-semibold text-sig-warn">
          {summary.degraded} degraded
        </span>
        <span className="rounded bg-bg-panel px-2 py-0.5 text-[10px] font-semibold text-text-faint">
          {summary.inactive} inactive
        </span>
        <span className="rounded bg-sig-crit/15 px-2 py-0.5 text-[10px] font-semibold text-sig-crit">
          {summary.unsupported} unsupported
        </span>
      </div>

      <section className="space-y-1.5">
        <h3 className="text-[10px] font-semibold uppercase tracking-wider text-text-faint">
          Features ({features.length})
        </h3>
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-border bg-bg-panel/40 text-[10px] uppercase tracking-wider text-text-faint">
                <th scope="col" className="px-2.5 py-1.5">Feature</th>
                <th scope="col" className="px-2.5 py-1.5">Verdict</th>
                <th scope="col" className="px-2.5 py-1.5">Deciding fields</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {features.map((feature) => (
                <tr key={feature.name}>
                  <td className="px-2.5 py-1.5 font-mono text-[11px] text-text">
                    {feature.name}
                  </td>
                  <td className="px-2.5 py-1.5">
                    <StateBadge state={feature.state} />
                  </td>
                  <td className="px-2.5 py-1.5">
                    {feature.fields.length > 0 ? (
                      <span className="flex flex-wrap gap-1">
                        {feature.fields.map((field) => (
                          <code
                            key={field}
                            className="rounded bg-bg-panel px-1 py-0.5 font-mono text-[10px] text-text-dim"
                          >
                            {field}
                          </code>
                        ))}
                      </span>
                    ) : (
                      <span className="text-text-faint">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-1.5">
        <h3 className="text-[10px] font-semibold uppercase tracking-wider text-text-faint">
          Fields ({fields.length})
        </h3>
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-border bg-bg-panel/40 text-[10px] uppercase tracking-wider text-text-faint">
                <th scope="col" className="px-2.5 py-1.5">Field</th>
                <th scope="col" className="px-2.5 py-1.5">State</th>
                <th scope="col" className="px-2.5 py-1.5">Source</th>
                <th scope="col" className="px-2.5 py-1.5">Completeness</th>
                <th scope="col" className="px-2.5 py-1.5 text-right">Seen</th>
                <th scope="col" className="px-2.5 py-1.5">Last seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {fields.map((field) => (
                <tr key={field.name}>
                  <td className="px-2.5 py-1.5">
                    <div className="font-mono text-[11px] text-text">{field.name}</div>
                    {field.note && (
                      <div className="mt-0.5 max-w-[32rem] text-[10px] leading-relaxed text-text-faint">
                        {field.note}
                      </div>
                    )}
                  </td>
                  <td className="px-2.5 py-1.5">
                    <StateBadge state={field.state} />
                  </td>
                  <td className="px-2.5 py-1.5 font-mono text-[10px] text-text-dim">
                    {field.source || '—'}
                  </td>
                  <td className="px-2.5 py-1.5 text-[10px] text-text-dim">
                    {field.completeness ? stateLabel(field.completeness) : '—'}
                  </td>
                  <td className="px-2.5 py-1.5 text-right font-mono text-[10px] text-text-dim">
                    {field.count > 0 ? field.count.toLocaleString() : '—'}
                  </td>
                  <td className="px-2.5 py-1.5 font-mono text-[10px] text-text-faint">
                    {field.last_seen ? formatRelativeTime(field.last_seen) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <details className="rounded-lg border border-border bg-bg-card p-3">
        <summary className="cursor-pointer text-xs font-semibold text-text">
          Raw capability JSON
        </summary>
        <pre className="mt-2 max-h-72 overflow-auto rounded border border-border bg-bg-panel p-2 font-mono text-[10px] text-text-dim">
          {JSON.stringify(capabilities, null, 2)}
        </pre>
      </details>
    </div>
  );
}
