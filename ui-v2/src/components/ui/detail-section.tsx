import type { ReactNode } from 'react';

/**
 * Labelled field grid used by the event/syslog/trap inspectors. Rows with an
 * empty value are dropped, so a section disappears entirely when the vendor
 * supplied none of its fields.
 */
export function DetailSection({
  title,
  fields,
}: {
  title: string;
  fields: Array<[string, ReactNode]>;
}) {
  const visible = fields.filter(
    ([, value]) => value !== null && value !== undefined && value !== '' && value !== '—',
  );
  if (visible.length === 0) return null;
  return (
    <section className="space-y-1.5">
      <h4 className="text-[10px] font-semibold uppercase tracking-wider text-text-faint">{title}</h4>
      <div className="grid grid-cols-2 gap-2">
        {visible.map(([label, value]) => (
          <div key={label} className="rounded-lg border border-border bg-bg-panel px-2.5 py-2">
            <div className="text-[10px] uppercase text-text-faint">{label}</div>
            <div className="break-words font-mono text-[11px] text-text">{value}</div>
          </div>
        ))}
      </div>
    </section>
  );
}
