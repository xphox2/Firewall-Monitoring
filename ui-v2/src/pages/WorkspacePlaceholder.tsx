import { ArrowLeftRight, Layers } from 'lucide-react';

export function WorkspacePlaceholder({
  title,
  description,
  phaseLabel,
  v1Path,
  subTabs = [],
}: {
  title: string;
  description: string;
  phaseLabel: string;
  v1Path: string;
  subTabs?: string[];
}) {
  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Layers className="h-5 w-5 text-accent" />
            <h1 className="font-display text-lg sm:text-xl font-bold text-text">{title}</h1>
            <span className="rounded bg-accent/15 px-2 py-0.5 font-mono text-[10px] font-semibold text-accent">
              {phaseLabel}
            </span>
          </div>
          <p className="text-xs text-text-faint mt-0.5">{description}</p>
        </div>

        <a
          href={v1Path}
          className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:border-border-strong self-start sm:self-auto"
        >
          <ArrowLeftRight className="h-3.5 w-3.5 text-accent" />
          <span>Open in Classic V1 ({v1Path})</span>
        </a>
      </div>

      {subTabs.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {subTabs.map((t, i) => (
            <span
              key={t}
              className={`rounded-md border px-3 py-1.5 text-xs font-medium ${
                i === 0
                  ? 'border-accent/40 bg-accent/10 text-accent'
                  : 'border-border bg-bg-card text-text-faint'
              }`}
            >
              {t}
            </span>
          ))}
        </div>
      )}

      <div className="rounded-lg border border-border bg-bg-card p-8 text-center space-y-3">
        <div className="font-display text-sm font-bold text-text">
          {title} — Side-by-Side Migration Active ({phaseLabel})
        </div>
        <p className="text-xs text-text-faint max-w-lg mx-auto">
          This workspace is part of the incremental V2 rollout. While {phaseLabel} is being wired up, you can jump to the live V1 view at any time with one click.
        </p>
        <div className="pt-2">
          <a
            href={v1Path}
            className="inline-flex items-center gap-1.5 rounded-md bg-accent px-4 py-2 text-xs font-semibold text-white hover:bg-accent-hover"
          >
            <ArrowLeftRight className="h-3.5 w-3.5" />
            <span>Open {title} in V1</span>
          </a>
        </div>
      </div>
    </div>
  );
}
