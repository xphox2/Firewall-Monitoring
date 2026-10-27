import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Filter, Search, X } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn } from '@/lib/utils';
import { Select } from '@/components/ui/input';
import { ACTIVITY_NAMES } from '@/lib/events';
import type { EventFilters } from '@/lib/event-filters';

interface DeviceOption {
  id: number;
  name: string;
  site_id?: number | null;
}

interface ProbeOption {
  id: number;
  name: string;
}

interface SiteOption {
  id: number;
  name: string;
}

export interface EventFilterBarProps {
  filters: EventFilters;
  onChange: (next: EventFilters) => void;
  /** The site's filters are not accepted by the security-events endpoint. */
  withSite?: boolean;
  /** The net events only: the rule key and the destination address. */
  withRuleKey?: boolean;
  withDestination?: boolean;
  /** The security events only: the substring filters. */
  withSecText?: boolean;
  /**
   * The event streams only: the activity filter.
   *
   * The syslog and trap endpoints do NOT accept an `activity` parameter, so
   * offering the control there would be a control that silently does
   * nothing — the selection would snap straight back.
   */
  withActivity?: boolean;
  /** Rendered before the filters — the action/class selects. */
  children?: React.ReactNode;
  /**
   * Called when the operator clears the bar.
   *
   * The bar only knows its OWN fields, so the default is to clear those.
   * A page that holds filters elsewhere — the net tab keeps the action and
   * the source address in their own state — passes this so "Clear" resets
   * everything the operator can see.
   */
  onClear?: () => void;
  className?: string;
}

/**
 * The event filters.
 *
 * The console offered two of the server's eight net-event filters and two
 * of the eleven security-event filters. The rest were simply not in the
 * console: an operator could not narrow either stream by device, probe,
 * site or rule.
 *
 * The numeric filters are only sent when they parse, because the server
 * rejects a non-numeric one with a 400 rather than ignoring it.
 */
export function EventFilterBar({
  filters,
  onChange,
  withSite = false,
  withRuleKey = false,
  withDestination = false,
  withSecText = false,
  withActivity = false,
  children,
  onClear,
  className,
}: EventFilterBarProps) {
  const { data: devices } = useQuery({
    queryKey: ['devices'],
    queryFn: () => apiFetch<DeviceOption[]>('/admin/api/devices'),
    staleTime: 300_000,
  });

  const { data: probes } = useQuery({
    queryKey: ['probes'],
    queryFn: () => apiFetch<ProbeOption[]>('/admin/api/probes'),
    staleTime: 300_000,
  });

  const { data: sites } = useQuery({
    queryKey: ['sites'],
    queryFn: () => apiFetch<SiteOption[]>('/admin/api/sites'),
    staleTime: 300_000,
    enabled: withSite,
  });

  const set = (patch: Partial<EventFilters>) => onChange({ ...filters, ...patch });

  const active = useMemo(
    () =>
      Object.entries(filters).filter(
        ([, value]) => value !== undefined && value !== null && String(value).trim() !== '',
      ).length,
    [filters],
  );

  const text = (
    label: string,
    key: keyof EventFilters,
    placeholder: string,
    width = 'w-36',
  ) => (
    <input
      type="text"
      value={String(filters[key] ?? '')}
      onChange={(e) => set({ [key]: e.target.value } as Partial<EventFilters>)}
      placeholder={placeholder}
      aria-label={label}
      className={cn(
        'rounded-md border border-border bg-bg-card px-2.5 py-1 text-[11px] text-text',
        'focus:border-accent focus:outline-hidden focus-visible:outline-2 focus-visible:outline-solid focus-visible:outline-offset-2 focus-visible:outline-accent',
        width,
      )}
    />
  );

  return (
    <div
      className={cn(
        'flex flex-wrap items-center gap-2 rounded-lg border border-border bg-bg-card p-2.5',
        className,
      )}
    >
      <Filter className="ml-1 h-3.5 w-3.5 text-text-faint" />
      {children}

      <Select
        className="px-2.5 py-1"
        value={filters.deviceId ?? ''}
        onChange={(e) => set({ deviceId: e.target.value })}
        aria-label="Filter by device"
      >
        <option value="">All devices</option>
        {(devices ?? []).map((d) => (
          <option key={d.id} value={String(d.id)}>
            {d.name}
          </option>
        ))}
      </Select>

      <Select
        className="px-2.5 py-1"
        value={filters.probeId ?? ''}
        onChange={(e) => set({ probeId: e.target.value })}
        aria-label="Filter by probe"
      >
        <option value="">All probes</option>
        {(probes ?? []).map((p) => (
          <option key={p.id} value={String(p.id)}>
            {p.name}
          </option>
        ))}
      </Select>

      {withSite ? (
        <Select
          className="px-2.5 py-1"
          value={filters.siteId ?? ''}
          onChange={(e) => set({ siteId: e.target.value })}
          aria-label="Filter by site"
        >
          <option value="">All sites</option>
          {(sites ?? []).map((s) => (
            <option key={s.id} value={String(s.id)}>
              {s.name}
            </option>
          ))}
        </Select>
      ) : null}

      {withActivity ? (
        <Select
          className="px-2.5 py-1"
          value={filters.activity ?? ''}
          onChange={(e) => set({ activity: e.target.value })}
          aria-label="Filter by activity"
        >
          <option value="">Any activity</option>
          {Object.entries(ACTIVITY_NAMES).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </Select>
      ) : null}

      {withRuleKey ? text('Filter by rule key', 'ruleKey', 'rule key') : null}
      {withDestination ? text('Filter by destination address', 'dstIp', 'dst IP') : null}
      {withSecText ? (
        <>
          {text('Filter by admin user', 'adminUser', 'admin user')}
          {text('Filter by signature', 'sigName', 'signature')}
          {text('Filter by tunnel', 'tunnelName', 'tunnel')}
          {text('Filter by WAN interface', 'wanName', 'wan')}
        </>
      ) : null}

      {active > 0 ? (
        <button
          type="button"
          onClick={() => {
            onChange({});
            onClear?.();
          }}
          className="inline-flex items-center gap-1 rounded-md border border-border bg-bg-panel px-2 py-1 text-[11px] text-text-dim hover:text-text"
        >
          <X className="h-3 w-3" />
          Clear {active}
        </button>
      ) : null}
    </div>
  );
}

/** The search box the net-event stream already had. */
export function EventSearchBox({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (next: string) => void;
  placeholder: string;
}) {
  return (
    <div className="relative flex-1 min-w-[200px]">
      <Search className="h-3.5 w-3.5 text-text-faint absolute left-2.5 top-1/2 -translate-y-1/2" />
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        className="w-full rounded-md border border-border bg-bg-card pl-8 pr-3 py-1 text-xs text-text focus:border-accent focus:outline-hidden focus-visible:outline-2 focus-visible:outline-solid focus-visible:outline-offset-2 focus-visible:outline-accent"
      />
    </div>
  );
}
