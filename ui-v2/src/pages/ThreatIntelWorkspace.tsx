import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  CheckCircle2,
  Globe,
  Plus,
  Search,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { apiFetch, ApiError } from '@/lib/api';
import { cn, countryCodeToFlag, formatRelativeTime } from '@/lib/utils';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { useToast } from '@/components/ui/toast';
import { ColumnDef } from '@tanstack/react-table';
import {
  EMPTY_INDICATOR_FILTERS,
  buildIndicatorQuery,
  feedState,
  lookupVerdict,
  type FeedStatusRow,
  type IndicatorFilters,
  type ThreatLookup,
} from '@/lib/threat-intel';
import { Select } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

type ThreatTab = 'lookup' | 'feeds' | 'storm';

interface FeedsResponse {
  feeds_enabled?: boolean;
  interval?: string;
  ttl_days?: number;
  loaded_count?: number;
  status?: FeedStatusRow[];
  by_source?: Array<{ source: string; count: number }>;
}

interface Indicator {
  id: number;
  cidr: string;
  category?: string;
  source?: string;
  severity?: string;
  first_seen?: string;
  last_seen?: string;
  expires_at?: string | null;
}

const PAGE_SIZE = 50;

function expiryLabel(value: string): string {
  const ms = new Date(value).getTime() - Date.now();
  if (!Number.isFinite(ms)) return '—';
  if (ms < 0) return 'expired';
  const days = Math.round(ms / 86_400_000);
  if (Math.abs(ms) < 86_400_000) return 'today';
  return `in ${days}d`;
}

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-sig-crit/15 text-sig-crit',
  warning: 'bg-sig-warn/15 text-sig-warn',
  info: 'bg-accent/15 text-accent-text',
};

const FEED_TONE: Record<string, string> = {
  ok: 'bg-sig-ok/15 text-sig-ok',
  warn: 'bg-sig-warn/15 text-sig-warn',
  crit: 'bg-sig-crit/15 text-sig-crit',
  muted: 'bg-bg-panel text-text-faint',
};

export function ThreatIntelWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = (searchParams.get('tab') as ThreatTab) || 'lookup';

  const setTab = (tab: ThreatTab) => {
    setSearchParams({ tab }, { replace: true });
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <ShieldAlert className="h-3.5 w-3.5" />
            Security & Alerts / Threat Intelligence
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            Reputation Lookup, Threat Feeds & Custom Indicators
          </h1>
        </div>

        <div className="flex items-center gap-1 rounded-lg border border-border bg-bg-panel p-1">
          {(
            [
              { id: 'lookup', label: 'IP / ASN Lookup' },
              { id: 'feeds', label: 'Feeds & Indicators' },
              { id: 'storm', label: 'Storm Tuning' },
            ] as const
          ).map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={cn(
                'rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
                activeTab === t.id
                  ? 'bg-bg-card text-text shadow-xs border border-border'
                  : 'text-text-dim hover:text-text',
              )}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {activeTab === 'lookup' && <LookupTab />}
      {activeTab === 'feeds' && <FeedsTab />}
      {activeTab === 'storm' && <StormTab />}
    </div>
  );
}

function LookupTab() {
  const [query, setQuery] = useState('');
  const [result, setResult] = useState<ThreatLookup | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (loading) return;
    const q = query.trim();
    if (!q) return;
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch<ThreatLookup>(
        `/admin/api/threat-intel/lookup?q=${encodeURIComponent(q)}`,
      );
      setResult(res);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Lookup failed');
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const verdict = result ? lookupVerdict(result) : null;
  const scopes = result?.threats ?? (result?.threat ? [result.threat] : []);

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
        <div className="flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-faint" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void run();
              }}
              placeholder="IPv4, IPv6 or AS number (e.g. 203.0.113.9, AS64500)"
              className="w-full rounded-md border border-border bg-bg-panel py-2 pl-8 pr-3 font-mono text-xs text-text focus:border-accent focus:outline-hidden"
            />
          </div>
          <button
            type="button"
            onClick={run}
            disabled={!query.trim() || loading}
            className="rounded-md bg-accent px-4 py-2 text-xs font-semibold text-on-accent hover:opacity-90 disabled:opacity-50"
          >
            {loading ? 'Checking…' : 'Look up'}
          </button>
        </div>

        {error && (
          <div className="flex items-start gap-2 rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {verdict && (
          <div
            className={cn(
              'rounded-lg border px-3.5 py-3',
              verdict.tone === 'crit' && 'border-sig-crit/40 bg-sig-crit/10',
              verdict.tone === 'warn' && 'border-sig-warn/40 bg-sig-warn/10',
              verdict.tone === 'ok' && 'border-sig-ok/40 bg-sig-ok/10',
            )}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                {verdict.tone === 'crit' ? (
                  <ShieldAlert className="h-5 w-5 text-sig-crit" />
                ) : verdict.tone === 'ok' ? (
                  <ShieldCheck className="h-5 w-5 text-sig-ok" />
                ) : (
                  <AlertTriangle className="h-5 w-5 text-sig-warn" />
                )}
                <span className="font-display text-base font-bold text-text">{verdict.label}</span>
              </div>
              <span className="font-mono text-xs text-text-dim">{result?.query}</span>
            </div>
            <p className="mt-1 text-xs text-text-dim">{verdict.detail}</p>

            {result?.kind === 'ip' && (
              <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-2">
                <div className="rounded-lg border border-border bg-bg-panel p-2.5">
                  <div className="text-[10px] uppercase text-text-faint">Country</div>
                  <div className="mt-0.5 flex items-center gap-1.5 font-mono text-xs text-text">
                    {result.country ? (
                      <>
                        <span className="fwmon-flag">{countryCodeToFlag(result.country)}</span>
                        {result.country}
                      </>
                    ) : (
                      '—'
                    )}
                  </div>
                </div>
                <div className="rounded-lg border border-border bg-bg-panel p-2.5">
                  <div className="text-[10px] uppercase text-text-faint">ASN</div>
                  <div className="mt-0.5 font-mono text-xs text-text">
                    {result.asn ? `AS${result.asn}` : '—'}
                  </div>
                </div>
                <div className="rounded-lg border border-border bg-bg-panel p-2.5 md:col-span-2">
                  <div className="text-[10px] uppercase text-text-faint">Organisation / prefix</div>
                  <div className="mt-0.5 font-mono text-xs text-text">
                    {result.asn_org || '—'}
                    {result.asn_prefix ? ` · ${result.asn_prefix}` : ''}
                  </div>
                </div>
              </div>
            )}

            {result?.kind === 'asn' && (
              <div className="mt-3 font-mono text-xs text-text-dim">
                AS{result.asn} — reputation matching only (no geolocation for a bare ASN).
              </div>
            )}

            {scopes.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1.5">
                {scopes.map((scope, idx) => (
                  <span
                    key={`${scope.scope}-${idx}`}
                    className={cn(
                      'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
                      SEVERITY_STYLE[scope.severity ?? 'info'] ?? SEVERITY_STYLE['info'],
                    )}
                  >
                    {scope.scope}: {scope.category || 'known-bad'}
                    {scope.severity ? ` (${scope.severity})` : ''}
                  </span>
                ))}
              </div>
            )}

            {result?.geo_enabled === false && result.kind === 'ip' && (
              <p className="mt-2 text-[11px] text-text-faint">
                GeoIP enrichment is disabled on the server (GEOIP_ENABLED), so country/ASN fields
                may be empty.
              </p>
            )}

            <div className="mt-3 flex items-center gap-2 text-[11px] text-text-faint">
              <Globe className="h-3 w-3" />
              Reputation comes from the enabled feeds plus custom operator indicators.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function FeedsTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const {
    data: feeds,
    isLoading,
    isError: feedsError,
    error: feedsErrorObj,
  } = useQuery({
    queryKey: ['threat-feeds'],
    queryFn: () => apiFetch<FeedsResponse>('/admin/api/threat-intel/feeds'),
    refetchInterval: 30_000,
  });

  const [masterConfirmOpen, setMasterConfirmOpen] = useState(false);
  const [feedToggleTarget, setFeedToggleTarget] = useState<FeedStatusRow | null>(null);

  const feedsEnabled = feeds?.feeds_enabled !== false;
  const status = feeds?.status ?? [];

  const masterMutation = useMutation({
    mutationFn: async (enabled: boolean) =>
      apiFetch('/admin/api/threat-intel/global', { method: 'PATCH', body: { enabled } }),
    onSuccess: (_data, enabled) => {
      toast({
        title: enabled ? 'Threat feeds enabled' : 'Threat feeds disabled',
        description: enabled
          ? 'Matching resumed; indicators are still loaded.'
          : 'Matching stopped; stored indicators are retained for re-enable.',
        variant: 'info',
      });
      setMasterConfirmOpen(false);
      queryClient.invalidateQueries({ queryKey: ['threat-feeds'] });
    },
    onError: (err: Error) =>
      toast({ title: 'Could not change feed state', description: err.message, variant: 'error' }),
  });

  const feedToggleMutation = useMutation({
    mutationFn: async ({ source, enabled }: { source: string; enabled: boolean }) =>
      apiFetch(`/admin/api/threat-intel/feeds/${encodeURIComponent(source)}`, {
        method: 'PATCH',
        body: { enabled },
      }),
    onSuccess: (_data, vars) => {
      toast({
        title: vars.enabled ? 'Feed enabled' : 'Feed disabled',
        description: vars.enabled ? 'It will sync on the next poll.' : 'Its indicators were purged.',
        variant: 'info',
      });
      setFeedToggleTarget(null);
      queryClient.invalidateQueries({ queryKey: ['threat-feeds'] });
      queryClient.invalidateQueries({ queryKey: ['threat-indicators'] });
    },
    onError: (err: Error) =>
      toast({ title: 'Could not change feed state', description: err.message, variant: 'error' }),
  });

  const columns = useMemo<ColumnDef<FeedStatusRow, unknown>[]>(
    () => [
      {
        accessorKey: 'source',
        header: 'Source',
        cell: ({ row }) => (
          <div>
            <div className="font-mono text-xs font-semibold text-text">{row.original.source}</div>
            <div className="text-[10px] text-text-faint">
              {row.original.kind || 'ip'} · {row.original.category || 'mixed'}
            </div>
          </div>
        ),
      },
      {
        accessorKey: 'entry_count',
        header: 'Entries',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-accent">{row.original.entry_count ?? 0}</span>
        ),
      },
      {
        accessorKey: 'last_sync_at',
        header: 'Last sync',
        cell: ({ row }) => (
          <span className="font-mono text-[11px] text-text-dim">
            {row.original.last_sync_at ? formatRelativeTime(row.original.last_sync_at) : 'Never'}
          </span>
        ),
      },
      {
        id: 'status',
        header: 'Status',
        cell: ({ row }) => {
          const state = feedState(row.original);
          return (
            <span
              className={cn(
                'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
                FEED_TONE[state.tone],
              )}
              title={state.detail}
            >
              {state.label}
            </span>
          );
        },
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => {
          const enabled = row.original.enabled !== false;
          return (
            <div className="flex justify-end">
              <button
                type="button"
                onClick={() => {
                  if (enabled) setFeedToggleTarget(row.original);
                  else feedToggleMutation.mutate({ source: row.original.source, enabled: true });
                }}
                className={cn(
                  'rounded border px-2 py-1 text-[10px] font-semibold uppercase',
                  enabled
                    ? 'border-sig-crit/30 bg-sig-crit/10 text-sig-crit'
                    : 'border-sig-ok/30 bg-sig-ok/10 text-sig-ok',
                )}
              >
                {enabled ? 'Disable' : 'Enable'}
              </button>
            </div>
          );
        },
      },
    ],
    [feedToggleMutation],
  );

  return (
    <div className="space-y-4">
      {feedsError && (
        <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit" role="alert">
          Could not load threat feeds: {feedsErrorObj instanceof Error ? feedsErrorObj.message : 'request failed'}
        </div>
      )}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5">
        <div className="rounded-lg border border-border bg-bg-card p-3">
          <div className="text-[10px] uppercase text-text-faint">Indicators loaded</div>
          <div className="mt-0.5 font-mono text-lg font-bold text-text">
            {feeds?.loaded_count ?? 0}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-bg-card p-3">
          <div className="text-[10px] uppercase text-text-faint">Feeds</div>
          <div className="mt-0.5 font-mono text-lg font-bold text-text">{status.length}</div>
        </div>
        <div className="rounded-lg border border-border bg-bg-card p-3">
          <div className="text-[10px] uppercase text-text-faint">Sync interval</div>
          <div className="mt-0.5 font-mono text-sm text-text">{feeds?.interval || '—'}</div>
        </div>
        <div className="rounded-lg border border-border bg-bg-card p-3">
          <div className="text-[10px] uppercase text-text-faint">Indicator TTL</div>
          <div className="mt-0.5 font-mono text-sm text-text">
            {feeds?.ttl_days ? `${feeds.ttl_days} days` : '—'}
          </div>
        </div>
      </div>

      <div
        className={cn(
          'flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3.5 py-2.5',
          feedsEnabled ? 'border-sig-ok/40 bg-sig-ok/10' : 'border-sig-warn/40 bg-sig-warn/10',
        )}
      >
        <div className="flex items-center gap-2 text-xs">
          {feedsEnabled ? (
            <CheckCircle2 className="h-4 w-4 text-sig-ok" />
          ) : (
            <AlertTriangle className="h-4 w-4 text-sig-warn" />
          )}
          <span className="font-semibold text-text">
            {feedsEnabled ? 'Threat matching is ON' : 'Threat matching is OFF'}
          </span>
          <span className="text-text-dim">
            {feedsEnabled
              ? 'Flows are matched against every enabled source.'
              : 'Stored indicators are retained; matching resumes instantly.'}
          </span>
        </div>
        <button
          type="button"
          onClick={() => {
            if (feedsEnabled) setMasterConfirmOpen(true);
            else masterMutation.mutate(true);
          }}
          disabled={masterMutation.isPending}
          className={cn(
            'rounded-md px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50',
            feedsEnabled ? 'bg-sig-crit' : 'bg-sig-ok',
          )}
        >
          {feedsEnabled ? 'Disable all feeds' : 'Enable feeds'}
        </button>
      </div>

      <ResponsiveDataView
        data={status}
        columns={columns}
        isLoading={isLoading}
        emptyTitle="No threat feeds registered."
        emptyDescription="The poller registers a feed on its first sync."
        renderMobileCard={(f) => (
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-semibold text-text">{f.source}</span>
              <span className="font-mono text-[10px] text-accent">{f.entry_count ?? 0}</span>
            </div>
            <div className="text-[11px] text-text-dim">
              {f.last_sync_at ? formatRelativeTime(f.last_sync_at) : 'Never synced'}
            </div>
          </div>
        )}
      />

      <IndicatorsSection />

      <ConfirmDialog
        open={masterConfirmOpen}
        onOpenChange={setMasterConfirmOpen}
        title="Disable all threat feeds?"
        description="Matching stops immediately. Stored indicators are retained and matching resumes instantly when re-enabled."
        confirmLabel="Disable matching"
        destructive
        pending={masterMutation.isPending}
        onConfirm={() => masterMutation.mutate(false)}
      />

      <ConfirmDialog
        open={!!feedToggleTarget}
        onOpenChange={(open) => {
          if (!open) setFeedToggleTarget(null);
        }}
        title={`Disable feed ${feedToggleTarget?.source ?? ''}?`}
        description="Its stored indicators are purged immediately; matching for this source stops until it is re-enabled and re-synced."
        confirmLabel="Disable feed"
        destructive
        pending={feedToggleMutation.isPending}
        onConfirm={() =>
          feedToggleTarget &&
          feedToggleMutation.mutate({ source: feedToggleTarget.source, enabled: false })
        }
      />
    </div>
  );
}

function IndicatorsSection() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState<IndicatorFilters>(EMPTY_INDICATOR_FILTERS);
  const [page, setPage] = useState(0);
  const [cidr, setCidr] = useState('');
  const [category, setCategory] = useState('');
  const [severity, setSeverity] = useState('warning');
  const [expires, setExpires] = useState('');
  const [indicatorToDelete, setIndicatorToDelete] = useState<Indicator | null>(null);

  const offset = page * PAGE_SIZE;
  const {
    data: search,
    isLoading,
    isError: searchError,
    error: searchErrorObj,
  } = useQuery({
    queryKey: ['threat-indicators', filters, page],
    queryFn: () =>
      apiFetch<{ entries?: Indicator[]; total?: number }>(
        `/admin/api/threat-intel/search?${buildIndicatorQuery(filters, offset, PAGE_SIZE)}`,
      ),
  });
  const entries = search?.entries ?? [];
  const total = search?.total ?? 0;

  const addMutation = useMutation({
    mutationFn: async () =>
      apiFetch('/admin/api/flows/threat-intel', {
        method: 'POST',
        body: {
          cidr: cidr.trim(),
          category: category.trim(),
          source: 'manual',
          severity,
          // Local midnight: the date picker speaks the operator's timezone.
          expires_at: expires ? new Date(`${expires}T00:00:00`).toISOString() : null,
        },
      }),
    onSuccess: () => {
      toast({ title: 'Custom indicator added', variant: 'success' });
      setCidr('');
      setCategory('');
      setExpires('');
      queryClient.invalidateQueries({ queryKey: ['threat-indicators'] });
      queryClient.invalidateQueries({ queryKey: ['threat-feeds'] });
    },
    onError: (err: Error) =>
      toast({ title: 'Could not add indicator', description: err.message, variant: 'error' }),
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: number) =>
      apiFetch(`/admin/api/flows/threat-intel/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      toast({ title: 'Indicator removed', variant: 'info' });
      queryClient.invalidateQueries({ queryKey: ['threat-indicators'] });
      queryClient.invalidateQueries({ queryKey: ['threat-feeds'] });
    },
    onError: (err: Error) =>
      toast({ title: 'Delete failed', description: err.message, variant: 'error' }),
  });

  const columns = useMemo<ColumnDef<Indicator, unknown>[]>(
    () => [
      {
        accessorKey: 'cidr',
        header: 'Indicator',
        cell: ({ row }) => (
          <span className="font-mono text-xs font-semibold text-text">{row.original.cidr}</span>
        ),
      },
      {
        accessorKey: 'category',
        header: 'Category',
        cell: ({ row }) => (
          <span className="font-mono text-[11px] text-text-dim">{row.original.category || '—'}</span>
        ),
      },
      {
        accessorKey: 'source',
        header: 'Source',
        cell: ({ row }) => (
          <span className="font-mono text-[11px] text-text-faint">{row.original.source || '—'}</span>
        ),
      },
      {
        accessorKey: 'severity',
        header: 'Severity',
        cell: ({ row }) => (
          <span
            className={cn(
              'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
              SEVERITY_STYLE[row.original.severity ?? 'info'] ?? SEVERITY_STYLE['info'],
            )}
          >
            {row.original.severity || 'info'}
          </span>
        ),
      },
      {
        id: 'expires',
        header: 'Expires',
        cell: ({ row }) => (
          <span className="font-mono text-[11px] text-text-dim">
            {row.original.expires_at ? expiryLabel(row.original.expires_at) : 'never'}
          </span>
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex justify-end">
            <Button  variant="danger-icon"
              type="button"
              aria-label={`Delete ${row.original.cidr}`}
              onClick={() => setIndicatorToDelete(row.original)}
              
            >
              <Trash2 className="h-3.5 w-3.5" />
            </Button>
          </div>
        ),
      },
    ],
    [deleteMutation],
  );

  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-border bg-bg-card p-3.5 space-y-3">
        <h2 className="text-sm font-semibold text-text">Add custom operator indicator</h2>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-2">
          <input
            type="text"
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            placeholder="IP or CIDR"
            className="rounded-md border border-border bg-bg-panel px-3 py-1.5 font-mono text-xs text-text"
          />
          <input
            type="text"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            placeholder="Category / ticket"
            className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text"
          />
          <Select  className="rounded-md px-3 py-1.5"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            aria-label="Indicator severity"
            
          >
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
            <option value="info">Info</option>
          </Select>
          <input
            type="date"
            value={expires}
            onChange={(e) => setExpires(e.target.value)}
            aria-label="Expiry date (optional)"
            className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text"
          />
        </div>
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] text-text-faint">
            Source is recorded as <span className="font-mono">manual</span>. Expiry is optional.
          </span>
          <button
            type="button"
            disabled={!cidr.trim() || addMutation.isPending}
            onClick={() => addMutation.mutate()}
            className="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-on-accent disabled:opacity-50"
          >
            <Plus className="h-3.5 w-3.5" />
            Add indicator
          </button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-bg-card p-2.5">
        <Search className="ml-1 h-3.5 w-3.5 text-text-faint" />
        <input
          type="search"
          value={filters.q}
          onChange={(e) => {
            setFilters((f) => ({ ...f, q: e.target.value }));
            setPage(0);
          }}
          placeholder="Search indicator…"
          className="min-w-[160px] flex-1 rounded border border-border bg-bg-panel px-2.5 py-1 font-mono text-xs text-text"
        />
        <input
          type="text"
          value={filters.source}
          onChange={(e) => {
            setFilters((f) => ({ ...f, source: e.target.value }));
            setPage(0);
          }}
          placeholder="source"
          className="w-28 rounded border border-border bg-bg-panel px-2.5 py-1 font-mono text-xs text-text"
        />
        <input
          type="text"
          value={filters.category}
          onChange={(e) => {
            setFilters((f) => ({ ...f, category: e.target.value }));
            setPage(0);
          }}
          placeholder="category"
          className="w-28 rounded border border-border bg-bg-panel px-2.5 py-1 font-mono text-xs text-text"
        />
        <Select className="px-2.5 py-1"
          value={filters.severity}
          onChange={(e) => {
            setFilters((f) => ({ ...f, severity: e.target.value }));
            setPage(0);
          }}
          aria-label="Filter by severity"
         
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="warning">Warning</option>
          <option value="info">Info</option>
        </Select>
        <label className="inline-flex items-center gap-1.5 text-[11px] text-text-dim">
          <input
            type="checkbox"
            checked={filters.activeOnly}
            onChange={(e) => {
              setFilters((f) => ({ ...f, activeOnly: e.target.checked }));
              setPage(0);
            }}
          />
          Active only
        </label>
        <button
          type="button"
          onClick={() => {
            setFilters(EMPTY_INDICATOR_FILTERS);
            setPage(0);
          }}
          className="ml-auto rounded border border-border bg-bg-panel px-2.5 py-1 text-[11px] text-text-dim hover:text-text"
        >
          Clear
        </button>
      </div>

      {searchError && (
        <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit">
          Could not search indicators: {searchErrorObj instanceof Error ? searchErrorObj.message : 'request failed'}
        </div>
      )}

      <ResponsiveDataView
        data={entries}
        columns={columns}
        isLoading={isLoading}
        emptyTitle="No indicators match."
        emptyDescription="Adjust the filters or add a custom indicator."
        renderMobileCard={(ind) => (
          <div className="flex items-center justify-between">
            <div>
              <div className="font-mono text-xs font-semibold text-text">{ind.cidr}</div>
              <div className="text-[10px] text-text-dim">
                {ind.category || 'uncategorized'} · {ind.source || 'manual'}
              </div>
            </div>
            <span
              className={cn(
                'rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
                SEVERITY_STYLE[ind.severity ?? 'info'] ?? SEVERITY_STYLE['info'],
              )}
            >
              {ind.severity || 'info'}
            </span>
          </div>
        )}
      />

      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[11px] text-text-dim">
          {entries.length === 0
            ? `0 of ${total}`
            : `${offset + 1}–${offset + entries.length} of ${total}`}
        </span>
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            disabled={page === 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            className="rounded border border-border bg-bg-panel px-2.5 py-1 text-[11px] text-text disabled:opacity-40"
          >
            Prev
          </button>
          <button
            type="button"
            disabled={offset + entries.length >= total}
            onClick={() => setPage((p) => p + 1)}
            className="rounded border border-border bg-bg-panel px-2.5 py-1 text-[11px] text-text disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </div>

      <ConfirmDialog
        open={!!indicatorToDelete}
        onOpenChange={(open) => {
          if (!open) setIndicatorToDelete(null);
        }}
        title={`Delete indicator ${indicatorToDelete?.cidr ?? ''}?`}
        description="A manual indicator cannot be recovered; a feed-sourced one returns on the next sync."
        confirmLabel="Delete indicator"
        destructive
        pending={deleteMutation.isPending}
        onConfirm={() => {
          if (!indicatorToDelete) return;
          deleteMutation.mutate(indicatorToDelete.id, {
            onSuccess: () => setIndicatorToDelete(null),
          });
        }}
      />
    </div>
  );
}

function StormTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { data, isError, error, isLoading } = useQuery({
    queryKey: ['storm-tuning'],
    queryFn: () => apiFetch<{ storm_sources?: number }>('/admin/api/threat-intel/storm-tuning'),
  });
  const [value, setValue] = useState<string | null>(null);
  // While the threshold is loading the field is EMPTY, not 25: a prefilled
  // number reads as the server's value, and saving it would overwrite the
  // real threshold with a guess.
  const current = value ?? (isLoading ? '' : String(data?.storm_sources ?? 25));
  const valid = current.trim() !== '' && Number.isFinite(Number(current));

  const save = useMutation({
    mutationFn: async () =>
      apiFetch('/admin/api/threat-intel/storm-tuning', {
        method: 'PATCH',
        body: { storm_sources: Math.max(0, Math.floor(Number(current) || 0)) },
      }),
    onSuccess: () => {
      toast({ title: 'Storm threshold saved', variant: 'success' });
      setValue(null);
      queryClient.invalidateQueries({ queryKey: ['storm-tuning'] });
    },
    onError: (err: Error) =>
      toast({ title: 'Save failed', description: err.message, variant: 'error' }),
  });

  return (
    <div className="max-w-xl rounded-xl border border-border bg-bg-card p-5 space-y-3">
      {isError && (
        <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit" role="alert">
          Could not load the storm threshold: {error instanceof Error ? error.message : 'request failed'}
        </div>
      )}
      <h2 className="text-sm font-semibold text-text">Security storm digest threshold</h2>
      <p className="text-xs text-text-dim">
        When more distinct attacking sources than this cross the detector in a window, alerts are
        coalesced into one digest instead of one alert per source. <span className="font-mono">0</span>{' '}
        disables the digest.
      </p>
      <label className="block">
        <span className="mb-1 block text-xs font-medium text-text-dim">Distinct sources</span>
        <input
          type="number"
          min={0}
          max={100000}
          value={current}
          disabled={isLoading}
          onChange={(e) => setValue(e.target.value)}
          className="w-40 rounded-md border border-border bg-bg-panel px-3 py-2 font-mono text-xs text-text disabled:opacity-60"
        />
        {isLoading ? (
          <span className="mt-1 block text-[11px] text-text-faint">Loading the current threshold…</span>
        ) : null}
      </label>
      <Button
        type="button"
        disabled={save.isPending || value === null || !valid || isLoading}
        onClick={() => save.mutate()}
        
      >
        {save.isPending ? 'Saving…' : 'Save threshold'}
      </Button>
    </div>
  );
}
