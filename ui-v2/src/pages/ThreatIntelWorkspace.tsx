import { useState, useMemo } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ShieldAlert, Search, Plus, Trash2, Globe, Sliders } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn } from '@/lib/utils';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { useToast } from '@/components/ui/toast';
import { ColumnDef } from '@tanstack/react-table';

type ThreatTab = 'lookup' | 'feeds' | 'storm';

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
            IP Reputation Lookup, Threat Feeds & Storm Digest Controls
          </h1>
        </div>

        <div className="flex items-center gap-1 rounded-lg bg-bg-panel p-1 border border-border self-start">
          <button
            type="button"
            onClick={() => setTab('lookup')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'lookup'
                ? 'bg-bg-card text-text shadow-sm border border-border'
                : 'text-text-dim hover:text-text'
            )}
          >
            <Globe className="h-3.5 w-3.5 text-accent" />
            IP & Geo Lookup
          </button>
          <button
            type="button"
            onClick={() => setTab('feeds')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'feeds'
                ? 'bg-bg-card text-text shadow-sm border border-border'
                : 'text-text-dim hover:text-text'
            )}
          >
            <ShieldAlert className="h-3.5 w-3.5 text-accent" />
            Feeds & Indicators
          </button>
          <button
            type="button"
            onClick={() => setTab('storm')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'storm'
                ? 'bg-bg-card text-text shadow-sm border border-border'
                : 'text-text-dim hover:text-text'
            )}
          >
            <Sliders className="h-3.5 w-3.5 text-accent" />
            Storm Digest Tuning
          </button>
        </div>
      </div>

      {activeTab === 'lookup' && <IpLookupSubTab />}
      {activeTab === 'feeds' && <FeedsAndIndicatorsSubTab />}
      {activeTab === 'storm' && <StormTuningSubTab />}
    </div>
  );
}

function IpLookupSubTab() {
  const [ipInput, setIpInput] = useState('');
  const [lookupResult, setLookupResult] = useState<any>(null);
  const [geoResult, setGeoResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const runLookup = async () => {
    const ip = ipInput.trim();
    if (!ip) return;
    setLoading(true);
    try {
      // LookupThreatIntel reads ?q= (not ?ip=). Resolve both panels
      // independently: a threat-lookup 400 used to take the geo panel down with
      // it because the pair shared one Promise.all rejection.
      const [ti, geo] = await Promise.allSettled([
        apiFetch<any>(`/admin/api/threat-intel/lookup?q=${encodeURIComponent(ip)}`),
        apiFetch<any>(`/admin/api/geo/lookup?ips=${encodeURIComponent(ip)}`),
      ]);
      setLookupResult(ti.status === 'fulfilled' ? ti.value : { error: ti.reason?.message });
      setGeoResult(geo.status === 'fulfilled' ? geo.value : { error: geo.reason?.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
        <h2 className="text-sm font-semibold text-text">Real-Time IP Reputation & DB-IP Geolocation Lookup</h2>
        <div className="flex items-center gap-2 max-w-xl">
          <input
            type="text"
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            placeholder="Enter IPv4 or IPv6 address (e.g. 1.1.1.1)"
            className="flex-1 rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text focus:border-accent focus:outline-none"
          />
          <button
            type="button"
            disabled={!ipInput.trim() || loading}
            onClick={runLookup}
            className="flex items-center gap-1.5 rounded-md bg-accent px-4 py-2 text-xs font-semibold text-white hover:opacity-90"
          >
            <Search className="h-3.5 w-3.5" />
            {loading ? 'Checking…' : 'Lookup IP'}
          </button>
        </div>

        {(lookupResult || geoResult) && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            <div className="rounded-lg border border-border bg-bg-panel p-3.5">
              <div className="text-xs font-semibold text-text mb-2">Threat Feed Matches</div>
              <pre className="font-mono text-xs text-text overflow-x-auto">
                {JSON.stringify(lookupResult, null, 2)}
              </pre>
            </div>
            <div className="rounded-lg border border-border bg-bg-panel p-3.5">
              <div className="text-xs font-semibold text-text mb-2">Geolocation & ASN (DB-IP)</div>
              <pre className="font-mono text-xs text-text overflow-x-auto">
                {JSON.stringify(geoResult, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function FeedsAndIndicatorsSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [newIndicator, setNewIndicator] = useState('');
  const [newLabel, setNewLabel] = useState('');

  const { data: feedsRes, isLoading } = useQuery({
    queryKey: ['threat-feeds'],
    queryFn: () => apiFetch<any>('/admin/api/threat-intel/feeds'),
  });

  const { data: indicatorsRes } = useQuery({
    queryKey: ['threat-indicators'],
    queryFn: () => apiFetch<any>('/admin/api/threat-intel/search?limit=50'),
  });

  // GetThreatFeeds returns the per-feed rows under `status`
  // ({feeds, loaded_count, by_source}); SearchThreatIntel returns `entries`.
  const feeds: Array<{
    source: string;
    entry_count: number;
    enabled: boolean;
    last_error?: string;
  }> = feedsRes?.status ?? [];
  const indicators: Array<{
    id: number;
    cidr: string;
    category?: string;
    source?: string;
    severity?: string;
  }> = indicatorsRes?.entries ?? [];

  const toggleFeedMutation = useMutation({
    mutationFn: async ({ source, enabled }: { source: string; enabled: boolean }) =>
      apiFetch(`/admin/api/threat-intel/feeds/${encodeURIComponent(source)}`, {
        method: 'PATCH',
        body: { enabled },
      }),
    onSuccess: () => {
      toast({ title: 'Threat feed state updated', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['threat-feeds'] });
    },
  });

  const addIndicatorMutation = useMutation({
    mutationFn: async () =>
      apiFetch('/admin/api/flows/threat-intel', {
        method: 'POST',
        // AddThreatIntel requires `cidr`; the old ip_or_cidr/description body
        // was silently dropped and every add 400'd. threat_intel has no
        // description column, so the free-text box is the category.
        body: {
          cidr: newIndicator.trim(),
          category: newLabel.trim(),
          source: 'manual',
          severity: 'warning',
        },
      }),
    onSuccess: () => {
      toast({ title: 'Custom IOC indicator added', variant: 'success' });
      setNewIndicator('');
      setNewLabel('');
      queryClient.invalidateQueries({ queryKey: ['threat-indicators'] });
    },
  });

  const deleteIndicatorMutation = useMutation({
    mutationFn: async (id: number) => apiFetch(`/admin/api/flows/threat-intel/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      toast({ title: 'Indicator removed', variant: 'info' });
      queryClient.invalidateQueries({ queryKey: ['threat-indicators'] });
    },
  });

  const feedCols = useMemo<ColumnDef<any, unknown>[]>(
    () => [
      {
        accessorKey: 'source',
        header: 'Threat Feed Source',
        cell: ({ row }) => (
          <span className="font-semibold text-xs text-text">
            {row.original.name || row.original.source}
          </span>
        ),
      },
      {
        accessorKey: 'entry_count',
        header: 'Active IOCs',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-accent">{row.original.entry_count ?? 0}</span>
        ),
      },
      {
        id: 'toggle',
        header: 'Enabled',
        cell: ({ row }) => {
          const src = row.original.source || row.original.name;
          const enabled = row.original.enabled !== false;
          return (
            <button
              type="button"
              onClick={() => toggleFeedMutation.mutate({ source: src, enabled: !enabled })}
              className={cn(
                'rounded px-2.5 py-1 text-xs font-semibold',
                enabled ? 'bg-sig-ok/15 text-sig-ok' : 'bg-bg-panel text-text-dim'
              )}
            >
              {enabled ? 'Enabled' : 'Disabled'}
            </button>
          );
        },
      },
    ],
    [toggleFeedMutation]
  );

  return (
    <div className="space-y-5">
      <ResponsiveDataView
        data={feeds}
        columns={feedCols}
        isLoading={isLoading}
        emptyTitle="No threat feeds registered."
        renderMobileCard={(f) => (
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-text">{f.source}</span>
            <span className="font-mono text-accent">{f.entry_count ?? 0} IOCs</span>
          </div>
        )}
      />

      <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
        <h3 className="text-sm font-semibold text-text">Custom Operator Indicators ({indicators.length})</h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          <input
            type="text"
            value={newIndicator}
            onChange={(e) => setNewIndicator(e.target.value)}
            placeholder="IP or CIDR (e.g. 198.51.100.0/24)"
            className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text"
          />
          <input
            type="text"
            value={newLabel}
            onChange={(e) => setNewLabel(e.target.value)}
            placeholder="Category / Ticket ID"
            className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text"
          />
          <button
            type="button"
            disabled={!newIndicator.trim() || addIndicatorMutation.isPending}
            onClick={() => addIndicatorMutation.mutate()}
            className="flex items-center justify-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white"
          >
            <Plus className="h-3.5 w-3.5" /> Add Custom IOC
          </button>
        </div>

        {indicators.length > 0 && (
          <div className="space-y-1.5 pt-2">
            {indicators.slice(0, 15).map((ind) => (
              <div
                key={ind.id || ind.cidr}
                className="flex items-center justify-between rounded border border-border bg-bg-panel px-3 py-1.5 text-xs"
              >
                <span className="font-mono text-text">
                  {ind.cidr} —{' '}
                  <span className="text-text-dim">{ind.category || ind.source || 'manual'}</span>
                </span>
                {ind.id && (
                  <button
                    type="button"
                    onClick={() => deleteIndicatorMutation.mutate(ind.id)}
                    className="text-sig-crit hover:opacity-80"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function StormTuningSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: tuning } = useQuery({
    queryKey: ['storm-tuning'],
    queryFn: () => apiFetch<any>('/admin/api/threat-intel/storm-tuning'),
  });

  const [threshold, setThreshold] = useState<number>(10);

  const saveMutation = useMutation({
    mutationFn: async () =>
      apiFetch('/admin/api/threat-intel/storm-tuning', {
        method: 'PATCH',
        body: { digest_threshold: threshold },
      }),
    onSuccess: () => {
      toast({ title: 'Storm digest threshold updated', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['storm-tuning'] });
    },
  });

  return (
    <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4 max-w-xl">
      <h2 className="text-sm font-semibold text-text">Threat-Intel Alert Storm Digest Tuning</h2>
      <p className="text-xs text-text-dim">
        Coalesces bursts of threat-intel flow matches into a single digest notification when volume exceeds the threshold.
      </p>
      <div className="flex items-center gap-3">
        <input
          type="number"
          min={1}
          value={threshold || tuning?.digest_threshold || 10}
          onChange={(e) => setThreshold(Number(e.target.value))}
          className="w-32 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text"
        />
        <button
          type="button"
          onClick={() => saveMutation.mutate()}
          className="rounded-md bg-accent px-4 py-1.5 text-xs font-semibold text-white"
        >
          Save Threshold
        </button>
      </div>
    </div>
  );
}
