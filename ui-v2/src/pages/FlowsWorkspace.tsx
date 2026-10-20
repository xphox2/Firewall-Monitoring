import { useState, useMemo } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Waves, Check, ArrowRight } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn, formatBytes, formatRelativeTime } from '@/lib/utils';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { useToast } from '@/components/ui/toast';
import { ColumnDef } from '@tanstack/react-table';

type FlowsTab = 'talkers' | 'conversations' | 'samples' | 'detections';
type TimeWindow = '1h' | '6h' | '24h' | '7d';

export function FlowsWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = (searchParams.get('tab') as FlowsTab) || 'talkers';
  const [windowRange, setWindowRange] = useState<TimeWindow>('1h');

  const setTab = (tab: FlowsTab) => {
    setSearchParams({ tab }, { replace: true });
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3 border-b border-border pb-3">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <Waves className="h-3.5 w-3.5" />
            Telemetry / Network Flows (sFlow & NetFlow)
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            Top Talkers, Conversations, Flow Samples & Anomaly Detections
          </h1>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-0.5 rounded-lg bg-bg-panel p-1 border border-border">
            {(['1h', '6h', '24h', '7d'] as TimeWindow[]).map((w) => (
              <button
                key={w}
                type="button"
                onClick={() => setWindowRange(w)}
                className={cn(
                  'rounded px-2 py-1 text-xs font-mono font-medium transition-colors',
                  windowRange === w ? 'bg-accent text-white' : 'text-text-dim hover:text-text'
                )}
              >
                {w}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 rounded-lg bg-bg-panel p-1 border border-border">
            {(
              [
                { id: 'talkers', label: 'Top Talkers' },
                { id: 'conversations', label: 'Conversations' },
                { id: 'samples', label: 'Flow Samples' },
                { id: 'detections', label: 'Detections' },
              ] as const
            ).map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id)}
                className={cn(
                  'rounded-md px-3 py-1 text-xs font-medium transition-colors',
                  activeTab === t.id
                    ? 'bg-bg-card text-text shadow-sm border border-border'
                    : 'text-text-dim hover:text-text'
                )}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {activeTab === 'talkers' && <TopTalkersSubTab windowRange={windowRange} />}
      {activeTab === 'conversations' && <ConversationsSubTab windowRange={windowRange} />}
      {activeTab === 'samples' && <FlowSamplesSubTab />}
      {activeTab === 'detections' && <FlowDetectionsSubTab />}
    </div>
  );
}

function windowToHours(w: TimeWindow): number {
  switch (w) {
    case '1h':
      return 1;
    case '6h':
      return 6;
    case '24h':
      return 24;
    case '7d':
      return 168;
  }
}

function TopTalkersSubTab({ windowRange }: { windowRange: TimeWindow }) {
  const hours = windowToHours(windowRange);
  const { data: stats, isLoading } = useQuery({
    queryKey: ['flow-stats', windowRange],
    queryFn: () => apiFetch<any>(`/admin/api/flows/stats?range=${windowRange}&hours=${hours}`),
    refetchInterval: 20_000,
  });

  if (isLoading) {
    return (
      <div className="rounded-xl border border-border bg-bg-card p-8 text-center text-sm text-text-dim">
        Loading sFlow / NetFlow top talkers…
      </div>
    );
  }

  // GetFlowStats emits top_sources / by_protocol as {key,count} where key is
  // the address or protocol name and count is BYTES. The invented
  // top_talkers/protocols names rendered both cards permanently empty.
  const talkers: Array<{ key: string; count: number }> = stats?.top_sources ?? [];
  const protocols: Array<{ key: string; count: number }> = stats?.by_protocol ?? [];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div className="lg:col-span-2 rounded-xl border border-border bg-bg-card p-4 space-y-3">
        <h2 className="text-sm font-semibold text-text">Top Source Talkers ({windowRange})</h2>
        {talkers.length === 0 ? (
          <p className="text-xs text-text-dim">No flow talkers recorded in this window.</p>
        ) : (
          <div className="space-y-2">
            {talkers.slice(0, 12).map((t, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between rounded-lg border border-border bg-bg-panel px-3 py-2 text-xs font-mono"
              >
                <div className="flex items-center gap-2">
                  <span className="text-text font-semibold">{t.key}</span>
                </div>
                <span className="text-accent">{formatBytes(t.count ?? 0)}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
        <h2 className="text-sm font-semibold text-text">Protocol Distribution</h2>
        {protocols.length === 0 ? (
          <p className="text-xs text-text-dim">No protocol distribution available.</p>
        ) : (
          <div className="space-y-2">
            {protocols.map((p, idx) => (
              <div key={idx} className="flex items-center justify-between text-xs font-mono">
                <span className="uppercase text-text">{p.key}</span>
                <span className="text-text-dim">{formatBytes(p.count ?? 0)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ConversationsSubTab({ windowRange }: { windowRange: TimeWindow }) {
  const hours = windowToHours(windowRange);
  const { data: stats, isLoading } = useQuery({
    queryKey: ['flow-stats', windowRange],
    queryFn: () => apiFetch<any>(`/admin/api/flows/stats?range=${windowRange}&hours=${hours}`),
  });

  // FlowConversation serializes src_addr/dst_addr (flow_samples has no
  // src_ip/dst_ip columns). Reading src_ip produced an empty pair column.
  const convos: Array<{
    src_addr: string;
    dst_addr: string;
    src_port: number;
    dst_port: number;
    protocol: string;
    bytes: number;
  }> = stats?.top_conversations ?? [];

  const columns = useMemo<ColumnDef<any, unknown>[]>(
    () => [
      {
        id: 'pair',
        header: 'Conversation Pair',
        cell: ({ row }) => (
          <div className="font-mono text-xs flex items-center gap-1.5">
            <span className="text-text">
              {row.original.src_addr}:{row.original.src_port}
            </span>
            <ArrowRight className="h-3 w-3 text-accent" />
            <span className="text-text">
              {row.original.dst_addr}:{row.original.dst_port}
            </span>
          </div>
        ),
      },
      {
        accessorKey: 'bytes',
        header: 'Estimated Volume',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-accent">
            {formatBytes(row.original.bytes ?? 0)}
          </span>
        ),
      },
    ],
    []
  );

  return (
    <ResponsiveDataView
      data={convos}
      columns={columns}
      isLoading={isLoading}
      emptyTitle="No flow conversations recorded in this window."
      renderMobileCard={(c) => (
        <div className="flex items-center justify-between font-mono text-xs">
          <span>
            {c.src_addr} → {c.dst_addr}
          </span>
          <span className="text-accent">{formatBytes(c.bytes ?? 0)}</span>
        </div>
      )}
    />
  );
}

function FlowSamplesSubTab() {
  const [selectedSample, setSelectedSample] = useState<any>(null);

  const { data: flowsRes, isLoading } = useQuery({
    queryKey: ['flow-samples'],
    queryFn: () => apiFetch<any>('/admin/api/flows?limit=100'),
    refetchInterval: 15_000,
  });

  const samples: any[] = Array.isArray(flowsRes)
    ? flowsRes
    : flowsRes?.flows ?? flowsRes?.items ?? [];

  const columns = useMemo<ColumnDef<any, unknown>[]>(
    () => [
      {
        accessorKey: 'timestamp',
        header: 'Time',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {formatRelativeTime(row.original.timestamp)}
          </span>
        ),
      },
      {
        accessorKey: 'src_addr',
        header: 'Source',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text">
            {row.original.src_addr}:{row.original.src_port}
          </span>
        ),
      },
      {
        accessorKey: 'dst_addr',
        header: 'Destination',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text">
            {row.original.dst_addr}:{row.original.dst_port}
          </span>
        ),
      },
      {
        accessorKey: 'bytes',
        header: 'Bytes',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">{formatBytes(row.original.bytes ?? 0)}</span>
        ),
      },
    ],
    []
  );

  return (
    <>
      <ResponsiveDataView
        data={samples}
        columns={columns}
        isLoading={isLoading}
        onRowClick={(row) => setSelectedSample(row)}
        emptyTitle="No raw sFlow/NetFlow samples received recently."
        renderMobileCard={(s) => (
          <div className="space-y-1 font-mono text-xs">
            <div className="text-text">
              {s.src_addr}:{s.src_port} → {s.dst_addr}:{s.dst_port}
            </div>
            <div className="text-text-dim">{formatBytes(s.bytes ?? 0)}</div>
          </div>
        )}
      />

      <SlideOverDrawer
        open={Boolean(selectedSample)}
        onOpenChange={(open) => {
          if (!open) setSelectedSample(null);
        }}
        title="Flow Sample Inspector"
      >
        <pre className="rounded-lg border border-border bg-bg-panel p-3 font-mono text-xs text-text overflow-x-auto">
          {JSON.stringify(selectedSample ?? {}, null, 2)}
        </pre>
      </SlideOverDrawer>
    </>
  );
}

function FlowDetectionsSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: detectionsRes, isLoading } = useQuery({
    queryKey: ['flow-detections'],
    queryFn: () => apiFetch<any>('/admin/api/flows/detections?limit=100'),
  });

  const detections: any[] = Array.isArray(detectionsRes)
    ? detectionsRes
    : detectionsRes?.detections ?? detectionsRes?.items ?? [];

  const ackMutation = useMutation({
    mutationFn: async (id: number) => apiFetch(`/admin/api/flows/detections/${id}/ack`, { method: 'POST' }),
    onSuccess: () => {
      toast({ title: 'Flow detection acknowledged', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['flow-detections'] });
    },
  });

  const columns = useMemo<ColumnDef<any, unknown>[]>(
    () => [
      {
        accessorKey: 'detected_at',
        header: 'Detected',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {formatRelativeTime(row.original.detected_at || row.original.timestamp)}
          </span>
        ),
      },
      {
        accessorKey: 'detector',
        header: 'Detector',
        cell: ({ row }) => (
          <span className="rounded bg-sig-warn/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-sig-warn">
            {row.original.detector || 'Anomaly'}
          </span>
        ),
      },
      {
        accessorKey: 'src_addr',
        header: 'Subject IP',
        cell: ({ row }) => <span className="font-mono text-xs text-text">{row.original.src_addr || '—'}</span>,
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex justify-end">
            {!row.original.acknowledged && (
              <button
                type="button"
                onClick={() => ackMutation.mutate(row.original.id)}
                className="flex items-center gap-1 rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text hover:bg-bg-hover"
              >
                <Check className="h-3 w-3 text-sig-ok" /> Ack
              </button>
            )}
          </div>
        ),
      },
    ],
    [ackMutation]
  );

  return (
    <ResponsiveDataView
      data={detections}
      columns={columns}
      isLoading={isLoading}
      emptyTitle="No sFlow anomaly detections triggered."
      renderMobileCard={(d) => (
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-sig-warn">{d.detector || 'Anomaly'}</span>
          <span className="font-mono text-text">{d.src_addr}</span>
        </div>
      )}
    />
  );
}
