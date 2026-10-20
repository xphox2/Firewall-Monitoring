import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { RadioTower, Search } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { formatRelativeTime } from '@/lib/utils';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { ColumnDef } from '@tanstack/react-table';

interface TrapRow {
  id: number;
  timestamp: string;
  device_id?: number;
  device_name?: string;
  source_ip?: string;
  trap_oid: string;
  trap_type?: string;
  severity?: string;
  variables?: string | Record<string, any>;
}

export function TrapsWorkspace() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTrap, setSelectedTrap] = useState<TrapRow | null>(null);

  const { data: trapsRes, isLoading } = useQuery({
    queryKey: ['snmp-traps', searchQuery],
    queryFn: () => {
      const params = new URLSearchParams({ limit: '100' });
      if (searchQuery.trim()) params.set('search', searchQuery.trim());
      return apiFetch<any>(`/admin/api/traps?${params.toString()}`);
    },
    refetchInterval: 15_000,
  });

  const traps: TrapRow[] = Array.isArray(trapsRes)
    ? trapsRes
    : trapsRes?.traps ?? trapsRes?.items ?? trapsRes?.data ?? [];

  const columns = useMemo<ColumnDef<TrapRow, unknown>[]>(
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
        accessorKey: 'device_name',
        header: 'Source Device',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text">
            {row.original.device_name || row.original.source_ip || `Dev #${row.original.device_id ?? '?'}`}
          </span>
        ),
      },
      {
        accessorKey: 'trap_type',
        header: 'Trap Type / OID',
        cell: ({ row }) => (
          <div>
            <div className="font-semibold text-xs text-text">
              {row.original.trap_type || 'SNMP Trap'}
            </div>
            <div className="font-mono text-[11px] text-accent">{row.original.trap_oid}</div>
          </div>
        ),
      },
    ],
    []
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-border pb-3">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <RadioTower className="h-3.5 w-3.5" />
            Telemetry / SNMP Traps Explorer
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            Real-Time SNMPv2c / v3 Trap Stream & VarBind Inspector
          </h1>
        </div>

        <div className="relative w-full sm:w-72">
          <Search className="h-3.5 w-3.5 text-text-faint absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter by OID or trap type..."
            className="w-full rounded border border-border bg-bg-card pl-8 pr-3 py-1.5 text-xs font-mono text-text focus:border-accent focus:outline-none"
          />
        </div>
      </div>

      <ResponsiveDataView
        data={traps}
        columns={columns}
        isLoading={isLoading}
        onRowClick={(row) => setSelectedTrap(row)}
        emptyTitle="No SNMP traps received in this window."
        renderMobileCard={(t) => (
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs text-text">{t.trap_type || 'SNMP Trap'}</span>
              <span className="font-mono text-[11px] text-text-dim">{formatRelativeTime(t.timestamp)}</span>
            </div>
            <div className="font-mono text-xs text-accent break-all">{t.trap_oid}</div>
          </div>
        )}
      />

      <SlideOverDrawer
        open={Boolean(selectedTrap)}
        onOpenChange={(open) => {
          if (!open) setSelectedTrap(null);
        }}
        title="SNMP Trap VarBind Payload"
        subtitle={selectedTrap?.trap_oid}
      >
        <pre className="rounded-lg border border-border bg-bg-panel p-3 font-mono text-xs text-text overflow-x-auto whitespace-pre-wrap">
          {JSON.stringify(selectedTrap ?? {}, null, 2)}
        </pre>
      </SlideOverDrawer>
    </div>
  );
}
