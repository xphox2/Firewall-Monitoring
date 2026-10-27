import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  HardDrive,
  Database,
  Archive,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  PauseCircle,
  RotateCcw,
  Search,
  FolderOpen,
  Play,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { apiFetch, ApiError, type MeResponse } from '@/lib/api';
import { cn, formatBytes, formatNumber, formatRelativeTime } from '@/lib/utils';
import { StickySaveBar } from '@/components/ui/sticky-save-bar';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import type { ColumnDef } from '@tanstack/react-table';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { StepUpAuthDialog, type StepUpCredentials } from '@/components/ui/step-up-auth-dialog';
import { useToast } from '@/components/ui/toast';
import { Textarea } from '@/components/ui/input';

// --- Types matching Go backend ---

interface ArchiveGateStream {
  stream: string;
  enabled: boolean;
  override_active: boolean;
  override_until?: string | null;
}

interface ArchiveChunkAttention {
  id: number;
  table_name: string;
  seq: number;
  period_start?: string;
  period_end?: string;
  status?: string;
  attempts?: number;
  error?: string;
}

interface ArchiveGateResponse {
  streams?: ArchiveGateStream[];
  needs_attention?: ArchiveChunkAttention[];
  max_hours?: number;
}

interface SystemSettingRow {
  key: string;
  value: string;
  category: string;
  type: string;
}

interface RetentionField {
  key: string;
  env_key: string;
  label: string;
  hint: string;
  unit: string;
  min: number;
  max: number;
  value: string;
  stored: string;
  env_value: string;
  source: 'ui' | 'env' | 'default';
}

interface SyslogSeverityRow {
  severity: number;
  name: string;
  days: number;
  months?: number;
  forever?: boolean;
  inherited?: boolean;
  tracked?: boolean;
  est_rows?: number;
  est_bytes?: number;
  rate_available?: boolean;
  rows_per_day?: number;
  bytes_per_day?: number;
  projected_bytes?: number;
  projected_forever?: boolean;
}

interface SyslogRetentionResponse {
  default_set: boolean;
  stats_available: boolean;
  rate_hours?: number;
  disk_width_measured?: boolean;
  volume_known?: boolean;
  volume_total_bytes?: number;
  volume_total_derived?: boolean;
  database_bytes?: number;
  current_syslog_bytes?: number;
  projected_syslog_bytes?: number;
  projected_forever?: boolean;
  severities: SyslogSeverityRow[];
}

interface ArchiveStatusResponse {
  health?: {
    verdict: 'healthy' | 'warning' | 'error' | 'disabled' | 'not_configured';
    summary: string;
    errors?: number;
    warnings?: number;
    last_success_at?: string;
    backlog_chunks?: number;
    eta_seconds?: number;
    verified_through?: string;
    findings?: Array<{
      severity: 'error' | 'warning' | 'info';
      title: string;
      meaning?: string;
      risk?: string;
      action?: string;
    }>;
  };
  config?: {
    target: 's3' | 'local';
    bucket?: string;
    local_dir?: string;
    prefix?: string;
    object_lock_mode?: string;
    object_lock_days?: number;
  };
  streams?: Array<{
    stream: string;
    state: string;
    verified_through?: string;
    backlog_chunks?: number;
    stored_bytes?: number;
    raw_bytes?: number;
    compression_ratio?: number;
  }>;
  needs_attention?: Array<{
    id: number;
    stream: string;
    period_start: string;
    period_end: string;
    last_error?: string;
    attempts?: number;
  }>;
}

interface ArchiveSettingField {
  key: string;
  kind: 'string' | 'int' | 'bool' | 'secret';
  value: string;
  source: 'ui' | 'env' | 'default';
  set?: boolean;
  hint?: string;
  location?: boolean;
}

interface ArchiveSettingsResponse {
  target: 's3' | 'local';
  location_locked?: boolean;
  fields: ArchiveSettingField[];
}

interface ArchiveRestoreJob {
  id: number;
  stream: string;
  // models.ArchiveRestoreJob wire names. The previous start_time/state/
  // chunks_*/rows_restored keys rendered every row as "undefined".
  from_day: string;
  to_day: string;
  status: string;
  objects_total: number;
  objects_done: number;
  rows_loaded: number;
  error?: string;
  created_at: string;
  expires_at?: string;
}

type StorageTab = 'retention' | 'archive-status' | 'archive-config';

function categorizeRetentionKey(key: string): string {
  if (key.includes('flow') || key.includes('sflow')) return 'Network Flows';
  if (key.includes('syslog') || key.includes('event') || key.includes('trap') || key.includes('alert'))
    return 'Logs, Events & Alerts';
  if (
    key.includes('interface') ||
    key.includes('status') ||
    key.includes('ping') ||
    key.includes('vpn') ||
    key.includes('sensor') ||
    key.includes('proc')
  )
    return 'Device Telemetry';
  return 'System & History';
}

const ARCHIVE_LABELS: Record<string, { label: string; hint: string; group: string }> = {
  ARCHIVE_TARGET: {
    label: 'Archive Storage Target',
    hint: 'S3-compatible object storage (Backblaze B2, AWS S3, MinIO) or a host-mounted local/NFS directory.',
    group: 'Target & Endpoint',
  },
  ARCHIVE_LOCAL_DIR: {
    label: 'Local Archive Directory',
    hint: 'Existing directory under ARCHIVE_ALLOWED_ROOT outside the Postgres volume.',
    group: 'Target & Endpoint',
  },
  ARCHIVE_S3_ENDPOINT: {
    label: 'S3 Endpoint URL',
    hint: 'https://host only (e.g. https://s3.us-west-002.example.com).',
    group: 'Target & Endpoint',
  },
  ARCHIVE_S3_REGION: {
    label: 'S3 Region',
    hint: 'Bucket region identifier (e.g. us-west-002).',
    group: 'Target & Endpoint',
  },
  ARCHIVE_S3_ACCESS_KEY_ID: {
    label: 'S3 Access Key ID',
    hint: 'Application key restricted to this bucket/prefix without delete privileges.',
    group: 'Credentials',
  },
  ARCHIVE_S3_SECRET_ACCESS_KEY: {
    label: 'S3 Secret Access Key',
    hint: 'Write-only encrypted secret. Leave blank to keep current secret.',
    group: 'Credentials',
  },
  ARCHIVE_S3_BUCKET: {
    label: 'Bucket Name',
    hint: 'Target S3/B2 bucket name.',
    group: 'Bucket & Object Lock',
  },
  ARCHIVE_S3_PREFIX: {
    label: 'Object Key Prefix',
    hint: 'Prefix prepended to every object (e.g. fwmon/prod).',
    group: 'Bucket & Object Lock',
  },
  ARCHIVE_S3_PATH_STYLE: {
    label: 'Use Path-Style Addressing',
    hint: 'Enable for Backblaze B2, MinIO, and Ceph RGW.',
    group: 'Bucket & Object Lock',
  },
  ARCHIVE_OBJECT_LOCK_MODE: {
    label: 'Object Lock Mode',
    hint: 'GOVERNANCE (recommended) or COMPLIANCE.',
    group: 'Bucket & Object Lock',
  },
  ARCHIVE_OBJECT_LOCK_DAYS: {
    label: 'Object Lock Retention (Days)',
    hint: '0 disables per-object lock retention (max 3000).',
    group: 'Bucket & Object Lock',
  },
  ARCHIVE_STAGING_DIR: {
    label: 'Local Staging Directory',
    hint: 'Directory with >= 2 GiB free where chunks are compressed before upload.',
    group: 'Streams & Staging',
  },
  ARCHIVE_SYSLOG_ENABLED: {
    label: 'Archive Raw Syslog Stream',
    hint: 'Export, verify, and gate raw syslog pruning on verified archive chunks.',
    group: 'Streams & Staging',
  },
  ARCHIVE_FLOWS_ENABLED: {
    label: 'Archive Raw Flows Stream',
    hint: 'Export and verify sFlow, NetFlow, and sFlow interface counters.',
    group: 'Streams & Staging',
  },
  ARCHIVE_WINDOW: {
    label: 'Syslog Export Window (UTC)',
    hint: 'HH:MM-HH:MM (or blank to run continuously).',
    group: 'Schedule & Pacing',
  },
  ARCHIVE_MIN_AGE_HOURS: {
    label: 'Minimum Chunk Age Before Export (Hours)',
    hint: '1 to 168 hours.',
    group: 'Schedule & Pacing',
  },
  ARCHIVE_SEAL_GRACE_HOURS: {
    label: 'Monthly Seal Grace Period (Hours)',
    hint: '6 to 168 hours after month end.',
    group: 'Schedule & Pacing',
  },
  ARCHIVE_SEAL_REVERIFY: {
    label: 'Monthly Seal Verification Mode',
    hint: 'head (check size + ETag) or full (stream back every object).',
    group: 'Schedule & Pacing',
  },
  ARCHIVE_SYSLOG_RATE_ROWS_PER_SEC: {
    label: 'Syslog Export Read Rate (rows/sec)',
    hint: '100 to 100,000 rows/sec.',
    group: 'Schedule & Pacing',
  },
  ARCHIVE_FLOW_RATE_ROWS_PER_SEC: {
    label: 'Flow Export Read Rate (rows/sec)',
    hint: '100 to 100,000 rows/sec.',
    group: 'Schedule & Pacing',
  },
  ARCHIVE_ALLOW_HTTP: {
    label: 'Allow Unencrypted HTTP Endpoint (Lab Only)',
    hint: 'Never enable on untrusted networks.',
    group: 'Schedule & Pacing',
  },
  ARCHIVE_ALLOW_PRIVATE_ENDPOINT: {
    label: 'Allow Private / RFC1918 Endpoint',
    hint: 'Enable for self-hosted MinIO, Garage, or SeaweedFS on LAN.',
    group: 'Schedule & Pacing',
  },
};

const S3_ONLY_RE =
  /^ARCHIVE_(S3_(ENDPOINT|REGION|BUCKET|PATH_STYLE|ACCESS_KEY_ID|SECRET_ACCESS_KEY)|OBJECT_LOCK_|ALLOW_)/;

/**
 * The archived telemetry streams.
 *
 * Read-only, so the columns are at module level. The table used to be a raw
 * `<table>` in a horizontal scroller, so a phone got a sideways scroll for
 * five columns.
 */
const archivedStreamColumns: ColumnDef<any, any>[] = [
  {
    accessorKey: 'stream',
    header: 'Stream',
    cell: ({ row }) => (
      <span className="font-semibold capitalize text-text">{row.original.stream}</span>
    ),
  },
  {
    accessorKey: 'state',
    header: 'Status',
    cell: ({ row }) => (
      <span
        className={cn(
          'inline-flex rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase',
          row.original.state === 'ok' && 'bg-sig-ok/15 text-sig-ok',
          (row.original.state === 'error' || row.original.state === 'stalled') &&
            'bg-sig-crit/15 text-sig-crit',
          row.original.state !== 'ok' &&
            row.original.state !== 'error' &&
            row.original.state !== 'stalled' &&
            'bg-bg-panel text-text-dim',
        )}
      >
        {row.original.state}
      </span>
    ),
  },
  {
    accessorKey: 'verified_through',
    header: 'Verified Through',
    cell: ({ row }) => (
      <span className="font-mono text-text-dim">
        {row.original.verified_through
          ? row.original.verified_through.slice(0, 16).replace('T', ' ') + ' UTC'
          : '—'}
      </span>
    ),
  },
  {
    accessorKey: 'backlog_chunks',
    header: 'Backlog',
    cell: ({ row }) => (
      <span className="font-mono text-text">{row.original.backlog_chunks ?? 0} chunks</span>
    ),
  },
  {
    accessorKey: 'stored_bytes',
    header: 'Stored Size',
    cell: ({ row }) => (
      <span className="font-mono text-text">{formatBytes(row.original.stored_bytes)}</span>
    ),
  },
];

/**
 * The effective retention window for one syslog severity.
 *
 * The table and the mobile card both show it, so it is computed once.
 */
function syslogEffectiveWindow(sev: any): string {
  if (sev.forever) return 'Kept forever';
  if (sev.months) return `${sev.months} ${sev.months === 1 ? 'month' : 'months'}`;
  return `${sev.days} days`;
}

export function StorageWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = ((searchParams.get('tab') as StorageTab) || 'retention') as StorageTab;
  const setTab = (tab: StorageTab) => {
    setSearchParams({ tab }, { replace: true });
  };

  const queryClient = useQueryClient();
  const toast = useToast();

  const { data: me } = useQuery({
    queryKey: ['me'],
    queryFn: () => apiFetch<MeResponse>('/admin/api/me'),
  });

  // --- Queries for Sub-Tab 1: Hot Retention Matrix ---
  const { data: allSettings = [] } = useQuery({
    queryKey: ['settings-all'],
    queryFn: () => apiFetch<SystemSettingRow[]>('/admin/api/settings'),
  });

  const { data: retentionData, isLoading: loadingRetention } = useQuery({
    queryKey: ['settings-retention-knobs'],
    queryFn: () => apiFetch<{ fields: RetentionField[] }>('/admin/api/settings/retention'),
  });

  const { data: syslogRetention, isLoading: loadingSyslogRet } = useQuery({
    queryKey: ['settings-syslog-retention'],
    queryFn: () => apiFetch<SyslogRetentionResponse>('/admin/api/settings/syslog-retention'),
  });

  // --- Queries for Sub-Tab 2: Archive Status & Restores ---
  const {
    data: archiveStatus,
    isLoading: loadingArchStatus,
    refetch: refetchArchiveStatus,
  } = useQuery({
    queryKey: ['archive-status'],
    queryFn: () => apiFetch<ArchiveStatusResponse>('/admin/api/archive/status'),
    refetchInterval: activeTab === 'archive-status' ? 15_000 : false,
  });

  const { data: restoresData, refetch: refetchRestores } = useQuery({
    queryKey: ['archive-restores'],
    queryFn: () => apiFetch<{ restores?: ArchiveRestoreJob[] } | ArchiveRestoreJob[]>('/admin/api/archive/restores'),
    enabled: activeTab === 'archive-status',
    refetchInterval: activeTab === 'archive-status' ? 15_000 : false,
  });

  // --- Queries for Sub-Tab 3: Archive Settings ---
  const { data: archiveSettings, isLoading: loadingArchSettings } = useQuery({
    queryKey: ['archive-settings'],
    queryFn: () => apiFetch<ArchiveSettingsResponse>('/admin/api/archive/settings'),
  });

  // =========================================================================
  // SUB-TAB 1 STATE: Hot Retention Matrix + Syslog Per-Severity Retention
  // =========================================================================
  const [retEdits, setRetEdits] = useState<Record<string, string>>({});
  const [retSearch, setRetSearch] = useState('');
  const [retCategory, setRetCategory] = useState<string>('ALL');
  const [onlyOverridden, setOnlyOverridden] = useState(false);
  const [savingRetention, setSavingRetention] = useState(false);

  // Baseline map for Retention tab (combines 26 data retention knobs + syslog severity keys)
  const retentionBaseline = useMemo(() => {
    const map: Record<string, string> = {};
    for (const f of retentionData?.fields || []) {
      map[f.key] = f.stored ?? '';
    }
    const findStored = (k: string) => allSettings.find((s) => s.key === k)?.value ?? '';
    map['syslog_retention_days_default'] = findStored('syslog_retention_days_default');
    map['syslog_summary_retention_days'] = findStored('syslog_summary_retention_days');
    for (let sev = 0; sev <= 7; sev++) {
      const k = `syslog_retention_days_${sev}`;
      map[k] = findStored(k);
    }
    return map;
  }, [retentionData, allSettings]);

  // Reset edits when baseline first loads
  useEffect(() => {
    setRetEdits({});
  }, [retentionBaseline]);

  const dirtyRetentionKeys = useMemo(() => {
    return Object.keys(retEdits).filter(
      (k) => (retEdits[k] ?? '') !== (retentionBaseline[k] ?? ''),
    );
  }, [retEdits, retentionBaseline]);

  const getRetVal = (key: string) =>
    key in retEdits ? retEdits[key] : (retentionBaseline[key] ?? '');


  /*
   * The syslog severity retention rows.
   *
   * The columns close over the retention edits, so they live inside the
   * component. The table used to be a raw `<table>` in a horizontal
   * scroller, so a phone got a sideways scroll for six columns — and the
   * "keep days" input was off-screen.
   */
  const syslogSeverityColumns: ColumnDef<any, any>[] = useMemo(
    () => [
      {
        accessorKey: 'severity',
        header: 'Severity',
        cell: ({ row }) => (
          <span className="font-medium whitespace-nowrap text-text">
            <span className="inline-block w-5 font-mono text-text-faint">{row.original.severity}</span>
            <span>{row.original.name}</span>
          </span>
        ),
      },
      {
        id: 'keep',
        header: 'Keep (Days)',
        cell: ({ row }) => {
          const key = `syslog_retention_days_${row.original.severity}`;
          return (
            <input
              type="number"
              aria-label={`Keep days for severity ${row.original.name}`}
              min={0}
              max={3650}
              value={getRetVal(key)}
              onChange={(e) =>
                setRetEdits((prev) => ({ ...prev, [key]: e.target.value }))
              }
              placeholder="inherit"
              className="w-24 rounded-md border border-border bg-bg-panel px-2 py-1 font-mono text-xs text-text focus:border-accent focus:outline-hidden focus-visible:outline-2 focus-visible:outline-solid focus-visible:outline-offset-2 focus-visible:outline-accent"
            />
          );
        },
      },
      {
        id: 'effective',
        header: 'Effective Window',
        cell: ({ row }) => (
          <span className="whitespace-nowrap font-mono text-xs text-text">
            {syslogEffectiveWindow(row.original)}{' '}
            {row.original.inherited && (
              <span className="font-sans text-text-faint">(inherited)</span>
            )}
          </span>
        ),
      },
      {
        id: 'volume',
        header: 'Current Volume',
        meta: { hideOnTablet: true },
        cell: ({ row }) => (
          <span className="whitespace-nowrap font-mono text-text-faint">
            {row.original.tracked
              ? `~${formatNumber(row.original.est_rows)} rows (${formatBytes(row.original.est_bytes)})`
              : 'below threshold'}
          </span>
        ),
      },
      {
        id: 'ingest',
        header: 'Daily Ingest',
        meta: { hideOnTablet: true },
        cell: ({ row }) => (
          <span className="whitespace-nowrap font-mono text-text-dim">
            {row.original.rate_available
              ? `~${formatNumber(row.original.rows_per_day)}/d (${formatBytes(row.original.bytes_per_day)}/d)`
              : 'measuring...'}
          </span>
        ),
      },
      {
        id: 'footprint',
        header: 'Projected Footprint',
        meta: { hideOnTablet: true },
        cell: ({ row }) => (
          <span className="whitespace-nowrap font-mono text-text">
            {!row.original.rate_available
              ? '—'
              : row.original.projected_forever
                ? 'Unbounded'
                : `~${formatBytes(row.original.projected_bytes)}`}
          </span>
        ),
      },
    ],
    [getRetVal, setRetEdits],
  );


  /*
   * The archive restore jobs.
   *
   * The columns close over the step-up re-auth, so they live inside the
   * component. The table used to be a raw `<table>` in a horizontal
   * scroller, so a phone got a sideways scroll for six columns.
   */
  const dropRestore = (job: any) => {
    setStepUpContext({
      title: `Drop Staged Restore #${job.id}`,
      description: 'Dropping a staged restore deletes its restored rows from staging.',
      confirmLabel: 'Drop Restore',
      danger: true,
      action: async (creds: any) => {
        await apiFetch(`/admin/api/archive/restores/${job.id}`, {
          method: 'DELETE',
          body: creds,
        });
        toast.success(`Dropped restore #${job.id}`);
        refetchRestores();
      },
    });
    setStepUpOpen(true);
  };

  const restoreJobColumns: ColumnDef<any, any>[] = useMemo(
    () => [
      {
        accessorKey: 'id',
        header: 'ID',
        cell: ({ row }) => <span className="font-mono">#{row.original.id}</span>,
      },
      {
        accessorKey: 'stream',
        header: 'Stream',
        cell: ({ row }) => <span className="font-medium capitalize">{row.original.stream}</span>,
      },
      {
        id: 'window',
        header: 'Window',
        cell: ({ row }) => (
          <span className="font-mono text-text-dim">
            {row.original.from_day} → {row.original.to_day}
          </span>
        ),
      },
      {
        accessorKey: 'status',
        header: 'State',
        cell: ({ row }) => (
          <span className="font-mono uppercase" title={row.original.error || undefined}>
            {row.original.status}
          </span>
        ),
      },
      {
        id: 'progress',
        header: 'Progress',
        cell: ({ row }) => (
          <span className="font-mono">
            {row.original.objects_done}/{row.original.objects_total} objects (
            {formatNumber(row.original.rows_loaded)} rows)
          </span>
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <button
            type="button"
            onClick={() => dropRestore(row.original)}
            className="inline-flex items-center gap-1 rounded border border-sig-crit/40 bg-sig-crit/10 px-2 py-1 text-[11px] text-sig-crit hover:bg-sig-crit/20"
          >
            <Trash2 className="h-3 w-3" />
            Drop
          </button>
        ),
      },
    ],
    [],
  );


  const handleSaveRetention = async () => {
    if (dirtyRetentionKeys.length === 0) return;
    setSavingRetention(true);
    try {
      const payload = dirtyRetentionKeys.map((key) => ({
        key,
        value: (retEdits[key] ?? '').trim(),
        category: 'retention',
        type: 'string',
      }));
      await apiFetch('/admin/api/settings', {
        method: 'POST',
        body: payload,
      });
      toast.success(
        'Retention settings saved',
        `Updated ${dirtyRetentionKeys.length} retention ${
          dirtyRetentionKeys.length === 1 ? 'setting' : 'settings'
        }.`,
      );
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['settings-all'] }),
        queryClient.invalidateQueries({ queryKey: ['settings-retention-knobs'] }),
        queryClient.invalidateQueries({ queryKey: ['settings-syslog-retention'] }),
      ]);
      setRetEdits({});
    } catch (err) {
      toast.error(
        'Failed to save retention settings',
        err instanceof ApiError ? err.message : 'Unexpected error',
      );
    } finally {
      setSavingRetention(false);
    }
  };

  // =========================================================================
  // SUB-TAB 3 STATE: Archive Target Configuration
  // =========================================================================
  const [archEdits, setArchEdits] = useState<Record<string, string>>({});
  const [archReverts, setArchReverts] = useState<Record<string, boolean>>({});
  const [testingArchive, setTestingArchive] = useState(false);
  const [testResult, setTestResult] = useState<{
    ok: boolean;
    // TestArchiveSettings answers with `message` (the refusal/failure reason)
    // and `warnings`; `checks` only exists on the local-target path. Reading
    // `summary` hid every S3 preflight failure.
    message?: string;
    warnings?: string[];
    checks?: Array<{ name: string; ok: boolean; detail?: string }>;
  } | null>(null);
  const [folderPickerKey, setFolderPickerKey] = useState<string | null>(null);
  const [folderPickerPath, setFolderPickerPath] = useState<string>('');
  const [folderList, setFolderList] = useState<string[]>([]);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [stepUpContext, setStepUpContext] = useState<{
    title: string;
    description: string;
    confirmLabel: string;
    danger?: boolean;
    action: (creds: StepUpCredentials) => Promise<void>;
  } | null>(null);

  const archBaseline = useMemo(() => {
    const map: Record<string, string> = {};
    for (const f of archiveSettings?.fields || []) {
      map[f.key] = f.kind === 'secret' ? '' : f.value ?? '';
    }
    return map;
  }, [archiveSettings]);

  useEffect(() => {
    setArchEdits({});
    setArchReverts({});
  }, [archBaseline]);

  const getArchVal = (key: string) =>
    key in archEdits ? archEdits[key] : (archBaseline[key] ?? '');

  const dirtyArchiveKeys = useMemo(() => {
    const changed = new Set<string>();
    for (const k of Object.keys(archEdits)) {
      if ((archEdits[k] ?? '') !== (archBaseline[k] ?? '')) {
        changed.add(k);
      }
    }
    for (const [k, rev] of Object.entries(archReverts)) {
      if (rev) changed.add(k);
    }
    return Array.from(changed);
  }, [archEdits, archReverts, archBaseline]);

  const currentArchiveTarget = (getArchVal('ARCHIVE_TARGET') || archiveSettings?.target || 's3') as
    | 's3'
    | 'local';

  const handleTestArchiveConnection = async () => {
    setTestingArchive(true);
    setTestResult(null);
    try {
      const set: Record<string, string> = {};
      for (const f of archiveSettings?.fields || []) {
        const val = getArchVal(f.key);
        if (f.kind === 'secret' && !val) continue;
        set[f.key] = val;
      }
      const res = await apiFetch<{
        ok: boolean;
        message?: string;
        warnings?: string[];
        checks?: Array<{ name: string; ok: boolean; detail?: string }>;
      }>('/admin/api/archive/settings/test', {
        method: 'POST',
        // The handler binds `set`, not `values`. With the wrong key the test
        // silently preflighted the SAVED config instead of the typed one.
        body: { set, revert: Object.keys(archReverts).filter((k) => archReverts[k]) },
      });
      setTestResult(res);
      if (res.ok) {
        toast.success('Archive target preflight passed', res.message || 'All checks succeeded.');
      } else {
        toast.warning('Archive target preflight reported issues', res.message || 'Check details below.');
      }
    } catch (err) {
      toast.error(
        'Archive connection test failed',
        err instanceof ApiError ? err.message : 'Preflight failed',
      );
    } finally {
      setTestingArchive(false);
    }
  };

  const triggerSaveArchiveSettings = () => {
    if (dirtyArchiveKeys.length === 0) return;
    setStepUpContext({
      title: 'Confirm Archive Configuration Change',
      description: `Saving ${dirtyArchiveKeys.length} archive ${
        dirtyArchiveKeys.length === 1 ? 'setting' : 'settings'
      } requires admin password verification.`,
      confirmLabel: 'Verify & Save Archive Config',
      action: async (creds) => {
        const set: Record<string, string> = {};
        for (const k of dirtyArchiveKeys) {
          if (!archReverts[k]) {
            set[k] = getArchVal(k);
          }
        }
        await apiFetch('/admin/api/archive/settings', {
          method: 'POST',
          body: {
            set,
            revert: Object.keys(archReverts).filter((k) => archReverts[k]),
            password: creds.password,
            totp_code: creds.totp_code,
          },
        });
        toast.success('Archive configuration saved');
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: ['archive-settings'] }),
          queryClient.invalidateQueries({ queryKey: ['archive-status'] }),
        ]);
        setArchEdits({});
        setArchReverts({});
      },
    });
    setStepUpOpen(true);
  };

  const browseFolders = async (key: string, dirPath = '') => {
    try {
      const q = dirPath ? `?path=${encodeURIComponent(dirPath)}` : '';
      const res = await apiFetch<{ path: string; folders: string[] }>(
        `/admin/api/archive/settings/folders${q}`,
      );
      setFolderPickerKey(key);
      setFolderPickerPath(res.path || '/');
      setFolderList(res.folders || []);
    } catch (err) {
      toast.error(
        'Cannot browse server folders',
        err instanceof ApiError ? err.message : 'Folder listing failed',
      );
    }
  };

  // Filtered retention rows
  const filteredRetentionFields = useMemo(() => {
    const list = retentionData?.fields || [];
    return list.filter((f) => {
      const cat = categorizeRetentionKey(f.key);
      if (retCategory !== 'ALL' && cat !== retCategory) return false;
      const curVal = getRetVal(f.key);
      const isOverridden = curVal !== '' || f.source === 'ui' || f.source === 'env';
      if (onlyOverridden && !isOverridden) return false;
      if (retSearch.trim()) {
        const q = retSearch.toLowerCase();
        return (
          f.label.toLowerCase().includes(q) ||
          f.env_key.toLowerCase().includes(q) ||
          f.key.toLowerCase().includes(q) ||
          f.hint.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [retentionData, retCategory, onlyOverridden, retSearch, retEdits, retentionBaseline]);

  // Projected volume calculation for Syslog banner
  const volumeProjection = useMemo(() => {
    if (!syslogRetention?.volume_known || !syslogRetention.volume_total_bytes) return null;
    const otherBytes = Math.max(
      0,
      (syslogRetention.database_bytes || 0) - (syslogRetention.current_syslog_bytes || 0),
    );
    const projectedTotal = (syslogRetention.projected_syslog_bytes || 0) + otherBytes;
    const pct = Math.round((projectedTotal / syslogRetention.volume_total_bytes) * 100);
    const fits = projectedTotal <= syslogRetention.volume_total_bytes;
    return {
      projectedTotal,
      syslogBytes: syslogRetention.projected_syslog_bytes || 0,
      otherBytes,
      totalVolume: syslogRetention.volume_total_bytes,
      pct,
      fits,
    };
  }, [syslogRetention]);

  const restoreList: ArchiveRestoreJob[] = Array.isArray(restoresData)
    ? restoresData
    : restoresData?.restores || [];

  return (
    <div className="space-y-5 pb-20">
      {/* Workspace Header + Sub-Tab Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <HardDrive className="h-5 w-5 text-accent" />
            <h1 className="font-display text-lg sm:text-xl font-bold text-text">
              Storage, Retention & Raw Archive
            </h1>
          </div>
          <p className="text-xs text-text-faint mt-0.5">
            Manage hot PostgreSQL table retention windows, syslog severity tiers, and immutable S3/B2 or local raw archive pipelines.
          </p>
        </div>

        {/* 3 Cohesive Sub-Tabs (Replaces the 9,589px single-column scroll wall!) */}
        <div
          role="tablist"
          aria-label="Storage and Archive sections"
          className="inline-flex rounded-lg border border-border bg-bg-panel p-1 self-start sm:self-auto overflow-x-auto max-w-full"
        >
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'retention'}
            onClick={() => setTab('retention')}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap',
              activeTab === 'retention'
                ? 'bg-bg-card text-accent shadow-xs font-semibold'
                : 'text-text-faint hover:text-text',
            )}
          >
            <Database className="h-3.5 w-3.5" />
            <span>Hot Retention Matrix</span>
            {dirtyRetentionKeys.length > 0 && (
              <span className="ml-1 rounded-full bg-sig-warn/20 px-1.5 py-0.2 font-mono text-[10px] text-sig-warn">
                {dirtyRetentionKeys.length}
              </span>
            )}
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'archive-status'}
            onClick={() => setTab('archive-status')}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap',
              activeTab === 'archive-status'
                ? 'bg-bg-card text-accent shadow-xs font-semibold'
                : 'text-text-faint hover:text-text',
            )}
          >
            <Archive className="h-3.5 w-3.5" />
            <span>Archive Health & Restore</span>
            {archiveStatus?.health?.verdict && (
              <span
                className={cn(
                  'h-2 w-2 rounded-full',
                  archiveStatus.health.verdict === 'healthy' && 'bg-sig-ok',
                  archiveStatus.health.verdict === 'warning' && 'bg-sig-warn',
                  archiveStatus.health.verdict === 'error' && 'bg-sig-crit',
                  (archiveStatus.health.verdict === 'disabled' ||
                    archiveStatus.health.verdict === 'not_configured') &&
                    'bg-text-mute',
                )}
              />
            )}
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'archive-config'}
            onClick={() => setTab('archive-config')}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap',
              activeTab === 'archive-config'
                ? 'bg-bg-card text-accent shadow-xs font-semibold'
                : 'text-text-faint hover:text-text',
            )}
          >
            <Sliders className="h-3.5 w-3.5" />
            <span>Archive Target Config</span>
            {dirtyArchiveKeys.length > 0 && (
              <span className="ml-1 rounded-full bg-sig-warn/20 px-1.5 py-0.2 font-mono text-[10px] text-sig-warn">
                {dirtyArchiveKeys.length}
              </span>
            )}
          </button>
        </div>
      </div>

      {/* ===================================================================
       * SUB-TAB 1: HOT RETENTION MATRIX + SYSLOG SEVERITY WINDOWS
       * =================================================================== */}
      {activeTab === 'retention' && (
        <div className="space-y-6">
          {/* Volume Projection Strip */}
          {volumeProjection && (
            <div className="rounded-lg border border-border bg-bg-card p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-xs font-semibold text-text">
                  <span>Projected Steady-State Database Footprint:</span>
                  <span className="font-mono text-sm text-accent">
                    ~{formatBytes(volumeProjection.projectedTotal)}
                  </span>
                  <span className="text-text-faint font-normal">
                    on {formatBytes(volumeProjection.totalVolume)} volume
                  </span>
                </div>
                <div className="text-xs text-text-faint">
                  Syslog ~{formatBytes(volumeProjection.syslogBytes)} + Other tables ~
                  {formatBytes(volumeProjection.otherBytes)}
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="w-40 h-2.5 rounded-full bg-bg-panel overflow-hidden border border-border">
                  <div
                    className={cn(
                      'h-full rounded-full transition-all',
                      volumeProjection.fits ? 'bg-sig-ok' : 'bg-sig-crit',
                    )}
                    style={{ width: `${Math.min(100, volumeProjection.pct)}%` }}
                  />
                </div>
                <span
                  className={cn(
                    'font-mono text-xs font-semibold',
                    volumeProjection.fits ? 'text-sig-ok' : 'text-sig-crit',
                  )}
                >
                  {volumeProjection.fits
                    ? `Fits (~${volumeProjection.pct}%)`
                    : `Exceeds volume (${volumeProjection.pct}%)`}
                </span>
              </div>
            </div>
          )}

          {/* Section A: Compact 26-Knob Data Retention Matrix */}
          <section className="rounded-lg border border-border bg-bg-card overflow-hidden">
            <div className="border-b border-border bg-bg-panel/50 px-4 py-3.5 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              <div>
                <h2 className="font-display text-sm font-bold text-text">
                  Table Retention Policy Matrix ({filteredRetentionFields.length} of{' '}
                  {retentionData?.fields?.length || 0} tables)
                </h2>
                <p className="text-xs text-text-faint mt-0.5">
                  Leave any override blank to inherit from its environment variable or built-in default.
                </p>
              </div>

              {/* Filter & Category Bar */}
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative flex-1 sm:flex-initial sm:w-52">
                  <Search className="h-3.5 w-3.5 text-text-faint absolute left-2.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={retSearch}
                    onChange={(e) => setRetSearch(e.target.value)}
                    placeholder="Filter tables or ENV..."
                    aria-label="Filter retention tables"
                    className="w-full rounded-md border border-border bg-bg-card pl-8 pr-2.5 py-1.5 text-xs text-text focus:border-accent focus:outline-hidden"
                  />
                </div>

                <select
                  value={retCategory}
                  onChange={(e) => setRetCategory(e.target.value)}
                  aria-label="Filter by retention category"
                  className="rounded-md border border-border bg-bg-card px-2.5 py-1.5 text-xs text-text focus:border-accent focus:outline-hidden"
                >
                  <option value="ALL">All Categories</option>
                  <option value="Device Telemetry">Device Telemetry</option>
                  <option value="Logs, Events & Alerts">Logs, Events & Alerts</option>
                  <option value="Network Flows">Network Flows</option>
                  <option value="System & History">System & History</option>
                </select>

                <label className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-card px-2.5 py-1.5 text-xs text-text-dim cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={onlyOverridden}
                    onChange={(e) => setOnlyOverridden(e.target.checked)}
                    className="rounded border-border"
                  />
                  <span>Overridden Only</span>
                </label>
              </div>
            </div>

            {loadingRetention ? (
              <div className="p-6 text-center text-xs text-text-faint">
                Loading retention policy matrix...
              </div>
            ) : (
              <>
                {/* Desktop & Tablet High-Density Table */}
                <div className="hidden md:block overflow-x-auto">
                  <table className="w-full border-collapse text-left text-xs">
                    <thead>
                      <tr className="border-b border-border bg-bg-panel text-[11px] font-semibold uppercase tracking-wider text-text-faint">
                        <th className="px-4 py-2.5">Data Stream / Table</th>
                        <th className="px-3 py-2.5 hidden lg:table-cell">Category</th>
                        <th className="px-3 py-2.5">Source</th>
                        <th className="px-3 py-2.5">Effective</th>
                        <th className="px-4 py-2.5 w-56">Custom Override</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/60">
                      {filteredRetentionFields.map((f) => {
                        const val = getRetVal(f.key);
                        const isEdited = (val ?? '') !== (retentionBaseline[f.key] ?? '');
                        const cat = categorizeRetentionKey(f.key);
                        return (
                          <tr
                            key={f.key}
                            className={cn(
                              'hover:bg-bg-hover transition-colors',
                              isEdited && 'bg-accent/5',
                            )}
                          >
                            <td className="px-4 py-2.5">
                              <div className="font-medium text-text flex items-center gap-2 flex-wrap">
                                <span>{f.label}</span>
                                <code className="rounded bg-bg-panel px-1.5 py-0.5 font-mono text-[10px] text-text-faint border border-border/70">
                                  {f.env_key}
                                </code>
                              </div>
                              <div className="text-[11px] text-text-faint mt-0.5">{f.hint}</div>
                            </td>
                            <td className="px-3 py-2.5 hidden lg:table-cell whitespace-nowrap text-text-faint">
                              {cat}
                            </td>
                            <td className="px-3 py-2.5 whitespace-nowrap">
                              <span
                                className={cn(
                                  'inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase',
                                  f.source === 'ui' && 'bg-accent/15 text-accent-text',
                                  f.source === 'env' && 'bg-sig-ok/15 text-sig-ok',
                                  f.source === 'default' && 'bg-bg-panel text-text-mute',
                                )}
                              >
                                {f.source === 'ui'
                                  ? 'Custom UI'
                                  : f.source === 'env'
                                    ? 'Env Var'
                                    : 'Default'}
                              </span>
                            </td>
                            <td className="px-3 py-2.5 whitespace-nowrap font-mono font-semibold text-text tabular-nums">
                              {f.value} {f.unit}
                            </td>
                            <td className="px-4 py-2.5">
                              <div className="flex items-center gap-1.5">
                                <input
                                  type="number"
                                  aria-label={f.label}
                                  min={f.min}
                                  max={f.max}
                                  step={1}
                                  value={val}
                                  onChange={(e) =>
                                    setRetEdits((prev) => ({ ...prev, [f.key]: e.target.value }))
                                  }
                                  placeholder={`inherit (${f.env_value} ${f.unit})`}
                                  className={cn(
                                    'w-36 rounded-md border bg-bg-panel px-2.5 py-1 font-mono text-xs text-text focus:border-accent focus:outline-hidden tabular-nums',
                                    isEdited ? 'border-accent' : 'border-border',
                                  )}
                                />
                                {val !== '' && (
                                  <button
                                    type="button"
                                    onClick={() =>
                                      setRetEdits((prev) => ({ ...prev, [f.key]: '' }))
                                    }
                                    title="Clear override and inherit default"
                                    aria-label={`Reset ${f.label} to default`}
                                    className="rounded p-1 text-text-faint hover:bg-bg-panel hover:text-text"
                                  >
                                    <RotateCcw className="h-3.5 w-3.5" />
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Mobile (<768px) Compact Card Stack */}
                <div className="md:hidden divide-y divide-border">
                  {filteredRetentionFields.map((f) => {
                    const val = getRetVal(f.key);
                    return (
                      <div key={f.key} className="p-3.5 space-y-2">
                        <div className="flex items-start justify-between gap-2">
                          <div>
                            <div className="text-xs font-semibold text-text">{f.label}</div>
                            <code className="font-mono text-[10px] text-text-mute">
                              {f.env_key}
                            </code>
                          </div>
                          <span className="font-mono text-xs font-semibold text-accent shrink-0">
                            {f.value} {f.unit}
                          </span>
                        </div>
                        <div className="text-[11px] text-text-faint">{f.hint}</div>
                        <div className="flex items-center gap-2 pt-1">
                          <input
                            type="number"
                            aria-label={f.label}
                            min={f.min}
                            max={f.max}
                            value={val}
                            onChange={(e) =>
                              setRetEdits((prev) => ({ ...prev, [f.key]: e.target.value }))
                            }
                            placeholder={`inherit (${f.env_value} ${f.unit})`}
                            className="flex-1 rounded-md border border-border bg-bg-panel px-2.5 py-1.5 font-mono text-xs text-text"
                          />
                          {val !== '' && (
                            <button
                              type="button"
                              onClick={() => setRetEdits((prev) => ({ ...prev, [f.key]: '' }))}
                              className="rounded-md border border-border bg-bg-panel px-2.5 py-1.5 text-xs text-text-faint"
                            >
                              Reset
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </section>

          {/* Section B: Syslog Per-Severity Retention & Summary Horizon */}
          <section className="rounded-lg border border-border bg-bg-card overflow-hidden">
            <div className="border-b border-border bg-bg-panel/50 px-4 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h2 className="font-display text-sm font-bold text-text">
                  Syslog Retention by Severity (RFC 5424 Levels 0–7)
                </h2>
                <p className="text-xs text-text-faint mt-0.5">
                  Set a global default or uncouple high-volume informational/notice severities independently.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <div className="flex items-center gap-2">
                  <label
                    htmlFor="v2-syslog-default-days"
                    className="text-xs font-medium text-text-dim whitespace-nowrap"
                  >
                    Default (days):
                  </label>
                  <input
                    id="v2-syslog-default-days"
                    type="number"
                    min={0}
                    max={3650}
                    value={getRetVal('syslog_retention_days_default')}
                    onChange={(e) =>
                      setRetEdits((prev) => ({
                        ...prev,
                        syslog_retention_days_default: e.target.value,
                      }))
                    }
                    placeholder={syslogRetention?.default_set ? '' : 'not set'}
                    className="w-24 rounded-md border border-border bg-bg-card px-2.5 py-1 font-mono text-xs text-text focus:border-accent focus:outline-hidden"
                  />
                </div>
                <div className="flex items-center gap-2">
                  <label
                    htmlFor="v2-syslog-summary-days"
                    className="text-xs font-medium text-text-dim whitespace-nowrap"
                  >
                    Summaries (days):
                  </label>
                  <input
                    id="v2-syslog-summary-days"
                    type="number"
                    min={0}
                    max={3650}
                    value={getRetVal('syslog_summary_retention_days')}
                    onChange={(e) =>
                      setRetEdits((prev) => ({
                        ...prev,
                        syslog_summary_retention_days: e.target.value,
                      }))
                    }
                    placeholder="365"
                    className="w-24 rounded-md border border-border bg-bg-card px-2.5 py-1 font-mono text-xs text-text focus:border-accent focus:outline-hidden"
                  />
                </div>
              </div>
            </div>

            {loadingSyslogRet ? (
              <div className="p-6 text-center text-xs text-text-faint">
                Loading syslog severity statistics...
              </div>
            ) : (
              <ResponsiveDataView
                data={syslogRetention?.severities ?? []}
                columns={syslogSeverityColumns}
                getRowId={(row) => String(row.severity)}
                renderMobileCard={(sev) => (
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[11px] text-text-faint">{sev.severity}</span>
                      <span className="text-xs font-medium text-text">{sev.name}</span>
                    </div>
                    <div className="font-mono text-[11px] text-text">
                      {syslogEffectiveWindow(sev)}
                    </div>
                    <label className="block">
                      <span className="mb-1 block text-[10px] font-medium text-text-dim">
                        Keep (days)
                      </span>
                      <input
                        type="number"
                        aria-label={`Keep days for severity ${sev.name}`}
                        min={0}
                        max={3650}
                        value={getRetVal(`syslog_retention_days_${sev.severity}`)}
                        onChange={(e) =>
                          setRetEdits((prev) => ({
                            ...prev,
                            [`syslog_retention_days_${sev.severity}`]: e.target.value,
                          }))
                        }
                        placeholder="inherit"
                        className="w-24 rounded-md border border-border bg-bg-panel px-2 py-1 font-mono text-xs text-text focus:border-accent focus:outline-hidden focus-visible:outline-2 focus-visible:outline-solid focus-visible:outline-offset-2 focus-visible:outline-accent"
                      />
                    </label>
                  </div>
                )}
              />
            )}
          </section>

          <StickySaveBar
            isDirty={dirtyRetentionKeys.length > 0}
            dirtyCount={dirtyRetentionKeys.length}
            isSaving={savingRetention}
            onDiscard={() => setRetEdits({})}
            onSave={handleSaveRetention}
            saveLabel="Save Retention Policy"
          />
        </div>
      )}

      {/* ===================================================================
       * SUB-TAB 2: ARCHIVE HEALTH, STREAMS & STAGING RESTORES
       * =================================================================== */}
      {activeTab === 'archive-status' && (
        <div className="space-y-6">
          <ArchiveGatePanel me={me} />
          {/* Health Verdict Banner */}
          <section className="rounded-lg border border-border bg-bg-card p-5">
            {loadingArchStatus ? (
              <div className="text-xs text-text-faint">Loading archive health status...</div>
            ) : (
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="flex items-start gap-3.5">
                  <div
                    className={cn(
                      'rounded-lg p-2.5 shrink-0',
                      archiveStatus?.health?.verdict === 'healthy' && 'bg-sig-ok/15 text-sig-ok',
                      archiveStatus?.health?.verdict === 'warning' &&
                        'bg-sig-warn/15 text-sig-warn',
                      archiveStatus?.health?.verdict === 'error' && 'bg-sig-crit/15 text-sig-crit',
                      (!archiveStatus?.health?.verdict ||
                        archiveStatus.health.verdict === 'disabled' ||
                        archiveStatus.health.verdict === 'not_configured') &&
                        'bg-bg-panel text-text-faint',
                    )}
                  >
                    {archiveStatus?.health?.verdict === 'healthy' && (
                      <CheckCircle2 className="h-6 w-6" />
                    )}
                    {archiveStatus?.health?.verdict === 'warning' && (
                      <AlertTriangle className="h-6 w-6" />
                    )}
                    {archiveStatus?.health?.verdict === 'error' && <XCircle className="h-6 w-6" />}
                    {(!archiveStatus?.health?.verdict ||
                      archiveStatus.health.verdict === 'disabled' ||
                      archiveStatus.health.verdict === 'not_configured') && (
                      <PauseCircle className="h-6 w-6" />
                    )}
                  </div>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <h2 className="font-display text-base font-bold text-text capitalize">
                        Raw Archive Verdict:{' '}
                        {(archiveStatus?.health?.verdict || 'unknown').replace('_', ' ')}
                      </h2>
                      <button
                        type="button"
                        onClick={() => refetchArchiveStatus()}
                        className="inline-flex items-center gap-1 rounded border border-border bg-bg-panel px-2 py-0.5 text-[11px] text-text-faint hover:text-text"
                      >
                        <RefreshCw className="h-3 w-3" />
                        Refresh
                      </button>
                    </div>
                    <p className="text-xs text-text-dim mt-1">
                      {archiveStatus?.health?.summary || 'No archive summary reported.'}
                    </p>
                    <div className="mt-3 flex flex-wrap items-center gap-4 text-xs text-text-faint">
                      <div>
                        <span className="text-text-mute">Last Success: </span>
                        <span className="font-mono text-text">
                          {formatRelativeTime(archiveStatus?.health?.last_success_at)}
                        </span>
                      </div>
                      <div>
                        <span className="text-text-mute">Backlog: </span>
                        <span className="font-mono text-text">
                          {archiveStatus?.health?.backlog_chunks ?? 0} chunks
                        </span>
                      </div>
                      <div>
                        <span className="text-text-mute">Target: </span>
                        <code className="font-mono text-text">
                          {archiveStatus?.config?.target === 'local'
                            ? archiveStatus?.config?.local_dir || 'local'
                            : archiveStatus?.config?.bucket || 'none'}
                        </code>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-start lg:self-center">
                  <button
                    type="button"
                    onClick={() => setTab('archive-config')}
                    className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:bg-bg-hover"
                  >
                    <Sliders className="h-3.5 w-3.5 text-accent" />
                    Configure Target
                  </button>
                </div>
              </div>
            )}
          </section>

          {/* Per-Stream Status Table */}
          {archiveStatus?.streams && archiveStatus.streams.length > 0 && (
            <section className="rounded-lg border border-border bg-bg-card overflow-hidden">
              <div className="border-b border-border bg-bg-panel/50 px-4 py-3">
                <h3 className="font-display text-sm font-bold text-text">
                  Archived Telemetry Streams
                </h3>
              </div>
              <ResponsiveDataView
                data={archiveStatus.streams}
                columns={archivedStreamColumns}
                getRowId={(row) => row.stream}
                renderMobileCard={(st) => (
                  <div className="space-y-1">
                    <div className="text-xs font-semibold capitalize text-text">{st.stream}</div>
                    <div
                      className={cn(
                        'inline-flex rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase',
                        st.state === 'ok' && 'bg-sig-ok/15 text-sig-ok',
                        (st.state === 'error' || st.state === 'stalled') &&
                          'bg-sig-crit/15 text-sig-crit',
                        st.state !== 'ok' &&
                          st.state !== 'error' &&
                          st.state !== 'stalled' &&
                          'bg-bg-panel text-text-dim',
                      )}
                    >
                      {st.state}
                    </div>
                    <div className="font-mono text-[11px] text-text-dim">
                      {st.verified_through
                        ? st.verified_through.slice(0, 16).replace('T', ' ') + ' UTC'
                        : '—'}
                    </div>
                    <div className="font-mono text-[11px] text-text">
                      {st.backlog_chunks ?? 0} chunks · {formatBytes(st.stored_bytes)}
                    </div>
                  </div>
                )}
              />
            </section>
          )}

          {/* Staging Restores Card */}
          <section className="rounded-lg border border-border bg-bg-card overflow-hidden">
            <div className="border-b border-border bg-bg-panel/50 px-4 py-3 flex items-center justify-between">
              <div>
                <h3 className="font-display text-sm font-bold text-text">
                  Restores to Staging Database
                </h3>
                <p className="text-xs text-text-faint mt-0.5">
                  Download archived chunks back into staging tables for historical forensics.
                </p>
              </div>
              <button
                type="button"
                onClick={() => refetchRestores()}
                className="inline-flex items-center gap-1 rounded border border-border bg-bg-panel px-2.5 py-1 text-xs text-text-dim hover:text-text"
              >
                <RefreshCw className="h-3 w-3" />
                Refresh
              </button>
            </div>
            {restoreList.length === 0 ? (
              <div className="p-6 text-center text-xs text-text-faint">
                No active or staged archive restore jobs.
              </div>
            ) : (
              <ResponsiveDataView
                data={restoreList}
                columns={restoreJobColumns}
                getRowId={(row) => String(row.id)}
                renderMobileCard={(job) => (
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-medium capitalize text-text">{job.stream}</span>
                      <span className="font-mono text-[11px] text-text-dim">#{job.id}</span>
                    </div>
                    <div className="font-mono text-[11px] text-text-dim">
                      {job.from_day} → {job.to_day}
                    </div>
                    <div className="font-mono text-[11px] uppercase text-text">{job.status}</div>
                    <div className="font-mono text-[11px] text-text">
                      {job.objects_done}/{job.objects_total} objects (
                      {formatNumber(job.rows_loaded)} rows)
                    </div>
                    <button
                      type="button"
                      onClick={() => dropRestore(job)}
                      className="inline-flex items-center gap-1 rounded border border-sig-crit/40 bg-sig-crit/10 px-2 py-1 text-[11px] text-sig-crit hover:bg-sig-crit/20"
                    >
                      <Trash2 className="h-3 w-3" />
                      Drop
                    </button>
                  </div>
                )}
              />
            )}
          </section>
        </div>
      )}

      {/* ===================================================================
       * SUB-TAB 3: ARCHIVE TARGET CONFIGURATION
       * =================================================================== */}
      {activeTab === 'archive-config' && (
        <div className="space-y-6">
          <div className="rounded-lg border border-border bg-bg-card p-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="font-display text-sm font-bold text-text">
                Raw Archive Target & Pipeline Configuration
              </h2>
              <p className="text-xs text-text-faint mt-0.5">
                Configure S3/Backblaze B2 object storage or a local/NFS directory. Test connection runs a full non-destructive preflight.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleTestArchiveConnection}
                disabled={testingArchive}
                className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-semibold text-text hover:border-border-strong disabled:opacity-50"
              >
                <Play className="h-3.5 w-3.5 text-sig-ok" />
                <span>{testingArchive ? 'Running Preflight...' : 'Test Connection'}</span>
              </button>
            </div>
          </div>

          {testResult && (
            <div
              className={cn(
                'rounded-lg border p-4 space-y-2',
                testResult.ok
                  ? 'border-sig-ok/40 bg-sig-ok/10'
                  : 'border-sig-warn/40 bg-sig-warn/10',
              )}
            >
              <div className="flex items-center gap-2 text-xs font-bold text-text">
                <ShieldCheck
                  className={cn('h-4 w-4', testResult.ok ? 'text-sig-ok' : 'text-sig-warn')}
                />
                <span>{testResult.message || 'Preflight Check Results'}</span>
              </div>
              {testResult.warnings && testResult.warnings.length > 0 && (
                <ul className="space-y-1 text-xs text-sig-warn pl-6 list-disc">
                  {testResult.warnings.map((w, idx) => (
                    <li key={idx}>{w}</li>
                  ))}
                </ul>
              )}
              {testResult.checks && testResult.checks.length > 0 && (
                <ul className="space-y-1 text-xs text-text-dim pl-6 list-disc">
                  {testResult.checks.map((c, idx) => (
                    <li key={idx}>
                      <strong className={c.ok ? 'text-sig-ok' : 'text-sig-crit'}>
                        {c.ok ? 'PASS' : 'FAIL'}
                      </strong>{' '}
                      — {c.name}: {c.detail}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {loadingArchSettings ? (
            <div className="p-6 text-center text-xs text-text-faint">
              Loading archive configuration...
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              {[
                'Target & Endpoint',
                'Credentials',
                'Bucket & Object Lock',
                'Streams & Staging',
                'Schedule & Pacing',
              ].map((groupTitle) => {
                const groupFields = (archiveSettings?.fields || []).filter((f) => {
                  const meta = ARCHIVE_LABELS[f.key];
                  if ((meta?.group || 'Schedule & Pacing') !== groupTitle) return false;
                  if (currentArchiveTarget === 'local' && S3_ONLY_RE.test(f.key)) return false;
                  if (currentArchiveTarget === 's3' && f.key === 'ARCHIVE_LOCAL_DIR') return false;
                  return true;
                });

                if (groupFields.length === 0) return null;

                return (
                  <section
                    key={groupTitle}
                    className="rounded-lg border border-border bg-bg-card p-4 space-y-4"
                  >
                    <h3 className="font-display text-xs font-bold uppercase tracking-wider text-accent border-b border-border pb-2">
                      {groupTitle}
                    </h3>
                    <div className="space-y-3.5">
                      {groupFields.map((f) => {
                        const meta = ARCHIVE_LABELS[f.key] || {
                          label: f.key,
                          hint: f.hint || '',
                        };
                        const val = getArchVal(f.key);
                        const locked = f.location && archiveSettings?.location_locked;
                        const canBrowse =
                          (f.key === 'ARCHIVE_LOCAL_DIR' || f.key === 'ARCHIVE_STAGING_DIR') &&
                          !locked;

                        return (
                          <div key={f.key} className="space-y-1">
                            <div className="flex items-center justify-between gap-2">
                              <label
                                htmlFor={`arch-${f.key}`}
                                className="text-xs font-medium text-text"
                              >
                                {meta.label}
                              </label>
                              <div className="flex items-center gap-1.5">
                                <code className="font-mono text-[10px] text-text-mute">
                                  {f.key}
                                </code>
                                {f.source === 'ui' && (
                                  <button
                                    type="button"
                                    onClick={() =>
                                      setArchReverts((prev) => ({
                                        ...prev,
                                        [f.key]: !prev[f.key],
                                      }))
                                    }
                                    className={cn(
                                      'rounded px-1.5 py-0.2 font-mono text-[10px]',
                                      archReverts[f.key]
                                        ? 'bg-sig-warn/20 text-sig-warn'
                                        : 'bg-accent/15 text-accent-text',
                                    )}
                                  >
                                    {archReverts[f.key] ? 'Will Revert' : 'Custom (Revert)'}
                                  </button>
                                )}
                              </div>
                            </div>

                            {f.kind === 'bool' ? (
                              <label className="inline-flex items-center gap-2 text-xs text-text-dim cursor-pointer pt-0.5">
                                <input
                                  id={`arch-${f.key}`}
                                  type="checkbox"
                                  disabled={locked}
                                  checked={val === 'true'}
                                  onChange={(e) =>
                                    setArchEdits((prev) => ({
                                      ...prev,
                                      [f.key]: String(e.target.checked),
                                    }))
                                  }
                                  className="rounded border-border bg-bg-panel"
                                />
                                <span>Enabled</span>
                              </label>
                            ) : f.key === 'ARCHIVE_TARGET' ? (
                              <select
                                id={`arch-${f.key}`}
                                disabled={locked}
                                value={val || 's3'}
                                onChange={(e) =>
                                  setArchEdits((prev) => ({ ...prev, [f.key]: e.target.value }))
                                }
                                className="w-full rounded-md border border-border bg-bg-panel px-2.5 py-1.5 text-xs text-text focus:border-accent focus:outline-hidden"
                              >
                                <option value="s3">s3 — S3-Compatible Object Storage</option>
                                <option value="local">
                                  local — Local Partition or Mounted Network Share
                                </option>
                              </select>
                            ) : f.key === 'ARCHIVE_OBJECT_LOCK_MODE' ? (
                              <select
                                id={`arch-${f.key}`}
                                value={val.toUpperCase()}
                                onChange={(e) =>
                                  setArchEdits((prev) => ({ ...prev, [f.key]: e.target.value }))
                                }
                                className="w-full rounded-md border border-border bg-bg-panel px-2.5 py-1.5 text-xs text-text focus:border-accent focus:outline-hidden"
                              >
                                <option value="">(none)</option>
                                <option value="GOVERNANCE">GOVERNANCE (Recommended)</option>
                                <option value="COMPLIANCE">COMPLIANCE</option>
                              </select>
                            ) : (
                              <div className="flex items-center gap-1.5">
                                <input
                                  id={`arch-${f.key}`}
                                  type={
                                    f.kind === 'secret'
                                      ? 'password'
                                      : f.kind === 'int'
                                        ? 'number'
                                        : 'text'
                                  }
                                  disabled={locked}
                                  value={val}
                                  onChange={(e) =>
                                    setArchEdits((prev) => ({ ...prev, [f.key]: e.target.value }))
                                  }
                                  placeholder={
                                    f.kind === 'secret'
                                      ? f.set
                                        ? `Stored (key ID ends in ${f.hint || '...'}); type to replace`
                                        : 'Not set'
                                      : ''
                                  }
                                  className="flex-1 rounded-md border border-border bg-bg-panel px-2.5 py-1.5 font-mono text-xs text-text focus:border-accent focus:outline-hidden"
                                />
                                {canBrowse && (
                                  <button
                                    type="button"
                                    onClick={() => browseFolders(f.key, val)}
                                    className="inline-flex items-center gap-1 rounded-md border border-border bg-bg-panel px-2.5 py-1.5 text-xs text-text-dim hover:text-text"
                                  >
                                    <FolderOpen className="h-3.5 w-3.5 text-accent" />
                                    Browse
                                  </button>
                                )}
                              </div>
                            )}

                            {folderPickerKey === f.key && (
                              <div className="mt-2 rounded-md border border-border bg-bg-panel p-2.5 space-y-2">
                                <div className="flex items-center justify-between text-xs">
                                  <code className="font-mono text-accent">{folderPickerPath}</code>
                                  <div className="flex items-center gap-1.5">
                                    <button
                                      type="button"
                                      onClick={() => {
                                        setArchEdits((prev) => ({
                                          ...prev,
                                          [f.key]: folderPickerPath,
                                        }));
                                        setFolderPickerKey(null);
                                      }}
                                      className="rounded bg-accent px-2 py-0.5 text-[11px] font-semibold text-on-accent"
                                    >
                                      Use This Folder
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => setFolderPickerKey(null)}
                                      className="text-text-faint hover:text-text text-[11px]"
                                    >
                                      Close
                                    </button>
                                  </div>
                                </div>
                                <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
                                  {folderList.map((sub) => (
                                    <button
                                      key={sub}
                                      type="button"
                                      onClick={() =>
                                        browseFolders(
                                          f.key,
                                          `${folderPickerPath.replace(/\/$/, '')}/${sub}`,
                                        )
                                      }
                                      className="rounded border border-border bg-bg-card px-2 py-1 font-mono text-[11px] text-text hover:border-accent"
                                    >
                                      📁 {sub}
                                    </button>
                                  ))}
                                </div>
                              </div>
                            )}

                            {meta.hint && (
                              <div className="text-[11px] text-text-faint">{meta.hint}</div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </section>
                );
              })}
            </div>
          )}

          <StickySaveBar
            isDirty={dirtyArchiveKeys.length > 0}
            dirtyCount={dirtyArchiveKeys.length}
            onDiscard={() => {
              setArchEdits({});
              setArchReverts({});
            }}
            onSave={triggerSaveArchiveSettings}
            saveLabel="Verify & Save Archive Config"
          />
        </div>
      )}

      {/* Step-Up Password + TOTP Verification Modal */}
      {stepUpContext && (
        <StepUpAuthDialog
          open={stepUpOpen}
          onOpenChange={setStepUpOpen}
          title={stepUpContext.title}
          description={stepUpContext.description}
          confirmLabel={stepUpContext.confirmLabel}
          danger={stepUpContext.danger}
          totpEnabled={me?.totp_enabled}
          onConfirm={stepUpContext.action}
        />
      )}
    </div>
  );
}

function ArchiveGatePanel({ me }: { me?: MeResponse }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const { data, refetch, isLoading } = useQuery({
    queryKey: ['archive-gate'],
    queryFn: () => apiFetch<ArchiveGateResponse>('/admin/api/archive/override'),
    refetchInterval: 30_000,
  });

  const [release, setRelease] = useState<{ stream: string; hours: string; reason: string } | null>(
    null,
  );
  const [reset, setReset] = useState<{ chunk: ArchiveChunkAttention; reason: string } | null>(null);

  /*
   * The parked chunks.
   *
   * The columns close over the reset dialog, so they live inside the
   * component.
   */
  const parkedChunkColumns: ColumnDef<any, any>[] = useMemo(
    () => [
      {
        accessorKey: 'id',
        header: 'Chunk',
        cell: ({ row }) => <span className="font-mono">#{row.original.id}</span>,
      },
      {
        accessorKey: 'table_name',
        header: 'Stream',
        cell: ({ row }) => <span className="font-mono text-text-dim">{row.original.table_name}</span>,
      },
      {
        id: 'period',
        header: 'Period',
        cell: ({ row }) => (
          <span className="font-mono text-text-dim">
            {row.original.period_start
              ? new Date(row.original.period_start).toLocaleString()
              : '—'}
            {row.original.period_end
              ? ` → ${new Date(row.original.period_end).toLocaleString()}`
              : ''}
          </span>
        ),
      },
      {
        accessorKey: 'attempts',
        header: 'Attempts',
        cell: ({ row }) => (
          <span className="text-right font-mono">{row.original.attempts ?? 0}</span>
        ),
      },
      {
        accessorKey: 'error',
        header: 'Error',
        cell: ({ row }) => (
          <span
            className="block max-w-[22rem] truncate text-[10px] text-sig-warn"
            title={row.original.error}
          >
            {row.original.error || '—'}
          </span>
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <button
            type="button"
            onClick={() => setReset({ chunk: row.original, reason: '' })}
            className="rounded border border-border bg-bg-panel px-2.5 py-1 text-[10px] font-semibold uppercase text-text hover:bg-bg-hover"
          >
            Reset…
          </button>
        ),
      },
    ],
    [],
  );
  const [stepUp, setStepUp] = useState<{
    title: string;
    description: string;
    confirmLabel: string;
    action: (creds: StepUpCredentials) => Promise<void>;
  } | null>(null);

  const refresh = () => {
    refetch();
    queryClient.invalidateQueries({ queryKey: ['archive-status'] });
  };

  const reengage = async (stream: string) => {
    try {
      await apiFetch('/admin/api/archive/override', {
        method: 'POST',
        body: { stream, hours: 0, reason: 're-engaged from V2' },
      });
      toast.success(`Re-engaged the ${stream} retention gate`);
      refresh();
    } catch (err) {
      toast.error('Could not re-engage the gate', err instanceof Error ? err.message : undefined);
    }
  };

  const continueRelease = () => {
    if (!release) return;
    const payload = release;
    const hours = Math.max(1, Math.floor(Number(payload.hours) || 0));
    setRelease(null);
    setStepUp({
      title: `Release ${payload.stream} retention gate`,
      description: `Raw ${payload.stream} deletes resume for ${hours}h. The release is audit-logged and expires automatically.`,
      confirmLabel: 'Release gate',
      action: async (creds) => {
        await apiFetch('/admin/api/archive/override', {
          method: 'POST',
          body: {
            stream: payload.stream,
            hours,
            reason: payload.reason.trim(),
            password: creds.password,
            totp_code: creds.totp_code,
          },
        });
        toast.success(`Gate released for ${hours}h`);
        refresh();
      },
    });
  };

  const continueReset = () => {
    if (!reset) return;
    const payload = reset;
    setReset(null);
    setStepUp({
      title: `Reset archive chunk #${payload.chunk.id}`,
      description:
        'The worker exports, uploads and verifies this chunk again on its next pass. Each attempt writes another Object-Lock-retained copy, so fix the cause first.',
      confirmLabel: 'Reset chunk',
      action: async (creds) => {
        await apiFetch(`/admin/api/archive/chunks/${payload.chunk.id}/reset`, {
          method: 'POST',
          body: {
            reason: payload.reason.trim(),
            password: creds.password,
            totp_code: creds.totp_code,
          },
        });
        toast.success(`Chunk #${payload.chunk.id} is pending again`);
        refresh();
      },
    });
  };

  const streams = data?.streams ?? [];
  const parked = data?.needs_attention ?? [];
  const maxHours = data?.max_hours ?? 24;

  return (
    <div className="space-y-4">
      <section className="rounded-lg border border-border bg-bg-card p-4">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-text">Retention gate</h2>
            <p className="text-[11px] text-text-faint">
              While a stream is archived, raw-row deletion waits for verified chunks. Releasing the
              gate lets deletion proceed for a bounded window; it re-engages automatically.
            </p>
          </div>
          <RefreshCw
            className={cn('h-3.5 w-3.5 text-text-faint', isLoading && 'animate-spin motion-reduce:animate-none')}
            aria-hidden="true"
          />
        </div>
        {streams.length === 0 ? (
          <p className="text-[11px] text-text-faint">No archive streams configured.</p>
        ) : (
          <div className="space-y-1.5">
            {streams.map((stream) => (
              <div
                key={stream.stream}
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border bg-bg-panel px-3 py-2"
              >
                <div className="flex flex-wrap items-center gap-2 text-[11px]">
                  <span className="font-mono font-semibold text-text">{stream.stream}</span>
                  <span
                    className={cn(
                      'rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
                      stream.enabled
                        ? 'bg-sig-ok/15 text-sig-ok'
                        : 'bg-bg-card text-text-faint',
                    )}
                  >
                    {stream.enabled ? 'archiving' : 'off'}
                  </span>
                  {stream.override_active ? (
                    <span className="text-sig-warn">
                      released until{' '}
                      {stream.override_until
                        ? new Date(stream.override_until).toLocaleString()
                        : 'unknown'}
                    </span>
                  ) : (
                    <span className="text-text-dim">
                      {stream.enabled ? 'gated' : 'deletes ungated'}
                    </span>
                  )}
                </div>
                {stream.override_active ? (
                  <button
                    type="button"
                    onClick={() => reengage(stream.stream)}
                    className="rounded border border-border bg-bg-card px-2.5 py-1 text-[10px] font-semibold uppercase text-text hover:bg-bg-hover"
                  >
                    Re-engage
                  </button>
                ) : (
                  <button
                    type="button"
                    disabled={!stream.enabled}
                    onClick={() =>
                      setRelease({ stream: stream.stream, hours: '6', reason: '' })
                    }
                    className="rounded border border-sig-warn/40 bg-sig-warn/10 px-2.5 py-1 text-[10px] font-semibold uppercase text-sig-warn disabled:opacity-40"
                  >
                    Release…
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="rounded-lg border border-border bg-bg-card p-4">
        <h2 className="text-sm font-semibold text-text">
          Chunks needing attention ({parked.length})
        </h2>
        <p className="text-[11px] text-text-faint">
          Parked chunks hold their raw rows in the database. Reset one only after fixing the cause
          in the chunk's error.
        </p>
        {parked.length === 0 ? (
          <p className="mt-2 text-[11px] text-text-faint">No parked chunks.</p>
        ) : (
          <div className="mt-2">
            <ResponsiveDataView
              data={parked}
              columns={parkedChunkColumns}
              getRowId={(row) => String(row.id)}
              renderMobileCard={(chunk) => (
                <div className="space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[11px] text-text">#{chunk.id}</span>
                    <span className="font-mono text-[11px] text-text-dim">{chunk.table_name}</span>
                  </div>
                  <div className="font-mono text-[10px] text-text-dim">
                    {chunk.period_start ? new Date(chunk.period_start).toLocaleString() : '—'}
                    {chunk.period_end ? ` → ${new Date(chunk.period_end).toLocaleString()}` : ''}
                  </div>
                  <div className="font-mono text-[10px] text-sig-warn">{chunk.error || '—'}</div>
                  <button
                    type="button"
                    onClick={() => setReset({ chunk, reason: '' })}
                    className="rounded border border-border bg-bg-panel px-2.5 py-1 text-[10px] font-semibold uppercase text-text hover:bg-bg-hover"
                  >
                    Reset…
                  </button>
                </div>
              )}
            />
          </div>
        )}
      </section>

      <SlideOverDrawer
        open={!!release}
        onOpenChange={(open) => {
          if (!open) setRelease(null);
        }}
        title={`Release ${release?.stream ?? ''} retention gate`}
        subtitle="Raw deletion is allowed for a bounded window, then the gate re-engages."
        size="md"
      >
        <div className="space-y-3">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">
              Hours (1–{maxHours})
            </span>
            <input
              type="number"
              min={1}
              max={maxHours}
              value={release?.hours ?? '6'}
              onChange={(e) =>
                setRelease((current) => (current ? { ...current, hours: e.target.value } : current))
              }
              className="w-32 rounded-md border border-border bg-bg-panel px-3 py-2 font-mono text-xs text-text"
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">Reason</span>
            <Textarea className="p-2.5"
              rows={3}
              value={release?.reason ?? ''}
              onChange={(e) =>
                setRelease((current) => (current ? { ...current, reason: e.target.value } : current))
              }
              maxLength={500}
              placeholder="Why the gate must be released (audit-logged)"
             
            />
          </label>
          <button
            type="button"
            disabled={
              !release ||
              !release.reason.trim() ||
              Number(release.hours) < 1 ||
              Number(release.hours) > maxHours
            }
            onClick={continueRelease}
            className="rounded-md bg-sig-warn px-3.5 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
          >
            Continue to verification
          </button>
        </div>
      </SlideOverDrawer>

      <SlideOverDrawer
        open={!!reset}
        onOpenChange={(open) => {
          if (!open) setReset(null);
        }}
        title={`Reset archive chunk #${reset?.chunk.id ?? ''}`}
        subtitle="The worker re-exports, uploads and verifies it on its next pass."
        size="md"
      >
        <div className="space-y-3">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">
              Reason (audit-logged)
            </span>
            <Textarea className="p-2.5"
              rows={3}
              value={reset?.reason ?? ''}
              onChange={(e) =>
                setReset((current) => (current ? { ...current, reason: e.target.value } : current))
              }
              maxLength={500}
             
            />
          </label>
          <button
            type="button"
            disabled={!reset || !reset.reason.trim()}
            onClick={continueReset}
            className="rounded-md bg-accent px-3.5 py-1.5 text-xs font-semibold text-on-accent disabled:opacity-50"
          >
            Continue to verification
          </button>
        </div>
      </SlideOverDrawer>

      {stepUp && (
        <StepUpAuthDialog
          open={!!stepUp}
          onOpenChange={(open) => {
            if (!open) setStepUp(null);
          }}
          title={stepUp.title}
          description={stepUp.description}
          confirmLabel={stepUp.confirmLabel}
          danger
          totpEnabled={me?.totp_enabled}
          onConfirm={async (creds) => {
            await stepUp.action(creds);
          }}
        />
      )}
    </div>
  );
}
