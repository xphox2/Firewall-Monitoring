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
import { StepUpAuthDialog, type StepUpCredentials } from '@/components/ui/step-up-auth-dialog';
import { useToast } from '@/components/ui/toast';

// --- Types matching Go backend ---

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
  start_time: string;
  end_time: string;
  state: string;
  chunks_total: number;
  chunks_done: number;
  rows_restored: number;
  last_error?: string;
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
    summary?: string;
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
        summary?: string;
        checks?: Array<{ name: string; ok: boolean; detail?: string }>;
      }>('/admin/api/archive/settings/test', {
        method: 'POST',
        // The handler binds `set`, not `values`. With the wrong key the test
        // silently preflighted the SAVED config instead of the typed one.
        body: { set, revert: Object.keys(archReverts).filter((k) => archReverts[k]) },
      });
      setTestResult(res);
      if (res.ok) {
        toast.success('Archive target preflight passed', res.summary || 'All checks succeeded.');
      } else {
        toast.warning('Archive target preflight reported issues', res.summary || 'Check details below.');
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
                ? 'bg-bg-card text-accent shadow-sm font-semibold'
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
                ? 'bg-bg-card text-accent shadow-sm font-semibold'
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
                ? 'bg-bg-card text-accent shadow-sm font-semibold'
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
                    className="w-full rounded-md border border-border bg-bg-card pl-8 pr-2.5 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
                  />
                </div>

                <select
                  value={retCategory}
                  onChange={(e) => setRetCategory(e.target.value)}
                  aria-label="Filter by retention category"
                  className="rounded-md border border-border bg-bg-card px-2.5 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
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
                                  f.source === 'ui' && 'bg-accent/15 text-accent',
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
                                    'w-36 rounded-md border bg-bg-panel px-2.5 py-1 font-mono text-xs text-text focus:border-accent focus:outline-none tabular-nums',
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
                    className="w-24 rounded-md border border-border bg-bg-card px-2.5 py-1 font-mono text-xs text-text focus:border-accent focus:outline-none"
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
                    className="w-24 rounded-md border border-border bg-bg-card px-2.5 py-1 font-mono text-xs text-text focus:border-accent focus:outline-none"
                  />
                </div>
              </div>
            </div>

            {loadingSyslogRet ? (
              <div className="p-6 text-center text-xs text-text-faint">
                Loading syslog severity statistics...
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-border bg-bg-panel text-[11px] font-semibold uppercase tracking-wider text-text-faint">
                      <th className="px-4 py-2.5">Severity</th>
                      <th className="px-3 py-2.5">Keep (Days)</th>
                      <th className="px-3 py-2.5">Effective Window</th>
                      <th className="px-3 py-2.5 hidden sm:table-cell">Current Volume</th>
                      <th className="px-3 py-2.5 hidden md:table-cell">Daily Ingest</th>
                      <th className="px-4 py-2.5 hidden lg:table-cell">Projected Footprint</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {(syslogRetention?.severities || []).map((sev) => {
                      const key = `syslog_retention_days_${sev.severity}`;
                      const val = getRetVal(key);
                      const effectiveTxt = sev.forever
                        ? 'Kept forever'
                        : sev.months
                          ? `${sev.months} ${sev.months === 1 ? 'month' : 'months'}`
                          : `${sev.days} days`;
                      return (
                        <tr key={sev.severity} className="hover:bg-bg-hover">
                          <td className="px-4 py-2 font-medium text-text whitespace-nowrap">
                            <span className="inline-block w-5 font-mono text-text-faint">
                              {sev.severity}
                            </span>
                            <span>{sev.name}</span>
                          </td>
                          <td className="px-3 py-2">
                            <input
                              type="number"
                              aria-label={`Keep days for severity ${sev.name}`}
                              min={0}
                              max={3650}
                              value={val}
                              onChange={(e) =>
                                setRetEdits((prev) => ({ ...prev, [key]: e.target.value }))
                              }
                              placeholder="inherit"
                              className="w-24 rounded-md border border-border bg-bg-panel px-2 py-1 font-mono text-xs text-text focus:border-accent focus:outline-none"
                            />
                          </td>
                          <td className="px-3 py-2 font-mono text-xs text-text whitespace-nowrap">
                            {effectiveTxt}{' '}
                            {sev.inherited && (
                              <span className="text-text-faint font-sans">(inherited)</span>
                            )}
                          </td>
                          <td className="px-3 py-2 hidden sm:table-cell text-text-faint font-mono whitespace-nowrap">
                            {sev.tracked
                              ? `~${formatNumber(sev.est_rows)} rows (${formatBytes(sev.est_bytes)})`
                              : 'below threshold'}
                          </td>
                          <td className="px-3 py-2 hidden md:table-cell text-text-dim font-mono whitespace-nowrap">
                            {sev.rate_available
                              ? `~${formatNumber(sev.rows_per_day)}/d (${formatBytes(sev.bytes_per_day)}/d)`
                              : 'measuring...'}
                          </td>
                          <td className="px-4 py-2 hidden lg:table-cell font-mono text-text whitespace-nowrap">
                            {!sev.rate_available
                              ? '—'
                              : sev.projected_forever
                                ? 'Unbounded'
                                : `~${formatBytes(sev.projected_bytes)}`}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
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
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-border bg-bg-panel text-[11px] font-semibold uppercase tracking-wider text-text-faint">
                      <th className="px-4 py-2.5">Stream</th>
                      <th className="px-3 py-2.5">Status</th>
                      <th className="px-3 py-2.5">Verified Through</th>
                      <th className="px-3 py-2.5">Backlog</th>
                      <th className="px-4 py-2.5">Stored Size</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {archiveStatus.streams.map((s) => (
                      <tr key={s.stream} className="hover:bg-bg-hover">
                        <td className="px-4 py-2.5 font-semibold text-text capitalize">
                          {s.stream}
                        </td>
                        <td className="px-3 py-2.5">
                          <span
                            className={cn(
                              'inline-flex rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase',
                              s.state === 'ok' && 'bg-sig-ok/15 text-sig-ok',
                              (s.state === 'error' || s.state === 'stalled') &&
                                'bg-sig-crit/15 text-sig-crit',
                              s.state !== 'ok' &&
                                s.state !== 'error' &&
                                s.state !== 'stalled' &&
                                'bg-bg-panel text-text-dim',
                            )}
                          >
                            {s.state}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 font-mono text-text-dim">
                          {s.verified_through
                            ? s.verified_through.slice(0, 16).replace('T', ' ') + ' UTC'
                            : '—'}
                        </td>
                        <td className="px-3 py-2.5 font-mono text-text">
                          {s.backlog_chunks ?? 0} chunks
                        </td>
                        <td className="px-4 py-2.5 font-mono text-text">
                          {formatBytes(s.stored_bytes)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
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
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-border bg-bg-panel text-[11px] font-semibold uppercase tracking-wider text-text-faint">
                      <th className="px-4 py-2.5">ID</th>
                      <th className="px-3 py-2.5">Stream</th>
                      <th className="px-3 py-2.5">Window</th>
                      <th className="px-3 py-2.5">State</th>
                      <th className="px-3 py-2.5">Progress</th>
                      <th className="px-4 py-2.5 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {restoreList.map((job) => (
                      <tr key={job.id} className="hover:bg-bg-hover">
                        <td className="px-4 py-2.5 font-mono">#{job.id}</td>
                        <td className="px-3 py-2.5 font-medium capitalize">{job.stream}</td>
                        <td className="px-3 py-2.5 font-mono text-text-dim">
                          {job.start_time?.slice(0, 10)} → {job.end_time?.slice(0, 10)}
                        </td>
                        <td className="px-3 py-2.5 font-mono uppercase">{job.state}</td>
                        <td className="px-3 py-2.5 font-mono">
                          {job.chunks_done}/{job.chunks_total} chunks (
                          {formatNumber(job.rows_restored)} rows)
                        </td>
                        <td className="px-4 py-2.5 text-right">
                          <button
                            type="button"
                            onClick={() => {
                              setStepUpContext({
                                title: `Drop Staged Restore #${job.id}`,
                                description:
                                  'Dropping a staged restore deletes its restored rows from staging.',
                                confirmLabel: 'Drop Restore',
                                danger: true,
                                action: async (creds) => {
                                  await apiFetch(`/admin/api/archive/restores/${job.id}`, {
                                    method: 'DELETE',
                                    body: creds,
                                  });
                                  toast.success(`Dropped restore #${job.id}`);
                                  refetchRestores();
                                },
                              });
                              setStepUpOpen(true);
                            }}
                            className="inline-flex items-center gap-1 rounded border border-sig-crit/40 bg-sig-crit/10 px-2 py-1 text-[11px] text-sig-crit hover:bg-sig-crit/20"
                          >
                            <Trash2 className="h-3 w-3" />
                            Drop
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
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
                <span>{testResult.summary || 'Preflight Check Results'}</span>
              </div>
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
                                        : 'bg-accent/15 text-accent',
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
                                className="w-full rounded-md border border-border bg-bg-panel px-2.5 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
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
                                className="w-full rounded-md border border-border bg-bg-panel px-2.5 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
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
                                  className="flex-1 rounded-md border border-border bg-bg-panel px-2.5 py-1.5 font-mono text-xs text-text focus:border-accent focus:outline-none"
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
                                      className="rounded bg-accent px-2 py-0.5 text-[11px] font-semibold text-white"
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
