import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Sliders,
  ShieldAlert,
  BellRing,
  Layers,
  RotateCcw,
  Plus,
  Copy,
  Trash2,
  Edit3,
  CheckCircle2,
  FlaskConical,
} from 'lucide-react';
import { apiFetch, ApiError, type MeResponse } from '@/lib/api';
import { buildAlertPolicyBody, type AlertPolicy } from '@/lib/alert-policy';
import { cn } from '@/lib/utils';
import { StickySaveBar } from '@/components/ui/sticky-save-bar';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { useToast } from '@/components/ui/toast';

type AlertingTab = 'thresholds' | 'event-rules' | 'notification-profiles' | 'effective';

interface SystemSettingRow {
  key: string;
  value: string;
  category: string;
  type: string;
}

interface AlertOverviewResponse {
  global: Record<string, any>;
  overrides: Array<{
    scope: string;
    scope_id: number;
    scope_name: string;
    alert_type: string;
    kind?: string;
    value?: any;
    shadowed_by_rule?: boolean;
  }>;
}

interface EventRuleProfile {
  id: number;
  name: string;
  description?: string;
  is_default?: boolean;
  device_count?: number;
  site_count?: number;
  disabled_count?: number;
}

interface EventRule {
  id: number;
  name: string;
  description?: string;
  enabled: boolean;
  priority: number;
  vendor?: string;
  action: 'alert' | 'suppress' | 'customize';
  alert_type?: string;
  severity?: string;
  match_pattern?: string;
}

// Structured metadata for the 27 sFlow & Deny Anomaly Detection keys
interface DetectorKnobMeta {
  key: string;
  label: string;
  defaultVal: string;
  unit?: string;
  kind: 'number' | 'toggle' | 'text';
  step?: string;
  group:
    | 'Port & Host Scans'
    | 'DDoS Volumetric & Prefix Protection'
    | 'Exfiltration & C2 Beaconing'
    | 'Firewall Deny Storms'
    | 'Capacity & Sampling Guards';
  hint: string;
}

const DETECTOR_KNOBS: DetectorKnobMeta[] = [
  // Group 1: Port & Host Scans
  {
    key: 'detect_port_scan_ports',
    label: 'Port Scan Threshold',
    defaultVal: '100',
    unit: 'distinct dst ports',
    kind: 'number',
    group: 'Port & Host Scans',
    hint: 'Distinct destination ports contacted by one source within the detection window.',
  },
  {
    key: 'detect_super_spreader_hosts',
    label: 'Super-Spreader Threshold',
    defaultVal: '100',
    unit: 'distinct dst hosts',
    kind: 'number',
    group: 'Port & Host Scans',
    hint: 'Distinct destination hosts contacted by one source within the detection window.',
  },
  // Group 2: DDoS Protection
  {
    key: 'detect_ddos_volumetric_enabled',
    label: 'Enable Per-Host Volumetric DDoS Detector',
    defaultVal: '1',
    kind: 'toggle',
    group: 'DDoS Volumetric & Prefix Protection',
    hint: 'Fires when traffic toward a single victim IP crosses the bps, pps, or fps threshold.',
  },
  {
    key: 'detect_ddos_prefix_enabled',
    label: 'Enable /24 Prefix DDoS Detector',
    defaultVal: '1',
    kind: 'toggle',
    group: 'DDoS Volumetric & Prefix Protection',
    hint: 'Aggregates inbound traffic across /24 subnets to catch carpet-bombing attacks.',
  },
  {
    key: 'detect_ddos_bps',
    label: 'DDoS Victim Bandwidth Ceiling',
    defaultVal: '1000000000',
    unit: 'bits/s (1 Gbps)',
    kind: 'number',
    group: 'DDoS Volumetric & Prefix Protection',
    hint: 'Peak-minute bits/sec per victim host (1000000000 = 1 Gbps).',
  },
  {
    key: 'detect_ddos_pps',
    label: 'DDoS Victim Packet Rate Ceiling',
    defaultVal: '20000',
    unit: 'packets/s',
    kind: 'number',
    group: 'DDoS Volumetric & Prefix Protection',
    hint: 'Packets/sec per victim host.',
  },
  {
    key: 'detect_ddos_fps',
    label: 'DDoS Victim Flow Rate Ceiling (NetFlow)',
    defaultVal: '3500',
    unit: 'flows/s',
    kind: 'number',
    group: 'DDoS Volumetric & Prefix Protection',
    hint: 'Flows/sec per victim host (NetFlow streams).',
  },
  {
    key: 'detect_ddos_prefix_bps',
    label: 'DDoS /24 Prefix Bandwidth Ceiling',
    defaultVal: 'per-host',
    unit: 'bits/s',
    kind: 'number',
    group: 'DDoS Volumetric & Prefix Protection',
    hint: 'Blank inherits per-host bps threshold.',
  },
  {
    key: 'detect_ddos_prefix_pps',
    label: 'DDoS /24 Prefix Packet Rate Ceiling',
    defaultVal: 'per-host',
    unit: 'packets/s',
    kind: 'number',
    group: 'DDoS Volumetric & Prefix Protection',
    hint: 'Blank inherits per-host pps threshold.',
  },
  {
    key: 'detect_ddos_prefix_fps',
    label: 'DDoS /24 Prefix Flow Rate Ceiling',
    defaultVal: 'per-host',
    unit: 'flows/s',
    kind: 'number',
    group: 'DDoS Volumetric & Prefix Protection',
    hint: 'Blank inherits per-host fps threshold.',
  },
  // Group 3: Exfiltration & C2 Beaconing
  {
    key: 'detect_data_exfil_bytes',
    label: 'Outbound Data Exfiltration Threshold',
    defaultVal: '1073741824',
    unit: 'bytes (1 GiB)',
    kind: 'number',
    group: 'Exfiltration & C2 Beaconing',
    hint: 'Outbound bytes transferred by an internal host (1073741824 = 1 GiB).',
  },
  {
    key: 'detect_beacon_min_samples',
    label: 'C2 Beacon Minimum Flow Samples',
    defaultVal: '8',
    unit: 'flows',
    kind: 'number',
    group: 'Exfiltration & C2 Beaconing',
    hint: 'Minimum periodic flows required before evaluating interval regularity.',
  },
  {
    key: 'detect_beacon_max_avg_bytes',
    label: 'C2 Beacon Maximum Average Flow Size',
    defaultVal: '1500',
    unit: 'bytes',
    kind: 'number',
    group: 'Exfiltration & C2 Beaconing',
    hint: 'Filters out bulk transfers so only small heartbeat flows match.',
  },
  {
    key: 'detect_beacon_max_cv',
    label: 'C2 Beacon Max Interval Coefficient of Variation',
    defaultVal: '0.35',
    unit: 'CV (0–5)',
    kind: 'number',
    step: '0.01',
    group: 'Exfiltration & C2 Beaconing',
    hint: 'Lower CV means stricter periodicity (0.35 = highly regular interval).',
  },
  // Group 4: Firewall Deny Storms
  {
    key: 'detect_deny_storm_enabled',
    label: 'Enable Source Deny-Storm Detector',
    defaultVal: '1',
    kind: 'toggle',
    group: 'Firewall Deny Storms',
    hint: 'Alerts when a single source triggers excessive firewall denies in 15 minutes.',
  },
  {
    key: 'detect_deny_storm_victim_enabled',
    label: 'Enable Distributed Deny-Storm Victim Detector',
    defaultVal: '1',
    kind: 'toggle',
    group: 'Firewall Deny Storms',
    hint: 'Alerts when a destination is targeted by many denied sources.',
  },
  {
    key: 'detect_denied_then_allowed_enabled',
    label: 'Enable Denied-Then-Allowed Breach Detector',
    defaultVal: '1',
    kind: 'toggle',
    group: 'Firewall Deny Storms',
    hint: 'Alerts when a source is repeatedly denied and subsequently permitted.',
  },
  {
    key: 'detect_deny_storm_min_denies',
    label: 'External (WAN) Deny Storm Threshold',
    defaultVal: '300',
    unit: 'denies / 15m',
    kind: 'number',
    group: 'Firewall Deny Storms',
    hint: 'Minimum WAN denies in 15 minutes from one external source.',
  },
  {
    key: 'detect_deny_storm_min_denies_internal',
    label: 'Internal (LAN) Deny Storm Threshold',
    defaultVal: '100',
    unit: 'denies / 15m',
    kind: 'number',
    group: 'Firewall Deny Storms',
    hint: 'Minimum LAN denies in 15 minutes from an internal host.',
  },
  {
    key: 'detect_deny_storm_victim_min_sources',
    label: 'Deny Storm Victim — Distinct Sources',
    defaultVal: '200',
    unit: 'sources',
    kind: 'number',
    group: 'Firewall Deny Storms',
    hint: 'Distinct denied source IPs hitting the same victim.',
  },
  {
    key: 'detect_deny_storm_victim_min_denies',
    label: 'Deny Storm Victim — Total Denies',
    defaultVal: '2000',
    unit: 'denies',
    kind: 'number',
    group: 'Firewall Deny Storms',
    hint: 'Raw denied count hitting the same victim.',
  },
  {
    key: 'detect_denied_then_allowed_min',
    label: 'Denied-Then-Allowed Prior Denies',
    defaultVal: '2',
    unit: 'prior denies',
    kind: 'number',
    group: 'Firewall Deny Storms',
    hint: 'Number of prior denies before an allow triggers an alert.',
  },
  {
    key: 'detect_deny_policy_pattern',
    label: 'Block-Policy Name Glob',
    defaultVal: 'IP_BLOCK*',
    kind: 'text',
    group: 'Firewall Deny Storms',
    hint: 'Policy name pattern treated as known blocklist drops (e.g. IP_BLOCK*).',
  },
  // Group 5: Capacity & Sampling Guards
  {
    key: 'detect_capacity_threshold',
    label: 'Interface Capacity Utilisation Fraction',
    defaultVal: '0.80',
    unit: 'fraction (0–1)',
    kind: 'number',
    step: '0.01',
    group: 'Capacity & Sampling Guards',
    hint: '0.80 = alert at 80% sustained link utilisation.',
  },
  {
    key: 'detect_sampling_rate_change_enabled',
    label: 'Enable sFlow Sampling-Rate Drift Guard',
    defaultVal: '1',
    kind: 'toggle',
    group: 'Capacity & Sampling Guards',
    hint: 'Alerts when a device unexpectedly changes its sFlow packet sampling rate.',
  },
  {
    key: 'detect_samprate_min_rows',
    label: 'Sampling-Rate Guard Minimum Samples',
    defaultVal: '3',
    unit: 'samples',
    kind: 'number',
    group: 'Capacity & Sampling Guards',
    hint: 'Minimum samples at the new rate before alerting.',
  },
];

const GLOBAL_THRESHOLD_META: Array<{
  key: string;
  label: string;
  unit: string;
  category: 'alerts' | 'spike';
  group: string;
  step?: string;
}> = [
  { key: 'cpu_threshold', label: 'Firewall CPU High', unit: '%', category: 'alerts', group: 'Device Resource Thresholds' },
  { key: 'memory_threshold', label: 'Firewall Memory High', unit: '%', category: 'alerts', group: 'Device Resource Thresholds' },
  { key: 'disk_threshold', label: 'Firewall Disk High', unit: '%', category: 'alerts', group: 'Device Resource Thresholds' },
  { key: 'session_threshold', label: 'Concurrent Sessions High', unit: 'sessions', category: 'alerts', group: 'Device Resource Thresholds' },
  { key: 'telemetry_stale_minutes', label: 'Polled Telemetry Stale After', unit: 'minutes', category: 'alerts', group: 'Server & Collector Health' },
  { key: 'server_disk_threshold', label: 'Monitoring Server Disk High', unit: '%', category: 'alerts', group: 'Server & Collector Health' },
  { key: 'server_disk_free_floor_gb', label: 'Server Disk Free Floor', unit: 'GiB', category: 'alerts', group: 'Server & Collector Health' },
  { key: 'spike_stddev_threshold', label: 'Traffic Spike StdDev Multiplier', unit: 'σ (1–10)', category: 'spike', group: 'Bandwidth Spike Detector', step: '0.1' },
  { key: 'spike_min_duration_minutes', label: 'Spike Sustained Duration', unit: 'minutes', category: 'spike', group: 'Bandwidth Spike Detector' },
  { key: 'spike_min_throughput_mbps', label: 'Spike Minimum Throughput Floor', unit: 'Mbps', category: 'spike', group: 'Bandwidth Spike Detector' },
  { key: 'archive_lag_alert_hours_syslog', label: 'Archive Syslog Lag Alert', unit: 'hours late', category: 'alerts', group: 'Raw Archive Health Alerts' },
  { key: 'archive_lag_alert_hours_flows', label: 'Archive Flows Lag Alert', unit: 'hours late', category: 'alerts', group: 'Raw Archive Health Alerts' },
  { key: 'archive_lag_alert_hours_counters', label: 'Archive Counters Lag Alert', unit: 'hours late', category: 'alerts', group: 'Raw Archive Health Alerts' },
  { key: 'archive_seal_overdue_alert_days', label: 'Monthly Seal Overdue Alert', unit: 'days', category: 'alerts', group: 'Raw Archive Health Alerts' },
  { key: 'retention_held_alert_hours', label: 'Retention Gate Held Alert', unit: 'hours', category: 'alerts', group: 'Raw Archive Health Alerts' },
  { key: 'archive_unsettled_alert_hours', label: 'Unsettled Chunk Alert', unit: 'hours', category: 'alerts', group: 'Raw Archive Health Alerts' },
];

export function AlertingWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = ((searchParams.get('tab') as AlertingTab) || 'thresholds') as AlertingTab;
  const setTab = (tab: AlertingTab) => setSearchParams({ tab }, { replace: true });

  const queryClient = useQueryClient();
  const toast = useToast();

  const { data: me } = useQuery({
    queryKey: ['me'],
    queryFn: () => apiFetch<MeResponse>('/admin/api/me'),
  });

  // --- Queries ---
  const { data: overview } = useQuery({
    queryKey: ['alert-config-overview'],
    queryFn: () => apiFetch<AlertOverviewResponse>('/admin/api/alert-config/overview'),
  });

  const { data: allSettings = [] } = useQuery({
    queryKey: ['settings-all'],
    queryFn: () => apiFetch<SystemSettingRow[]>('/admin/api/settings'),
  });

  const { data: policies = [], refetch: refetchPolicies } = useQuery({
    queryKey: ['alert-policies'],
    queryFn: () => apiFetch<AlertPolicy[]>('/admin/api/alert-policies'),
    enabled: activeTab === 'notification-profiles' || activeTab === 'effective',
  });

  const { data: eventProfiles = [] } = useQuery({
    queryKey: ['event-rule-profiles'],
    queryFn: () => apiFetch<EventRuleProfile[]>('/admin/api/event-rule-profiles'),
    enabled: activeTab === 'event-rules' || activeTab === 'effective',
  });

  const { data: eventRules = [], refetch: refetchEventRules } = useQuery({
    queryKey: ['event-rules'],
    queryFn: () => apiFetch<EventRule[]>('/admin/api/event-rules'),
    enabled: activeTab === 'event-rules',
  });

  const { data: devices = [] } = useQuery({
    queryKey: ['devices-list'],
    queryFn: () => apiFetch<Array<{ id: number; name: string; site_id?: number }>>('/admin/api/devices'),
    enabled: activeTab === 'effective',
  });

  // =========================================================================
  // SUB-TAB 1: Unified Global Thresholds + 27 Detection Knobs State
  // =========================================================================
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [onlyOverriddenDetectors, setOnlyOverriddenDetectors] = useState(false);
  const [savingThresholds, setSavingThresholds] = useState(false);

  const baseline = useMemo(() => {
    const map: Record<string, string> = {};
    const g = overview?.global || {};
    for (const m of GLOBAL_THRESHOLD_META) {
      map[m.key] = g[m.key] !== undefined && g[m.key] !== null ? String(g[m.key]) : '';
    }
    map['spike_alert_enabled'] = g.spike_alert_enabled === true ? 'true' : 'false';

    for (const d of DETECTOR_KNOBS) {
      const found = allSettings.find((s) => s.key === d.key);
      map[d.key] = found ? found.value : '';
    }
    return map;
  }, [overview, allSettings]);

  useEffect(() => {
    setEdits({});
  }, [baseline]);

  const getVal = (key: string) => (key in edits ? edits[key] : (baseline[key] ?? ''));

  const dirtyKeys = useMemo(() => {
    return Object.keys(edits).filter((k) => (edits[k] ?? '') !== (baseline[k] ?? ''));
  }, [edits, baseline]);

  const handleSaveThresholdsAndDetectors = async () => {
    if (dirtyKeys.length === 0) return;
    setSavingThresholds(true);
    try {
      const payload = dirtyKeys.map((key) => {
        if (key === 'spike_alert_enabled') {
          return { key, value: getVal(key), category: 'spike', type: 'bool' };
        }
        const gMeta = GLOBAL_THRESHOLD_META.find((m) => m.key === key);
        if (gMeta) {
          return {
            key,
            value: getVal(key).trim(),
            category: gMeta.category,
            type: 'string',
          };
        }
        return {
          key,
          value: getVal(key).trim(),
          category: 'detection',
          type: 'string',
        };
      });

      await apiFetch('/admin/api/settings', {
        method: 'POST',
        body: payload,
      });
      toast.success(
        'Alerting & detection thresholds saved',
        `Updated ${dirtyKeys.length} ${dirtyKeys.length === 1 ? 'setting' : 'settings'}.`,
      );
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['alert-config-overview'] }),
        queryClient.invalidateQueries({ queryKey: ['settings-all'] }),
      ]);
      setEdits({});
    } catch (err) {
      toast.error(
        'Failed to save thresholds',
        err instanceof ApiError ? err.message : 'Save failed',
      );
    } finally {
      setSavingThresholds(false);
    }
  };

  // =========================================================================
  // SUB-TAB 2: Event Rules & Live Tester Drawer State
  // =========================================================================
  const [testerOpen, setTesterOpen] = useState(false);
  const [testMatchJson, setTestMatchJson] = useState('');
  const [testResultJson, setTestResultJson] = useState<any>(null);

  const handleRunRuleTest = async () => {
    if (!testMatchJson.trim()) return;
    try {
      // TestEventRule binds match_json and evaluates it against recent syslog;
      // raw_message was ignored, so every "test" compiled a match-all rule.
      const res = await apiFetch('/admin/api/event-rules/test', {
        method: 'POST',
        body: { match_json: testMatchJson.trim() },
      });
      setTestResultJson(res);
    } catch (err) {
      toast.error('Rule test failed', err instanceof ApiError ? err.message : 'Test error');
    }
  };

  // =========================================================================
  // SUB-TAB 3: Notification Profile Slide-Over Drawer (Replaces 2,746px Modal!)
  // =========================================================================
  const [editingPolicy, setEditingPolicy] = useState<AlertPolicy | null>(null);
  const [policyDrawerTab, setPolicyDrawerTab] = useState<'general' | 'channels' | 'matrix'>('general');
  const [policyName, setPolicyName] = useState('');
  const [policyDesc, setPolicyDesc] = useState('');
  const [policyCooldown, setPolicyCooldown] = useState('15');
  const [policyEmail, setPolicyEmail] = useState(false);
  const [policySlack, setPolicySlack] = useState(false);
  const [policyDiscord, setPolicyDiscord] = useState(false);
  const [policyTeams, setPolicyTeams] = useState(false);
  const [policyWebhook, setPolicyWebhook] = useState(false);
  const [policyPagerduty, setPolicyPagerduty] = useState(false);
  const [policyRecipients, setPolicyRecipients] = useState('');
  const [savingPolicy, setSavingPolicy] = useState(false);

  const openPolicyDrawer = (pol?: AlertPolicy) => {
    if (pol) {
      setEditingPolicy(pol);
      setPolicyName(pol.name || '');
      setPolicyDesc(pol.description || '');
      setPolicyCooldown(String(pol.cooldown_minutes ?? 15));
      setPolicyEmail(!!pol.notify_email);
      setPolicySlack(!!pol.notify_slack);
      setPolicyDiscord(!!pol.notify_discord);
      setPolicyTeams(!!pol.notify_teams);
      setPolicyWebhook(!!pol.notify_webhook);
      setPolicyPagerduty(!!pol.notify_pagerduty);
      setPolicyRecipients(pol.email_recipients || '');
    } else {
      setEditingPolicy({ id: 0, name: '' });
      setPolicyName('');
      setPolicyDesc('');
      setPolicyCooldown('15');
      setPolicyEmail(true);
      setPolicySlack(false);
      setPolicyDiscord(false);
      setPolicyTeams(false);
      setPolicyWebhook(false);
      setPolicyPagerduty(false);
      setPolicyRecipients('');
    }
    setPolicyDrawerTab('general');
  };

  const handleSavePolicy = async () => {
    if (!editingPolicy) return;
    if (!policyName.trim()) {
      toast.error('Profile name is required');
      return;
    }
    setSavingPolicy(true);
    try {
      const body = buildAlertPolicyBody(editingPolicy, {
        name: policyName,
        description: policyDesc,
        cooldown: policyCooldown,
        email: policyEmail,
        slack: policySlack,
        discord: policyDiscord,
        teams: policyTeams,
        webhook: policyWebhook,
        pagerduty: policyPagerduty,
        recipients: policyRecipients,
      });
      if (editingPolicy.id === 0) {
        await apiFetch('/admin/api/alert-policies', { method: 'POST', body });
        toast.success('Notification profile created');
      } else {
        await apiFetch(`/admin/api/alert-policies/${editingPolicy.id}`, { method: 'PUT', body });
        toast.success('Notification profile updated');
      }
      setEditingPolicy(null);
      refetchPolicies();
    } catch (err) {
      toast.error('Failed to save profile', err instanceof ApiError ? err.message : 'Error');
    } finally {
      setSavingPolicy(false);
    }
  };

  // =========================================================================
  // SUB-TAB 4: Effective Policy Simulator State
  // =========================================================================
  const [simDeviceId, setSimDeviceId] = useState<string>('');
  // GetEffectiveAlertConfig REQUIRES alert_type and 400s without it.
  const [simAlertType, setSimAlertType] = useState('CPU_HIGH');
  const { data: effectiveConfig } = useQuery({
    queryKey: ['effective-alert-config', simDeviceId, simAlertType],
    queryFn: () =>
      apiFetch<Record<string, any>>(
        `/admin/api/alert-config/effective?device_id=${encodeURIComponent(simDeviceId)}&alert_type=${encodeURIComponent(simAlertType)}`,
      ),
    enabled: activeTab === 'effective' && !!simDeviceId,
  });

  const isAdmin = me?.role === 'admin';

  return (
    <div className="space-y-5 pb-20">
      {/* Header & 4 Unified Sub-Tabs */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Sliders className="h-5 w-5 text-accent" />
            <h1 className="font-display text-lg sm:text-xl font-bold text-text">
              Unified Alerting, Anomaly Detection & Rules
            </h1>
          </div>
          <p className="text-xs text-text-faint mt-0.5">
            Single source of truth for resource thresholds, sFlow/Deny anomaly detectors, event rule profiles, and notification routing.
          </p>
        </div>

        <div
          role="tablist"
          aria-label="Alerting configuration sections"
          className="inline-flex rounded-lg border border-border bg-bg-panel p-1 self-start lg:self-auto overflow-x-auto max-w-full"
        >
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'thresholds'}
            onClick={() => setTab('thresholds')}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium whitespace-nowrap transition-colors',
              activeTab === 'thresholds'
                ? 'bg-bg-card text-accent shadow-sm font-semibold'
                : 'text-text-faint hover:text-text',
            )}
          >
            <Sliders className="h-3.5 w-3.5" />
            <span>Thresholds & Detection</span>
            {dirtyKeys.length > 0 && (
              <span className="rounded-full bg-sig-warn/20 px-1.5 py-0.2 font-mono text-[10px] text-sig-warn">
                {dirtyKeys.length}
              </span>
            )}
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'event-rules'}
            onClick={() => setTab('event-rules')}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium whitespace-nowrap transition-colors',
              activeTab === 'event-rules'
                ? 'bg-bg-card text-accent shadow-sm font-semibold'
                : 'text-text-faint hover:text-text',
            )}
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            <span>Event Profiles & Rules</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'notification-profiles'}
            onClick={() => setTab('notification-profiles')}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium whitespace-nowrap transition-colors',
              activeTab === 'notification-profiles'
                ? 'bg-bg-card text-accent shadow-sm font-semibold'
                : 'text-text-faint hover:text-text',
            )}
          >
            <BellRing className="h-3.5 w-3.5" />
            <span>Notification Profiles</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'effective'}
            onClick={() => setTab('effective')}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium whitespace-nowrap transition-colors',
              activeTab === 'effective'
                ? 'bg-bg-card text-accent shadow-sm font-semibold'
                : 'text-text-faint hover:text-text',
            )}
          >
            <Layers className="h-3.5 w-3.5" />
            <span>Effective Policy Simulator</span>
          </button>
        </div>
      </div>

      {/* ===================================================================
       * SUB-TAB 1: GLOBAL THRESHOLDS & 5-CARD ANOMALY DETECTION
       * =================================================================== */}
      {activeTab === 'thresholds' && (
        <div className="space-y-6">
          {/* Part 1: Global Resource, Spike & Archive Thresholds */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[
              'Device Resource Thresholds',
              'Bandwidth Spike Detector',
              'Server & Collector Health',
              'Raw Archive Health Alerts',
            ].map((groupName) => {
              const items = GLOBAL_THRESHOLD_META.filter((m) => m.group === groupName);
              return (
                <section
                  key={groupName}
                  className="rounded-lg border border-border bg-bg-card p-4 space-y-3"
                >
                  <div className="flex items-center justify-between border-b border-border pb-2">
                    <h2 className="font-display text-xs font-bold uppercase tracking-wider text-accent">
                      {groupName}
                    </h2>
                    {groupName === 'Bandwidth Spike Detector' && (
                      <label className="inline-flex items-center gap-2 text-xs text-text cursor-pointer">
                        <input
                          type="checkbox"
                          disabled={!isAdmin}
                          checked={getVal('spike_alert_enabled') === 'true'}
                          onChange={(e) =>
                            setEdits((prev) => ({
                              ...prev,
                              spike_alert_enabled: String(e.target.checked),
                            }))
                          }
                          className="rounded border-border"
                        />
                        <span className="font-medium">Enable Spike Alerts</span>
                      </label>
                    )}
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {items.map((item) => {
                      const val = getVal(item.key);
                      const isEdited = (val ?? '') !== (baseline[item.key] ?? '');
                      return (
                        <div key={item.key} className="space-y-1">
                          <label
                            htmlFor={`g-${item.key}`}
                            className="block text-xs font-medium text-text-dim"
                          >
                            {item.label}
                          </label>
                          <div className="flex items-center gap-1.5">
                            <input
                              id={`g-${item.key}`}
                              type="number"
                              disabled={!isAdmin}
                              step={item.step || '1'}
                              value={val}
                              onChange={(e) =>
                                setEdits((prev) => ({ ...prev, [item.key]: e.target.value }))
                              }
                              className={cn(
                                'w-full rounded-md border bg-bg-panel px-2.5 py-1.5 font-mono text-xs text-text focus:border-accent focus:outline-none tabular-nums',
                                isEdited ? 'border-accent' : 'border-border',
                              )}
                            />
                            <span className="font-mono text-[11px] text-text-faint shrink-0">
                              {item.unit}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </section>
              );
            })}
          </div>

          {/* Part 2: 5-Domain Anomaly Detection Cards (Replaces 2,822px 1-column dump!) */}
          <section className="rounded-lg border border-border bg-bg-card overflow-hidden">
            <div className="border-b border-border bg-bg-panel/50 px-4 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h2 className="font-display text-sm font-bold text-text">
                  Network Flow (sFlow/NetFlow) & Firewall Deny Anomaly Detectors
                </h2>
                <p className="text-xs text-text-faint mt-0.5">
                  Leave any numeric threshold blank to inherit the built-in default. Toggle switches control detector activation live.
                </p>
              </div>
              <label className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-card px-2.5 py-1.5 text-xs text-text-dim cursor-pointer select-none self-start sm:self-auto">
                <input
                  type="checkbox"
                  checked={onlyOverriddenDetectors}
                  onChange={(e) => setOnlyOverriddenDetectors(e.target.checked)}
                  className="rounded border-border"
                />
                <span>Show Overridden Only</span>
              </label>
            </div>

            <div className="p-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
              {(
                [
                  'Port & Host Scans',
                  'DDoS Volumetric & Prefix Protection',
                  'Exfiltration & C2 Beaconing',
                  'Firewall Deny Storms',
                  'Capacity & Sampling Guards',
                ] as const
              ).map((domain) => {
                const knobs = DETECTOR_KNOBS.filter((k) => {
                  if (k.group !== domain) return false;
                  if (onlyOverriddenDetectors && getVal(k.key) === '') return false;
                  return true;
                });
                if (knobs.length === 0) return null;

                return (
                  <div
                    key={domain}
                    className="rounded-lg border border-border bg-bg-panel/30 p-4 space-y-3"
                  >
                    <h3 className="font-display text-xs font-bold uppercase tracking-wider text-accent border-b border-border pb-2">
                      {domain}
                    </h3>

                    <div className="space-y-3">
                      {knobs.map((k) => {
                        const rawVal = getVal(k.key);
                        const isEdited = (rawVal ?? '') !== (baseline[k.key] ?? '');

                        if (k.kind === 'toggle') {
                          // In DB: "" or "1" = enabled (when defaultVal is '1'), "0" = disabled
                          const isChecked = rawVal === '' ? k.defaultVal === '1' : rawVal !== '0';
                          return (
                            <div
                              key={k.key}
                              className="flex items-start justify-between gap-3 rounded-md border border-border/70 bg-bg-card p-2.5"
                            >
                              <div>
                                <label
                                  htmlFor={`det-${k.key}`}
                                  className="text-xs font-semibold text-text cursor-pointer"
                                >
                                  {k.label}
                                </label>
                                <div className="text-[11px] text-text-faint mt-0.5">{k.hint}</div>
                              </div>
                              <input
                                id={`det-${k.key}`}
                                type="checkbox"
                                disabled={!isAdmin}
                                checked={isChecked}
                                onChange={(e) =>
                                  setEdits((prev) => ({
                                    ...prev,
                                    [k.key]: e.target.checked ? '1' : '0',
                                  }))
                                }
                                className="mt-1 h-4 w-4 rounded border-border text-accent"
                              />
                            </div>
                          );
                        }

                        return (
                          <div key={k.key} className="space-y-1">
                            <div className="flex items-center justify-between gap-2">
                              <label
                                htmlFor={`det-${k.key}`}
                                className="text-xs font-medium text-text"
                              >
                                {k.label}
                              </label>
                              {k.unit && (
                                <span className="font-mono text-[10px] text-text-mute">
                                  {k.unit}
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-1.5">
                              <input
                                id={`det-${k.key}`}
                                type={k.kind === 'text' ? 'text' : 'number'}
                                disabled={!isAdmin}
                                step={k.step || '1'}
                                min={k.kind === 'number' ? 0 : undefined}
                                value={rawVal}
                                onChange={(e) =>
                                  setEdits((prev) => ({ ...prev, [k.key]: e.target.value }))
                                }
                                placeholder={`default (${k.defaultVal})`}
                                className={cn(
                                  'flex-1 rounded-md border bg-bg-card px-2.5 py-1.5 font-mono text-xs text-text focus:border-accent focus:outline-none tabular-nums',
                                  isEdited ? 'border-accent' : 'border-border',
                                )}
                              />
                              {rawVal !== '' && isAdmin && (
                                <button
                                  type="button"
                                  onClick={() =>
                                    setEdits((prev) => ({ ...prev, [k.key]: '' }))
                                  }
                                  title="Reset to default"
                                  aria-label={`Reset ${k.label} to default`}
                                  className="rounded p-1.5 text-text-faint hover:bg-bg-card hover:text-text"
                                >
                                  <RotateCcw className="h-3.5 w-3.5" />
                                </button>
                              )}
                            </div>
                            <div className="text-[11px] text-text-faint">{k.hint}</div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Part 3: Active Scoped Overrides Summary */}
          <section className="rounded-lg border border-border bg-bg-card overflow-hidden">
            <div className="border-b border-border bg-bg-panel/50 px-4 py-3">
              <h2 className="font-display text-sm font-bold text-text">
                Active Scoped Overrides ({overview?.overrides?.length || 0})
              </h2>
              <p className="text-xs text-text-faint mt-0.5">
                Sites, Devices, Notification Profiles, and Event Profiles that override global defaults.
              </p>
            </div>
            {!overview?.overrides || overview.overrides.length === 0 ? (
              <div className="p-6 text-center text-xs text-text-faint">
                No scoped overrides — global defaults apply across the entire fleet.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-border bg-bg-panel text-[11px] font-semibold uppercase tracking-wider text-text-faint">
                      <th className="px-4 py-2.5">Scope</th>
                      <th className="px-3 py-2.5">Target Name</th>
                      <th className="px-3 py-2.5">Alert / Metric</th>
                      <th className="px-4 py-2.5">Override Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {overview.overrides.map((ov, i) => (
                      <tr key={i} className="hover:bg-bg-hover">
                        <td className="px-4 py-2.5 font-mono uppercase text-[11px] text-text-faint">
                          {ov.scope}
                        </td>
                        <td className="px-3 py-2.5 font-semibold text-text">{ov.scope_name}</td>
                        <td className="px-3 py-2.5 font-mono text-text-dim">
                          {ov.kind === 'disabled'
                            ? `${ov.alert_type || 'All alerts'} (Disabled)`
                            : ov.alert_type}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-accent">
                          {ov.value !== undefined && ov.value !== null ? String(ov.value) : 'Off'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <StickySaveBar
            isDirty={dirtyKeys.length > 0}
            dirtyCount={dirtyKeys.length}
            isSaving={savingThresholds}
            onDiscard={() => setEdits({})}
            onSave={handleSaveThresholdsAndDetectors}
            saveLabel="Save Thresholds & Detectors"
          />
        </div>
      )}

      {/* ===================================================================
       * SUB-TAB 2: EVENT PROFILES & CUSTOM EVENT RULES
       * =================================================================== */}
      {activeTab === 'event-rules' && (
        <div className="space-y-6">
          {/* Event Rule Profiles */}
          <section className="rounded-lg border border-border bg-bg-card overflow-hidden">
            <div className="border-b border-border bg-bg-panel/50 px-4 py-3 flex items-center justify-between">
              <div>
                <h2 className="font-display text-sm font-bold text-text">
                  Event Rule Profiles (Default → Site → Device Toggle Chain)
                </h2>
                <p className="text-xs text-text-faint mt-0.5">
                  Enable or mute built-in alert types across sites or devices without writing regex rules.
                </p>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5 p-4">
              {eventProfiles.map((prof) => (
                <div
                  key={prof.id}
                  className="rounded-lg border border-border bg-bg-panel/30 p-4 flex flex-col justify-between gap-3"
                >
                  <div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-display text-xs font-bold text-text">{prof.name}</span>
                      {prof.is_default && (
                        <span className="rounded bg-accent/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-accent">
                          DEFAULT
                        </span>
                      )}
                    </div>
                    {prof.description && (
                      <p className="text-xs text-text-faint mt-1">{prof.description}</p>
                    )}
                  </div>
                  <div className="flex items-center justify-between text-[11px] font-mono text-text-faint border-t border-border pt-2.5">
                    <span>{prof.disabled_count ?? 0} muted types</span>
                    <span>
                      {prof.site_count ?? 0} sites · {prof.device_count ?? 0} devices
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Custom Event Rules Table + Tester Trigger */}
          <section className="rounded-lg border border-border bg-bg-card overflow-hidden">
            <div className="border-b border-border bg-bg-panel/50 px-4 py-3 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="font-display text-sm font-bold text-text">
                  Custom Syslog & Flow Event Rules ({eventRules.length})
                </h2>
                <p className="text-xs text-text-faint mt-0.5">
                  Vendor-aware suppress, alert, and severity customization rules evaluated in priority order.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setTesterOpen(true)}
                className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-semibold text-accent hover:border-accent"
              >
                <FlaskConical className="h-3.5 w-3.5" />
                <span>Test Sample Syslog</span>
              </button>
            </div>

            {eventRules.length === 0 ? (
              <div className="p-6 text-center text-xs text-text-faint">
                No custom event rules configured.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-border bg-bg-panel text-[11px] font-semibold uppercase tracking-wider text-text-faint">
                      <th className="px-4 py-2.5">Priority</th>
                      <th className="px-3 py-2.5">Rule Name</th>
                      <th className="px-3 py-2.5">Action</th>
                      <th className="px-3 py-2.5">Vendor</th>
                      <th className="px-4 py-2.5 text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {eventRules.map((r) => (
                      <tr key={r.id} className="hover:bg-bg-hover">
                        <td className="px-4 py-2.5 font-mono">#{r.priority}</td>
                        <td className="px-3 py-2.5 font-semibold text-text">{r.name}</td>
                        <td className="px-3 py-2.5">
                          <span
                            className={cn(
                              'rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase',
                              r.action === 'suppress' && 'bg-sig-warn/15 text-sig-warn',
                              r.action === 'alert' && 'bg-sig-crit/15 text-sig-crit',
                              r.action === 'customize' && 'bg-accent/15 text-accent',
                            )}
                          >
                            {r.action}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 font-mono text-text-faint">
                          {r.vendor || 'any'}
                        </td>
                        <td className="px-4 py-2.5 text-right">
                          <button
                            type="button"
                            onClick={async () => {
                              await apiFetch(`/admin/api/event-rules/${r.id}`, {
                                method: 'PUT',
                                body: { ...r, enabled: !r.enabled },
                              });
                              refetchEventRules();
                            }}
                            className={cn(
                              'rounded px-2 py-0.5 font-mono text-[10px] font-semibold uppercase',
                              r.enabled
                                ? 'bg-sig-ok/15 text-sig-ok'
                                : 'bg-bg-panel text-text-mute',
                            )}
                          >
                            {r.enabled ? 'Enabled' : 'Disabled'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {/* Slide-Over Syslog Rule Tester */}
          <SlideOverDrawer
            open={testerOpen}
            onOpenChange={setTesterOpen}
            title="Event Rule Match Tester"
            subtitle="Test a match expression against the most recent syslog messages and see the sample matches."
            size="lg"
            footer={
              <>
                <button
                  type="button"
                  onClick={() => setTesterOpen(false)}
                  className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text-dim"
                >
                  Close
                </button>
                <button
                  type="button"
                  onClick={handleRunRuleTest}
                  className="rounded-md bg-accent px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-accent-hover"
                >
                  Test Match Expression
                </button>
              </>
            }
          >
            <div className="space-y-4">
              <div>
                <label
                  htmlFor="rule-test-input"
                  className="block text-xs font-medium text-text-dim mb-1"
                >
                  Match Expression (JSON)
                </label>
                <textarea
                  id="rule-test-input"
                  rows={5}
                  value={testMatchJson}
                  onChange={(e) => setTestMatchJson(e.target.value)}
                  placeholder='{"op":"contains","field":"src_ip","value":"198.51.100."}'
                  className="w-full rounded-md border border-border bg-bg-panel p-2.5 font-mono text-xs text-text focus:border-accent focus:outline-none"
                />
                <p className="mt-1 text-[11px] text-text-faint">
                  Operators: and, or, in, regex, gt, lt over extracted fields such as src_ip,
                  dst_ip, user, action, device, interface.
                </p>
              </div>

              {testResultJson && (
                <pre className="rounded-md border border-border bg-bg-panel p-3 font-mono text-[11px] text-text overflow-x-auto">
                  {JSON.stringify(testResultJson, null, 2)}
                </pre>
              )}
            </div>
          </SlideOverDrawer>
        </div>
      )}

      {/* ===================================================================
       * SUB-TAB 3: NOTIFICATION PROFILES (Replaces 2,746px Modal with Drawer!)
       * =================================================================== */}
      {activeTab === 'notification-profiles' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-display text-sm font-bold text-text">
                Notification Profiles ({policies.length})
              </h2>
              <p className="text-xs text-text-faint">
                Define delivery channels, cooldowns, and alert-type routing without scrolling a 2,700px modal.
              </p>
            </div>
            {isAdmin && (
              <button
                type="button"
                onClick={() => openPolicyDrawer()}
                data-testid="new-notification-profile-btn"
                className="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-hover"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>New Profile</span>
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {policies.map((pol) => {
              const activeChannels = [
                pol.notify_email && 'Email',
                pol.notify_slack && 'Slack',
                pol.notify_discord && 'Discord',
                pol.notify_teams && 'Teams',
                pol.notify_webhook && 'Webhook',
                pol.notify_pagerduty && 'PagerDuty',
                pol.notify_opsgenie && 'Opsgenie',
              ].filter(Boolean);

              return (
                <div
                  key={pol.id}
                  className="rounded-lg border border-border bg-bg-card p-4 flex flex-col justify-between gap-4"
                >
                  <div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-display text-sm font-bold text-text">{pol.name}</span>
                      {pol.is_default && (
                        <span className="rounded bg-sig-ok/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-sig-ok">
                          DEFAULT
                        </span>
                      )}
                    </div>
                    {pol.description && (
                      <p className="text-xs text-text-faint mt-1">{pol.description}</p>
                    )}

                    <div className="mt-3 flex flex-wrap gap-1.5">
                      {activeChannels.length > 0 ? (
                        activeChannels.map((ch) => (
                          <span
                            key={String(ch)}
                            className="rounded border border-border bg-bg-panel px-2 py-0.5 font-mono text-[10px] text-text-dim"
                          >
                            {ch}
                          </span>
                        ))
                      ) : (
                        <span className="text-[11px] text-text-mute">No channels enabled</span>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center justify-between border-t border-border pt-3">
                    <span className="font-mono text-[11px] text-text-faint">
                      Cooldown: {pol.cooldown_minutes ?? 15}m
                    </span>
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => openPolicyDrawer(pol)}
                        data-testid={`edit-policy-${pol.id}`}
                        className="inline-flex items-center gap-1 rounded border border-border bg-bg-panel px-2.5 py-1 text-xs font-medium text-text hover:border-accent"
                      >
                        <Edit3 className="h-3 w-3 text-accent" />
                        Edit in Drawer
                      </button>
                      <button
                        type="button"
                        onClick={async () => {
                          await apiFetch(`/admin/api/alert-policies/${pol.id}/clone`, {
                            method: 'POST',
                          });
                          toast.success(`Cloned "${pol.name}"`);
                          refetchPolicies();
                        }}
                        title="Clone profile"
                        aria-label={`Clone ${pol.name}`}
                        className="rounded border border-border bg-bg-panel p-1 text-text-faint hover:text-text"
                      >
                        <Copy className="h-3.5 w-3.5" />
                      </button>
                      {!pol.is_default && (
                        <button
                          type="button"
                          onClick={async () => {
                            await apiFetch(`/admin/api/alert-policies/${pol.id}`, {
                              method: 'DELETE',
                            });
                            toast.success(`Deleted "${pol.name}"`);
                            refetchPolicies();
                          }}
                          title="Delete profile"
                          aria-label={`Delete ${pol.name}`}
                          className="rounded border border-border bg-bg-panel p-1 text-text-faint hover:text-sig-crit"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Tabbed Slide-Over Drawer for Notification Profile (Pinned Header & Sticky Footer!) */}
          <SlideOverDrawer
            open={!!editingPolicy}
            onOpenChange={(open) => !open && setEditingPolicy(null)}
            title={
              editingPolicy?.id ? `Edit Profile: ${editingPolicy.name}` : 'New Notification Profile'
            }
            subtitle="Configure delivery channels, cooldown window, and alert routing with a permanently pinned save bar."
            size="xl"
            tabs={[
              { id: 'general', label: '1. General & Cooldown' },
              { id: 'channels', label: '2. Delivery Channels' },
              {
                id: 'matrix',
                label: '3. Alert Routing Rules',
                badge: editingPolicy?.rules?.length || 0,
              },
            ]}
            activeTab={policyDrawerTab}
            onTabChange={(id) => setPolicyDrawerTab(id as any)}
            footer={
              <>
                <button
                  type="button"
                  onClick={() => setEditingPolicy(null)}
                  className="rounded-md border border-border bg-bg-card px-3 py-1.5 text-xs font-medium text-text-dim hover:text-text"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleSavePolicy}
                  disabled={savingPolicy}
                  data-testid="save-policy-drawer-btn"
                  className="inline-flex items-center gap-1.5 rounded-md bg-accent px-4 py-1.5 text-xs font-semibold text-white hover:bg-accent-hover disabled:opacity-50"
                >
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  <span>{savingPolicy ? 'Saving...' : 'Save Profile'}</span>
                </button>
              </>
            }
          >
            {policyDrawerTab === 'general' && (
              <div className="space-y-4">
                <div>
                  <label
                    htmlFor="pol-name"
                    className="block text-xs font-medium text-text-dim mb-1"
                  >
                    Profile Name
                  </label>
                  <input
                    id="pol-name"
                    type="text"
                    value={policyName}
                    onChange={(e) => setPolicyName(e.target.value)}
                    placeholder="e.g. 24x7 NOC Critical Pager"
                    className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text focus:border-accent focus:outline-none"
                  />
                </div>
                <div>
                  <label
                    htmlFor="pol-desc"
                    className="block text-xs font-medium text-text-dim mb-1"
                  >
                    Description
                  </label>
                  <input
                    id="pol-desc"
                    type="text"
                    value={policyDesc}
                    onChange={(e) => setPolicyDesc(e.target.value)}
                    placeholder="Optional notes on which sites/devices use this profile"
                    className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text focus:border-accent focus:outline-none"
                  />
                </div>
                <div>
                  <label
                    htmlFor="pol-cooldown"
                    className="block text-xs font-medium text-text-dim mb-1"
                  >
                    Repeat Notification Cooldown (Minutes)
                  </label>
                  <input
                    id="pol-cooldown"
                    type="number"
                    min={0}
                    max={1440}
                    value={policyCooldown}
                    onChange={(e) => setPolicyCooldown(e.target.value)}
                    className="w-40 rounded-md border border-border bg-bg-panel px-3 py-2 font-mono text-xs text-text focus:border-accent focus:outline-none"
                  />
                </div>
              </div>
            )}

            {policyDrawerTab === 'channels' && (
              <div className="space-y-3">
                {[
                  { id: 'email', label: 'SMTP Email Notifications', state: policyEmail, set: setPolicyEmail },
                  { id: 'slack', label: 'Slack Incoming Webhook', state: policySlack, set: setPolicySlack },
                  { id: 'discord', label: 'Discord Webhook', state: policyDiscord, set: setPolicyDiscord },
                  { id: 'teams', label: 'Microsoft Teams Webhook', state: policyTeams, set: setPolicyTeams },
                  { id: 'webhook', label: 'Generic JSON Webhook (HMAC-SHA256)', state: policyWebhook, set: setPolicyWebhook },
                  { id: 'pagerduty', label: 'PagerDuty Events API v2', state: policyPagerduty, set: setPolicyPagerduty },
                ].map((ch) => (
                  <label
                    key={ch.id}
                    className="flex items-center justify-between rounded-md border border-border bg-bg-panel/50 p-3 cursor-pointer"
                  >
                    <span className="text-xs font-medium text-text">{ch.label}</span>
                    <input
                      type="checkbox"
                      checked={ch.state}
                      onChange={(e) => ch.set(e.target.checked)}
                      className="h-4 w-4 rounded border-border"
                    />
                  </label>
                ))}

                {policyEmail && (
                  <div className="pt-2">
                    <label
                      htmlFor="pol-recipients"
                      className="block text-xs font-medium text-text-dim mb-1"
                    >
                      Override Email Recipients (comma-separated, blank = global SMTP To)
                    </label>
                    <input
                      id="pol-recipients"
                      type="text"
                      value={policyRecipients}
                      onChange={(e) => setPolicyRecipients(e.target.value)}
                      placeholder="noc@example.com, oncall@example.com"
                      className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 font-mono text-xs text-text focus:border-accent focus:outline-none"
                    />
                  </div>
                )}
              </div>
            )}

            {policyDrawerTab === 'matrix' && (
              <div className="space-y-3">
                <p className="text-xs text-text-faint">
                  Per-alert-type routing overrides for this profile ({editingPolicy?.rules?.length || 0} configured rules).
                </p>
                {editingPolicy?.rules && editingPolicy.rules.length > 0 ? (
                  <div className="divide-y divide-border rounded-md border border-border">
                    {editingPolicy.rules.map((r) => (
                      <div
                        key={r.alert_type}
                        className="flex items-center justify-between px-3 py-2 text-xs"
                      >
                        <code className="font-mono text-text">{r.alert_type}</code>
                        <span
                          className={cn(
                            'font-mono text-[10px] uppercase px-1.5 py-0.5 rounded',
                            r.enabled
                              ? 'bg-sig-ok/15 text-sig-ok'
                              : 'bg-sig-crit/15 text-sig-crit',
                          )}
                        >
                          {r.enabled ? `Enabled (${r.min_severity || 'any'})` : 'Muted'}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="rounded-md border border-border bg-bg-panel/40 p-4 text-xs text-text-faint">
                    All alert types use the profile&apos;s default channel settings.
                  </div>
                )}
              </div>
            )}
          </SlideOverDrawer>
        </div>
      )}

      {/* ===================================================================
       * SUB-TAB 4: EFFECTIVE POLICY SIMULATOR
       * =================================================================== */}
      {activeTab === 'effective' && (
        <section className="rounded-lg border border-border bg-bg-card p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border pb-3">
            <div>
              <h2 className="font-display text-sm font-bold text-text">
                Effective Alert Policy Simulator (Global → Profile → Site → Device)
              </h2>
              <p className="text-xs text-text-faint mt-0.5">
                Select any monitored firewall to inspect the exact thresholds and notification channels that apply to it at runtime.
              </p>
            </div>
            <select
              value={simDeviceId}
              onChange={(e) => setSimDeviceId(e.target.value)}
              aria-label="Select device to simulate effective policy"
              className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
            >
              <option value="">-- Select a Firewall Device --</option>
              {devices.map((d) => (
                <option key={d.id} value={String(d.id)}>
                  {d.name} (#{d.id})
                </option>
              ))}
            </select>
            <select
              value={simAlertType}
              onChange={(e) => setSimAlertType(e.target.value)}
              aria-label="Alert type to simulate"
              className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
            >
              <option value="CPU_HIGH">CPU high</option>
              <option value="MEMORY_HIGH">Memory high</option>
              <option value="DISK_HIGH">Disk high</option>
              <option value="SESSIONS_HIGH">Sessions high</option>
            </select>
          </div>

          {!simDeviceId ? (
            <div className="p-6 text-center text-xs text-text-faint">
              Choose a firewall above to compute its resolved alerting & event rule chain.
            </div>
          ) : (
            <pre className="rounded-md border border-border bg-bg-panel p-4 font-mono text-xs text-text overflow-x-auto">
              {JSON.stringify(effectiveConfig || {}, null, 2)}
            </pre>
          )}
        </section>
      )}
    </div>
  );
}
