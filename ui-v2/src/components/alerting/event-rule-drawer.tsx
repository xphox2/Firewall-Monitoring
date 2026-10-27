import { useEffect, useMemo, useState } from 'react';
import { apiFetch } from '@/lib/api';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { useToast } from '@/components/ui/toast';
import { FlaskConical, Plus, Trash2 } from 'lucide-react';
import {
  EMPTY_DRAFT,
  buildDampen,
  buildMatch,
  buildRulePayload,
  draftError,
  draftFromRule,
  parseMatch,
  type Draft,
  type EventRuleRecord,
} from '@/lib/event-rule';
import { Input, Select } from '@/components/ui/input';
import { Textarea } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

/** Re-exported so pages can type their lists from one place. */
export type { EventRuleRecord } from '@/lib/event-rule';

interface Option {
  id: number;
  name: string;
}

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  rule: EventRuleRecord | null;
  profiles: Option[];
  devices: Array<{ id: number; name: string; site_id?: number; retired_at?: string | null }>;
  sites: Option[];
  policies: Option[];
  onSaved: () => void;
}

type Tab = 'basics' | 'match' | 'dampen' | 'preview';

const SOURCES = [
  ['syslog', 'Syslog (raw message)'],
  ['flow', 'Flow (sFlow / NetFlow)'],
  ['flow_security', 'Flow security'],
  ['state', 'Device / interface / VPN state'],
  ['metric', 'Metric threshold'],
  ['spike', 'Traffic spike'],
  ['trap', 'SNMP trap'],
  ['device', 'Device up/down'],
  ['any', 'Any source'],
] as const;

const OPS = [
  ['eq', 'equals'],
  ['neq', 'not equals'],
  ['contains', 'contains'],
  ['not_contains', 'does not contain'],
  ['regex', 'regex'],
  ['in', 'in list'],
  ['gt', 'greater than'],
  ['lt', 'less than'],
  ['exists', 'field exists'],
] as const;

const COMMON_FIELDS = [
  'src_ip',
  'dst_ip',
  'src_port',
  'dst_port',
  'user',
  'action',
  'device',
  'interface',
  'tunnel_name',
  'vendor',
  'severity',
  'event_type',
  'app',
  'policy',
];

const SEVERITIES = [
  ['', 'Default'],
  ['info', 'Info'],
  ['warning', 'Warning'],
  ['critical', 'Critical'],
] as const;

const VENDORS = [
  ['', 'Any vendor'],
  ['fortigate', 'FortiGate'],
  ['paloalto', 'Palo Alto'],
  ['cisco_asa', 'Cisco ASA'],
  ['sonicwall', 'SonicWall'],
  ['opnsense', 'OPNsense'],
  ['pfsense', 'pfSense'],
  ['generic', 'Generic'],
] as const;

export function EventRuleDrawer({
  open,
  onOpenChange,
  rule,
  profiles,
  devices,
  sites,
  policies,
  onSaved,
}: Props) {
  const { toast } = useToast();
  const [tab, setTab] = useState<Tab>('basics');
  const [draft, setDraft] = useState<Draft>(EMPTY_DRAFT);
  const [saving, setSaving] = useState(false);
  const [preview, setPreview] = useState<any>(null);
  const [previewing, setPreviewing] = useState(false);
  const [initialisedFor, setInitialisedFor] = useState<number | 'new' | null>(null);

  const defaultProfileId = useMemo(() => {
    const def = profiles.find((p) => (p as any).is_default);
    return def ? String(def.id) : profiles[0] ? String(profiles[0].id) : '';
  }, [profiles]);

  // Initialise once per open/rule change. Profiles load asynchronously, so the
  // guard (not the effect deps) is what prevents a late profile list from
  // clobbering edits the operator has already started.
  const key = rule ? rule.id : 'new';
  useEffect(() => {
    if (!open) {
      setInitialisedFor(null);
      return;
    }
    if (initialisedFor === key) return;
    setInitialisedFor(key);
    setDraft(draftFromRule(rule, defaultProfileId));
    setTab('basics');
    setPreview(null);
  }, [open, key, rule, initialisedFor, defaultProfileId]);

  const set = <K extends keyof Draft>(field: K, value: Draft[K]) =>
    setDraft((d) => ({ ...d, [field]: value }));

  const matchJson = buildMatch(draft);
  const showDampen = ['state', 'metric', 'spike'].includes(draft.source);

  const runPreview = async () => {
    setPreviewing(true);
    try {
      const res = await apiFetch<any>('/admin/api/event-rules/test', {
        method: 'POST',
        body: {
          match_json: matchJson,
          vendor_scope: draft.vendor || '',
          limit: 200,
        },
      });
      setPreview(res);
    } catch (err) {
      toast({
        title: 'Preview failed',
        description: err instanceof Error ? err.message : 'Could not test this rule',
        variant: 'error',
      });
    } finally {
      setPreviewing(false);
    }
  };

  const save = async () => {
    const problem = draftError(draft);
    if (problem) {
      toast({ title: problem, variant: 'error' });
      return;
    }
    const body = buildRulePayload(draft);
    setSaving(true);
    try {
      if (rule) {
        await apiFetch(`/admin/api/event-rules/${rule.id}`, { method: 'PUT', body });
        toast({ title: 'Event rule updated', variant: 'success' });
      } else {
        await apiFetch('/admin/api/event-rules', { method: 'POST', body });
        toast({ title: 'Event rule created', variant: 'success' });
      }
      onSaved();
      onOpenChange(false);
    } catch (err) {
      toast({
        title: 'Save failed',
        description: err instanceof Error ? err.message : 'Could not save the rule',
        variant: 'error',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <SlideOverDrawer
      open={open}
      onOpenChange={onOpenChange}
      title={rule ? `Edit Event Rule: ${rule.name}` : 'Create Event Rule'}
      subtitle="Rules are evaluated in priority order (lower first). The first matching suppress rule drops the event; the first matching alert rule fires and stops."
      size="xl"
      tabs={[
        { id: 'basics', label: 'Basics & Scope' },
        { id: 'match', label: 'Conditions' },
        {
          id: 'dampen',
          label: showDampen ? 'Dampening' : 'Dampening (n/a)',
          badge: showDampen ? undefined : '—',
        },
        { id: 'preview', label: 'Preview' },
      ]}
      activeTab={tab}
      onTabChange={(id) => setTab(id as Tab)}
      footer={
        <div className="flex w-full items-center justify-between gap-2">
          <span className="text-[11px] text-text-faint">
            {draft.action === 'suppress'
              ? 'Suppress rules silence every matching event.'
              : 'Alert rules fire when the conditions match.'}
          </span>
          <div className="flex items-center gap-2">
            <Button  variant="secondary"
              type="button"
              onClick={() => onOpenChange(false)}
              
            >
              Cancel
            </Button>
            <Button  className="px-4"
              type="button"
              disabled={saving}
              onClick={save}
              
            >
              {saving ? 'Saving…' : rule ? 'Save changes' : 'Create rule'}
            </Button>
          </div>
        </div>
      }
    >
      {tab === 'basics' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">Rule name</span>
              <Input
                type="text"
                value={draft.name}
                onChange={(e) => set('name', e.target.value)}
                placeholder="Suppress FortiGate admin login failures"
               
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">Priority (lower first)</span>
              <Input mono
                type="number"
                value={draft.priority}
                onChange={(e) => set('priority', e.target.value)}
               
              />
            </label>
          </div>

          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">Description</span>
            <Textarea className="p-2.5"
              rows={2}
              value={draft.description}
              onChange={(e) => set('description', e.target.value)}
             
            />
          </label>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">Action</span>
              <Select
                value={draft.action}
                onChange={(e) => set('action', e.target.value as 'alert' | 'suppress')}
               
              >
                <option value="alert">Alert (fire)</option>
                <option value="suppress">Suppress (mute)</option>
              </Select>
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">Source</span>
              <Select
                value={draft.source}
                onChange={(e) => set('source', e.target.value)}
               
              >
                {SOURCES.map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </Select>
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">Enabled</span>
              <Select
                value={draft.enabled ? 'yes' : 'no'}
                onChange={(e) => set('enabled', e.target.value === 'yes')}
               
              >
                <option value="yes">Enabled</option>
                <option value="no">Disabled</option>
              </Select>
            </label>
          </div>

          <div className="rounded-lg border border-border bg-bg-panel/40 p-3 space-y-3">
            <div className="text-xs font-semibold text-text">Scope & layering</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <label className="block">
                <span className="mb-1 block text-[11px] font-medium text-text-dim">Profile (layer)</span>
                <Select
                  value={draft.profileId}
                  onChange={(e) => set('profileId', e.target.value)}
                 
                >
                  {profiles.length === 0 && <option value="">Default</option>}
                  {profiles.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                      {(p as any).is_default ? ' (Default)' : ''}
                    </option>
                  ))}
                </Select>
              </label>
              <label className="block">
                <span className="mb-1 block text-[11px] font-medium text-text-dim">Vendor</span>
                <Select
                  value={draft.vendor}
                  onChange={(e) => set('vendor', e.target.value)}
                 
                >
                  {VENDORS.map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </Select>
              </label>
              <label className="block">
                <span className="mb-1 block text-[11px] font-medium text-text-dim">Device</span>
                <Select
                  value={draft.deviceId}
                  onChange={(e) => set('deviceId', e.target.value)}
                 
                >
                  <option value="">Any device</option>
                  {devices
                    .filter(
                      (d) =>
                        !d.retired_at ||
                        (rule?.device_id != null && String(rule.device_id) === String(d.id)),
                    )
                    .map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.name}
                        {d.retired_at ? ' (retired)' : ''}
                      </option>
                    ))}
                </Select>
              </label>
              <label className="block">
                <span className="mb-1 block text-[11px] font-medium text-text-dim">Site</span>
                <Select
                  value={draft.siteId}
                  onChange={(e) => set('siteId', e.target.value)}
                 
                >
                  <option value="">Any site</option>
                  {sites.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </Select>
              </label>
            </div>
            <p className="text-[11px] leading-relaxed text-text-faint">
              Profile decides the layer (Default &lt; Site &lt; Device). Vendor/device/site narrow the
              rule within that layer.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">
                Notification policy {draft.action === 'suppress' ? '(unused)' : ''}
              </span>
              <select
                value={draft.policyId}
                onChange={(e) => set('policyId', e.target.value)}
                disabled={draft.action === 'suppress'}
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text disabled:opacity-50"
              >
                <option value="">Device&apos;s resolved policy</option>
                {policies.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">
                Temporary rule (hours, blank = permanent)
              </span>
              <Input mono
                type="number"
                min={1}
                value={draft.expiresHours}
                onChange={(e) => set('expiresHours', e.target.value)}
                placeholder="e.g. 24"
               
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">Alert type</span>
              <Input mono
                type="text"
                value={draft.alertType}
                onChange={(e) => set('alertType', e.target.value)}
                placeholder="LOG_RULE_MATCH (default)"
               
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">Severity</span>
              <Select
                value={draft.severity}
                onChange={(e) => set('severity', e.target.value)}
               
              >
                {SEVERITIES.map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </Select>
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">Group by field</span>
              <Input mono
                type="text"
                value={draft.groupBy}
                onChange={(e) => set('groupBy', e.target.value)}
                placeholder="src_ip (rate-limit per source)"
               
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">Cooldown (minutes)</span>
              <Input mono
                type="number"
                value={draft.cooldown}
                onChange={(e) => set('cooldown', e.target.value)}
                placeholder="inherit"
               
              />
            </label>
          </div>
        </div>
      )}

      {tab === 'match' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs font-semibold text-text">Match conditions</div>
              <p className="text-[11px] text-text-faint">
                An empty condition list matches everything — unusual for an alert rule.
              </p>
            </div>
            <label className="inline-flex items-center gap-2 text-[11px] text-text-dim">
              <input
                type="checkbox"
                checked={draft.advanced}
                onChange={(e) => {
                  const advanced = e.target.checked;
                  if (advanced) {
                    setDraft((d) => ({ ...d, advanced: true, rawMatch: buildMatch(d) }));
                  } else {
                    const parsed = parseMatch(draft.rawMatch);
                    setDraft((d) => ({
                      ...d,
                      advanced: false,
                      joiner: parsed.joiner,
                      rows: parsed.rows.length
                        ? parsed.rows
                        : [{ field: '', op: 'contains', value: '' }],
                    }));
                  }
                }}
              />
              Advanced raw JSON
            </label>
          </div>

          {draft.advanced ? (
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">
                Match expression (JSON)
              </span>
              <Textarea  className="p-3 font-mono text-[11px]"
                rows={12}
                value={draft.rawMatch}
                onChange={(e) => set('rawMatch', e.target.value)}
                spellCheck={false}
                
                placeholder='{"op":"and","conditions":[{"op":"eq","field":"src_ip","value":"198.51.100.9"}]}'
              />
              <span className="mt-1 block text-[11px] text-text-faint">
                Ops: and, or, eq, neq, contains, not_contains, regex, in, gt, lt, exists.
              </span>
            </label>
          ) : (
            <>
              <div className="flex items-center gap-2 text-[11px] text-text-dim">
                {/*
                  The select had a `<span>Match</span>` beside it, which is
                  not a label: the control had no accessible name at all.
                  The text and the control are now wrapped together, so the
                  association is implicit.
                */}
                <label className="inline-flex items-center gap-2">
                  <span>Match</span>
                  <select
                    value={draft.joiner}
                    onChange={(e) => set('joiner', e.target.value as 'and' | 'or')}
                    className="rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text focus:outline-hidden focus-visible:outline-2 focus-visible:outline-solid focus-visible:outline-offset-2 focus-visible:outline-accent"
                  >
                    <option value="and">ALL of</option>
                    <option value="or">ANY of</option>
                  </select>
                </label>
                <span>the following conditions</span>
              </div>

              <div className="space-y-2">
                {draft.rows.map((row, idx) => (
                  <div
                    key={idx}
                    className="grid grid-cols-1 sm:grid-cols-[1fr_1fr_1.4fr_auto] gap-2 rounded-lg border border-border bg-bg-panel/40 p-2"
                  >
                    <input
                      list="event-rule-fields"
                      value={row.field}
                      onChange={(e) =>
                        setDraft((d) => ({
                          ...d,
                          rows: d.rows.map((r, i) =>
                            i === idx ? { ...r, field: e.target.value } : r,
                          ),
                        }))
                      }
                      placeholder="field (src_ip…)"
                      className="rounded border border-border bg-bg-panel px-2 py-1.5 font-mono text-[11px] text-text"
                    />
                    <select
                      value={row.op}
                      onChange={(e) =>
                        setDraft((d) => ({
                          ...d,
                          rows: d.rows.map((r, i) =>
                            i === idx ? { ...r, op: e.target.value } : r,
                          ),
                        }))
                      }
                      className="rounded border border-border bg-bg-panel px-2 py-1.5 text-[11px] text-text"
                    >
                      {OPS.map(([value, label]) => (
                        <option key={value} value={value}>
                          {label}
                        </option>
                      ))}
                    </select>
                    <input
                      value={row.value}
                      disabled={row.op === 'exists'}
                      onChange={(e) =>
                        setDraft((d) => ({
                          ...d,
                          rows: d.rows.map((r, i) =>
                            i === idx ? { ...r, value: e.target.value, values: undefined } : r,
                          ),
                        }))
                      }
                      placeholder={row.op === 'in' ? 'a, b, c' : 'value'}
                      className="rounded border border-border bg-bg-panel px-2 py-1.5 font-mono text-[11px] text-text disabled:opacity-40"
                    />
                    <button
                      type="button"
                      aria-label="Remove condition"
                      disabled={draft.rows.length === 1}
                      onClick={() =>
                        setDraft((d) => ({
                          ...d,
                          rows:
                            d.rows.length === 1
                              ? d.rows
                              : d.rows.filter((_, i) => i !== idx),
                        }))
                      }
                      className="rounded border border-border bg-bg-panel p-1.5 text-text-dim hover:text-sig-crit disabled:opacity-40"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>

              <datalist id="event-rule-fields">
                {COMMON_FIELDS.map((f) => (
                  <option key={f} value={f} />
                ))}
              </datalist>

              <button
                type="button"
                onClick={() =>
                  setDraft((d) => ({
                    ...d,
                    rows: [...d.rows, { field: '', op: 'contains', value: '' }],
                  }))
                }
                className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:bg-bg-hover"
              >
                <Plus className="h-3.5 w-3.5" />
                Add condition
              </button>

              <pre className="overflow-x-auto rounded-lg border border-border bg-bg-panel p-3 font-mono text-[10px] text-text-dim">
                {matchJson || '(matches every event)'}
              </pre>
            </>
          )}
        </div>
      )}

      {tab === 'dampen' && (
        <div className="space-y-4">
          {!showDampen && (
            <div className="rounded-lg border border-border bg-bg-panel/40 p-3 text-xs text-text-dim">
              Dampening applies to state, metric and spike rules. A{' '}
              <span className="font-mono">{draft.source}</span> rule carries no per-source
              dampening — scope it with conditions and a cooldown instead.
            </div>
          )}

          {draft.source === 'state' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <label className="block">
                <span className="mb-1 block text-xs font-medium text-text-dim">
                  Minimum up time (minutes)
                </span>
                <Input mono
                  type="number"
                  value={draft.minUpMinutes}
                  onChange={(e) => set('minUpMinutes', e.target.value)}
                  placeholder="60 (default)"
                 
                />
                <span className="mt-1 block text-[11px] text-text-faint">
                  Suppress flaps: the state must hold this long before firing. 0 disables the
                  fast-path.
                </span>
              </label>
              <label className="block">
                <span className="mb-1 block text-xs font-medium text-text-dim">Daily cap</span>
                <Input mono
                  type="number"
                  value={draft.dailyCap}
                  onChange={(e) => set('dailyCap', e.target.value)}
                  placeholder="1"
                 
                />
                <span className="mt-1 block text-[11px] text-text-faint">
                  Maximum fires per source per day (0 = unlimited).
                </span>
              </label>
            </div>
          )}

          {draft.source === 'metric' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <label className="block">
                <span className="mb-1 block text-xs font-medium text-text-dim">Mode</span>
                <Select
                  value={draft.metricMode}
                  onChange={(e) => set('metricMode', e.target.value)}
                 
                >
                  <option value="static">Static threshold</option>
                  <option value="zscore">Z-score vs own baseline</option>
                </Select>
              </label>
              <label className="block">
                <span className="mb-1 block text-xs font-medium text-text-dim">
                  Threshold (blank = inherit)
                </span>
                <Input mono
                  type="number"
                  value={draft.threshold}
                  onChange={(e) => set('threshold', e.target.value)}
                 
                />
              </label>
              <label className="block">
                <span className="mb-1 block text-xs font-medium text-text-dim">
                  Clear threshold (hysteresis)
                </span>
                <Input mono
                  type="number"
                  value={draft.clearThreshold}
                  onChange={(e) => set('clearThreshold', e.target.value)}
                 
                />
              </label>
              <label className="block">
                <span className="mb-1 block text-xs font-medium text-text-dim">Z-score K</span>
                <Input mono
                  type="number"
                  value={draft.zscoreK}
                  onChange={(e) => set('zscoreK', e.target.value)}
                  placeholder="3"
                 
                />
              </label>
            </div>
          )}

          {draft.source === 'spike' && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <label className="block">
                <span className="mb-1 block text-xs font-medium text-text-dim">Std-dev K</span>
                <Input mono
                  type="number"
                  value={draft.stddevK}
                  onChange={(e) => set('stddevK', e.target.value)}
                  placeholder="3"
                 
                />
              </label>
              <label className="block">
                <span className="mb-1 block text-xs font-medium text-text-dim">
                  Sustain (minutes)
                </span>
                <Input mono
                  type="number"
                  value={draft.minDuration}
                  onChange={(e) => set('minDuration', e.target.value)}
                  placeholder="15"
                 
                />
              </label>
              <label className="block">
                <span className="mb-1 block text-xs font-medium text-text-dim">
                  Floor (Mbps, 0 disables)
                </span>
                <Input mono
                  type="number"
                  value={draft.minThroughput}
                  onChange={(e) => set('minThroughput', e.target.value)}
                 
                />
              </label>
            </div>
          )}

          <pre className="overflow-x-auto rounded-lg border border-border bg-bg-panel p-3 font-mono text-[10px] text-text-dim">
            {buildDampen(draft) || '(no dampening)'}
          </pre>
        </div>
      )}

      {tab === 'preview' && (
        <div className="space-y-4">
          <p className="text-xs text-text-dim">
            Tests the match expression against up to 200 recent syslog messages using the device
            vendor the live engine would use. Nothing is saved.
          </p>
          <button
            type="button"
            disabled={previewing}
            onClick={runPreview}
            className="inline-flex items-center gap-1.5 rounded-md bg-accent px-3.5 py-1.5 text-xs font-semibold text-on-accent hover:opacity-90 disabled:opacity-50"
          >
            <FlaskConical className="h-3.5 w-3.5" />
            {previewing ? 'Scanning…' : 'Run preview'}
          </button>

          {preview && (
            <div className="space-y-3">
              <div className="grid grid-cols-3 gap-2">
                <div className="rounded-lg border border-border bg-bg-panel p-3">
                  <div className="text-[10px] uppercase text-text-faint">Scanned</div>
                  <div className="font-mono text-sm text-text">{preview.scanned ?? 0}</div>
                </div>
                <div className="rounded-lg border border-border bg-bg-panel p-3">
                  <div className="text-[10px] uppercase text-text-faint">Matched</div>
                  <div className="font-mono text-sm text-accent">{preview.matched ?? 0}</div>
                </div>
                <div className="rounded-lg border border-border bg-bg-panel p-3">
                  <div className="text-[10px] uppercase text-text-faint">Rate</div>
                  <div className="font-mono text-sm text-sig-warn">
                    {((Number(preview.rate) || 0) * 100).toFixed(1)}%
                  </div>
                </div>
              </div>
              {Array.isArray(preview.samples) && preview.samples.length > 0 && (
                <div>
                  <div className="mb-1 text-xs font-semibold text-text">Sample matches</div>
                  <ul className="space-y-1">
                    {preview.samples.slice(0, 8).map((s: string, i: number) => (
                      <li
                        key={i}
                        className="truncate rounded border border-border bg-bg-panel px-2 py-1 font-mono text-[10px] text-text-dim"
                        title={s}
                      >
                        {s}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </SlideOverDrawer>
  );
}
