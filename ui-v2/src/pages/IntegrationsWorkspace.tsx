import { useState, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Mail,
  Webhook,
  MessageSquare,
  Send,
  CheckCircle2,
  AlertTriangle,
  Play,
  Plus,
  Trash2,
  Edit3,
  Power,
  PowerOff,
  Terminal,
  ShieldCheck,
} from 'lucide-react';
import { apiFetch, SystemSetting } from '@/lib/api';
import { cn } from '@/lib/utils';
import { StickySaveBar } from '@/components/ui/sticky-save-bar';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { useToast } from '@/components/ui/toast';
import { ColumnDef } from '@tanstack/react-table';

type IntegrationsSubTab = 'smtp' | 'webhooks' | 'irc';

interface SmtpTraceStep {
  step: string;
  detail?: string;
  response?: string;
  status: 'ok' | 'skipped' | 'fail';
  error?: string;
  hint?: string;
  duration_ms: number;
}

interface SmtpTestResponse {
  success: boolean;
  message: string;
  trace?: SmtpTraceStep[];
  total_ms?: number;
  host?: string;
  port?: number;
  auth_method?: string;
  from?: string;
  to?: string;
}

interface IRCServer {
  id: number;
  name: string;
  server_host: string;
  server_port: number;
  use_tls: boolean;
  nick: string;
  username: string;
  real_name: string;
  server_password?: string;
  nickserv_password?: string;
  sasl_enabled: boolean;
  sasl_username?: string;
  sasl_password?: string;
  enabled: boolean;
  status: string;
  last_connected?: string;
  last_error?: string;
  channels?: IRCChannel[];
}

interface IRCChannel {
  id: number;
  server_id: number;
  channel_name: string;
  channel_key?: string;
  send_alerts: boolean;
  send_status: boolean;
  allow_commands: boolean;
  min_alert_severity: string;
  enabled: boolean;
}

interface IRCCommand {
  id: number;
  command: string;
  description: string;
  command_type: string;
  response_template: string;
  admin_only: boolean;
  enabled: boolean;
}

const SMTP_KEYS = [
  'email_enabled',
  'smtp_host',
  'smtp_port',
  'smtp_username',
  'smtp_password',
  'smtp_from',
  'smtp_to',
] as const;

const WEBHOOK_KEYS = [
  'slack_webhook',
  'teams_webhook',
  'discord_webhook',
  'webhook_url',
  'webhook_secret',
  'pagerduty_routing_key',
  'opsgenie_api_key',
] as const;

export function IntegrationsWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = (searchParams.get('tab') as IntegrationsSubTab) || 'smtp';

  const setTab = (tab: IntegrationsSubTab) => {
    setSearchParams({ tab }, { replace: true });
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <Webhook className="h-3.5 w-3.5" />
            Configuration / Integrations
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            Integrations & Notification Channels
          </h1>
          <p className="text-xs text-text-dim mt-0.5">
            Configure outbound SMTP email with live protocol diagnostics, ChatOps/Incident Webhooks, and interactive IRC Bots.
          </p>
        </div>

        <div className="flex items-center gap-1 rounded-lg bg-bg-panel p-1 border border-border self-start">
          <button
            type="button"
            onClick={() => setTab('smtp')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'smtp'
                ? 'bg-bg-card text-text shadow-sm border border-border'
                : 'text-text-dim hover:text-text'
            )}
          >
            <Mail className="h-3.5 w-3.5 text-accent" />
            Email / SMTP
          </button>
          <button
            type="button"
            onClick={() => setTab('webhooks')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'webhooks'
                ? 'bg-bg-card text-text shadow-sm border border-border'
                : 'text-text-dim hover:text-text'
            )}
          >
            <Webhook className="h-3.5 w-3.5 text-accent" />
            Webhooks & PagerDuty
          </button>
          <button
            type="button"
            onClick={() => setTab('irc')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              activeTab === 'irc'
                ? 'bg-bg-card text-text shadow-sm border border-border'
                : 'text-text-dim hover:text-text'
            )}
          >
            <MessageSquare className="h-3.5 w-3.5 text-accent" />
            IRC Bots
          </button>
        </div>
      </div>

      {activeTab === 'smtp' && <SmtpSubTab />}
      {activeTab === 'webhooks' && <WebhooksSubTab />}
      {activeTab === 'irc' && <IrcBotsSubTab />}
    </div>
  );
}

// ============================================================================
// SUB-TAB 1: EMAIL / SMTP + LIVE PROTOCOL DIAGNOSTICS
// ============================================================================
function SmtpSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: settingsList, isLoading } = useQuery({
    queryKey: ['settings'],
    queryFn: () => apiFetch<SystemSetting[]>('/admin/api/settings'),
  });

  const serverMap = useMemo(() => {
    const m: Record<string, string> = {
      email_enabled: 'false',
      smtp_host: '',
      smtp_port: '587',
      smtp_username: '',
      smtp_password: '',
      smtp_from: '',
      smtp_to: '',
    };
    for (const s of settingsList ?? []) {
      if ((SMTP_KEYS as readonly string[]).includes(s.key)) {
        m[s.key] = s.value ?? '';
      }
    }
    return m;
  }, [settingsList]);

  const [draft, setDraft] = useState<Record<string, string>>({});
  const [testToOverride, setTestToOverride] = useState('');
  const [smtpDiag, setSmtpDiag] = useState<SmtpTestResponse | null>(null);

  useEffect(() => {
    setDraft(serverMap);
  }, [serverMap]);

  const dirtyKeys = useMemo(() => {
    return SMTP_KEYS.filter((k) => (draft[k] ?? '') !== (serverMap[k] ?? ''));
  }, [draft, serverMap]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      const payload: SystemSetting[] = dirtyKeys.map((key) => ({
        key,
        value: draft[key] ?? '',
        category: 'notifications',
        is_secret: key === 'smtp_password',
      }));
      return apiFetch<{ message?: string; warnings?: string[] }>('/admin/api/settings', {
        method: 'POST',
        body: payload,
      });
    },
    onSuccess: (res) => {
      const warns = res?.warnings;
      if (warns && warns.length > 0) {
        toast({ title: 'SMTP settings saved with warnings', description: warns.join('; '), variant: 'info' });
      } else {
        toast({ title: 'SMTP settings saved', variant: 'success' });
      }
      queryClient.invalidateQueries({ queryKey: ['settings'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to save SMTP settings', description: err.message, variant: 'error' });
    },
  });

  const testMutation = useMutation({
    mutationFn: async () => {
      return apiFetch<SmtpTestResponse>('/admin/api/settings/test-email', {
        method: 'POST',
        body: testToOverride.trim() ? { to: testToOverride.trim() } : {},
      });
    },
    onSuccess: (res) => {
      if (res) {
        setSmtpDiag(res);
        if (res.success) {
          toast({ title: 'Test email accepted', description: res.message, variant: 'success' });
        } else {
          toast({ title: 'SMTP test failed', description: res.message, variant: 'error' });
        }
      }
    },
    onError: (err: Error) => {
      toast({ title: 'SMTP test error', description: err.message, variant: 'error' });
    },
  });

  if (isLoading) {
    return (
      <div className="rounded-xl border border-border bg-bg-card p-8 text-center text-sm text-text-dim">
        Loading SMTP configuration…
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 pb-12">
      {/* Left: SMTP Settings Form */}
      <div className="lg:col-span-7 rounded-xl border border-border bg-bg-card p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div>
            <h2 className="text-sm font-semibold text-text">SMTP Server Configuration</h2>
            <p className="text-xs text-text-dim">
              Supports implicit TLS (port 465) and STARTTLS (port 587/25) with automatic PLAIN/LOGIN negotiation.
            </p>
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <span className="text-xs font-medium text-text">Enable Email</span>
            <button
              type="button"
              role="switch"
              aria-checked={draft.email_enabled === 'true'}
              onClick={() =>
                setDraft((prev) => ({
                  ...prev,
                  email_enabled: prev.email_enabled === 'true' ? 'false' : 'true',
                }))
              }
              className={cn(
                'relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors',
                draft.email_enabled === 'true' ? 'bg-accent' : 'bg-bg-hover'
              )}
            >
              <span
                className={cn(
                  'pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow transition',
                  draft.email_enabled === 'true' ? 'translate-x-4' : 'translate-x-0'
                )}
              />
            </button>
          </label>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="sm:col-span-2">
            <label className="block text-xs font-medium text-text-dim mb-1">SMTP Host</label>
            <input
              type="text"
              value={draft.smtp_host ?? ''}
              onChange={(e) => setDraft((prev) => ({ ...prev, smtp_host: e.target.value }))}
              placeholder="smtp.example.com"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text focus:border-accent focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Port</label>
            <input
              type="number"
              min={1}
              max={65535}
              value={draft.smtp_port ?? '587'}
              onChange={(e) => setDraft((prev) => ({ ...prev, smtp_port: e.target.value }))}
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text focus:border-accent focus:outline-none"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">SMTP Username</label>
            <input
              type="text"
              value={draft.smtp_username ?? ''}
              onChange={(e) => setDraft((prev) => ({ ...prev, smtp_username: e.target.value }))}
              placeholder="alerts@example.com"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text focus:border-accent focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">
              SMTP Password <span className="text-text-faint">(Encrypted at rest)</span>
            </label>
            <input
              type="password"
              value={draft.smtp_password ?? ''}
              onChange={(e) => setDraft((prev) => ({ ...prev, smtp_password: e.target.value }))}
              placeholder="Leave ******** to keep stored secret"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text focus:border-accent focus:outline-none"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Sender Address (MAIL FROM)</label>
            <input
              type="email"
              value={draft.smtp_from ?? ''}
              onChange={(e) => setDraft((prev) => ({ ...prev, smtp_from: e.target.value }))}
              placeholder="fwmon@example.com"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text focus:border-accent focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Default Recipients (To)</label>
            <input
              type="text"
              value={draft.smtp_to ?? ''}
              onChange={(e) => setDraft((prev) => ({ ...prev, smtp_to: e.target.value }))}
              placeholder="noc@example.com, ops@example.com"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text focus:border-accent focus:outline-none"
            />
          </div>
        </div>
      </div>

      {/* Right: Live SMTP Protocol Diagnostics */}
      <div className="lg:col-span-5 rounded-xl border border-border bg-bg-card p-5 space-y-4">
        <div className="border-b border-border pb-3">
          <h2 className="text-sm font-semibold text-text flex items-center gap-2">
            <Terminal className="h-4 w-4 text-accent" />
            Live SMTP Protocol Diagnostics
          </h2>
          <p className="text-xs text-text-dim mt-0.5">
            Executes a stepped SMTP session (CONNECT → EHLO → STARTTLS → AUTH → MAIL FROM → RCPT TO → DATA) using saved credentials.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="email"
            value={testToOverride}
            onChange={(e) => setTestToOverride(e.target.value)}
            placeholder="Optional recipient override (uses saved To if blank)"
            className="flex-1 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text focus:border-accent focus:outline-none"
          />
          <button
            type="button"
            disabled={testMutation.isPending}
            onClick={() => testMutation.mutate()}
            className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
          >
            <Send className="h-3.5 w-3.5" />
            {testMutation.isPending ? 'Dialing…' : 'Send Test'}
          </button>
        </div>

        {smtpDiag && (
          <div className="space-y-3">
            <div
              className={cn(
                'rounded-lg border p-3 text-xs flex items-start gap-2',
                smtpDiag.success
                  ? 'border-sig-ok/40 bg-sig-ok/10 text-sig-ok'
                  : 'border-sig-crit/40 bg-sig-crit/10 text-sig-crit'
              )}
            >
              {smtpDiag.success ? (
                <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" />
              ) : (
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
              )}
              <div>
                <div className="font-semibold">{smtpDiag.message}</div>
                {smtpDiag.total_ms !== undefined && (
                  <div className="text-[11px] opacity-85 mt-0.5">
                    Total time: {smtpDiag.total_ms}ms • Auth: {smtpDiag.auth_method}
                  </div>
                )}
              </div>
            </div>

            {smtpDiag.trace && smtpDiag.trace.length > 0 && (
              <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
                {smtpDiag.trace.map((step, i) => (
                  <div
                    key={i}
                    className="rounded-md border border-border bg-bg-panel px-3 py-2 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-semibold uppercase text-text">
                        {step.step}
                      </span>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] text-text-faint">{step.duration_ms}ms</span>
                        <span
                          className={cn(
                            'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
                            step.status === 'ok'
                              ? 'bg-sig-ok/15 text-sig-ok'
                              : step.status === 'fail'
                                ? 'bg-sig-crit/15 text-sig-crit'
                                : 'bg-bg-card text-text-faint'
                          )}
                        >
                          {step.status}
                        </span>
                      </div>
                    </div>
                    {step.detail && <div className="text-[11px] text-text-dim mt-0.5">{step.detail}</div>}
                    {step.response && (
                      <div className="text-[11px] font-mono text-text-faint mt-0.5">{step.response}</div>
                    )}
                    {step.error && (
                      <div className="text-[11px] font-mono text-sig-crit mt-1">{step.error}</div>
                    )}
                    {step.hint && (
                      <div className="mt-1.5 rounded border border-sig-warn/30 bg-sig-warn/10 p-2 text-[11px] text-sig-warn">
                        {step.hint}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <StickySaveBar
        isDirty={dirtyKeys.length > 0}
        dirtyCount={dirtyKeys.length}
        isSaving={saveMutation.isPending}
        onSave={() => saveMutation.mutate()}
        onDiscard={() => setDraft(serverMap)}
      />
    </div>
  );
}

// ============================================================================
// SUB-TAB 2: WEBHOOKS, SLACK, TEAMS, DISCORD & PAGERDUTY
// ============================================================================
function WebhooksSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: settingsList, isLoading } = useQuery({
    queryKey: ['settings'],
    queryFn: () => apiFetch<SystemSetting[]>('/admin/api/settings'),
  });

  const serverMap = useMemo(() => {
    const m: Record<string, string> = {};
    for (const k of WEBHOOK_KEYS) m[k] = '';
    for (const s of settingsList ?? []) {
      if ((WEBHOOK_KEYS as readonly string[]).includes(s.key)) {
        m[s.key] = s.value ?? '';
      }
    }
    return m;
  }, [settingsList]);

  const [draft, setDraft] = useState<Record<string, string>>({});
  const [testingChannel, setTestingChannel] = useState<string | null>(null);

  useEffect(() => {
    setDraft(serverMap);
  }, [serverMap]);

  const dirtyKeys = useMemo(() => {
    return WEBHOOK_KEYS.filter((k) => (draft[k] ?? '') !== (serverMap[k] ?? ''));
  }, [draft, serverMap]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      const secretSet = new Set(['webhook_secret', 'pagerduty_routing_key', 'opsgenie_api_key']);
      const payload: SystemSetting[] = dirtyKeys.map((key) => ({
        key,
        value: draft[key] ?? '',
        category: 'notifications',
        is_secret: secretSet.has(key),
      }));
      return apiFetch('/admin/api/settings', {
        method: 'POST',
        body: payload,
      });
    },
    onSuccess: () => {
      toast({ title: 'Webhook & incident settings saved', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['settings'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to save webhook settings', description: err.message, variant: 'error' });
    },
  });

  const runWebhookTest = async (type: string, url?: string) => {
    setTestingChannel(type);
    try {
      const res = await apiFetch<{ success: boolean; message: string }>('/admin/api/settings/test-webhook', {
        method: 'POST',
        body: { type, url: url || '' },
      });
      if (res?.success) {
        toast({ title: 'Webhook test succeeded', description: res.message, variant: 'success' });
      } else {
        toast({
          title: 'Webhook test failed',
          description: res?.message || 'Remote endpoint rejected test',
          variant: 'error',
        });
      }
    } catch (err) {
      toast({
        title: 'Webhook test error',
        description: err instanceof Error ? err.message : 'Error testing webhook',
        variant: 'error',
      });
    } finally {
      setTestingChannel(null);
    }
  };

  if (isLoading) {
    return (
      <div className="rounded-xl border border-border bg-bg-card p-8 text-center text-sm text-text-dim">
        Loading webhook channels…
      </div>
    );
  }

  const chatChannels = [
    {
      key: 'slack_webhook',
      label: 'Slack Incoming Webhook URL',
      placeholder: 'https://hooks.slack.com/services/...',
    },
    {
      key: 'teams_webhook',
      label: 'Microsoft Teams Webhook URL',
      placeholder: 'https://outlook.office.com/webhook/...',
    },
    {
      key: 'discord_webhook',
      label: 'Discord Webhook URL',
      placeholder: 'https://discord.com/api/webhooks/...',
    },
  ];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 pb-12">
      {/* ChatOps Webhooks */}
      <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
        <div className="border-b border-border pb-3">
          <h2 className="text-sm font-semibold text-text">ChatOps Channels (Slack, Teams, Discord)</h2>
          <p className="text-xs text-text-dim mt-0.5">
            Default webhook URLs used when a Notification Profile routes to Slack, Teams, or Discord without a custom URL override.
          </p>
        </div>

        {chatChannels.map((ch) => (
          <div key={ch.key}>
            <label className="block text-xs font-medium text-text-dim mb-1">{ch.label}</label>
            <div className="flex items-center gap-2">
              <input
                type="url"
                value={draft[ch.key] ?? ''}
                onChange={(e) => setDraft((prev) => ({ ...prev, [ch.key]: e.target.value }))}
                placeholder={ch.placeholder}
                className="flex-1 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text focus:border-accent focus:outline-none"
              />
              <button
                type="button"
                disabled={testingChannel === ch.key}
                onClick={() => runWebhookTest(ch.key, draft[ch.key])}
                className="flex items-center gap-1 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:bg-bg-hover"
              >
                <Play className="h-3 w-3 text-accent" />
                {testingChannel === ch.key ? 'Testing…' : 'Test'}
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Signed Generic Webhook & Incident Paging */}
      <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
        <div className="border-b border-border pb-3">
          <h2 className="text-sm font-semibold text-text flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-accent" />
            Signed Generic Webhook & Incident Response
          </h2>
          <p className="text-xs text-text-dim mt-0.5">
            HMAC-SHA256 signed JSON webhook (`X-FirewallMon-Signature`) plus PagerDuty Events v2 and Opsgenie Alerts v2.
          </p>
        </div>

        <div>
          <label className="block text-xs font-medium text-text-dim mb-1">Generic Webhook URL</label>
          <div className="flex items-center gap-2">
            <input
              type="url"
              value={draft.webhook_url ?? ''}
              onChange={(e) => setDraft((prev) => ({ ...prev, webhook_url: e.target.value }))}
              placeholder="https://api.example.com/fwmon/webhook"
              className="flex-1 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text focus:border-accent focus:outline-none"
            />
            <button
              type="button"
              disabled={testingChannel === 'webhook_url'}
              onClick={() => runWebhookTest('webhook_url', draft.webhook_url)}
              className="flex items-center gap-1 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:bg-bg-hover"
            >
              <Play className="h-3 w-3 text-accent" />
              Test
            </button>
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-text-dim mb-1">
            Webhook HMAC Signing Secret <span className="text-text-faint">(Encrypted at rest)</span>
          </label>
          <input
            type="password"
            value={draft.webhook_secret ?? ''}
            onChange={(e) => setDraft((prev) => ({ ...prev, webhook_secret: e.target.value }))}
            placeholder="Leave ******** to keep stored secret"
            className="w-full rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text focus:border-accent focus:outline-none"
          />
        </div>

        <div className="pt-2 border-t border-border space-y-3">
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">
              PagerDuty Events v2 Routing Key <span className="text-text-faint">(Encrypted at rest)</span>
            </label>
            <div className="flex items-center gap-2">
              <input
                type="password"
                value={draft.pagerduty_routing_key ?? ''}
                onChange={(e) => setDraft((prev) => ({ ...prev, pagerduty_routing_key: e.target.value }))}
                placeholder="32-char integration key"
                className="flex-1 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text focus:border-accent focus:outline-none"
              />
              <button
                type="button"
                disabled={testingChannel === 'pagerduty'}
                onClick={() => runWebhookTest('pagerduty')}
                className="flex items-center gap-1 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:bg-bg-hover"
              >
                <Play className="h-3 w-3 text-accent" />
                Test PD
              </button>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">
              Opsgenie API Key <span className="text-text-faint">(Encrypted at rest)</span>
            </label>
            <div className="flex items-center gap-2">
              <input
                type="password"
                value={draft.opsgenie_api_key ?? ''}
                onChange={(e) => setDraft((prev) => ({ ...prev, opsgenie_api_key: e.target.value }))}
                placeholder="GenieKey ..."
                className="flex-1 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text focus:border-accent focus:outline-none"
              />
              <button
                type="button"
                disabled={testingChannel === 'opsgenie'}
                onClick={() => runWebhookTest('opsgenie')}
                className="flex items-center gap-1 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:bg-bg-hover"
              >
                <Play className="h-3 w-3 text-accent" />
                Test OG
              </button>
            </div>
          </div>
        </div>
      </div>

      <StickySaveBar
        isDirty={dirtyKeys.length > 0}
        dirtyCount={dirtyKeys.length}
        isSaving={saveMutation.isPending}
        onSave={() => saveMutation.mutate()}
        onDiscard={() => setDraft(serverMap)}
      />
    </div>
  );
}

// ============================================================================
// SUB-TAB 3: IRC BOTS (SERVERS, CHANNELS, COMMANDS, SEND MESSAGE)
// ============================================================================
function IrcBotsSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: serversList, isLoading } = useQuery({
    queryKey: ['irc-servers'],
    queryFn: () => apiFetch<IRCServer[]>('/admin/api/irc/servers'),
    refetchInterval: 15_000,
  });

  const { data: channelsList } = useQuery({
    queryKey: ['irc-channels'],
    queryFn: () => apiFetch<IRCChannel[]>('/admin/api/irc/channels'),
  });

  const { data: commandsList } = useQuery({
    queryKey: ['irc-commands'],
    queryFn: () => apiFetch<IRCCommand[]>('/admin/api/irc/commands'),
  });

  const servers = serversList ?? [];
  const channels = channelsList ?? [];
  const commands = commandsList ?? [];

  const [serverDrawerOpen, setServerDrawerOpen] = useState(false);
  const [editingServer, setEditingServer] = useState<Partial<IRCServer>>({
    name: '',
    server_host: '',
    server_port: 6697,
    use_tls: true,
    nick: 'fwmon-bot',
    username: 'fwmon',
    real_name: 'Firewall Monitor Bot',
    sasl_enabled: false,
    enabled: true,
  });

  const [sendServerId, setSendServerId] = useState<number>(0);
  const [sendTarget, setSendTarget] = useState('');
  const [sendMessageText, setSendMessageText] = useState('');

  const saveServerMutation = useMutation({
    mutationFn: async () => {
      if (editingServer.id) {
        // The detail row arrives with its preloaded `channels` association;
        // UpdateIRCServer binds into a map and would try to write a column that
        // does not exist on irc_servers.
        const { channels: _channels, ...server } = editingServer;
        void _channels;
        return apiFetch(`/admin/api/irc/servers/${editingServer.id}`, {
          method: 'PUT',
          body: server,
        });
      }
      return apiFetch('/admin/api/irc/servers', {
        method: 'POST',
        body: editingServer,
      });
    },
    onSuccess: () => {
      toast({ title: editingServer.id ? 'IRC Server updated' : 'IRC Server created', variant: 'success' });
      setServerDrawerOpen(false);
      queryClient.invalidateQueries({ queryKey: ['irc-servers'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to save IRC server', description: err.message, variant: 'error' });
    },
  });

  const toggleConnectionMutation = useMutation({
    mutationFn: async ({ id, action }: { id: number; action: 'connect' | 'disconnect' }) =>
      apiFetch(`/admin/api/irc/servers/${id}/${action}`, { method: 'POST' }),
    onSuccess: () => {
      toast({ title: 'IRC bot state updated', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['irc-servers'] });
    },
    onError: (err: Error) => {
      toast({ title: 'IRC connection action failed', description: err.message, variant: 'error' });
    },
  });

  const [serverToDelete, setServerToDelete] = useState<IRCServer | null>(null);
  const deleteServerMutation = useMutation({
    mutationFn: async (id: number) => apiFetch(`/admin/api/irc/servers/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      toast({ title: 'IRC server deleted', variant: 'info' });
      setServerToDelete(null);
      queryClient.invalidateQueries({ queryKey: ['irc-servers'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Delete failed', description: err.message, variant: 'error' });
    },
  });

  const sendIrcMutation = useMutation({
    mutationFn: async () =>
      apiFetch('/admin/api/irc/send', {
        method: 'POST',
        body: {
          server_id: sendServerId || servers[0]?.id,
          channel: sendTarget,
          message: sendMessageText,
        },
      }),
    onSuccess: () => {
      toast({ title: 'IRC message dispatched', variant: 'success' });
      setSendMessageText('');
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to send IRC message', description: err.message, variant: 'error' });
    },
  });

  const serverCols = useMemo<ColumnDef<IRCServer, unknown>[]>(
    () => [
      {
        accessorKey: 'name',
        header: 'Server',
        cell: ({ row }) => (
          <div>
            <div className="font-semibold text-text">{row.original.name}</div>
            <div className="text-[11px] font-mono text-text-dim">
              {row.original.server_host}:{row.original.server_port} {row.original.use_tls ? '(TLS)' : ''}
            </div>
          </div>
        ),
      },
      {
        accessorKey: 'nick',
        header: 'Bot Nick',
        cell: ({ row }) => <span className="font-mono text-xs">{row.original.nick}</span>,
      },
      {
        accessorKey: 'status',
        header: 'Status',
        cell: ({ row }) => (
          <span
            className={cn(
              'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
              row.original.status === 'connected'
                ? 'bg-sig-ok/15 text-sig-ok'
                : 'bg-bg-panel text-text-dim'
            )}
          >
            {row.original.status || (row.original.enabled ? 'disconnected' : 'disabled')}
          </span>
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex items-center justify-end gap-1.5">
            {row.original.status === 'connected' ? (
              <button
                type="button"
                onClick={() => toggleConnectionMutation.mutate({ id: row.original.id, action: 'disconnect' })}
                className="flex items-center gap-1 rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text-dim hover:text-text"
              >
                <PowerOff className="h-3 w-3" /> Disconnect
              </button>
            ) : (
              <button
                type="button"
                onClick={() => toggleConnectionMutation.mutate({ id: row.original.id, action: 'connect' })}
                className="flex items-center gap-1 rounded border border-sig-ok/40 bg-sig-ok/10 px-2 py-1 text-[11px] text-sig-ok"
              >
                <Power className="h-3 w-3" /> Connect
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                setEditingServer(row.original);
                setServerDrawerOpen(true);
              }}
              className="rounded border border-border bg-bg-panel p-1 text-text-dim hover:text-text"
            >
              <Edit3 className="h-3.5 w-3.5" />
            </button>
            <button
              type="button"
              onClick={() => setServerToDelete(row.original)}
              className="rounded border border-sig-crit/30 bg-sig-crit/10 p-1 text-sig-crit"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          </div>
        ),
      },
    ],
    [toggleConnectionMutation, deleteServerMutation]
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-text">Configured IRC Servers</h2>
          <p className="text-xs text-text-dim">
            Manage IRC bot connections, channels ({channels.length}), and interactive commands ({commands.length}).
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            setEditingServer({
              name: '',
              server_host: '',
              server_port: 6697,
              use_tls: true,
                        nick: 'fwmon-bot',
              username: 'fwmon',
              real_name: 'Firewall Monitor Bot',
                        sasl_enabled: false,
              enabled: true,
            });
            setServerDrawerOpen(true);
          }}
          className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90"
        >
          <Plus className="h-3.5 w-3.5" />
          Add IRC Server
        </button>
      </div>

      <ResponsiveDataView
        data={servers}
        columns={serverCols}
        isLoading={isLoading}
        emptyTitle="No IRC servers configured."
        renderMobileCard={(srv) => (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-sm text-text">{srv.name}</span>
              <span className="rounded bg-bg-panel px-2 py-0.5 text-[10px] font-semibold uppercase text-text-dim">
                {srv.status || 'disconnected'}
              </span>
            </div>
            <div className="text-xs font-mono text-text-dim">
              {srv.server_host}:{srv.server_port} • Nick: {srv.nick}
            </div>
          </div>
        )}
      />

      {/* Quick Send Message Card */}
      {servers.length > 0 && (
        <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-text-dim">
            Send Direct IRC Message
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
            <select
              value={sendServerId || servers[0]?.id || 0}
              onChange={(e) => setSendServerId(Number(e.target.value))}
              className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text"
            >
              {servers.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.server_host})
                </option>
              ))}
            </select>
            <input
              type="text"
              value={sendTarget}
              onChange={(e) => setSendTarget(e.target.value)}
              placeholder="#noc-alerts"
              className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text"
            />
            <input
              type="text"
              value={sendMessageText}
              onChange={(e) => setSendMessageText(e.target.value)}
              placeholder="Message text..."
              className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text"
            />
            <button
              type="button"
              disabled={!sendTarget.trim() || !sendMessageText.trim() || sendIrcMutation.isPending}
              onClick={() => sendIrcMutation.mutate()}
              className="flex items-center justify-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
            >
              <Send className="h-3.5 w-3.5" />
              Send to Channel
            </button>
          </div>
        </div>
      )}

      <SlideOverDrawer
        open={serverDrawerOpen}
        onOpenChange={setServerDrawerOpen}
        title={editingServer.id ? `Edit IRC Server: ${editingServer.name}` : 'New IRC Server'}
        subtitle="Configure IRC connection, TLS, NickServ/SASL credentials, and command prefix."
        footer={
          <div className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => setServerDrawerOpen(false)}
              className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text-dim"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={saveServerMutation.isPending}
              onClick={() => saveServerMutation.mutate()}
              className="rounded-md bg-accent px-4 py-1.5 text-xs font-semibold text-white hover:opacity-90"
            >
              {saveServerMutation.isPending ? 'Saving…' : 'Save IRC Server'}
            </button>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-text-dim mb-1">Server Name</label>
              <input
                type="text"
                value={editingServer.name ?? ''}
                onChange={(e) => setEditingServer((p) => ({ ...p, name: e.target.value }))}
                placeholder="Internal IRC"
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-text-dim mb-1">Hostname</label>
              <input
                type="text"
                value={editingServer.server_host ?? ''}
                onChange={(e) => setEditingServer((p) => ({ ...p, server_host: e.target.value }))}
                placeholder="irc.example.com"
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">Port</label>
              <input
                type="number"
                value={editingServer.server_port ?? 6697}
                onChange={(e) => setEditingServer((p) => ({ ...p, server_port: Number(e.target.value) }))}
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">Bot Nick</label>
              <input
                type="text"
                value={editingServer.nick ?? ''}
                onChange={(e) => setEditingServer((p) => ({ ...p, nick: e.target.value }))}
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">Username</label>
              <input
                type="text"
                value={editingServer.username ?? ''}
                onChange={(e) => setEditingServer((p) => ({ ...p, username: e.target.value }))}
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">Real Name</label>
              <input
                type="text"
                value={editingServer.real_name ?? ''}
                onChange={(e) => setEditingServer((p) => ({ ...p, real_name: e.target.value }))}
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
              />
            </div>
          </div>

          <div className="flex flex-wrap gap-4 pt-1">
            <label className="flex items-center gap-2 text-xs text-text">
              <input
                type="checkbox"
                checked={editingServer.use_tls !== false}
                onChange={(e) => setEditingServer((p) => ({ ...p, use_tls: e.target.checked }))}
                className="h-4 w-4 rounded accent-accent"
              />
              Use TLS
            </label>
            <label className="flex items-center gap-2 text-xs text-text">
              <input
                type="checkbox"
                checked={editingServer.enabled !== false}
                onChange={(e) => setEditingServer((p) => ({ ...p, enabled: e.target.checked }))}
                className="h-4 w-4 rounded accent-accent"
              />
              Enable Bot
            </label>
          </div>
        </div>
      </SlideOverDrawer>

      <ConfirmDialog
        open={!!serverToDelete}
        onOpenChange={(open) => {
          if (!open) setServerToDelete(null);
        }}
        title={`Delete IRC server ${serverToDelete?.name ?? ''}?`}
        description="The bot disconnects immediately and its channels stop receiving notifications."
        confirmLabel="Delete server"
        destructive
        pending={deleteServerMutation.isPending}
        onConfirm={() => serverToDelete && deleteServerMutation.mutate(serverToDelete.id)}
      />
    </div>
  );
}
