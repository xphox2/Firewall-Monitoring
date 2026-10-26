import { useState, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Users,
  Key,
  Globe,
  FileText,
  History,
  UserCheck,
  Plus,
  Trash2,
  Copy,
  Check,
  RefreshCw,
  Send,
  Eye,
  Lock,
} from 'lucide-react';
import { apiFetch, SystemSetting, type MeResponse } from '@/lib/api';
import { cn, formatDate, formatRelativeTime, setDisplayTimezone } from '@/lib/utils';
import { StickySaveBar } from '@/components/ui/sticky-save-bar';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { PasskeyCard, TwoFactorCard } from '@/components/profile/security-panels';
import { ResponsiveDataView } from '@/components/ui/responsive-data-view';
import { StepUpAuthDialog } from '@/components/ui/step-up-auth-dialog';
import { useToast } from '@/components/ui/toast';
import { ColumnDef } from '@tanstack/react-table';

type SystemSubTab = 'users' | 'tokens' | 'display' | 'reports' | 'audit' | 'profile';

interface AdminUser {
  id: number;
  username: string;
  role: 'admin' | 'operator' | 'viewer';
  email?: string;
  display_name?: string;
  totp_enabled: boolean;
  disabled?: boolean;
  must_change_password?: boolean;
  last_login_at?: string;
  created_at?: string;
}

interface APITokenRow {
  id: number;
  name: string;
  prefix: string;
  scope: 'read' | 'write' | 'admin';
  expires_at?: string | null;
  last_used_at?: string | null;
  revoked_at?: string | null;
  created_at: string;
}

interface AuditLogEntry {
  id: number;
  // models.AuditLog wire names. `timestamp`/`status_code`/`path` do not exist,
  // so every row showed a blank time and a red "undefined" status.
  created_at: string;
  actor: string;
  actor_id: number;
  method: string;
  action: string;
  target: string;
  status: number;
  ip_address: string;
  user_agent: string;
}

export function SystemWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = (searchParams.get('tab') as SystemSubTab) || 'users';

  const setTab = (tab: SystemSubTab) => {
    setSearchParams({ tab }, { replace: true });
  };

  const tabs: { id: SystemSubTab; label: string; icon: typeof Users }[] = [
    { id: 'users', label: 'Users & RBAC', icon: Users },
    { id: 'tokens', label: 'API Tokens', icon: Key },
    { id: 'display', label: 'Display & Flows', icon: Globe },
    { id: 'reports', label: 'Email Reports', icon: FileText },
    { id: 'audit', label: 'Audit Log', icon: History },
    { id: 'profile', label: 'My Profile & 2FA', icon: UserCheck },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-3 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <Users className="h-3.5 w-3.5" />
            Configuration / System & Access
          </div>
          <h1 className="text-xl font-semibold text-text mt-0.5">
            System, Users, RBAC & Audit Trail
          </h1>
          <p className="text-xs text-text-dim mt-0.5">
            Role-based access control, scoped API tokens, timezone & internal network classification, scheduled reports, and security audit trail.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1 rounded-lg bg-bg-panel p-1 border border-border self-start">
          {tabs.map((t) => {
            const Icon = t.icon;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id)}
                className={cn(
                  'flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors',
                  activeTab === t.id
                    ? 'bg-bg-card text-text shadow-xs border border-border'
                    : 'text-text-dim hover:text-text'
                )}
              >
                <Icon className="h-3.5 w-3.5 text-accent" />
                {t.label}
              </button>
            );
          })}
        </div>
      </div>

      {activeTab === 'users' && <UsersRbacSubTab />}
      {activeTab === 'tokens' && <ApiTokensSubTab />}
      {activeTab === 'display' && <DisplayAndFlowsSubTab />}
      {activeTab === 'reports' && <EmailReportsSubTab />}
      {activeTab === 'audit' && <AuditLogSubTab />}
      {activeTab === 'profile' && <MyProfileSubTab />}
    </div>
  );
}

// ============================================================================
// SUB-TAB 1: USERS & RBAC
// ============================================================================
function UsersRbacSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: usersList, isLoading } = useQuery({
    queryKey: ['admin-users'],
    queryFn: () => apiFetch<AdminUser[]>('/admin/api/users'),
  });

  const users = usersList ?? [];
  const { data: me } = useQuery({
    queryKey: ['me'],
    queryFn: () => apiFetch<MeResponse>('/admin/api/me'),
  });

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newRole, setNewRole] = useState<'admin' | 'operator' | 'viewer'>('operator');
  // The backend generates the temporary password and returns it exactly once;
  // there is no reset-password UI, so losing it here meant creating an account
  // nobody could ever sign in to.
  const [createdCred, setCreatedCred] = useState<{
    username: string;
    password: string;
    note: string;
    title: string;
  } | null>(null);
  const [userToDelete, setUserToDelete] = useState<AdminUser | null>(null);
  const [userToClearPasskeys, setUserToClearPasskeys] = useState<AdminUser | null>(null);

  const createUserMutation = useMutation({
    mutationFn: async () =>
      apiFetch<{ user?: { username?: string }; temp_password?: string }>('/admin/api/users', {
        method: 'POST',
        body: {
          username: newUsername.trim(),
          role: newRole,
        },
      }),
    onSuccess: (data) => {
      setCreatedCred({
        username: data?.user?.username ?? newUsername.trim(),
        password: data?.temp_password ?? '',
        note: 'Copy the temporary password now — it is not stored in plaintext and cannot be shown again.',
        title: 'Account created',
      });
      toast({ title: 'User created', variant: 'success' });
      setDrawerOpen(false);
      setNewUsername('');
      setNewRole('operator');
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to create user', description: err.message, variant: 'error' });
    },
  });

  const updateRoleMutation = useMutation({
    mutationFn: async ({ id, role }: { id: number; role: string }) =>
      apiFetch(`/admin/api/users/${id}`, { method: 'PUT', body: { role } }),
    onSuccess: () => {
      toast({ title: 'User role updated', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Role update failed', description: err.message, variant: 'error' });
    },
  });

  const reset2faMutation = useMutation({
    mutationFn: async (id: number) => apiFetch(`/admin/api/users/${id}/reset-2fa`, { method: 'POST' }),
    onSuccess: () => {
      toast({ title: 'User 2FA reset', variant: 'info' });
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Could not reset 2FA', description: err.message, variant: 'error' });
    },
  });

  const deleteUserMutation = useMutation({
    mutationFn: async (id: number) => apiFetch(`/admin/api/users/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      toast({ title: 'User deleted', variant: 'info' });
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Delete failed', description: err.message, variant: 'error' });
    },
  });

  const resetPasswordMutation = useMutation({
    mutationFn: async (userId: number) =>
      apiFetch<{ temp_password?: string }>(`/admin/api/users/${userId}/reset-password`, {
        method: 'POST',
      }),
    onSuccess: (data, userId) => {
      const user = users.find((u) => u.id === userId);
      setCreatedCred({
        username: user?.username ?? `user ${userId}`,
        password: data?.temp_password ?? '',
        note: 'Password reset. Every session was revoked and all passkeys removed. Copy the temporary password now.',
        title: 'Password reset',
      });
      toast({ title: 'Password reset', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
    onError: (err: Error) =>
      toast({ title: 'Password reset failed', description: err.message, variant: 'error' }),
  });

  const toggleDisabledMutation = useMutation({
    mutationFn: async ({ id, disabled }: { id: number; disabled: boolean }) =>
      apiFetch(`/admin/api/users/${id}`, { method: 'PUT', body: { disabled } }),
    onSuccess: (_data, vars) => {
      toast({ title: vars.disabled ? 'User disabled' : 'User enabled', variant: 'info' });
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
    onError: (err: Error) =>
      toast({ title: 'Update failed', description: err.message, variant: 'error' }),
  });

  const removePasskeysMutation = useMutation({
    mutationFn: async (id: number) =>
      apiFetch(`/admin/api/users/${id}/passkeys`, { method: 'DELETE' }),
    onSuccess: () => {
      toast({ title: 'Passkeys removed', variant: 'info' });
      setUserToClearPasskeys(null);
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
    onError: (err: Error) =>
      toast({ title: 'Could not remove passkeys', description: err.message, variant: 'error' }),
  });

  const columns = useMemo<ColumnDef<AdminUser, unknown>[]>(
    () => [
      {
        accessorKey: 'username',
        header: 'User',
        cell: ({ row }) => (
          <div>
            <div className="font-semibold text-text">{row.original.username}</div>
            {row.original.email && (
              <div className="text-[11px] text-text-dim">{row.original.email}</div>
            )}
          </div>
        ),
      },
      {
        accessorKey: 'role',
        header: 'RBAC Role',
        cell: ({ row }) => (
          <select
            value={row.original.role}
            disabled={row.original.id === me?.id}
            title={row.original.id === me?.id ? 'You cannot change your own role' : undefined}
            onChange={(e) => updateRoleMutation.mutate({ id: row.original.id, role: e.target.value })}
            aria-label={`Role for ${row.original.username}`}
            className="rounded border border-border bg-bg-panel px-2 py-1 text-xs font-medium text-text disabled:opacity-50"
          >
            <option value="viewer">Viewer (Read-Only)</option>
            <option value="operator">Operator (Day-to-Day Ops)</option>
            <option value="admin">Admin (Full Control)</option>
          </select>
        ),
      },
      {
        id: 'status',
        header: 'Status',
        cell: ({ row }) => (
          <div className="flex flex-wrap gap-1">
            {row.original.disabled && (
              <span className="rounded bg-sig-crit/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-sig-crit">
                Disabled
              </span>
            )}
            {row.original.must_change_password && (
              <span className="rounded bg-sig-warn/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-sig-warn">
                Password change
              </span>
            )}
            {!row.original.disabled && !row.original.must_change_password && (
              <span className="rounded bg-sig-ok/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-sig-ok">
                Active
              </span>
            )}
          </div>
        ),
      },
      {
        accessorKey: 'totp_enabled',
        header: 'MFA Status',
        cell: ({ row }) => (
          <div className="flex items-center gap-1.5">
            <span
              className={cn(
                'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
                row.original.totp_enabled
                  ? 'bg-sig-ok/15 text-sig-ok'
                  : 'bg-bg-panel text-text-dim'
              )}
            >
              {row.original.totp_enabled ? 'TOTP Active' : 'No TOTP'}
            </span>
          </div>
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex items-center justify-end gap-1.5">
            <button
              type="button"
              disabled={row.original.id === me?.id}
              title={row.original.id === me?.id ? 'You cannot disable your own account' : undefined}
              onClick={() =>
                toggleDisabledMutation.mutate({
                  id: row.original.id,
                  disabled: !row.original.disabled,
                })
              }
              className="rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text-dim hover:text-text disabled:opacity-40"
            >
              {row.original.disabled ? 'Enable' : 'Disable'}
            </button>
            <button
              type="button"
              onClick={() => resetPasswordMutation.mutate(row.original.id)}
              disabled={resetPasswordMutation.isPending}
              className="rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text-dim hover:text-text disabled:opacity-40"
            >
              Reset password
            </button>
            {row.original.totp_enabled && (
              <button
                type="button"
                onClick={() => reset2faMutation.mutate(row.original.id)}
                className="rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text-dim hover:text-text"
              >
                Reset 2FA
              </button>
            )}
            <button
              type="button"
              onClick={() => setUserToClearPasskeys(row.original)}
              className="rounded border border-border bg-bg-panel px-2 py-1 text-[11px] text-text-dim hover:text-text"
              title="Remove every passkey for this user"
            >
              Passkeys
            </button>
            <button
              type="button"
              onClick={() => setUserToDelete(row.original)}
              className="rounded border border-sig-crit/30 bg-sig-crit/10 p-1 text-sig-crit hover:bg-sig-crit/20"
              title="Delete user"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          </div>
        ),
      },
    ],
    [
      updateRoleMutation,
      reset2faMutation,
      deleteUserMutation,
      resetPasswordMutation,
      toggleDisabledMutation,
      me?.id,
    ]
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-text">Admin Console Users ({users.length})</h2>
          <p className="text-xs text-text-dim">
            Manage RBAC roles (`viewer`, `operator`, `admin`), MFA status, and account lifecycle.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setDrawerOpen(true)}
          className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90"
        >
          <Plus className="h-3.5 w-3.5" />
          Create User
        </button>
      </div>

      <ResponsiveDataView
        data={users}
        columns={columns}
        isLoading={isLoading}
        emptyTitle="No users found."
        renderMobileCard={(u) => (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-sm text-text">{u.username}</span>
              <span className="rounded bg-accent/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-accent">
                {u.role}
              </span>
            </div>
            <div className="text-xs text-text-dim">{u.email || 'No email'}</div>
          </div>
        )}
      />

      <SlideOverDrawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        title="Create Admin User"
        subtitle="New accounts are flagged to rotate their temporary password on first login."
        footer={
          <div className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => setDrawerOpen(false)}
              className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text-dim"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={!newUsername.trim() || createUserMutation.isPending}
              onClick={() => createUserMutation.mutate()}
              className="rounded-md bg-accent px-4 py-1.5 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
            >
              {createUserMutation.isPending ? 'Creating…' : 'Create User'}
            </button>
          </div>
        }
      >
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Username</label>
            <input
              type="text"
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              placeholder="jdoe"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">RBAC Role</label>
            <select
              value={newRole}
              onChange={(e) => setNewRole(e.target.value as 'admin' | 'operator' | 'viewer')}
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            >
              <option value="viewer">Viewer (Read-Only)</option>
              <option value="operator">Operator (Day-to-Day Ops)</option>
              <option value="admin">Admin (Full Control)</option>
            </select>
          </div>
          <p className="text-[11px] leading-relaxed text-text-dim">
            The server generates a temporary password and shows it once after the account is
            created. The account is forced to rotate it at first login.
          </p>
        </div>
      </SlideOverDrawer>

      <SlideOverDrawer
        open={!!createdCred}
        onOpenChange={(open) => {
          if (!open) setCreatedCred(null);
        }}
        title={createdCred?.title ?? 'Credential'}
        subtitle={createdCred?.note ?? ''}
        footer={
          <button
            type="button"
            onClick={() => setCreatedCred(null)}
            className="rounded-md bg-accent px-4 py-1.5 text-xs font-semibold text-white hover:opacity-90"
          >
            I have copied it
          </button>
        }
      >
        {createdCred && (
          <div className="space-y-3">
            <div>
              <span className="block text-xs font-medium text-text-dim">Username</span>
              <span className="font-mono text-sm text-text">{createdCred.username}</span>
            </div>
            <div>
              <span className="block text-xs font-medium text-text-dim">Temporary password</span>
              <div className="mt-1 flex items-center gap-2">
                <code className="flex-1 break-all rounded-md border border-border bg-bg-panel px-3 py-2 font-mono text-xs text-text">
                  {createdCred.password || '(server returned no password)'}
                </code>
                <button
                  type="button"
                  onClick={() => {
                    void navigator.clipboard
                      ?.writeText(createdCred.password)
                      .then(() => toast({ title: 'Password copied', variant: 'success' }))
                      .catch(() =>
                        toast({
                          title: 'Copy failed',
                          description: 'Select the password and copy it manually.',
                          variant: 'error',
                        }),
                      );
                  }}
                  className="rounded-md border border-border px-2.5 py-2 text-xs text-text-dim hover:text-text"
                >
                  Copy
                </button>
              </div>
            </div>
          </div>
        )}
      </SlideOverDrawer>

      <ConfirmDialog
        open={!!userToClearPasskeys}
        onOpenChange={(open) => {
          if (!open) setUserToClearPasskeys(null);
        }}
        title={`Remove every passkey for ${userToClearPasskeys?.username ?? ''}?`}
        description="Their registered passkeys stop working and their sessions are revoked. They can register new ones after signing in." 
        confirmLabel="Remove passkeys"
        destructive
        pending={removePasskeysMutation.isPending}
        onConfirm={() =>
          userToClearPasskeys && removePasskeysMutation.mutate(userToClearPasskeys.id)
        }
      />

      <ConfirmDialog
        open={!!userToDelete}
        onOpenChange={(open) => {
          if (!open) setUserToDelete(null);
        }}
        title={`Delete user ${userToDelete?.username ?? ''}?`}
        description="The account and its API tokens stop working immediately. This cannot be undone."
        confirmLabel="Delete user"
        destructive
        pending={deleteUserMutation.isPending}
        onConfirm={() => {
          if (!userToDelete) return;
          deleteUserMutation.mutate(userToDelete.id, {
            onSuccess: () => setUserToDelete(null),
          });
        }}
      />
    </div>
  );
}

// ============================================================================
// SUB-TAB 2: API TOKENS
// ============================================================================
function ApiTokensSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: tokensList, isLoading } = useQuery({
    queryKey: ['api-tokens'],
    queryFn: () => apiFetch<APITokenRow[]>('/admin/api/tokens'),
  });

  const tokens = tokensList ?? [];

  const [tokenName, setTokenName] = useState('');
  const [tokenScope, setTokenScope] = useState<'read' | 'write' | 'admin'>('read');
  const [tokenExpiryDays, setTokenExpiryDays] = useState('0');
  const [mintedSecret, setMintedSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const createTokenMutation = useMutation({
    mutationFn: async () =>
      apiFetch<{ token: string; token_meta?: APITokenRow }>('/admin/api/tokens', {
        method: 'POST',
        body: {
          name: tokenName.trim(),
          scope: tokenScope,
          // 0 = never expires; the server accepts 0..3650.
          expires_in_days: Math.max(0, Math.floor(Number(tokenExpiryDays) || 0)),
        },
      }),
    onSuccess: (res) => {
      if (res?.token) {
        setMintedSecret(res.token);
      }
      setTokenName('');
      toast({ title: 'API token minted', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to create token', description: err.message, variant: 'error' });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: async (id: number) => apiFetch(`/admin/api/tokens/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      toast({ title: 'API token revoked', variant: 'info' });
      queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
    },
    onError: (err: Error) => {
      // This one matters most: a silently-failed revoke leaves the operator
      // believing the token is dead when it is still live.
      toast({ title: 'Could not revoke the token', description: err.message, variant: 'error' });
    },
  });

  const columns = useMemo<ColumnDef<APITokenRow, unknown>[]>(
    () => [
      {
        accessorKey: 'name',
        header: 'Token Name',
        cell: ({ row }) => <span className="font-semibold text-text">{row.original.name}</span>,
      },
      {
        accessorKey: 'prefix',
        header: 'Prefix',
        cell: ({ row }) => (
          <code className="rounded bg-bg-panel px-2 py-0.5 text-xs font-mono text-text-dim">
            {row.original.prefix}…
          </code>
        ),
      },
      {
        accessorKey: 'scope',
        header: 'Scope',
        cell: ({ row }) => (
          <span className="rounded bg-accent/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-accent">
            {row.original.scope}
          </span>
        ),
      },
      {
        accessorKey: 'last_used_at',
        header: 'Last Used',
        cell: ({ row }) => (
          <span className="text-xs text-text-dim">
            {row.original.last_used_at ? formatRelativeTime(row.original.last_used_at) : 'Never'}
          </span>
        ),
      },
      {
        id: 'status',
        header: 'Status',
        cell: ({ row }) => {
          const revoked = Boolean(row.original.revoked_at);
          const expired = Boolean(
            row.original.expires_at &&
              new Date(row.original.expires_at).getTime() < Date.now(),
          );
          const label = revoked ? 'revoked' : expired ? 'expired' : 'active';
          return (
            <div className="space-y-0.5">
              <span
                className={cn(
                  'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase',
                  label === 'active'
                    ? 'bg-sig-ok/15 text-sig-ok'
                    : label === 'expired'
                      ? 'bg-sig-warn/15 text-sig-warn'
                      : 'bg-bg-panel text-text-faint',
                )}
              >
                {label}
              </span>
              {row.original.expires_at && (
                <div className="font-mono text-[10px] text-text-faint">
                  {(() => {
                    const diff =
                      new Date(row.original.expires_at as string).getTime() - Date.now();
                    if (!Number.isFinite(diff)) return 'expiry unknown';
                    if (Math.abs(diff) < 86_400_000) return diff < 0 ? 'expired today' : 'today';
                    const days = Math.round(Math.abs(diff) / 86_400_000);
                    return diff < 0 ? `${days}d ago` : `in ${days}d`;
                  })()}
                </div>
              )}
            </div>
          );
        },
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className="flex justify-end">
            {!row.original.revoked_at && (
              <button
                type="button"
                onClick={() => revokeMutation.mutate(row.original.id)}
                className="flex items-center gap-1 rounded border border-sig-crit/30 bg-sig-crit/10 px-2.5 py-1 text-xs font-medium text-sig-crit hover:bg-sig-crit/20"
              >
                <Trash2 className="h-3 w-3" />
                Revoke
              </button>
            )}
          </div>
        ),
      },
    ],
    [revokeMutation]
  );

  return (
    <div className="space-y-5">
      {/* Mint Token Bar */}
      <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
        <h2 className="text-sm font-semibold text-text">Mint New Scoped API Token</h2>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
          <input
            type="text"
            value={tokenName}
            onChange={(e) => setTokenName(e.target.value)}
            placeholder="Token description (e.g. Grafana Reader)"
            className="sm:col-span-2 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text"
          />
          <input
            type="number"
            min={0}
            max={3650}
            step={1}
            value={tokenExpiryDays}
            onChange={(e) => setTokenExpiryDays(e.target.value)}
            aria-label="Token lifetime in days (0 = never expires)"
            placeholder="Days (0 = never)"
            className="rounded-md border border-border bg-bg-panel px-3 py-1.5 font-mono text-xs text-text"
          />
          <select
            value={tokenScope}
            onChange={(e) => setTokenScope(e.target.value as 'read' | 'write' | 'admin')}
            className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text"
          >
            <option value="read">Scope: Read-Only (Viewer)</option>
            <option value="write">Scope: Read/Write (Operator)</option>
            <option value="admin">Scope: Admin</option>
          </select>
          <button
            type="button"
            disabled={!tokenName.trim() || createTokenMutation.isPending}
            onClick={() => createTokenMutation.mutate()}
            className="flex items-center justify-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
          >
            <Key className="h-3.5 w-3.5" />
            Generate Token
          </button>
        </div>

        {mintedSecret && (
          <div className="mt-3 rounded-lg border border-sig-ok/40 bg-sig-ok/10 p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <div className="text-xs font-semibold text-sig-ok">
                Copy your new API token now — it will never be shown again:
              </div>
              <code className="block mt-1 font-mono text-xs text-text break-all">
                {mintedSecret}
              </code>
            </div>
            <button
              type="button"
              onClick={() => {
                navigator.clipboard.writeText(mintedSecret);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
              className="flex items-center gap-1.5 rounded-md bg-bg-card px-3 py-1.5 text-xs font-semibold text-text border border-border shrink-0"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-sig-ok" /> : <Copy className="h-3.5 w-3.5" />}
              {copied ? 'Copied' : 'Copy Token'}
            </button>
          </div>
        )}
      </div>

      <ResponsiveDataView
        data={tokens}
        columns={columns}
        isLoading={isLoading}
        emptyTitle="No active API tokens."
        renderMobileCard={(t) => (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-sm text-text">{t.name}</span>
              <span className="rounded bg-accent/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-accent">
                {t.scope}
              </span>
            </div>
            <div className="text-xs font-mono text-text-dim">{t.prefix}…</div>
          </div>
        )}
      />
    </div>
  );
}

// ============================================================================
// SUB-TAB 3: DISPLAY, TIMEZONE, FLOW CLASSIFICATION & NORMALIZE BACKFILL
// ============================================================================
const DISPLAY_KEYS = [
  'display_timezone',
  'public_refresh_interval',
  'public_show_vpn',
  'public_show_connections',
  'dashboard_health_refresh_seconds',
  'flow_internal_auto',
  'flow_internal_networks',
] as const;

function DisplayAndFlowsSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: settingsList, isLoading } = useQuery({
    queryKey: ['settings'],
    queryFn: () => apiFetch<SystemSetting[]>('/admin/api/settings'),
  });

  const { data: backfillStatus } = useQuery({
    queryKey: ['normalize-backfill'],
    queryFn: () =>
      apiFetch<{ state?: string; processed?: number; total?: number; last_error?: string }>(
        '/admin/api/normalize/backfill/status'
      ),
    refetchInterval: 10_000,
  });

  const serverMap = useMemo(() => {
    const m: Record<string, string> = {
      display_timezone: 'America/New_York',
      public_refresh_interval: '30',
      public_show_vpn: 'false',
      public_show_connections: 'false',
      dashboard_health_refresh_seconds: '60',
      flow_internal_auto: 'true',
      flow_internal_networks: '',
    };
    for (const s of settingsList ?? []) {
      if ((DISPLAY_KEYS as readonly string[]).includes(s.key)) {
        m[s.key] = s.value ?? '';
      }
    }
    return m;
  }, [settingsList]);

  const [draft, setDraft] = useState<Record<string, string>>({});
  const [backfillAuthOpen, setBackfillAuthOpen] = useState(false);

  useEffect(() => {
    setDraft(serverMap);
    // Hydrate the shared display-timezone store from the server value so
    // timestamps elsewhere in the console render in the configured zone.
    if (serverMap.display_timezone) setDisplayTimezone(serverMap.display_timezone);
  }, [serverMap]);

  const dirtyKeys = useMemo(() => {
    return DISPLAY_KEYS.filter((k) => (draft[k] ?? '') !== (serverMap[k] ?? ''));
  }, [draft, serverMap]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      const payload: SystemSetting[] = dirtyKeys.map((key) => ({
        key,
        value: draft[key] ?? '',
        category: 'display',
      }));
      return apiFetch('/admin/api/settings', { method: 'POST', body: payload });
    },
    onSuccess: () => {
      if (dirtyKeys.includes('display_timezone')) {
        setDisplayTimezone(draft.display_timezone);
      }
      toast({ title: 'Display & classification settings saved', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['settings'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Save failed', description: err.message, variant: 'error' });
    },
  });

  const reclassifyMutation = useMutation({
    mutationFn: async () => apiFetch('/admin/api/flows/reclassify', { method: 'POST' }),
    onSuccess: () => {
      toast({ title: 'Historical flow reclassification queued', variant: 'info' });
    },
    onError: (err: Error) => {
      toast({ title: 'Reclassification failed', description: err.message, variant: 'error' });
    },
  });

  if (isLoading) {
    return (
      <div className="rounded-xl border border-border bg-bg-card p-8 text-center text-sm text-text-dim">
        Loading display & flow settings…
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 pb-12">
      {/* Display & Public Kiosk */}
      <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
        <div className="border-b border-border pb-3">
          <h2 className="text-sm font-semibold text-text">Display, Timezone & Health Cadence</h2>
          <p className="text-xs text-text-dim mt-0.5">
            Controls console timezone rendering, public status board options, and background system health refresh.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Display Timezone</label>
            <input
              type="text"
              value={draft.display_timezone ?? 'America/New_York'}
              onChange={(e) => setDraft((p) => ({ ...p, display_timezone: e.target.value }))}
              placeholder="America/New_York"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">
              Health Refresh Interval (15-3600s)
            </label>
            <input
              type="number"
              min={15}
              max={3600}
              value={draft.dashboard_health_refresh_seconds ?? '60'}
              onChange={(e) =>
                setDraft((p) => ({ ...p, dashboard_health_refresh_seconds: e.target.value }))
              }
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">
              Public Board Refresh (s)
            </label>
            <input
              type="number"
              min={10}
              max={3600}
              value={draft.public_refresh_interval ?? '30'}
              onChange={(e) => setDraft((p) => ({ ...p, public_refresh_interval: e.target.value }))}
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text"
            />
          </div>
          <div className="flex flex-col justify-end gap-2">
            <label className="flex items-center gap-2 text-xs text-text">
              <input
                type="checkbox"
                checked={draft.public_show_vpn === 'true'}
                onChange={(e) =>
                  setDraft((p) => ({ ...p, public_show_vpn: e.target.checked ? 'true' : 'false' }))
                }
                className="h-4 w-4 rounded accent-accent"
              />
              Show VPN Status on Public Board
            </label>
            <label className="flex items-center gap-2 text-xs text-text">
              <input
                type="checkbox"
                checked={draft.public_show_connections === 'true'}
                onChange={(e) =>
                  setDraft((p) => ({
                    ...p,
                    public_show_connections: e.target.checked ? 'true' : 'false',
                  }))
                }
                className="h-4 w-4 rounded accent-accent"
              />
              Show WAN Connections on Public Board
            </label>
          </div>
        </div>
      </div>

      {/* Flow Classification & Normalize Backfill */}
      <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
        <div className="border-b border-border pb-3 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-text">
              Internal Network Flow Classification
            </h2>
            <p className="text-xs text-text-dim mt-0.5">
              Defines which CIDRs are treated as internal for ingress/egress/lateral flow directionality.
            </p>
          </div>
          <button
            type="button"
            disabled={reclassifyMutation.isPending}
            onClick={() => reclassifyMutation.mutate()}
            className="flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-2.5 py-1.5 text-xs font-medium text-text hover:bg-bg-hover"
          >
            <RefreshCw className="h-3.5 w-3.5 text-accent" />
            Reclassify History
          </button>
        </div>

        <label className="flex items-center gap-2 text-xs text-text">
          <input
            type="checkbox"
            checked={draft.flow_internal_auto !== 'false'}
            onChange={(e) =>
              setDraft((p) => ({ ...p, flow_internal_auto: e.target.checked ? 'true' : 'false' }))
            }
            className="h-4 w-4 rounded accent-accent"
          />
          Auto-include RFC1918 & Device Interface Subnets
        </label>

        <div>
          <label className="block text-xs font-medium text-text-dim mb-1">
            Additional Internal CIDRs (comma or newline separated)
          </label>
          <textarea
            rows={3}
            value={draft.flow_internal_networks ?? ''}
            onChange={(e) => setDraft((p) => ({ ...p, flow_internal_networks: e.target.value }))}
            placeholder="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
            className="w-full rounded-md border border-border bg-bg-panel p-2.5 text-xs font-mono text-text focus:border-accent focus:outline-hidden"
          />
        </div>

        <div className="pt-3 border-t border-border flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold text-text">Normalized Event Backfill</div>
            <div className="text-[11px] text-text-dim">
              Status: <span className="font-mono">{backfillStatus?.state || 'idle'}</span>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setBackfillAuthOpen(true)}
            className="flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:bg-bg-hover"
          >
            <Lock className="h-3.5 w-3.5 text-accent" />
            Start Backfill
          </button>
        </div>
      </div>

      <StepUpAuthDialog
        open={backfillAuthOpen}
        onOpenChange={setBackfillAuthOpen}
        title="Start Normalized Event Backfill"
        description="Re-parses historical raw syslog rows into net_events and sec_events. Enter your admin password to confirm."
        confirmLabel="Start Backfill"
        onConfirm={async ({ password, totp_code }) => {
          await apiFetch('/admin/api/normalize/backfill', {
            method: 'POST',
            body: { password, totp_code },
          });
          toast({ title: 'Backfill job started', variant: 'success' });
          queryClient.invalidateQueries({ queryKey: ['normalize-backfill'] });
        }}
      />

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
// SUB-TAB 4: EMAIL REPORTS
// ============================================================================
const REPORT_KEYS = [
  'report_daily_enabled',
  'report_daily_time',
  'report_weekly_enabled',
  'report_weekly_day',
  'report_recipients',
  'report_timezone',
  'report_email_theme',
] as const;

function EmailReportsSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: settingsList } = useQuery({
    queryKey: ['settings'],
    queryFn: () => apiFetch<SystemSetting[]>('/admin/api/settings'),
  });

  const serverMap = useMemo(() => {
    const m: Record<string, string> = {
      report_daily_enabled: 'false',
      report_daily_time: '08:00',
      report_weekly_enabled: 'false',
      report_weekly_day: 'monday',
      report_recipients: '',
      report_timezone: 'America/New_York',
      report_email_theme: 'dark',
    };
    for (const s of settingsList ?? []) {
      if ((REPORT_KEYS as readonly string[]).includes(s.key)) {
        m[s.key] = s.value ?? '';
      }
    }
    return m;
  }, [settingsList]);

  const [draft, setDraft] = useState<Record<string, string>>({});
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewHtml, setPreviewHtml] = useState('');

  useEffect(() => {
    setDraft(serverMap);
  }, [serverMap]);

  const dirtyKeys = useMemo(() => {
    return REPORT_KEYS.filter((k) => (draft[k] ?? '') !== (serverMap[k] ?? ''));
  }, [draft, serverMap]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      const payload: SystemSetting[] = dirtyKeys.map((key) => ({
        key,
        value: draft[key] ?? '',
        category: 'reports',
      }));
      return apiFetch('/admin/api/settings', { method: 'POST', body: payload });
    },
    onSuccess: () => {
      toast({ title: 'Report schedule saved', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['settings'] });
    },
    onError: (err: Error) => {
      toast({
        title: 'Could not save the report schedule',
        description: err.message,
        variant: 'error',
      });
    },
  });

  const sendNowMutation = useMutation({
    mutationFn: async () => apiFetch('/admin/api/reports/send', { method: 'POST' }),
    onSuccess: () => {
      toast({ title: 'Executive report sent', variant: 'success' });
    },
    onError: (err: Error) => {
      toast({ title: 'Report send failed', description: err.message, variant: 'error' });
    },
  });

  const loadPreview = async () => {
    try {
      // PreviewReport returns {success, data:{subject, html}} as JSON; putting
      // the raw body in srcDoc rendered the JSON, not the report.
      const res = await fetch('/admin/api/reports/preview', { credentials: 'same-origin' });
      if (!res.ok) throw new Error(`Preview failed (${res.status})`);
      const body = (await res.json()) as { data?: { html?: string } };
      setPreviewHtml(body.data?.html ?? '<p>Report preview returned no HTML.</p>');
      setPreviewOpen(true);
    } catch (err) {
      toast({
        title: 'Preview failed',
        description: err instanceof Error ? err.message : 'Unable to load preview',
        variant: 'error',
      });
    }
  };

  return (
    <div className="space-y-5 pb-12">
      <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-border pb-3">
          <div>
            <h2 className="text-sm font-semibold text-text">Scheduled Executive Email Reports</h2>
            <p className="text-xs text-text-dim">
              Automated daily or weekly fleet health, bandwidth, SLA, and alert digest emails.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={loadPreview}
              className="flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:bg-bg-hover"
            >
              <Eye className="h-3.5 w-3.5 text-accent" />
              Preview HTML
            </button>
            <button
              type="button"
              disabled={sendNowMutation.isPending}
              onClick={() => sendNowMutation.mutate()}
              className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
            >
              <Send className="h-3.5 w-3.5" />
              {sendNowMutation.isPending ? 'Sending…' : 'Send Report Now'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="rounded-lg border border-border bg-bg-panel p-3 space-y-2">
            <label className="flex items-center justify-between text-xs font-semibold text-text">
              <span>Daily Report</span>
              <input
                type="checkbox"
                checked={draft.report_daily_enabled === 'true'}
                onChange={(e) =>
                  setDraft((p) => ({ ...p, report_daily_enabled: e.target.checked ? 'true' : 'false' }))
                }
                className="h-4 w-4 rounded accent-accent"
              />
            </label>
            <input
              type="time"
              value={draft.report_daily_time ?? '08:00'}
              onChange={(e) => setDraft((p) => ({ ...p, report_daily_time: e.target.value }))}
              className="w-full rounded border border-border bg-bg-card px-2.5 py-1.5 text-xs font-mono text-text"
            />
          </div>

          <div className="rounded-lg border border-border bg-bg-panel p-3 space-y-2">
            <label className="flex items-center justify-between text-xs font-semibold text-text">
              <span>Weekly Report</span>
              <input
                type="checkbox"
                checked={draft.report_weekly_enabled === 'true'}
                onChange={(e) =>
                  setDraft((p) => ({ ...p, report_weekly_enabled: e.target.checked ? 'true' : 'false' }))
                }
                className="h-4 w-4 rounded accent-accent"
              />
            </label>
            <select
              value={draft.report_weekly_day ?? 'monday'}
              onChange={(e) => setDraft((p) => ({ ...p, report_weekly_day: e.target.value }))}
              className="w-full rounded border border-border bg-bg-card px-2.5 py-1.5 text-xs text-text"
            >
              {['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'].map((d) => (
                <option key={d} value={d}>
                  {d.charAt(0).toUpperCase() + d.slice(1)}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Report Timezone</label>
            <input
              type="text"
              value={draft.report_timezone ?? 'America/New_York'}
              onChange={(e) => setDraft((p) => ({ ...p, report_timezone: e.target.value }))}
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-text-dim mb-1">Email Theme</label>
            <select
              value={draft.report_email_theme ?? 'dark'}
              onChange={(e) => setDraft((p) => ({ ...p, report_email_theme: e.target.value }))}
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs text-text"
            >
              <option value="dark">Dark NOC Theme</option>
              <option value="light">Light Theme</option>
            </select>
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-text-dim mb-1">
            Report Recipients (comma-separated emails)
          </label>
          <input
            type="text"
            value={draft.report_recipients ?? ''}
            onChange={(e) => setDraft((p) => ({ ...p, report_recipients: e.target.value }))}
            placeholder="noc-leads@example.com, ciso@example.com"
            className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 text-xs font-mono text-text"
          />
        </div>
      </div>

      <SlideOverDrawer
        open={previewOpen}
        onOpenChange={setPreviewOpen}
        title="Executive Report HTML Preview"
        size="2xl"
      >
        <div className="rounded-lg border border-border overflow-hidden bg-white">
          <iframe
            title="Report Preview"
            srcDoc={previewHtml}
            className="w-full h-[640px] border-0"
            sandbox=""
          />
        </div>
      </SlideOverDrawer>

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
// SUB-TAB 5: AUDIT LOG
// ============================================================================
const AUDIT_PAGE_SIZE = 50;
const AUDIT_RANGES = [
  { value: '1', label: '1h' },
  { value: '24', label: '24h' },
  { value: '168', label: '7d' },
  { value: '720', label: '30d' },
] as const;

function AuditLogSubTab() {
  const [actorFilter, setActorFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [rangeHours, setRangeHours] = useState('24');
  const [page, setPage] = useState(0);
  const [selectedEntry, setSelectedEntry] = useState<AuditLogEntry | null>(null);

  const offset = page * AUDIT_PAGE_SIZE;
  const { data: auditRes, isLoading } = useQuery({
    queryKey: ['audit-logs', actorFilter, actionFilter, rangeHours, page],
    queryFn: () => {
      const params = new URLSearchParams({
        limit: String(AUDIT_PAGE_SIZE),
        offset: String(offset),
        hours: rangeHours,
      });
      if (actorFilter.trim()) params.set('actor', actorFilter.trim());
      if (actionFilter.trim()) params.set('action', actionFilter.trim());
      return apiFetch<any>(`/admin/api/audit?${params.toString()}`);
    },
  });

  const logs: AuditLogEntry[] = useMemo(() => {
    if (Array.isArray(auditRes)) return auditRes;
    return auditRes?.audit_logs ?? auditRes?.items ?? auditRes?.data ?? [];
  }, [auditRes]);
  const auditTotal: number = Array.isArray(auditRes)
    ? // Bare-array fallback: we cannot know the true total, so advertise one
      // more row when the page is full instead of disabling Next.
      offset + logs.length + (logs.length === AUDIT_PAGE_SIZE ? 1 : 0)
    : Number(auditRes?.total ?? logs.length) || 0;
  const resetAuditPage = () => setPage(0);

  const columns = useMemo<ColumnDef<AuditLogEntry, unknown>[]>(
    () => [
      {
        accessorKey: 'created_at',
        header: 'When',
        cell: ({ row }) => (
          <span className="font-mono text-xs text-text-dim">
            {formatRelativeTime(row.original.created_at)}
          </span>
        ),
      },
      {
        accessorKey: 'actor',
        header: 'Actor',
        cell: ({ row }) => (
          <span className="font-semibold text-text">{row.original.actor}</span>
        ),
      },
      {
        accessorKey: 'action',
        header: 'Method & Path',
        cell: ({ row }) => (
          <div className="font-mono text-xs">
            <span className="font-semibold text-accent">{row.original.method}</span>{' '}
            <span className="text-text" title={row.original.action}>
              {row.original.target || row.original.action}
            </span>
          </div>
        ),
      },
      {
        accessorKey: 'ip_address',
        header: 'Source IP',
        cell: ({ row }) => <span className="font-mono text-xs text-text-dim">{row.original.ip_address}</span>,
      },
      {
        accessorKey: 'status',
        header: 'Status',
        cell: ({ row }) => (
          <span
            className={cn(
              'rounded px-1.5 py-0.5 font-mono text-[11px] font-semibold',
              row.original.status < 400
                ? 'bg-sig-ok/15 text-sig-ok'
                : 'bg-sig-crit/15 text-sig-crit'
            )}
          >
            {row.original.status}
          </span>
        ),
      },
    ],
    []
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-text">Admin Mutation Audit Trail</h2>
          <p className="text-xs text-text-dim">
            Every authenticated admin POST/PUT/PATCH/DELETE action is recorded with actor, IP, and payload summary.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="search"
            value={actorFilter}
            onChange={(e) => {
              setActorFilter(e.target.value);
              resetAuditPage();
            }}
            placeholder="Filter by username..."
            aria-label="Filter by actor"
            className="rounded-md border border-border bg-bg-card px-3 py-1.5 text-xs text-text"
          />
          <input
            type="search"
            value={actionFilter}
            onChange={(e) => {
              setActionFilter(e.target.value);
              resetAuditPage();
            }}
            placeholder="Filter by route..."
            aria-label="Filter by action route"
            className="rounded-md border border-border bg-bg-card px-3 py-1.5 font-mono text-xs text-text"
          />
          <select
            value={rangeHours}
            onChange={(e) => {
              setRangeHours(e.target.value);
              resetAuditPage();
            }}
            aria-label="Audit time range"
            className="rounded-md border border-border bg-bg-card px-2.5 py-1.5 text-xs text-text"
          >
            {AUDIT_RANGES.map((r) => (
              <option key={r.value} value={r.value}>
                Last {r.label}
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={() => {
              setActorFilter('');
              setActionFilter('');
              setRangeHours('24');
              resetAuditPage();
            }}
            className="rounded-md border border-border bg-bg-panel px-2.5 py-1.5 text-[11px] text-text-dim hover:text-text"
          >
            Clear
          </button>
        </div>
      </div>

      <ResponsiveDataView
        data={logs}
        columns={columns}
        isLoading={isLoading}
        onRowClick={(row) => setSelectedEntry(row)}
        emptyTitle="No audit entries matching filter."
        renderMobileCard={(entry) => (
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs text-text">{entry.actor}</span>
              <span className="font-mono text-[11px] text-text-dim">
                {formatRelativeTime(entry.created_at)}
              </span>
            </div>
            <div className="font-mono text-xs text-accent">
              {entry.method} {entry.target || entry.action}
            </div>
          </div>
        )}
      />

      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[11px] text-text-dim">
          {logs.length === 0
            ? `0 of ${auditTotal}`
            : `${offset + 1}–${offset + logs.length} of ${auditTotal}`}
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
            disabled={offset + logs.length >= auditTotal}
            onClick={() => setPage((p) => p + 1)}
            className="rounded border border-border bg-bg-panel px-2.5 py-1 text-[11px] text-text disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </div>

      <SlideOverDrawer
        open={Boolean(selectedEntry)}
        onOpenChange={(open) => {
          if (!open) setSelectedEntry(null);
        }}
        title="Audit Log Event Inspector"
        subtitle={
          selectedEntry ? `${selectedEntry.method} ${selectedEntry.target || selectedEntry.action}` : undefined
        }
      >
        {selectedEntry && (
          <div className="space-y-3 text-xs">
            <div className="grid grid-cols-2 gap-2 rounded-lg border border-border bg-bg-panel p-3">
              <div>
                <div className="text-text-faint">Actor</div>
                <div className="font-semibold text-text">{selectedEntry.actor}</div>
              </div>
              <div>
                <div className="text-text-faint">Source IP</div>
                <div className="font-mono text-text">{selectedEntry.ip_address}</div>
              </div>
              <div>
                <div className="text-text-faint">Timestamp</div>
                <div className="font-mono text-text">{selectedEntry.created_at}</div>
              </div>
              <div>
                <div className="text-text-faint">HTTP Status</div>
                <div className="font-mono text-text">{selectedEntry.status}</div>
              </div>
            </div>
            <div>
              <div className="text-xs font-semibold text-text-dim mb-1">Route & User Agent</div>
              <pre className="rounded-lg border border-border bg-bg-panel p-3 font-mono text-[11px] text-text overflow-x-auto whitespace-pre-wrap">
                {selectedEntry.action}
                {selectedEntry.user_agent ? `\n${selectedEntry.user_agent}` : ''}
              </pre>
            </div>
          </div>
        )}
      </SlideOverDrawer>
    </div>
  );
}

// ============================================================================
// SUB-TAB 6: MY PROFILE, PASSWORD, TOTP 2FA & PASSKEYS
// ============================================================================
function MyProfileSubTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { data: me } = useQuery({
    queryKey: ['me'],
    queryFn: () => apiFetch<MeResponse>('/admin/api/me'),
  });

  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');

  useEffect(() => {
    if (me) {
      setDisplayName(me.full_name ?? '');
      setEmail(me.email ?? '');
    }
  }, [me]);

  const updateProfileMutation = useMutation({
    mutationFn: async () =>
      apiFetch('/admin/api/me', {
        method: 'PUT',
        body: { full_name: displayName, email },
      }),
    onSuccess: () => {
      toast({ title: 'Profile updated', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['me'] });
    },
    onError: (err: Error) => {
      toast({ title: 'Update failed', description: err.message, variant: 'error' });
    },
  });

  const changePasswordMutation = useMutation({
    mutationFn: async () =>
      apiFetch('/admin/api/settings/password', {
        method: 'POST',
        body: {
          current_password: currentPassword,
          new_password: newPassword,
          // The handler treats an ABSENT remove_passkeys as TRUE. A routine
          // password rotation must not silently delete every registered
          // passkey, so be explicit rather than relying on the default.
          remove_passkeys: false,
        },
      }),
    onSuccess: () => {
      toast({
        title: 'Password updated',
        description: 'Your passkeys were kept.',
        variant: 'success',
      });
      setCurrentPassword('');
      setNewPassword('');
    },
    onError: (err: Error) => {
      toast({ title: 'Password change failed', description: err.message, variant: 'error' });
    },
  });

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
      {/* Profile & Password */}
      <div className="space-y-5">
        <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-text">My Operator Profile</h2>
          <p className="text-[11px] text-text-faint">
            Member since {formatDate(me?.created_at)}
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">Username</label>
              <input
                type="text"
                disabled
                value={me?.username ?? 'admin'}
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text-dim"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">Assigned Role</label>
              <input
                type="text"
                disabled
                value={(me?.role ?? 'admin').toUpperCase()}
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-accent"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">Display Name</label>
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-text"
              />
            </div>
          </div>
          <div className="flex justify-end">
            <button
              type="button"
              disabled={updateProfileMutation.isPending}
              onClick={() => updateProfileMutation.mutate()}
              className="rounded-md bg-accent px-4 py-1.5 text-xs font-semibold text-white hover:opacity-90"
            >
              Save Profile
            </button>
          </div>
        </div>

        <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-text">Rotate Password</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">Current Password</label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-text-dim mb-1">New Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-mono text-text"
              />
            </div>
          </div>
          <div className="flex justify-end">
            <button
              type="button"
              disabled={!currentPassword || newPassword.length < 8 || changePasswordMutation.isPending}
              onClick={() => changePasswordMutation.mutate()}
              className="rounded-md bg-accent px-4 py-1.5 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
            >
              Update Password
            </button>
          </div>
        </div>
      </div>

      <div className="space-y-5">
        <TwoFactorCard
          me={me}
          onChanged={() => queryClient.invalidateQueries({ queryKey: ['me'] })}
        />
        <PasskeyCard
          me={me}
          onChanged={() => queryClient.invalidateQueries({ queryKey: ['me'] })}
        />
      </div>
    </div>
  );
}
