import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Pencil, Shield, Trash2 } from 'lucide-react';
import { apiFetch, ApiError, setSuppressAuthRedirect, type MeResponse } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { useToast } from '@/components/ui/toast';
import {
  decodeCreationOptions,
  encodeRegistrationCredential,
  passkeysSupported,
} from '@/lib/webauthn';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

interface PasskeyEntry {
  id: number;
  name: string;
  created_at: string;
  last_used_at?: string | null;
  backup_eligible?: boolean;
  backup_state?: boolean;
}

interface PanelProps {
  me: MeResponse | undefined;
  onChanged: () => void;
}

function errorMessage(err: unknown): string {
  return err instanceof ApiError || err instanceof Error ? err.message : 'Request failed';
}

export function TwoFactorCard({ me, onChanged }: PanelProps) {
  const { toast } = useToast();
  const [setupOpen, setSetupOpen] = useState(false);
  const [password, setPassword] = useState('');
  const [staged, setStaged] = useState<{
    secret: string;
    otpauth_url: string;
    qr_png?: string;
  } | null>(null);
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [disableOpen, setDisableOpen] = useState(false);
  const [disablePassword, setDisablePassword] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [declining, setDeclining] = useState(false);

  useEffect(() => {
    setSuppressAuthRedirect(recoveryCodes !== null);
    return () => setSuppressAuthRedirect(false);
  }, [recoveryCodes]);

  const decline = async () => {
    setDeclining(true);
    try {
      await apiFetch('/admin/api/me/mfa-decline', {
        method: 'POST',
        body: { acknowledge_risk: true },
      });
      toast({
        title: '2FA enrollment declined',
        description: 'You can enable it at any time from this page.',
        variant: 'info',
      });
      onChanged();
    } catch (err) {
      toast({
        title: 'Could not record the decline',
        description: errorMessage(err),
        variant: 'error',
      });
    } finally {
      setDeclining(false);
    }
  };

  const resetWizard = () => {
    setPassword('');
    setCode('');
    setStaged(null);
    setRecoveryCodes(null);
  };

  const startSetup = async () => {
    setBusy(true);
    try {
      const res = await apiFetch<{ secret: string; otpauth_url: string; qr_png?: string }>(
        '/admin/api/2fa/setup',
        { method: 'POST', body: { password } },
      );
      setStaged(res);
      setPassword('');
    } catch (err) {
      toast({ title: 'Could not start 2FA setup', description: errorMessage(err), variant: 'error' });
      if (err instanceof ApiError && err.status === 409) {
        onChanged();
        setSetupOpen(false);
      }
    } finally {
      setBusy(false);
    }
  };

  const verify = async () => {
    setBusy(true);
    try {
      const res = await apiFetch<{ recovery_codes?: string[] }>('/admin/api/2fa/verify', {
        method: 'POST',
        body: { code: code.trim() },
      });
      setRecoveryCodes(res?.recovery_codes ?? []);
      setCode('');
      // Do NOT refresh /me here: verification revokes every session, so an
      // immediate refetch would 401-redirect before the operator can save the
      // one-time recovery codes. Refresh when they dismiss this step.
    } catch (err) {
      toast({ title: 'Verification failed', description: errorMessage(err), variant: 'error' });
    } finally {
      setBusy(false);
    }
  };

  const disable = async () => {
    setBusy(true);
    try {
      await apiFetch('/admin/api/2fa/disable', {
        method: 'POST',
        body: { password: disablePassword, code: disableCode.trim() },
      });
      toast({ title: 'Two-factor authentication disabled', variant: 'info' });
      setDisableOpen(false);
      setDisablePassword('');
      setDisableCode('');
      onChanged();
    } catch (err) {
      toast({ title: 'Could not disable 2FA', description: errorMessage(err), variant: 'error' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-xl border border-border bg-bg-card p-5 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-semibold text-text">
            <Shield className="h-4 w-4 text-accent" />
            Two-Factor Authentication (TOTP)
          </h2>
          <p className="mt-0.5 text-xs text-text-dim">
            A time-based code from an authenticator app, required at every login and for sensitive
            actions.
          </p>
        </div>
        <span
          className={cn(
            'rounded px-2 py-0.5 text-[10px] font-semibold uppercase',
            me?.totp_enabled ? 'bg-sig-ok/15 text-sig-ok-text' : 'bg-bg-panel text-text-dim',
          )}
        >
          {me?.totp_enabled ? 'Enabled' : 'Off'}
        </span>
      </div>

      {me && !me.totp_enabled && me.mfa_prompt_dismissed === false && (
        <div className="space-y-1.5 rounded-lg border border-sig-warn/40 bg-sig-warn/10 px-3 py-2 text-[11px] text-sig-warn-text">
          <p>
            No authenticator is enrolled. Declining means a stolen password alone can sign in; you
            can still enable 2FA here at any time.
          </p>
          <button
            type="button"
            disabled={declining}
            onClick={decline}
            className="rounded border border-sig-warn/50 bg-bg-panel px-2.5 py-1 text-[10px] font-semibold uppercase text-sig-warn-text disabled:opacity-50"
          >
            {declining ? 'Recording…' : 'Don\'t ask again'}
          </button>
        </div>
      )}

      {me?.totp_enabled ? (
        <button
          type="button"
          onClick={() => setDisableOpen(true)}
          className="rounded-md border border-sig-crit/40 bg-sig-crit/10 px-3 py-1.5 text-xs font-semibold text-sig-crit-text"
        >
          Disable 2FA
        </button>
      ) : (
        <button
          type="button"
          onClick={() => {
            resetWizard();
            setSetupOpen(true);
          }}
          className="rounded-md bg-accent px-3.5 py-1.5 text-xs font-semibold text-on-accent hover:opacity-90"
        >
          Set up authenticator
        </button>
      )}

      <SlideOverDrawer
        open={setupOpen}
        onOpenChange={(open) => {
          setSetupOpen(open);
          if (!open) resetWizard();
        }}
        title="Set up two-factor authentication"
        subtitle="Scan the code with your authenticator, then confirm one code."
        size="md"
      >
        {!staged ? (
          <div className="space-y-3">
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">Current password</span>
              <Input mono
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
               
              />
            </label>
            <Button
              type="button"
              disabled={!password || busy}
              onClick={startSetup}
              
            >
              {busy ? 'Starting…' : 'Continue'}
            </Button>
          </div>
        ) : recoveryCodes ? (
          <div className="space-y-3">
            <div className="rounded-lg border border-sig-warn/40 bg-sig-warn/10 p-3 text-xs text-sig-warn-text">
              2FA is now enabled. Save these recovery codes — they are shown once and each works
              once if you lose your authenticator.
            </div>
            <pre className="rounded-lg border border-border bg-bg-panel p-3 font-mono text-xs text-text">
              {recoveryCodes.join('\n')}
            </pre>
            <button
              type="button"
              onClick={() => {
                void navigator.clipboard
                  ?.writeText(recoveryCodes.join('\n'))
                  .then(() => toast({ title: 'Recovery codes copied', variant: 'success' }))
                  .catch(() =>
                    toast({
                      title: 'Copy failed',
                      description: 'Select the codes and copy them manually.',
                      variant: 'error',
                    }),
                  );
              }}
              className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text"
            >
              Copy codes
            </button>
            <div className="rounded-lg border border-border bg-bg-panel p-3 text-[11px] text-text-dim">
              Every session was revoked. You will be asked to sign in again with your password and
              a code.
            </div>
            <Button
              type="button"
              onClick={() => {
                setSetupOpen(false);
                resetWizard();
                onChanged();
              }}
              
            >
              I have saved the codes
            </Button>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex flex-col items-center gap-2 rounded-lg border border-border bg-bg-panel p-4">
              {staged.qr_png ? (
                <img
                  src={`data:image/png;base64,${staged.qr_png}`}
                  alt="TOTP enrollment QR code"
                  className="h-[220px] w-[220px] rounded bg-white p-1"
                />
              ) : (
                <p className="text-xs text-text-dim">QR unavailable — enter the secret manually.</p>
              )}
              <code className="break-all font-mono text-[11px] text-text">{staged.secret}</code>
              <a
                href={staged.otpauth_url}
                className="break-all text-[10px] text-accent hover:underline"
              >
                {staged.otpauth_url}
              </a>
            </div>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">
                Code from the authenticator
              </span>
              <input
                type="text"
                inputMode="numeric"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="123456"
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 font-mono text-sm tracking-widest text-text"
              />
            </label>
            <Button
              type="button"
              disabled={code.trim().length < 6 || busy}
              onClick={verify}
              
            >
              {busy ? 'Verifying…' : 'Verify and enable'}
            </Button>
          </div>
        )}
      </SlideOverDrawer>

      <SlideOverDrawer
        open={disableOpen}
        onOpenChange={(open) => {
          setDisableOpen(open);
          if (!open) {
            setDisablePassword('');
            setDisableCode('');
          }
        }}
        title="Disable two-factor authentication"
        subtitle="Both your password and a current code are required."
        size="md"
      >
        <div className="space-y-3">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">Password</span>
            <Input mono
              type="password"
              value={disablePassword}
              onChange={(e) => setDisablePassword(e.target.value)}
              autoComplete="current-password"
             
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">Current code</span>
            <input
              type="text"
              inputMode="numeric"
              value={disableCode}
              onChange={(e) => setDisableCode(e.target.value)}
              placeholder="123456"
              className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 font-mono text-sm tracking-widest text-text"
            />
          </label>
          <button
            type="button"
            disabled={!disablePassword || disableCode.trim().length < 6 || busy}
            onClick={disable}
            className="rounded-md bg-sig-crit px-3.5 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
          >
            {busy ? 'Disabling…' : 'Disable 2FA'}
          </button>
        </div>
      </SlideOverDrawer>
    </div>
  );
}

export function PasskeyCard({ me, onChanged }: PanelProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const supported = passkeysSupported();

  const { data } = useQuery({
    queryKey: ['my-passkeys'],
    queryFn: () => apiFetch<{ passkeys?: PasskeyEntry[]; max?: number }>('/admin/api/passkeys'),
  });
  const passkeys = data?.passkeys ?? [];

  const [registerOpen, setRegisterOpen] = useState(false);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [removeTarget, setRemoveTarget] = useState<PasskeyEntry | null>(null);
  const [removePassword, setRemovePassword] = useState('');
  const [removeCode, setRemoveCode] = useState('');
  const [renameTarget, setRenameTarget] = useState<PasskeyEntry | null>(null);
  const [renameName, setRenameName] = useState('');
  const [renaming, setRenaming] = useState(false);

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['my-passkeys'] });
    onChanged();
  };

  const register = async () => {
    setBusy(true);
    try {
      const begin = await apiFetch<Record<string, any>>('/admin/api/passkeys/register/begin', {
        method: 'POST',
        body: { name: name.trim(), password, totp_code: totpCode.trim() },
      });
      const publicKey = decodeCreationOptions(begin);
      const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
      if (!credential) throw new Error('The authenticator returned no credential');
      await apiFetch('/admin/api/passkeys/register/finish', {
        method: 'POST',
        body: encodeRegistrationCredential(credential),
      });
      toast({ title: 'Passkey registered', variant: 'success' });
      setRegisterOpen(false);
      setName('');
      setPassword('');
      setTotpCode('');
      refresh();
    } catch (err) {
      toast({ title: 'Passkey registration failed', description: errorMessage(err), variant: 'error' });
    } finally {
      setBusy(false);
    }
  };

  const rename = async () => {
    if (!renameTarget || !renameName.trim()) return;
    setRenaming(true);
    try {
      await apiFetch(`/admin/api/passkeys/${renameTarget.id}`, {
        method: 'PUT',
        body: { name: renameName.trim() },
      });
      toast({ title: 'Passkey renamed', variant: 'success' });
      setRenameTarget(null);
      setRenameName('');
      refresh();
    } catch (err) {
      toast({ title: 'Could not rename passkey', description: errorMessage(err), variant: 'error' });
    } finally {
      setRenaming(false);
    }
  };

  const remove = async () => {
    if (!removeTarget) return;
    setBusy(true);
    try {
      await apiFetch(`/admin/api/passkeys/${removeTarget.id}`, {
        method: 'DELETE',
        body: { password: removePassword, totp_code: removeCode.trim() },
      });
      toast({ title: 'Passkey removed', variant: 'info' });
      setRemoveTarget(null);
      setRemovePassword('');
      setRemoveCode('');
      refresh();
    } catch (err) {
      toast({ title: 'Could not remove passkey', description: errorMessage(err), variant: 'error' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-xl border border-border bg-bg-card p-5 space-y-3">
      <div className="flex items-start justify-between gap-3 border-b border-border pb-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-semibold text-text">
            <KeyRound className="h-4 w-4 text-accent" />
            WebAuthn Passkeys ({passkeys.length})
          </h2>
          <p className="mt-0.5 text-xs text-text-dim">
            Phishing-resistant sign-in with Touch ID, Windows Hello or a hardware key.
          </p>
        </div>
        <button
          type="button"
          disabled={!supported}
          title={supported ? undefined : 'This browser does not support WebAuthn'}
          onClick={() => setRegisterOpen(true)}
          className="rounded-md bg-accent px-3.5 py-1.5 text-xs font-semibold text-on-accent disabled:opacity-40"
        >
          Register passkey
        </button>
      </div>

      {!supported && (
        <div className="rounded-lg border border-sig-warn/40 bg-sig-warn/10 px-3 py-2 text-[11px] text-sig-warn-text">
          This browser does not expose the WebAuthn API (it requires a secure context). Passkeys
          cannot be registered here.
        </div>
      )}

      {passkeys.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-panel p-4 text-xs text-text-dim">
          No passkeys registered for your account yet.
        </div>
      ) : (
        <div className="space-y-2">
          {passkeys.map((pk) => (
            <div
              key={pk.id}
              className="flex items-center justify-between rounded-lg border border-border bg-bg-panel px-3 py-2 text-xs"
            >
              <div>
                <div className="flex items-center gap-2 font-semibold text-text">
                  {pk.name}
                  {pk.backup_state && (
                    <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-accent-text">
                      synced
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-text-dim">
                  Created {formatRelativeTime(pk.created_at)}
                  {pk.last_used_at ? ` · last used ${formatRelativeTime(pk.last_used_at)}` : ''}
                </div>
              </div>
              <div className="flex items-center gap-1">
                <Button  variant="icon"
                  type="button"
                  onClick={() => {
                    setRenameTarget(pk);
                    setRenameName(pk.name);
                  }}
                  aria-label={`Rename ${pk.name}`}
                  
                >
                  <Pencil className="h-3.5 w-3.5" />
                </Button>
                <Button  variant="danger-icon"
                  type="button"
                  onClick={() => setRemoveTarget(pk)}
                  aria-label={`Remove ${pk.name}`}
                  
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      <SlideOverDrawer
        open={registerOpen}
        onOpenChange={(open) => {
          setRegisterOpen(open);
          if (!open) {
            setPassword('');
            setTotpCode('');
          }
        }}
        title="Register a passkey"
        subtitle="Confirm your password (and a 2FA code if enrolled), then follow the authenticator prompt."
        size="md"
      >
        <div className="space-y-3">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">Passkey name</span>
            <Input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="MacBook Touch ID"
              maxLength={64}
             
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">Password</span>
            <Input mono
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
             
            />
          </label>
          {me?.totp_enabled && (
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">
                Authenticator code
              </span>
              <input
                type="text"
                inputMode="numeric"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                placeholder="123456"
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 font-mono text-sm tracking-widest text-text"
              />
            </label>
          )}
          <Button
            type="button"
            disabled={!password || busy || (me?.totp_enabled && totpCode.trim().length < 6)}
            onClick={register}
            
          >
            {busy ? 'Waiting for authenticator…' : 'Register passkey'}
          </Button>
        </div>
      </SlideOverDrawer>

      <SlideOverDrawer
        open={!!renameTarget}
        onOpenChange={(open) => {
          if (!open) {
            setRenameTarget(null);
            setRenameName('');
          }
        }}
        title={`Rename passkey ${renameTarget?.name ?? ''}`}
        subtitle="The name is only a label; no re-authentication is required."
        size="md"
      >
        <div className="space-y-3">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">Passkey name</span>
            <Input
              type="text"
              value={renameName}
              onChange={(e) => setRenameName(e.target.value)}
              maxLength={64}
             
            />
          </label>
          <Button
            type="button"
            disabled={!renameName.trim() || renaming}
            onClick={rename}
            
          >
            {renaming ? 'Saving…' : 'Save name'}
          </Button>
        </div>
      </SlideOverDrawer>

      <SlideOverDrawer
        open={!!removeTarget}
        onOpenChange={(open) => {
          if (!open) {
            setRemoveTarget(null);
            setRemovePassword('');
            setRemoveCode('');
          }
        }}
        title={`Remove passkey ${removeTarget?.name ?? ''}`}
        subtitle="Confirm with your password (and a 2FA code if enrolled). Removing a passkey signs out your other sessions."
        size="md"
      >
        <div className="space-y-3">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-text-dim">Password</span>
            <Input mono
              type="password"
              value={removePassword}
              onChange={(e) => setRemovePassword(e.target.value)}
              autoComplete="current-password"
             
            />
          </label>
          {me?.totp_enabled && (
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text-dim">
                Authenticator code
              </span>
              <input
                type="text"
                inputMode="numeric"
                value={removeCode}
                onChange={(e) => setRemoveCode(e.target.value)}
                placeholder="123456"
                className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 font-mono text-sm tracking-widest text-text"
              />
            </label>
          )}
          <button
            type="button"
            disabled={!removePassword || busy || (me?.totp_enabled && removeCode.trim().length < 6)}
            onClick={remove}
            className="rounded-md bg-sig-crit px-3.5 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
          >
            {busy ? 'Removing…' : 'Remove passkey'}
          </button>
        </div>
      </SlideOverDrawer>
    </div>
  );
}
