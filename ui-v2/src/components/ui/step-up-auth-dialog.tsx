import React, { useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { ShieldAlert, Lock, KeyRound, Loader2, X } from 'lucide-react';
import { apiFetch, ApiError } from '@/lib/api';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

export interface StepUpCredentials {
  password: string;
  totp_code?: string;
}

export interface StepUpAuthDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel?: string;
  danger?: boolean;
  totpEnabled?: boolean;
  /**
   * Rendered above the credentials.
   *
   * A step-up is sometimes only half the confirmation: the permanent device
   * purge also needs the operator to type the device's name, and the server
   * compares it exactly. The extra control lives here so the whole
   * confirmation is read together rather than split across two dialogs.
   */
  children?: React.ReactNode;
  /**
   * Disables the confirm button. Used when the extra confirmation in
   * `children` has not been satisfied yet (the device name has to be typed
   * exactly before a permanent purge can proceed).
   */
  confirmDisabled?: boolean;
  onConfirm: (creds: StepUpCredentials) => Promise<void>;
}

export function StepUpAuthDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = 'Verify & Continue',
  danger = false,
  totpEnabled = false,
  children,
  confirmDisabled = false,
  onConfirm,
}: StepUpAuthDialogProps) {
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password) {
      setError('Current password is required.');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await onConfirm({
        password,
        totp_code: totpCode.trim() || undefined,
      });
      setPassword('');
      setTotpCode('');
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Verification failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog.Root
      open={open}
      onOpenChange={(next) => {
        if (!submitting) {
          setPassword('');
          setTotpCode('');
          setError(null);
          onOpenChange(next);
        }
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/70 backdrop-blur-[1px]" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-[calc(100vw-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-bg-card p-5 shadow-2xl focus:outline-hidden">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <div className="rounded-md bg-accent/15 p-2 text-accent-text">
                <ShieldAlert className="h-4 w-4" />
              </div>
              <div>
                <Dialog.Title className="font-display text-sm font-bold text-text">
                  {title}
                </Dialog.Title>
                <Dialog.Description className="text-xs text-text-faint mt-0.5">
                  {description}
                </Dialog.Description>
              </div>
            </div>
            <Dialog.Close
              aria-label="Close dialog"
              className="rounded p-1 text-text-faint hover:bg-bg-panel hover:text-text"
            >
              <X className="h-4 w-4" />
            </Dialog.Close>
          </div>

          <form onSubmit={handleSubmit} className="mt-4 space-y-3.5">
            {children}

            <div>
              <label
                htmlFor="stepup-password"
                className="block text-xs font-medium text-text-dim mb-1"
              >
                Confirm Your Admin Password
              </label>
              <div className="relative">
                <Lock className="h-3.5 w-3.5 text-text-faint absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  id="stepup-password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="w-full rounded-md border border-border bg-bg-panel pl-8 pr-3 py-2 text-xs text-text focus:border-accent focus:outline-hidden"
                  required
                />
              </div>
            </div>

            {totpEnabled && (
              <div>
                <label
                  htmlFor="stepup-totp"
                  className="block text-xs font-medium text-text-dim mb-1"
                >
                  2FA / TOTP Code (or Recovery Code)
                </label>
                <div className="relative">
                  <KeyRound className="h-3.5 w-3.5 text-text-faint absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    id="stepup-totp"
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value)}
                    placeholder="6-digit code"
                    className="w-full rounded-md border border-border bg-bg-panel pl-8 pr-3 py-2 font-mono text-xs text-text focus:border-accent focus:outline-hidden"
                  />
                </div>
              </div>
            )}

            {error && (
              <div
                role="alert"
                className="rounded-md border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit-text"
              >
                {error}
              </div>
            )}

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-border">
              <Button  variant="secondary"
                type="button"
                onClick={() => onOpenChange(false)}
                disabled={submitting}
                
              >
                Cancel
              </Button>
              <button
                type="submit"
                disabled={submitting || confirmDisabled}
                className={`inline-flex items-center gap-1.5 rounded-md px-3.5 py-1.5 text-xs font-semibold text-on-accent ${
                  danger
                    ? 'bg-sig-crit hover:opacity-90'
                    : 'bg-accent hover:bg-accent-hover'
                } disabled:opacity-50`}
              >
                {submitting && <Loader2 className="h-3.5 w-3.5 animate-spin motion-reduce:animate-none" />}
                {confirmLabel}
              </button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function ForcedPasswordChangeModal({
  open,
  onSuccess,
}: {
  open: boolean;
  onSuccess: () => void;
}) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [removePasskeys, setRemovePasskeys] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword.length < 12) {
      setError('New password must be at least 12 characters.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('New passwords do not match.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await apiFetch('/admin/api/settings/password', {
        method: 'POST',
        body: {
          current_password: currentPassword,
          new_password: newPassword,
          remove_passkeys: removePasskeys,
        },
      });
      onSuccess();
      window.location.href = '/admin/login';
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to update password.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog.Root open={open}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/80 backdrop-blur-xs" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-[calc(100vw-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg border border-sig-warn/50 bg-bg-card p-6 shadow-2xl focus:outline-hidden">
          <Dialog.Title className="font-display text-base font-bold text-text">
            Password Rotation Required
          </Dialog.Title>
          <Dialog.Description className="mt-1 text-xs text-text-faint">
            Your account is using a bootstrap or temporary password. Please set a new password (minimum 12 characters) to continue.
          </Dialog.Description>

          <form onSubmit={handleSubmit} className="mt-4 space-y-3">
            <div>
              <label htmlFor="fp-current" className="block text-xs font-medium text-text-dim mb-1">
                Current Password
              </label>
              <Input
                id="fp-current"
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
               
                required
              />
            </div>
            <div>
              <label htmlFor="fp-new" className="block text-xs font-medium text-text-dim mb-1">
                New Password (min 12 chars)
              </label>
              <Input
                id="fp-new"
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
               
                required
              />
            </div>
            <div>
              <label htmlFor="fp-confirm" className="block text-xs font-medium text-text-dim mb-1">
                Confirm New Password
              </label>
              <Input
                id="fp-confirm"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
               
                required
              />
            </div>
            <label className="flex items-center gap-2 text-xs text-text-dim pt-1">
              <input
                type="checkbox"
                checked={removePasskeys}
                onChange={(e) => setRemovePasskeys(e.target.checked)}
                className="rounded border-border bg-bg-panel"
              />
              Also remove any registered WebAuthn passkeys on this account
            </label>

            {error && (
              <div className="rounded-md border border-sig-crit/40 bg-sig-crit/10 px-3 py-2 text-xs text-sig-crit-text">
                {error}
              </div>
            )}

            <div className="pt-2">
              <button
                type="submit"
                disabled={saving}
                className="w-full inline-flex items-center justify-center gap-1.5 rounded-md bg-accent px-4 py-2 text-xs font-semibold text-on-accent hover:bg-accent-hover disabled:opacity-50"
              >
                {saving && <Loader2 className="h-3.5 w-3.5 animate-spin motion-reduce:animate-none" />}
                Update Password & Sign In Again
              </button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
