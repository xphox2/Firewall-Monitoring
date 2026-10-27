import { useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Copy, Key, Terminal } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { useToast } from '@/components/ui/toast';
import {
  KEY_UNAVAILABLE_NOTICE,
  buildProbeEnv,
  isRealRegistrationKey,
} from '@/lib/probe-deploy';

export interface ProbeDeployDrawerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  probe: {
    id: number;
    name?: string;
    site_id?: number | null;
    registration_key?: string;
  } | null;
  /** The server URL the collector is pointed at. */
  serverUrl: string;
  /**
   * Whether the operator may issue a new registration key.
   *
   * Issuing one is ADMIN-ONLY on the server, so a control that is visible
   * to an operator is a control that answers 403.
   */
  canIssueKey?: boolean;
}

/**
 * The collector's deploy information.
 *
 * The legacy console had a "Deploy Info" modal that showed the environment
 * block an operator pastes into the collector, and a "Regenerate Key"
 * button for the case where the key was lost.
 *
 * The block is composed on the client — the server has no deploy-env
 * endpoint — and the key is shown ONCE, at creation: every later read
 * returns the redaction mask, so the drawer says so rather than rendering
 * the mask as if it were a copyable key.
 */
export function ProbeDeployDrawer({
  open,
  onOpenChange,
  probe,
  serverUrl,
  canIssueKey = true,
}: ProbeDeployDrawerProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [copied, setCopied] = useState(false);

  const env = useMemo(
    () => (probe ? buildProbeEnv(probe, serverUrl) : ''),
    [probe, serverUrl],
  );

  const hasKey = isRealRegistrationKey(probe?.registration_key);

  const regenerateMutation = useMutation({
    mutationFn: async () =>
      apiFetch<{ registration_key?: string }>(`/admin/api/probes/${probe?.id}/regenerate-key`, {
        method: 'POST',
      }),
    onSuccess: (res) => {
      toast({
        title: 'Registration key issued',
        description: res?.registration_key
          ? 'Copy it now — it is shown once.'
          : 'The key was issued.',
        variant: 'success',
      });
      queryClient.invalidateQueries({ queryKey: ['probes'] });
      onOpenChange(false);
    },
    onError: (err: Error) => {
      toast({
        title: 'Could not issue a registration key',
        description: err.message,
        variant: 'error',
      });
    },
  });

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(env);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      toast({
        title: 'Could not copy',
        description: 'Select the text and copy it manually.',
        variant: 'warning',
      });
    }
  };

  return (
    <SlideOverDrawer
      open={open}
      onOpenChange={onOpenChange}
      title="Deploy Info"
      subtitle="The environment the collector reads."
      size="lg"
    >
      <div className="space-y-4">
        <div>
          <div className="mb-1 text-xs font-semibold text-text">Registration key</div>
          <div className="rounded-md border border-border bg-bg-panel px-3 py-2 font-mono text-xs text-text">
            {hasKey ? probe?.registration_key : KEY_UNAVAILABLE_NOTICE}
          </div>
        </div>

        <div>
          <div className="mb-1 flex items-center justify-between">
            <div className="text-xs font-semibold text-text">Environment</div>
            <button
              type="button"
              onClick={() => void copy()}
              className="inline-flex items-center gap-1 rounded-md border border-border bg-bg-panel px-2.5 py-1 text-[11px] text-text-dim hover:text-text"
            >
              <Copy className="h-3 w-3" />
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <pre className="overflow-x-auto rounded-md border border-border bg-bg-card p-3 font-mono text-[11px] text-text-dim">
            {env}
          </pre>
        </div>

        <div className="flex items-center gap-2 border-t border-border pt-3">
          <button
            type="button"
            disabled={regenerateMutation.isPending || !canIssueKey}
            onClick={() => regenerateMutation.mutate()}
            title={canIssueKey ? undefined : 'Admin role required'}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text hover:bg-bg-hover disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Key className="h-3.5 w-3.5" />
            {regenerateMutation.isPending ? 'Issuing…' : 'Regenerate Key'}
          </button>
          <span className="text-[11px] text-text-faint">
            Issuing a new key invalidates the one the running collector has.
          </span>
        </div>

        <div className="rounded-md border border-border bg-bg-panel p-3">
          <div className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-text">
            <Terminal className="h-3.5 w-3.5 text-accent" />
            On the collector
          </div>
          <pre className="overflow-x-auto font-mono text-[11px] text-text-dim">
{`set -a
. /etc/fwmon/collector.env
set +a
fwmon-collector --once`}
          </pre>
        </div>
      </div>
    </SlideOverDrawer>
  );
}
