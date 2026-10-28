import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { TriangleAlert, Loader2 } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { cn } from '@/lib/utils';
import { StepUpAuthDialog } from '@/components/ui/step-up-auth-dialog';
import { useToast } from '@/components/ui/toast';

export interface PurgeEstimateTable {
  table: string;
  rows: number;
  /** True when the count hit the cap, so the table holds MORE than `rows`. */
  capped?: boolean;
  /** Set when this table's count failed. The estimate is then incomplete. */
  error?: string;
}

export interface PurgeEstimate {
  tables?: PurgeEstimateTable[];
  total?: number;
  /**
   * True when a table's count hit the cap, so `total` is a LOWER BOUND.
   * The real number of rows may be much larger.
   */
  capped?: boolean;
  /**
   * The conditions that would make the purge answer 409 — an IPSec tunnel
   * that is deploying or rolling back, or a job already queued. The estimate
   * is what the operator reads BEFORE they commit, so the blockers belong
   * here rather than in the failure.
   */
  blockers?: string[];
  tunnels?: Array<{ id: number; name: string; peer_device: string }>;
}

export interface PurgeJob {
  id: number;
  device_id: number;
  device_name: string;
  requested_by: string;
  status: string;
  current_table?: string;
  rows_deleted: number;
  tables_done: number;
  tables_total: number;
  error?: string;
  started_at?: string | null;
  finished_at?: string | null;
}

export interface PurgeDeviceDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  deviceId: number;
  /** The device's name — the operator has to type it exactly. */
  deviceName: string;
  /** True when the operator's account has 2FA, so the TOTP code is required. */
  totpEnabled?: boolean;
  onPurged?: () => void;
}

/**
 * The permanent-purge confirmation.
 *
 * A purge is IRREVERSIBLE, so the server demands three things and this
 * dialog collects all three:
 *
 * - `confirm_name`: the operator types the device's name, so a purge cannot
 *   be triggered by a stray click;
 * - `password`: the operator re-authenticates;
 * - `totp_code`: when the account has 2FA.
 *
 * The console's previous purge dialog sent only the password and the TOTP
 * code, so the server rejected every purge with a 400 on `confirm_name` —
 * the feature was present and unusable.
 *
 * The estimate is advisory: it says what will be deleted BEFORE the operator
 * commits to it, and it is shown next to the confirmation rather than on a
 * separate screen, so the number and the action are read together.
 */
export function PurgeDeviceDialog({
  open,
  onOpenChange,
  deviceId,
  deviceName,
  totpEnabled = false,
  onPurged,
}: PurgeDeviceDialogProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [confirmName, setConfirmName] = useState('');
  // True while the purge POST is in flight: the name is locked so a
  // half-typed value cannot be sent.
  const [starting, setStarting] = useState(false);

  const { data: estimate, isLoading: estimateLoading } = useQuery({
    queryKey: ['device-purge-estimate', deviceId],
    queryFn: () => apiFetch<PurgeEstimate>(`/admin/api/devices/${deviceId}/purge/estimate`),
    enabled: open,
    retry: false,
  });

  const nameMatches = confirmName.trim() === deviceName;
  const tables = (estimate?.tables ?? []).filter((t) => t.rows > 0 || t.error);
  const incomplete = (estimate?.tables ?? []).some((t) => Boolean(t.error));

  const reset = () => {
    setConfirmName('');
    setStarting(false);
  };

  return (
    <StepUpAuthDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset();
        onOpenChange(next);
      }}
      danger
      title="Permanently Purge Retired Device"
      description="This irreversibly deletes this device and all of its historical telemetry. It cannot be undone."
      confirmLabel="Permanently Purge"
      totpEnabled={totpEnabled}
      // The name has to match before the purge can be armed, and a purge
      // the server would refuse right now is not armed either.
      confirmDisabled={!nameMatches || (estimate?.blockers ?? []).length > 0}
      onConfirm={async ({ password, totp_code }) => {
        setStarting(true);
        try {
          await apiFetch<PurgeJob>(`/admin/api/devices/${deviceId}/purge`, {
            method: 'POST',
            body: {
              // All three. The name is what stops a stray click; the server
              // compares it to the device's name exactly.
              confirm_name: confirmName.trim(),
              password,
              totp_code,
            },
          });
          toast({ title: 'Device purge job started', variant: 'info' });
          queryClient.invalidateQueries({ queryKey: ['device-detail', deviceId] });
          queryClient.invalidateQueries({ queryKey: ['purge-jobs'] });
          onOpenChange(false);
          reset();
          onPurged?.();
        } catch (err) {
          // The dialog shows the error; the job is NOT started.
          throw err;
        } finally {
          setStarting(false);
        }
      }}
    >
      {/* What will be deleted, shown with the confirmation rather than on a
          separate screen. */}
      <div className="space-y-3">
        <div className="rounded-lg border border-sig-crit/40 bg-sig-crit/10 px-3 py-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-sig-crit-text">
            <TriangleAlert className="h-4 w-4 shrink-0" />
            This cannot be undone. There is no restore.
          </div>
        </div>

        {estimateLoading ? (
          <div className="flex items-center gap-2 text-xs text-text-dim">
            <Loader2 className="h-3.5 w-3.5 animate-spin motion-reduce:animate-none" />
            Counting what will be deleted…
          </div>
        ) : estimate ? (
          <div className="space-y-2 text-xs">
            <div className="text-text-dim">
              <span className="font-mono font-semibold text-text">
                {(estimate.total ?? 0).toLocaleString()}
                {estimate.capped ? '+' : ''}
              </span>{' '}
              row(s) across {tables.length} table(s) will be deleted.
            </div>
            {estimate.capped ? (
              <p className="text-sig-warn-text">
                At least one table holds more than the estimate shows, so the
                total is a LOWER BOUND. The purge removes every matching row
                either way.
              </p>
            ) : null}
            {(estimate.blockers ?? []).length > 0 ? (
              <div
                role="alert"
                className="rounded border border-sig-crit/40 bg-sig-crit/10 px-2.5 py-1.5 text-sig-crit-text"
              >
                <div className="font-semibold">The purge would be refused right now</div>
                <ul className="mt-1 list-disc pl-4">
                  {estimate.blockers!.map((b, i) => (
                    <li key={i}>{b}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {incomplete ? (
              <p className="text-sig-warn-text">
                The estimate is INCOMPLETE — at least one table could not be
                counted. The purge itself is not affected.
              </p>
            ) : null}
            {tables.length > 0 ? (
              <details className="rounded border border-border bg-bg-panel px-2.5 py-1.5">
                <summary className="cursor-pointer text-text-dim">
                  Show the per-table breakdown
                </summary>
                <ul className="mt-1.5 max-h-40 space-y-0.5 overflow-y-auto font-mono text-[10px] text-text-faint">
                  {tables.map((t) => (
                    <li key={t.table} className="flex justify-between gap-2">
                      <span className="truncate">{t.table}</span>
                      <span className={cn(t.error ? 'text-sig-warn-text' : 'text-text-dim')}>
                        {t.error ? 'not counted' : `${t.rows.toLocaleString()}${t.capped ? '+' : ''}`}
                      </span>
                    </li>
                  ))}
                </ul>
              </details>
            ) : null}
            {(estimate.tunnels ?? []).length > 0 ? (
              <div className="rounded border border-sig-warn/40 bg-sig-warn/10 px-2.5 py-1.5">
                <div className="font-medium text-sig-warn-text">
                  {estimate.tunnels!.length} IPSec tunnel intent(s) will be removed
                  too:
                </div>
                <ul className="mt-1 space-y-0.5 font-mono text-[10px] text-text-dim">
                  {estimate.tunnels!.map((t) => (
                    <li key={t.id}>
                      {t.name}
                      {t.peer_device ? ` (shared with ${t.peer_device})` : ''}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        ) : (
          <p className="text-xs text-text-dim">
            The estimate could not be read. The purge can still proceed.
          </p>
        )}

        <label className="block">
          <span className="mb-1 block text-xs font-medium text-text-dim">
            Type the device name to confirm
          </span>
          <input
            type="text"
            value={confirmName}
            disabled={starting}
            onChange={(e) => setConfirmName(e.target.value)}
            placeholder={deviceName}
            autoComplete="off"
            className="w-full rounded-md border border-border bg-bg-panel px-3 py-2 font-mono text-xs text-text disabled:opacity-60"
          />
          <span className="mt-1 block text-[10px] text-text-faint">
            The server compares this to the device name exactly.
          </span>
        </label>
      </div>
    </StepUpAuthDialog>
  );
}
