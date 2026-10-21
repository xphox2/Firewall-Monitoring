import { useEffect, useMemo, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Search } from 'lucide-react';
import { apiFetch, ApiError } from '@/lib/api';
import { cn } from '@/lib/utils';
import { SlideOverDrawer } from '@/components/ui/slide-over-drawer';
import { useToast } from '@/components/ui/toast';
import {
  buildTogglePayload,
  dirtyToggleCount,
  familyCounts,
  groupTypes,
  matrixFromToggles,
  setFamilyMode,
  type AlertTypeInfo,
  type ToggleMode,
} from '@/lib/event-profiles';

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  profile: { id: number; name: string } | null;
  types: AlertTypeInfo[];
  onSaved: () => void;
}

const MODES: Array<{ mode: ToggleMode; label: string }> = [
  { mode: 'on', label: 'On' },
  { mode: 'inherit', label: 'Inherit' },
  { mode: 'off', label: 'Off' },
];

const MODE_STYLE: Record<ToggleMode, string> = {
  on: 'bg-sig-ok/20 text-sig-ok border-sig-ok/40',
  inherit: 'bg-bg-panel text-text-dim border-border',
  off: 'bg-sig-crit/20 text-sig-crit border-sig-crit/40',
};

export function ProfileMatrixDrawer({ open, onOpenChange, profile, types, onSaved }: Props) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [matrix, setMatrix] = useState<Map<string, ToggleMode>>(new Map());
  const [baseline, setBaseline] = useState<Map<string, ToggleMode>>(new Map());
  const [search, setSearch] = useState('');
  const [saving, setSaving] = useState(false);
  const initKeyRef = useRef<string>('');
  const dataRef = useRef<unknown>(null);
  const dirty = dirtyToggleCount(types, matrix, baseline);

  const { data, isLoading } = useQuery({
    queryKey: ['event-profile', profile?.id],
    queryFn: () =>
      apiFetch<{ toggles?: Array<{ alert_type: string; enabled: boolean }> }>(
        `/admin/api/event-rule-profiles/${profile?.id}`,
      ),
    enabled: open && !!profile?.id,
  });

  useEffect(() => {
    if (!open) {
      initKeyRef.current = '';
      dataRef.current = null;
      setSearch('');
    }
  }, [open]);

  // Re-initialise when the profile/registry changes, and also when a refetch
  // delivers new data while there are no unsaved edits. The old guard keyed
  // only on the profile id, so a stale cached response could be shown after a
  // save and a later save would silently revert it.
  const initKey = `${profile?.id ?? 0}:${types.length}`;
  useEffect(() => {
    if (!open || !data || profile?.id == null || types.length === 0) return;
    const dataChanged = dataRef.current !== data;
    const keyChanged = initKeyRef.current !== initKey;
    // Unsaved edits always win: never re-init while dirty, whichever side
    // changed. (A registry arriving mid-edit keeps the current matrix.)
    if (dirty > 0) return;
    if (!keyChanged && !dataChanged) return;
    const next = matrixFromToggles(types, data.toggles);
    dataRef.current = data;
    initKeyRef.current = initKey;
    setMatrix(next);
    setBaseline(next);
  }, [open, data, types, profile?.id, dirty, initKey]);

  const groups = useMemo(() => groupTypes(types), [types]);
  const familyTypes = useMemo(
    () => new Map(groups.map((group) => [group.family, group.types])),
    [groups],
  );
  const needle = search.trim().toLowerCase();
  const filtered = groups
    .map((group) => ({
      ...group,
      types: group.types.filter(
        (t) =>
          !needle ||
          t.type.toLowerCase().includes(needle) ||
          t.family.toLowerCase().includes(needle) ||
          t.description.toLowerCase().includes(needle),
      ),
    }))
    .filter((group) => group.types.length > 0);

  const knownTypes = useMemo(() => new Set(types.map((t) => t.type)), [types]);
  // Stored rows for types the registry no longer lists are not rendered, but
  // they must survive a full-replace save.
  const unknownToggles = (data?.toggles ?? []).filter((t) => !knownTypes.has(t.alert_type));

  const save = async () => {
    if (!profile) return;
    setSaving(true);
    try {
      // The server rejects unknown types in the body, and preserves their
      // stored rows itself (ReplaceProfileToggles only replaces the togglable
      // registry), so do not append them here.
      const payload = buildTogglePayload(types, matrix);
      await apiFetch(`/admin/api/event-rule-profiles/${profile.id}/toggles`, {
        method: 'PUT',
        body: payload,
      });
      toast({ title: 'Profile toggles saved', variant: 'success' });
      setBaseline(new Map(matrix));
      await queryClient.invalidateQueries({ queryKey: ['event-profile', profile.id] });
      onSaved();
      onOpenChange(false);
    } catch (err) {
      toast({
        title: 'Could not save toggles',
        description: err instanceof ApiError ? err.message : 'Request failed',
        variant: 'error',
      });
    } finally {
      setSaving(false);
    }
  };

  const setMode = (type: string, mode: ToggleMode) =>
    setMatrix((current) => {
      const next = new Map(current);
      next.set(type, mode);
      return next;
    });

  return (
    <SlideOverDrawer
      open={open}
      onOpenChange={onOpenChange}
      title={profile ? `Toggle matrix — ${profile.name}` : 'Toggle matrix'}
      subtitle="Inherit falls through to the next layer; On/Off override it for this profile."
      size="xl"
      footer={
        <div className="flex w-full items-center justify-between gap-2">
          <span className="text-[11px] text-text-dim">
            {dirty === 0 ? 'No changes' : `${dirty} type${dirty === 1 ? '' : 's'} changed`}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              className="rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs font-medium text-text-dim"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={dirty === 0 || saving}
              onClick={save}
              className="rounded-md bg-accent px-3.5 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
            >
              {saving ? 'Saving…' : 'Save matrix'}
            </button>
          </div>
        </div>
      }
    >
      <div className="space-y-4">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-faint" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter alert types…"
            className="w-full rounded border border-border bg-bg-panel py-1.5 pl-8 pr-3 text-xs text-text focus:border-accent focus:outline-none"
          />
        </div>

        {unknownToggles.length > 0 && (
          <div className="rounded-lg border border-sig-warn/40 bg-sig-warn/10 px-3 py-2 text-[11px] text-sig-warn">
            {unknownToggles.length} stored toggle
            {unknownToggles.length === 1 ? ' uses a type' : 's use types'} the registry no longer
            lists. The server preserves them automatically; they cannot be edited here.
          </div>
        )}

        {isLoading || types.length === 0 ? (
          <p className="p-6 text-center text-xs text-text-dim">Loading toggles and alert types…</p>
        ) : filtered.length === 0 ? (
          <p className="p-6 text-center text-xs text-text-faint">No alert types match.</p>
        ) : (
          filtered.map((group) => {
            const fullFamily = familyTypes.get(group.family) ?? group.types;
            const counts = familyCounts(fullFamily, matrix);
            return (
              <section key={group.family} className="rounded-lg border border-border bg-bg-card">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border bg-bg-panel/40 px-3 py-2">
                  <div className="flex items-center gap-2">
                    <h3 className="text-xs font-semibold text-text">{group.family}</h3>
                    <span className="font-mono text-[10px] text-text-faint">
                      {counts.on} on · {counts.off} off · {counts.inherit} inherit
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    {MODES.map(({ mode, label }) => (
                      <button
                        key={mode}
                        type="button"
                        onClick={() =>
                          setMatrix((current) => setFamilyMode(current, fullFamily, mode))
                        }
                        className="rounded border border-border bg-bg-panel px-2 py-0.5 text-[10px] font-medium text-text-dim hover:text-text"
                        title={`Set every type in ${group.family} to ${label}`}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="divide-y divide-border/60">
                  {group.types.map((info) => {
                    const mode = matrix.get(info.type) ?? 'inherit';
                    return (
                      <div
                        key={info.type}
                        className="flex flex-col gap-1.5 px-3 py-2 sm:flex-row sm:items-center sm:justify-between"
                      >
                        <div className="min-w-0">
                          <div className="font-mono text-[11px] text-text">{info.type}</div>
                          <div className="text-[10px] text-text-faint">{info.description}</div>
                        </div>
                        <div
                          role="group"
                          aria-label={`${info.type} state`}
                          className="flex shrink-0 items-center gap-1"
                        >
                          {MODES.map(({ mode: option, label }) => (
                            <button
                              key={option}
                              type="button"
                              aria-pressed={mode === option}
                              onClick={() => setMode(info.type, option)}
                              className={cn(
                                'rounded border px-2 py-0.5 text-[10px] font-semibold uppercase',
                                mode === option
                                  ? MODE_STYLE[option]
                                  : 'border-border bg-bg-panel text-text-faint hover:text-text',
                              )}
                            >
                              {label}
                            </button>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </section>
            );
          })
        )}
      </div>
    </SlideOverDrawer>
  );
}
