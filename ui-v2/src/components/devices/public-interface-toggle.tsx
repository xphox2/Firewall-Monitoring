import { useMemo } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiFetch } from '@/lib/api';
import { cn } from '@/lib/utils';
import { useToast } from '@/components/ui/toast';

/** The whole map: device id → the interface names published for it. */
type PublicInterfaceMap = Record<string, string[]>;

const SETTINGS_KEY = 'display-settings';

export interface PublicInterfaceToggleProps {
  deviceId: number;
  /** The interface this toggle belongs to. */
  interfaceName: string;
  /**
   * Whether the operator may CHANGE the setting.
   *
   * Reading it is operator-level (GET /admin/api/display-settings is not
   * admin-only), but WRITING it is not: the setting is written through
   * POST /admin/api/settings, which is admin-only. A control that is visible
   * and 403s is worse than one that says why.
   */
  canEdit: boolean;
}

function parseMap(raw: string | undefined): PublicInterfaceMap | null {
  if (raw === undefined) return null;
  try {
    const parsed = JSON.parse(raw || '{}');
    if (!parsed || typeof parsed !== 'object') return {};
    const out: PublicInterfaceMap = {};
    for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (Array.isArray(value)) out[key] = value.map(String);
    }
    return out;
  } catch {
    return {};
  }
}

/**
 * The per-interface "Public" checkbox.
 *
 * This is NOT the device's `public_visible` flag. The device flag publishes
 * the whole device to the unauthenticated public dashboard; this one picks
 * WHICH of its interfaces are published, and it is stored as a display
 * SETTING (`public_interfaces`) rather than a column on the device.
 *
 * The setting holds the map for EVERY device, so the write is a
 * read-modify-write of the whole thing. Two things follow:
 *
 * - The toggle stays disabled until the whole map has loaded. Posting a
 *   partially-loaded map would erase every OTHER device's selection.
 * - The map is read from the shared query cache, not from a local copy. There
 *   is one toggle per interface, and each one used to hold its own copy of the
 *   map: toggling interface A and then interface B would have had B write the
 *   map as it was BEFORE A's change, erasing A's selection. The map is now
 *   read from the cache and the cache is updated optimistically, so the second
 *   toggle builds on the first one's result.
 */
export function PublicInterfaceToggle({ deviceId, interfaceName, canEdit }: PublicInterfaceToggleProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: settings } = useQuery({
    queryKey: [SETTINGS_KEY, 'public-interfaces'],
    queryFn: () => apiFetch<{ public_interfaces?: string }>('/admin/api/display-settings'),
    staleTime: 60_000,
  });

  const map = useMemo(() => parseMap(settings?.public_interfaces), [settings?.public_interfaces]);

  const writeMutation = useMutation({
    mutationFn: async (nextMap: PublicInterfaceMap) => {
      await apiFetch('/admin/api/settings', {
        method: 'POST',
        body: [
          {
            key: 'public_interfaces',
            value: JSON.stringify(nextMap),
            category: 'display',
            type: 'string',
          },
        ],
      });
      return nextMap;
    },
    onMutate: async (nextMap) => {
      // Optimistic, and SHARED: the cache is the map's home, so a second
      // toggle builds on this result instead of on the pre-toggle state.
      await queryClient.cancelQueries({ queryKey: [SETTINGS_KEY, 'public-interfaces'] });
      const previous = queryClient.getQueryData<{ public_interfaces?: string }>([
        SETTINGS_KEY,
        'public-interfaces',
      ]);
      queryClient.setQueryData<{ public_interfaces?: string }>(
        [SETTINGS_KEY, 'public-interfaces'],
        { public_interfaces: JSON.stringify(nextMap) },
      );
      return { previous };
    },
    onError: (err, _nextMap, context) => {
      if (context?.previous) {
        queryClient.setQueryData([SETTINGS_KEY, 'public-interfaces'], context.previous);
      }
      toast({
        title: 'Could not change the public interface',
        description: err instanceof Error ? err.message : 'request failed',
        variant: 'error',
      });
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: [SETTINGS_KEY, 'public-interfaces'] });
    },
  });

  const published = (map?.[String(deviceId)] ?? []).includes(interfaceName);

  const toggle = () => {
    if (!map || !canEdit) return;
    const key = String(deviceId);
    const current = map[key] ?? [];
    const next = current.includes(interfaceName)
      ? current.filter((name) => name !== interfaceName)
      : [...current, interfaceName];

    // The WHOLE map goes back, with this device's entry replaced. Writing
    // only this device's entry would drop every other device's selection.
    writeMutation.mutate({ ...map, [key]: next });
  };

  return (
    <button
      type="button"
      onClick={toggle}
      disabled={!map || !canEdit || writeMutation.isPending}
      aria-pressed={published}
      title={
        !canEdit
          ? 'Admin only — publishing an interface to the public dashboard is an admin action'
          : map
            ? published
              ? 'Published on the public dashboard'
              : 'Not published on the public dashboard'
            : 'Loading the public interface map…'
      }
      className={cn(
        'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase transition-colors',
        (!map || !canEdit) && 'cursor-not-allowed opacity-50',
        published
          ? 'bg-sig-warn/15 text-sig-warn'
          : 'bg-bg-panel text-text-faint hover:text-text',
      )}
    >
      {published ? 'Public' : 'Private'}
    </button>
  );
}
