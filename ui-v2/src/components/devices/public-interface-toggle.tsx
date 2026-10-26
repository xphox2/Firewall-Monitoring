import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '@/lib/api';
import { cn } from '@/lib/utils';
import { useToast } from '@/components/ui/toast';

/** The whole map: device id → the interface names published for it. */
type PublicInterfaceMap = Record<string, string[]>;

export interface PublicInterfaceToggleProps {
  deviceId: number;
  /** The interface this toggle belongs to. */
  interfaceName: string;
}

/**
 * The per-interface "Public" checkbox.
 *
 * This is NOT the device's `public_visible` flag. The device flag publishes
 * the whole device to the unauthenticated public dashboard; this one picks
 * WHICH of its interfaces are published, and it is stored as a display
 * SETTING (`public_interfaces`) rather than a column on the device.
 *
 * The setting holds the map for EVERY device, so the write is a read-modify-
 * write of the whole thing. That is the trap: posting a map built from a
 * partially-loaded state would silently erase every other device's selection.
 * So the toggle stays disabled until the whole map has loaded, and the map is
 * only ever sent complete.
 */
export function PublicInterfaceToggle({ deviceId, interfaceName }: PublicInterfaceToggleProps) {
  const { toast } = useToast();
  const [map, setMap] = useState<PublicInterfaceMap | null>(null);

  const { data: settings } = useQuery({
    queryKey: ['display-settings', 'public-interfaces'],
    queryFn: () => apiFetch<{ public_interfaces?: string }>('/admin/api/display-settings'),
    staleTime: 60_000,
  });

  // Parse the map only once the setting has arrived. Until then the toggle
  // is disabled, so nothing can be written from a half-loaded map.
  useEffect(() => {
    if (settings?.public_interfaces === undefined) return;
    try {
      const parsed = JSON.parse(settings.public_interfaces || '{}');
      setMap(parsed && typeof parsed === 'object' ? (parsed as PublicInterfaceMap) : {});
    } catch {
      setMap({});
    }
  }, [settings?.public_interfaces]);

  const published = (map?.[String(deviceId)] ?? []).includes(interfaceName);

  const toggle = async () => {
    if (!map) return;
    const key = String(deviceId);
    const current = map[key] ?? [];
    const next = current.includes(interfaceName)
      ? current.filter((name) => name !== interfaceName)
      : [...current, interfaceName];

    // The WHOLE map goes back, with this device's entry replaced. Writing
    // only this device's entry would drop every other device's selection.
    const payload = { ...map, [key]: next };
    const previous = map;
    setMap(payload); // optimistic
    try {
      await apiFetch('/admin/api/settings', {
        method: 'POST',
        body: [
          {
            key: 'public_interfaces',
            value: JSON.stringify(payload),
            category: 'display',
            type: 'string',
          },
        ],
      });
    } catch (err) {
      setMap(previous);
      toast({
        title: 'Could not change the public interface',
        description: err instanceof Error ? err.message : 'request failed',
        variant: 'error',
      });
    }
  };

  return (
    <button
      type="button"
      onClick={toggle}
      disabled={!map}
      aria-pressed={published}
      title={
        map
          ? published
            ? 'Published on the public dashboard'
            : 'Not published on the public dashboard'
          : 'Loading the public interface map…'
      }
      className={cn(
        'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase transition-colors',
        !map && 'cursor-not-allowed opacity-50',
        published
          ? 'bg-sig-warn/15 text-sig-warn'
          : 'bg-bg-card text-text-faint hover:text-text',
      )}
    >
      {published ? 'Public' : 'Private'}
    </button>
  );
}
