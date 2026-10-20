import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router';
import { Command } from 'cmdk';
import * as Dialog from '@radix-ui/react-dialog';
import { Search, Server, ArrowRight, Sun, Moon, ExternalLink } from 'lucide-react';
import { WORKSPACES } from './navigation';
import { useTheme } from '@/lib/theme';

export interface QuickDeviceItem {
  id: number;
  name: string;
  status: string;
}

export function CommandPalette({
  open,
  onOpenChange,
  devices = [],
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  devices?: QuickDeviceItem[];
}) {
  const navigate = useNavigate();
  const { theme, toggleTheme } = useTheme();
  const [search, setSearch] = useState('');

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        onOpenChange(!open);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, onOpenChange]);

  const runAction = (fn: () => void) => {
    onOpenChange(false);
    setSearch('');
    fn();
  };

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/65 backdrop-blur-[1px]" />
        <Dialog.Content className="fixed left-1/2 top-[15%] z-50 w-[calc(100vw-2rem)] max-w-xl -translate-x-1/2 rounded-xl border border-border-strong bg-bg-card shadow-2xl overflow-hidden focus:outline-none">
          <Dialog.Title className="sr-only">Command Palette</Dialog.Title>
          <Dialog.Description className="sr-only">
            Jump to any workspace, setting, or firewall device
          </Dialog.Description>
          <Command className="w-full bg-transparent text-text">
            <div className="flex items-center border-b border-border px-3.5 py-2.5 gap-2.5">
              <Search className="h-4 w-4 text-text-faint shrink-0" />
              <Command.Input
                value={search}
                onValueChange={setSearch}
                placeholder="Jump to workspace, setting, retention knob, or firewall..."
                className="w-full bg-transparent text-xs sm:text-sm text-text placeholder:text-text-faint focus:outline-none"
              />
              <kbd className="rounded bg-bg-panel px-1.5 py-0.5 font-mono text-[10px] text-text-faint border border-border">
                ESC
              </kbd>
            </div>

            <Command.List className="max-h-80 overflow-y-auto p-2 space-y-2">
              <Command.Empty className="py-6 text-center text-xs text-text-faint">
                No matching destinations or devices found.
              </Command.Empty>

              {WORKSPACES.map((ws) => (
                <Command.Group
                  key={ws.id}
                  heading={ws.title}
                  className="text-[10px] font-semibold uppercase tracking-wider text-text-mute px-2 py-1"
                >
                  {ws.items.map((item) => {
                    const Icon = item.icon;
                    return (
                      <Command.Item
                        key={item.id}
                        value={`${ws.title} ${item.label} ${item.description} ${item.keywords.join(' ')}`}
                        onSelect={() => runAction(() => navigate(item.path))}
                        className="flex items-center justify-between gap-3 rounded-md px-2.5 py-2 text-xs text-text cursor-pointer data-[selected=true]:bg-accent/15 data-[selected=true]:text-accent"
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <Icon className="h-4 w-4 shrink-0 text-text-faint" />
                          <div className="min-w-0">
                            <div className="font-medium truncate">{item.label}</div>
                            <div className="text-[11px] text-text-faint truncate">
                              {item.description}
                            </div>
                          </div>
                        </div>
                        <ArrowRight className="h-3.5 w-3.5 shrink-0 opacity-60" />
                      </Command.Item>
                    );
                  })}
                </Command.Group>
              ))}

              {devices.length > 0 && (
                <Command.Group
                  heading="Firewalls & Devices"
                  className="text-[10px] font-semibold uppercase tracking-wider text-text-mute px-2 py-1"
                >
                  {devices.slice(0, 15).map((dev) => (
                    <Command.Item
                      key={dev.id}
                      value={`device firewall ${dev.name} ${dev.status}`}
                      onSelect={() => runAction(() => navigate(`/devices/${dev.id}`))}
                      className="flex items-center justify-between gap-3 rounded-md px-2.5 py-2 text-xs text-text cursor-pointer data-[selected=true]:bg-accent/15 data-[selected=true]:text-accent"
                    >
                      <div className="flex items-center gap-2.5">
                        <Server className="h-3.5 w-3.5 text-text-faint" />
                        <span className="font-medium">{dev.name}</span>
                      </div>
                      <span
                        className={`font-mono text-[10px] uppercase px-1.5 py-0.5 rounded ${
                          dev.status === 'online'
                            ? 'bg-sig-ok/15 text-sig-ok'
                            : 'bg-sig-crit/15 text-sig-crit'
                        }`}
                      >
                        {dev.status}
                      </span>
                    </Command.Item>
                  ))}
                </Command.Group>
              )}

              <Command.Group
                heading="Quick Actions"
                className="text-[10px] font-semibold uppercase tracking-wider text-text-mute px-2 py-1"
              >
                <Command.Item
                  value="toggle day night theme dark light mode"
                  onSelect={() => runAction(toggleTheme)}
                  className="flex items-center justify-between gap-3 rounded-md px-2.5 py-2 text-xs text-text cursor-pointer data-[selected=true]:bg-accent/15 data-[selected=true]:text-accent"
                >
                  <div className="flex items-center gap-2.5">
                    {theme === 'dark' ? (
                      <Sun className="h-3.5 w-3.5 text-sig-warn" />
                    ) : (
                      <Moon className="h-3.5 w-3.5 text-accent" />
                    )}
                    <span>Switch to {theme === 'dark' ? 'Day (Light)' : 'Night (Dark)'} Theme</span>
                  </div>
                </Command.Item>
                <Command.Item
                  value="switch to classic v1 admin interface"
                  onSelect={() =>
                    runAction(() => {
                      window.location.href = '/admin/dashboard';
                    })
                  }
                  className="flex items-center justify-between gap-3 rounded-md px-2.5 py-2 text-xs text-text cursor-pointer data-[selected=true]:bg-accent/15 data-[selected=true]:text-accent"
                >
                  <div className="flex items-center gap-2.5">
                    <ExternalLink className="h-3.5 w-3.5 text-text-faint" />
                    <span>Switch to Classic V1 Admin UI</span>
                  </div>
                </Command.Item>
              </Command.Group>
            </Command.List>
          </Command>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
